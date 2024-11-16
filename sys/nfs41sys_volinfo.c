/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 * Roland Mainz <roland.mainz@nrubsig.org>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at
 * your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * without any warranty; without even the implied warranty of merchantability
 * or fitness for a particular purpose.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 */

#ifndef _KERNEL_MODE
#error module requires kernel mode
#endif

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

/* FIXME: Why does VS22 need this, but not VC19 ? */
#if _MSC_VER >= 1900
#if defined(_WIN64) && defined(_M_X64)
#ifndef _AMD64_
#define _AMD64_
#endif
#elif defined(_WIN32) && defined(_M_IX86)
#ifndef _X86_
#define _X86_
#endif
#elif defined(_WIN64) && defined(_M_ARM64)
#ifndef _ARM64_
#define _ARM64_
#endif
#elif defined(_WIN32) && defined(_M_ARM)
#ifndef _ARM_
#define _ARM_
#endif
#else
#error Unsupported arch
#endif
#endif /* _MSC_VER >= 1900 */

#define MINIRDR__NAME "Value is ignored, only fact of definition"
#include <rx.h>
#include <windef.h>
#include <winerror.h>

#include <Ntstrsafe.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"


NTSTATUS marshal_nfs41_volume(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status) goto out;
    else tmp += *len;

    header_len = *len + sizeof(FS_INFORMATION_CLASS);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Volume.query, sizeof(FS_INFORMATION_CLASS));
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_volume: class=%d\n", entry->u.Volume.query);
#endif
out:
    return status;
}

void unmarshal_nfs41_attrget(
    nfs41_updowncall_entry *cur,
    PVOID attr_value,
    ULONG *attr_len,
    unsigned char **buf)
{
    ULONG buf_len;
    RtlCopyMemory(&buf_len, *buf, sizeof(ULONG));
    if (buf_len > *attr_len) {
        cur->status = STATUS_BUFFER_TOO_SMALL;
        return;
    }
    *buf += sizeof(ULONG);
    *attr_len = buf_len;
    RtlCopyMemory(attr_value, *buf, buf_len);
    *buf += buf_len;
}

static void print_queryvolume_args(
    PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = '%s' BufferLen = %d\n",
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext),
        print_fs_information_class(RxContext->Info.FileInformationClass),
        RxContext->Info.LengthRemaining);
}

NTSTATUS map_volume_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_VC_DISCONNECTED:     return STATUS_CONNECTION_DISCONNECTED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_volume_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

void nfs41_create_volume_info(PFILE_FS_VOLUME_INFORMATION pVolInfo, DWORD *len)
{
    DECLARE_CONST_UNICODE_STRING(VolName, VOL_NAME);

    RtlZeroMemory(pVolInfo, sizeof(FILE_FS_VOLUME_INFORMATION));
    pVolInfo->VolumeSerialNumber = 0xBABAFACE;
    pVolInfo->VolumeLabelLength = VolName.Length;
    RtlCopyMemory(&pVolInfo->VolumeLabel[0], (PVOID)VolName.Buffer,
        VolName.MaximumLength);
    *len = sizeof(FILE_FS_VOLUME_INFORMATION) + VolName.Length;
}

NTSTATUS nfs41_QueryVolumeInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    ULONG RemainingLength = RxContext->Info.LengthRemaining, SizeUsed;
    FS_INFORMATION_CLASS InfoClass = RxContext->Info.FsInformationClass;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    NFS41GetDeviceExtension(RxContext, DevExt);

#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_VOLUME_QUERY
    DbgEn();
    print_queryvolume_args(RxContext);
#endif

    status = check_nfs41_dirquery_args(RxContext);
    if (status) goto out;

    RtlZeroMemory(RxContext->Info.Buffer, RxContext->Info.LengthRemaining);

    switch (InfoClass) {
    case FileFsVolumeInformation:
        if ((ULONG)RxContext->Info.LengthRemaining >= DevExt->VolAttrsLen) {
            RtlCopyMemory(RxContext->Info.Buffer, DevExt->VolAttrs,
                DevExt->VolAttrsLen);
            RxContext->Info.LengthRemaining -= DevExt->VolAttrsLen;
            status = STATUS_SUCCESS;
        } else {
            RtlCopyMemory(RxContext->Info.Buffer, DevExt->VolAttrs,
                RxContext->Info.LengthRemaining);
            status = STATUS_BUFFER_OVERFLOW;
        }
        goto out;
    case FileFsDeviceInformation:
    {
        PFILE_FS_DEVICE_INFORMATION pDevInfo = RxContext->Info.Buffer;

        SizeUsed = sizeof(FILE_FS_DEVICE_INFORMATION);
        if (RemainingLength < SizeUsed) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = SizeUsed;
            goto out;
        }
        pDevInfo->DeviceType = RxContext->pFcb->pNetRoot->DeviceType;
        pDevInfo->Characteristics = FILE_REMOTE_DEVICE | FILE_DEVICE_IS_MOUNTED;
        RxContext->Info.LengthRemaining -= SizeUsed;
        status = STATUS_SUCCESS;
        goto out;
    }
    case FileAccessInformation:
        status = STATUS_NOT_SUPPORTED;
        goto out;

    case FileFsAttributeInformation:
        if (RxContext->Info.LengthRemaining < FS_ATTR_LEN) {
            RxContext->InformationToReturn = FS_ATTR_LEN;
            status = STATUS_BUFFER_TOO_SMALL;
            goto out;
        }

        /* on attribute queries for the root directory,
         * use cached volume attributes from mount */
        if (is_root_directory(RxContext)) {
            PFILE_FS_ATTRIBUTE_INFORMATION attrs =
                (PFILE_FS_ATTRIBUTE_INFORMATION)RxContext->Info.Buffer;
            DECLARE_CONST_UNICODE_STRING(FsName, FS_NAME);

            RtlCopyMemory(attrs, &pVNetRootContext->FsAttrs,
                sizeof(pVNetRootContext->FsAttrs));

            /* fill in the FileSystemName */
            RtlCopyMemory(attrs->FileSystemName, FsName.Buffer,
                FsName.MaximumLength); /* 'MaximumLength' to include null */
            attrs->FileSystemNameLength = FsName.Length;

            RxContext->Info.LengthRemaining -= FS_ATTR_LEN;
            goto out;
        }
        /* else fall through and send the upcall */
    case FileFsSizeInformation:
    case FileFsFullSizeInformation:
        break;

    default:
        print_error("nfs41_QueryVolumeInformation: unhandled class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }
    status = nfs41_UpcallCreate(NFS41_SYSOP_VOLUME_QUERY, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Volume.query = InfoClass;
    entry->buf = RxContext->Info.Buffer;
    entry->buf_len = RxContext->Info.LengthRemaining;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) goto out;

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
        if (InfoClass == FileFsAttributeInformation) {
            /* fill in the FileSystemName */
            PFILE_FS_ATTRIBUTE_INFORMATION attrs =
                (PFILE_FS_ATTRIBUTE_INFORMATION)RxContext->Info.Buffer;
            DECLARE_CONST_UNICODE_STRING(FsName, FS_NAME);

            RtlCopyMemory(attrs->FileSystemName, FsName.Buffer,
                FsName.MaximumLength); /* 'MaximumLength' to include null */
            attrs->FileSystemNameLength = FsName.Length;

            entry->buf_len = FS_ATTR_LEN;
        }
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&volume.sops);
        InterlockedAdd64(&volume.size, entry->u.Volume.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->buf_len;
        status = STATUS_SUCCESS;
    } else {
        status = map_volume_errors(entry->status);
    }
    nfs41_UpcallDestroy(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&volume.tops);
    InterlockedAdd64(&volume.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryVolumeInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, volume.tops, volume.ticks);
#endif
#endif
#ifdef DEBUG_VOLUME_QUERY
    DbgEx();
#endif
    return status;
}
