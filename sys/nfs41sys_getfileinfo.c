/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2026 Roland Mainz <roland.mainz@nrubsig.org>
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

#define MINIRDR__NAME MRxNFS41
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


NTSTATUS marshal_nfs41_filequery(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status)
        goto out;
    tmp += *len;

    header_len = *len + 2 * sizeof(ULONG);
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_filequery: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_filequery: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_filequery: class=%d\n", entry->u.QueryFile.InfoClass);
#endif
out:
    return status;
}

void unmarshal_nfs41_getattr(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
#ifdef NFS41_WINSTREAMS_SUPPORT
    if (cur->u.QueryFile.InfoClass == FileStreamInformation) {
        /* FIXME: If we do a partial read, what happens to ChangeTime below ? */
        unmarshal_nfs41_attrget(cur,
            cur->u.QueryFile.buf, &cur->u.QueryFile.buf_len, buf, TRUE);
    }
    else
#endif /* NFS41_WINSTREAMS_SUPPORT */
    {
        unmarshal_nfs41_attrget(cur,
            cur->u.QueryFile.buf, &cur->u.QueryFile.buf_len, buf, FALSE);
    }

    RtlCopyMemory(&cur->ChangeTime, *buf, sizeof(cur->ChangeTime));
    *buf += sizeof(cur->ChangeTime);
#ifdef DEBUG_MARSHAL_DETAIL
    if (cur->u.QueryFile.InfoClass == FileBasicInformation)
        DbgP("[unmarshal_nfs41_getattr] ChangeTime %llu\n", cur->ChangeTime);
#endif
}

NTSTATUS map_queryfile_error(
    DWORD error)
{
    switch (error) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_NAME:        return STATUS_OBJECT_NAME_INVALID;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_NOT_SUPPORTED:       return STATUS_NOT_SUPPORTED;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_queryfile_error: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)error);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS nfs41_QueryFileInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    nfs41_updowncall_entry *entry = NULL;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_FILE_QUERY
    DbgEn();
    print_debug_filedirquery_header(RxContext);
    DbgP("--> nfs41_QueryFileInformation, RxContext->Info.LengthRemaining=%ld\n",
        (long)RxContext->Info.LengthRemaining);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_dirquery_args(RxContext);
    if (status) {
        print_error("nfs41_QueryFileInformation: "
            "check_nfs41_dirquery_args failed.\n");
        goto out;
    }

    RtlZeroMemory(RxContext->Info.Buffer, RxContext->Info.LengthRemaining);

#ifdef DEBUG_FILE_QUERY
    DbgP("nfs41_QueryFileInformation, RxContext->Info.LengthRemaining=%ld\n",
        (long)RxContext->Info.LengthRemaining);
#endif

    switch (InfoClass) {
#ifdef NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION
    /*
     * |FileNormalizedNameInformation| is specified to return an
     * absolute pathname where each short name component (e.g. 8.3
     * file name) has been replaced with the corresponding long
     * name component, and each name component uses the exact
     * letter casing stored on disk.
     *
     * So if we do not support 8.3 names (i.e.
     * |NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION| being
     * defined) and the exported NFS filesystem is case-sensitive,
     * then just handle |FileNormalizedNameInformation| like
     * |FileNameInformation|.
     */
    case FileNormalizedNameInformation:
    {
        ULONG fsattrs = pVNetRootContext->FsAttrs.FileSystemAttributes;

        /*
         * FIXME: If the underlying filesystem is case-insensitive we
         * would have to make an upcall to fetch the exact casing
         * from our namecache or the NFS server.
         */
        if ((fsattrs & FILE_CASE_SENSITIVE_SEARCH) == 0) {
            print_error("nfs41_QueryFileInformation: "
                "FileNormalizedNameInformation not supported for "
                "case-insensitive filesystems\n");
            status = STATUS_NOT_SUPPORTED;
            goto out;
        }

        if (RxContext->Info.LengthRemaining <
            FIELD_OFFSET(FILE_NAME_INFORMATION, FileName)) {
            RxContext->Info.Length = 0;
            status = STATUS_BUFFER_OVERFLOW;
            goto out;
        }

        PFILE_NAME_INFORMATION nameinfo =
            (PFILE_NAME_INFORMATION)RxContext->Info.Buffer;
        RxContext->Info.LengthRemaining -=
            FIELD_OFFSET(FILE_NAME_INFORMATION, FileName);

        RxConjureOriginalName((PFCB)RxContext->pFcb,
            (PFOBX)RxContext->pFobx,
            &nameinfo->FileNameLength,
            &nameinfo->FileName[0],
            &RxContext->Info.Length,
            VNetRoot_As_UNC_Name);

        if (RxContext->Info.LengthRemaining < 0) {
            RxContext->Info.Length = 0;
            status = STATUS_BUFFER_OVERFLOW;
            goto out;
        }

        status = STATUS_SUCCESS;
        goto out;
    }
#endif /* NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION */
    /*
     * |FileNetworkPhysicalNameInformation| - return UNC path -
     * basically the same logic as |FileNormalizedNameInformation|
     * above in our case (but without the 8.3 filename
     * restrictions).
     */
    case FileNetworkPhysicalNameInformation:
    {
        if (RxContext->Info.LengthRemaining <
            FIELD_OFFSET(FILE_NAME_INFORMATION, FileName)) {
            RxContext->Info.Length = 0;
            status = STATUS_BUFFER_OVERFLOW;
            goto out;
        }

        PFILE_NETWORK_PHYSICAL_NAME_INFORMATION fnpni =
            (PFILE_NETWORK_PHYSICAL_NAME_INFORMATION)
                RxContext->Info.Buffer;
        RxContext->Info.LengthRemaining -=
            FIELD_OFFSET(FILE_NETWORK_PHYSICAL_NAME_INFORMATION,
            FileName);

        RxConjureOriginalName((PFCB)RxContext->pFcb,
            (PFOBX)RxContext->pFobx,
            &fnpni->FileNameLength,
            &fnpni->FileName[0],
            &RxContext->Info.Length,
            VNetRoot_As_UNC_Name);

        if (RxContext->Info.LengthRemaining < 0) {
            RxContext->Info.Length = 0;
            status = STATUS_BUFFER_OVERFLOW;
            goto out;
        }

        status = STATUS_SUCCESS;
        goto out;
    }
    case FileEaInformation:
    {
        if (RxContext->Info.LengthRemaining <
            sizeof(FILE_EA_INFORMATION)) {
            print_error("nfs41_QueryFileInformation: "
                "FILE_EA_INFORMATION buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            goto out;
        }

        PFILE_EA_INFORMATION info =
            (PFILE_EA_INFORMATION)RxContext->Info.Buffer;
        info->EaSize = 0;
        RxContext->Info.LengthRemaining -= sizeof(FILE_EA_INFORMATION);
        status = STATUS_SUCCESS;
        goto out;
    }
    case FileCaseSensitiveInformation:
    {
        if (RxContext->Info.LengthRemaining <
            sizeof(FILE_CASE_SENSITIVE_INFORMATION)) {
            print_error("nfs41_QueryFileInformation: "
                "FILE_CASE_SENSITIVE_INFORMATION buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            goto out;
        }

        PFILE_CASE_SENSITIVE_INFORMATION info =
            (PFILE_CASE_SENSITIVE_INFORMATION)RxContext->Info.Buffer;

        ULONG fsattrs = pVNetRootContext->FsAttrs.FileSystemAttributes;

        /*
         * For NFSv4.1 |FATTR4_WORD0_CASE_INSENSITIVE| used
         * to fill |FsAttrs.FileSystemAttributes| is per
         * filesystem.
         * FIXME: Future NFSv4.x standards should make this a
         * per-filesystem, per-directory and
         * per-extended-attribute-dir attribute to support
         * Win32
         */
        if (fsattrs & FILE_CASE_SENSITIVE_SEARCH) {
            info->Flags = FILE_CS_FLAG_CASE_SENSITIVE_DIR;
        }

        RxContext->Info.LengthRemaining -=
            sizeof(FILE_CASE_SENSITIVE_INFORMATION);
        status = STATUS_SUCCESS;
        goto out;
    }
    case FileBasicInformation:
    case FileStandardInformation:
    case FileInternalInformation:
    case FileAttributeTagInformation:
    case FileNetworkOpenInformation:
    case FileRemoteProtocolInformation:
    case FileIdInformation:
#ifdef NFS41_DRIVER_WSL_SUPPORT
    case FileStatInformation:
    case FileStatLxInformation:
#endif /* NFS41_DRIVER_WSL_SUPPORT */
#ifdef NFS41_WINSTREAMS_SUPPORT
    case FileStreamInformation:
#endif /* NFS41_WINSTREAMS_SUPPORT */
        break;
    default:
        print_error("nfs41_QueryFileInformation: "
            "unhandled class %d\n", (int)InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_FILE_QUERY, &nfs41_srvopen->sec_ctx,
        pVNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) {
        print_error("nfs41_QueryFileInformation: "
            "nfs41_UpcallCreate() failed, status=0x%lx\n",
            (long)status);
        goto out;
    }

    entry->u.QueryFile.InfoClass = InfoClass;
    entry->u.QueryFile.buf = RxContext->Info.Buffer;
    entry->u.QueryFile.buf_len = RxContext->Info.LengthRemaining;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->u.QueryFile.buf_len;
        print_error("nfs41_QueryFileInformation: "
            "entry->status == STATUS_BUFFER_TOO_SMALL\n");
        status = STATUS_BUFFER_TOO_SMALL;
    }
    else
#ifdef NFS41_WINSTREAMS_SUPPORT
    if ((InfoClass == FileStreamInformation) &&
        (entry->status == STATUS_BUFFER_OVERFLOW)) {
        /*
         * |FileStreamInformation| must return |STATUS_BUFFER_OVERFLOW| if
         * the buffer is too small to store all data
         */
        RxContext->InformationToReturn = entry->u.QueryFile.buf_len;
        print_error("nfs41_QueryFileInformation: "
            "FileStreamInformation: "
            "entry->status == STATUS_BUFFER_OVERFLOW\n");
        status = STATUS_BUFFER_OVERFLOW;
    } else
#endif /* NFS41_WINSTREAMS_SUPPORT */
    if (entry->status == STATUS_SUCCESS) {
#ifdef DEBUG_FILE_QUERY
        print_error("nfs41_QueryFileInformation: entry->status == STATUS_SUCCESS\n");
#endif
        BOOLEAN DeletePending = FALSE;
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getattr.sops);
        InterlockedAdd64(&getattr.size, entry->u.QueryFile.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->u.QueryFile.buf_len;
        status = STATUS_SUCCESS;

        switch (InfoClass) {
        case FileBasicInformation:
            RtlCopyMemory(&nfs41_fcb->BasicInfo, RxContext->Info.Buffer,
                sizeof(nfs41_fcb->BasicInfo));
#ifdef DEBUG_FILE_QUERY
            print_basic_info(1, &nfs41_fcb->BasicInfo);
#endif
            break;
        case FileStandardInformation:
            /* this a fix for RDBSS behaviour when it first calls ExtendForCache,
             * then it sends a file query irp for standard attributes and
             * expects to receive EndOfFile of value set by the ExtendForCache.
             * It seems to cache the filesize based on that instead of sending
             * a file size query for after doing the write.
             */
        {
            PFILE_STANDARD_INFORMATION std_info;
            std_info = (PFILE_STANDARD_INFORMATION)RxContext->Info.Buffer;
            if (nfs41_fcb->StandardInfo.AllocationSize.QuadPart >
                    std_info->AllocationSize.QuadPart) {
#ifdef DEBUG_FILE_QUERY
                DbgP("Old AllocationSize is bigger: saving 0x%llx\n",
                    (long long)nfs41_fcb->StandardInfo.AllocationSize.QuadPart);
#endif
                std_info->AllocationSize.QuadPart =
                    nfs41_fcb->StandardInfo.AllocationSize.QuadPart;
            }
            if (nfs41_fcb->StandardInfo.EndOfFile.QuadPart >
                    std_info->EndOfFile.QuadPart) {
#ifdef DEBUG_FILE_QUERY
                DbgP("Old EndOfFile is bigger: saving 0x%llx\n",
                    (long long)nfs41_fcb->StandardInfo.EndOfFile.QuadPart);
#endif
                std_info->EndOfFile.QuadPart =
                    nfs41_fcb->StandardInfo.EndOfFile.QuadPart;
            }
            std_info->DeletePending = nfs41_fcb->DeletePending;
        }
            if (nfs41_fcb->StandardInfo.DeletePending)
                DeletePending = TRUE;
            RtlCopyMemory(&nfs41_fcb->StandardInfo, RxContext->Info.Buffer,
                sizeof(nfs41_fcb->StandardInfo));
            nfs41_fcb->StandardInfo.DeletePending = DeletePending;
#ifdef DEBUG_FILE_QUERY
            print_std_info(1, &nfs41_fcb->StandardInfo);
#endif
            break;
        case FileNetworkOpenInformation:
        case FileRemoteProtocolInformation:
        case FileIdInformation:
        case FileInternalInformation:
        case FileAttributeTagInformation:
#ifdef NFS41_DRIVER_WSL_SUPPORT
        case FileStatInformation:
        case FileStatLxInformation:
#endif /* NFS41_DRIVER_WSL_SUPPORT */
#ifdef NFS41_WINSTREAMS_SUPPORT
        case FileStreamInformation:
#endif /* NFS41_WINSTREAMS_SUPPORT */
            break;
        default:
            print_error("nfs41_QueryFileInformation: "
                "Unhandled/unsupported InfoClass(%d)\n", (int)InfoClass);
        }
    } else {
        status = map_queryfile_error(entry->status);
        print_error("nfs41_QueryFileInformation: "
            "status(0x%lx) = map_queryfile_error(entry->status(0x%lx));\n",
            (long)status, (long)entry->status);
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&getattr.tops);
    InterlockedAdd64(&getattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryFileInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, getattr.tops, getattr.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_FILE_QUERY
    DbgEx();
    DbgP("<-- nfs41_QueryFileInformation, status=0x%lx\n",
        (long)status);
#endif
    return status;
}
