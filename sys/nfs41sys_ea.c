/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
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

NTSTATUS marshal_nfs41_easet(
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

    header_len = *len + length_as_utf8(entry->filename) +
        sizeof(ULONG) + entry->buf_len  + sizeof(DWORD);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = marshall_unicode_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.SetEa.mode, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->buf, entry->buf_len);
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_easet: filename='%wZ', buflen=%d mode=0x%x\n",
        entry->filename,
        (int)entry->buf_len,
        (int)entry->u.SetEa.mode);
#endif
out:
    return status;
}

NTSTATUS marshal_nfs41_eaget(
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

    header_len = *len + length_as_utf8(entry->filename) +
        3 * sizeof(ULONG) + entry->u.QueryEa.EaListLength + 2 * sizeof(BOOLEAN);

    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = marshall_unicode_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.QueryEa.EaIndex, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryEa.RestartScan, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryEa.ReturnSingleEntry, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->u.QueryEa.EaListLength, sizeof(ULONG));
    tmp += sizeof(ULONG);
    if (entry->u.QueryEa.EaList && entry->u.QueryEa.EaListLength)
        RtlCopyMemory(tmp, entry->u.QueryEa.EaList,
            entry->u.QueryEa.EaListLength);
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_eaget: filename='%wZ', index=%d list_len=%d "
        "rescan=%d single=%d\n", entry->filename,
        entry->u.QueryEa.EaIndex, entry->u.QueryEa.EaListLength,
        entry->u.QueryEa.RestartScan, entry->u.QueryEa.ReturnSingleEntry);
#endif
out:
    return status;
}

void unmarshal_nfs41_eaget(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    RtlCopyMemory(&cur->u.QueryEa.Overflow, *buf, sizeof(ULONG));
    *buf += sizeof(ULONG);
    RtlCopyMemory(&cur->buf_len, *buf, sizeof(ULONG));
    *buf += sizeof(ULONG);
    if (cur->u.QueryEa.Overflow != ERROR_INSUFFICIENT_BUFFER) {
        RtlCopyMemory(cur->buf, *buf, cur->buf_len);
        *buf += cur->buf_len;
    }
}

static void print_nfs3_attrs(
    nfs3_attrs *attrs)
{
    DbgP("type=%d mode=0%o nlink=%d "
        "size=%lld used=%lld"
        "atime=(tv_sec=%ld,tv_nsec=%lu) "
        "mtime=(tv_sec=%ld,tv_nsec=%lu) "
        "ctime=(tv_sec=%ld,tv_nsec=%lu)\n",
        attrs->type, attrs->mode, attrs->nlink,
        (long long)attrs->size, (long long)attrs->used,
        (long)attrs->atime.tv_sec, (unsigned long)attrs->atime.tv_nsec,
        (long)attrs->mtime.tv_sec, (unsigned long)attrs->mtime.tv_nsec,
        (long)attrs->ctime.tv_sec, (unsigned long)attrs->ctime.tv_nsec);
}

static void file_time_to_nfs_time(
    IN const PLARGE_INTEGER file_time,
    OUT nfs3_attrs_timestruc_t *nfs_time)
{
    if (file_time->QuadPart == FILE_INFO_TIME_NOT_SET) {
        /*
         * Return tv_sec==-1 to indicate that this
         * value is not supported
         */
        nfs_time->tv_sec = -1L;
        nfs_time->tv_nsec = ~0UL;
        return;
    }

    /*
     * Win32 timestamps (|time_file|) use 100-nanosecond intervals
     * (10000000 intervals == one second) since January 1, 1601 (UTC),
     * while "old UNIX" timestamps count in seconds since 00:00:00 UTC
     * on 1 January 1970
     */
    LARGE_INTEGER diff = unix_time_diff;
    diff.QuadPart = file_time->QuadPart - diff.QuadPart;
    nfs_time->tv_sec  = (INT32)(diff.QuadPart / 10000000LL);
    nfs_time->tv_nsec = (UINT32)((diff.QuadPart % 10000000LL) * 100LL);
}

static void create_nfs3_attrs(
    nfs3_attrs *attrs,
    PNFS41_FCB nfs41_fcb)
{
    RtlZeroMemory(attrs, sizeof(nfs3_attrs));
    if (nfs41_fcb->BasicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        attrs->type = NF3LNK;
    else if (nfs41_fcb->StandardInfo.Directory)
        attrs->type = NF3DIR;
    else
        attrs->type = NF3REG;
    attrs->mode = nfs41_fcb->mode;
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    attrs->uid = nfs41_fcb->owner_local_uid;
    attrs->gid = nfs41_fcb->owner_group_local_gid;
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
    attrs->nlink = nfs41_fcb->StandardInfo.NumberOfLinks;
    attrs->size = nfs41_fcb->StandardInfo.EndOfFile.QuadPart;
    attrs->used = nfs41_fcb->StandardInfo.AllocationSize.QuadPart;

    /*
     * NFSv4.1 |nfs41_fsid| contains two 64bit fields (|major|,
     * |minor|), but the |nfs3_attrs.fsid| field is only one 64bit
     * value.
     *
     * For now we XOR both |nfs41_fsid.major|^|nfs41_fsid.minor|
     * to avoid loosing data and to deal with NFSv4.1 filesystems
     * which might have |0| in either |nfs41_fsid.major| or
     * |nfs41_fsid.minor|.
     */
    attrs->fsid = nfs41_fcb->fsid_major ^ nfs41_fcb->fsid_minor;
    attrs->fileid = nfs41_fcb->fileid;
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.LastAccessTime, &attrs->atime);
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.LastWriteTime, &attrs->mtime);
    file_time_to_nfs_time(&nfs41_fcb->BasicInfo.ChangeTime, &attrs->ctime);
}


NTSTATUS map_setea_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_FILE_NOT_FOUND:          return STATUS_NO_EAS_ON_FILE;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_FILE_TOO_LARGE:          return STATUS_EA_TOO_LARGE;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_BUFFER_OVERFLOW;
    case STATUS_BUFFER_TOO_SMALL:
    case ERROR_INSUFFICIENT_BUFFER:     return STATUS_BUFFER_TOO_SMALL;
    case ERROR_INVALID_EA_HANDLE:       return STATUS_NONEXISTENT_EA_ENTRY;
    case ERROR_NO_MORE_FILES:           return STATUS_NO_MORE_EAS;
    case ERROR_EA_FILE_CORRUPT:         return STATUS_EA_CORRUPT_ERROR;
    case ERROR_DISK_FULL:               return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED:     return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_INTERNAL_ERROR:          return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_setea_error: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_PARAMETER\n",
            (long)error);
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS check_nfs41_setea_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);
    __notnull NFS41_FILE_FS_ATTRIBUTE_INFORMATION *FsAttrs =
        &pVNetRootContext->FsAttrs;
    __notnull PFILE_FULL_EA_INFORMATION ea =
        (PFILE_FULL_EA_INFORMATION)RxContext->Info.Buffer;

    status = check_nfs41_dirquery_args(RxContext);
    if (status) goto out;

    if (ea == NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    if (AnsiStrEq(&NfsActOnLink, ea->EaName, ea->EaNameLength) ||
        AnsiStrEq(&NfsSymlinkTargetName, ea->EaName, ea->EaNameLength)) {
        status = STATUS_INVALID_PARAMETER; /* only allowed on create */
        goto out;
    }
    /* ignore cygwin EAs when checking support */
    if (!(FsAttrs->FileSystemAttributes & FILE_SUPPORTS_EXTENDED_ATTRIBUTES)
        && !AnsiStrEq(&NfsV3Attributes, ea->EaName, ea->EaNameLength)) {
        status = STATUS_EAS_NOT_SUPPORTED;
        goto out;
    }
    if ((RxContext->pRelevantSrvOpen->DesiredAccess & FILE_WRITE_EA) == 0) {
        status = STATUS_ACCESS_DENIED;
        goto out;
    }
    if (pVNetRootContext->read_only) {
        print_error("check_nfs41_setattr_args: Read-only mount\n");
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_SetEaInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_EAS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry = NULL;
    __notnull PFILE_FULL_EA_INFORMATION eainfo =
        (PFILE_FULL_EA_INFORMATION)RxContext->Info.Buffer;
    nfs3_attrs *attrs = NULL;
    ULONG buflen = RxContext->CurrentIrpSp->Parameters.SetEa.Length, error_offset;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_EA_SET
    DbgEn();
    print_debug_header(RxContext);
    print_ea_info(eainfo);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_setea_args(RxContext);
    if (status) goto out;

    status = nfs41_UpcallCreate(NFS41_SYSOP_EA_SET, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    if (AnsiStrEq(&NfsV3Attributes, eainfo->EaName, eainfo->EaNameLength)) {
        attrs = (nfs3_attrs *)(eainfo->EaName + eainfo->EaNameLength + 1);
#ifdef DEBUG_EA_SET
        print_nfs3_attrs(attrs);
        DbgP("old mode is 0%o new mode is 0%o\n", nfs41_fcb->mode, attrs->mode);
#endif
        entry->u.SetEa.mode = attrs->mode;
    } else {
        entry->u.SetEa.mode = 0;
        status = IoCheckEaBufferValidity(eainfo, buflen, &error_offset);
        if (status) {
            DbgP("nfs41_SetEaInformation: "
                "status(=0x%lx)=IoCheckEaBufferValidity"
                "(eainfo=0x%p, buflen=%lu, &(error_offset=%d))\n",
                (long)status, (void *)eainfo, buflen,
                (int)error_offset);
            goto out;
        }
    }
    entry->buf = eainfo;
    entry->buf_len = buflen;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }
#ifdef ENABLE_TIMINGS
    if (entry->status == STATUS_SUCCESS) {
        InterlockedIncrement(&setexattr.sops);
        InterlockedAdd64(&setexattr.size, entry->u.SetEa.buf_len);
    }
#endif
    status = map_setea_error(entry->status);
    if (!status) {
        if (!nfs41_fobx->deleg_type && entry->ChangeTime &&
                (SrvOpen->DesiredAccess &
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_fcb_list(RxContext->pFcb, entry->ChangeTime);
        nfs41_fcb->changeattr = entry->ChangeTime;
        nfs41_fcb->mode = entry->u.SetEa.mode;
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setexattr.tops);
    InterlockedAdd64(&setexattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetEaInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, setexattr.tops, setexattr.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_EA_SET
    DbgEx();
#endif
    return status;
}

NTSTATUS check_nfs41_queryea_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);
    __notnull NFS41_FILE_FS_ATTRIBUTE_INFORMATION *FsAttrs =
        &pVNetRootContext->FsAttrs;
    PFILE_GET_EA_INFORMATION ea = (PFILE_GET_EA_INFORMATION)
            RxContext->CurrentIrpSp->Parameters.QueryEa.EaList;

    status = check_nfs41_dirquery_args(RxContext);
    if (status) goto out;

    if (!(FsAttrs->FileSystemAttributes & FILE_SUPPORTS_EXTENDED_ATTRIBUTES)) {
        if (ea == NULL) {
            status = STATUS_EAS_NOT_SUPPORTED;
            goto out;
        }
        /* ignore cygwin EAs when checking support */
        if (!AnsiStrEq(&NfsV3Attributes, ea->EaName, ea->EaNameLength) &&
            !AnsiStrEq(&NfsActOnLink, ea->EaName, ea->EaNameLength) &&
            !AnsiStrEq(&NfsSymlinkTargetName, ea->EaName, ea->EaNameLength)) {
            status = STATUS_EAS_NOT_SUPPORTED;
            goto out;
        }
    }
    if ((RxContext->pRelevantSrvOpen->DesiredAccess & FILE_READ_EA) == 0) {
        status = STATUS_ACCESS_DENIED;
        goto out;
    }
out:
    return status;
}

NTSTATUS QueryCygwinSymlink(
    IN OUT PRX_CONTEXT RxContext,
    IN PFILE_GET_EA_INFORMATION query,
    OUT PFILE_FULL_EA_INFORMATION info)
{
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
            NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION NetRootContext =
            NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    nfs41_updowncall_entry *entry = NULL;
    UNICODE_STRING TargetName;
    const USHORT HeaderLen = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) +
        query->EaNameLength + 1;
    NTSTATUS status;

    if (RxContext->Info.LengthRemaining < HeaderLen) {
        status = STATUS_BUFFER_TOO_SMALL;
        RxContext->InformationToReturn = HeaderLen;
        goto out;
    }

    TargetName.Buffer = (PWCH)(info->EaName + query->EaNameLength + 1);
    TargetName.MaximumLength = (USHORT)min(RxContext->Info.LengthRemaining -
        HeaderLen, 0xFFFF);

    status = nfs41_UpcallCreate(NFS41_SYSOP_SYMLINK_GET, &Fobx->sec_ctx,
        VNetRootContext->session, Fobx->nfs41_open_state,
        NetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Symlink.target = &TargetName;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_setea_error(entry->status);
    if (status == STATUS_SUCCESS) {
        info->NextEntryOffset = 0;
        info->Flags = 0;
        info->EaNameLength = query->EaNameLength;
        info->EaValueLength = TargetName.Length - sizeof(UNICODE_NULL);
        TargetName.Buffer[TargetName.Length/sizeof(WCHAR)] = UNICODE_NULL;
        RtlCopyMemory(info->EaName, query->EaName, query->EaNameLength);
        RxContext->Info.LengthRemaining = HeaderLen + info->EaValueLength;
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = (ULONG_PTR)HeaderLen +
            entry->u.Symlink.target->Length;
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
    return status;
}

NTSTATUS QueryCygwinEA(
    IN OUT PRX_CONTEXT RxContext,
    IN PFILE_GET_EA_INFORMATION query,
    OUT PFILE_FULL_EA_INFORMATION info)
{
    NTSTATUS status = STATUS_NONEXISTENT_EA_ENTRY;

    if (query == NULL)
        goto out;

    if (AnsiStrEq(&NfsSymlinkTargetName, query->EaName, query->EaNameLength)) {
        __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
        if (nfs41_fcb->BasicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
            status = QueryCygwinSymlink(RxContext, query, info);
            goto out;
        } else {
            const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
                NfsSymlinkTargetName.Length - sizeof(CHAR);
            if (LengthRequired > RxContext->Info.LengthRemaining) {
                status = STATUS_BUFFER_TOO_SMALL;
                RxContext->InformationToReturn = LengthRequired;
                goto out;
            }
            info->NextEntryOffset = 0;
            info->Flags = 0;
            info->EaValueLength = 0;
            info->EaNameLength = (UCHAR)NfsActOnLink.Length;
            RtlCopyMemory(info->EaName, NfsSymlinkTargetName.Buffer,
                NfsSymlinkTargetName.Length);
            RxContext->Info.LengthRemaining = LengthRequired;
            status = STATUS_SUCCESS;
            goto out;
        }
    }

    if (AnsiStrEq(&NfsV3Attributes, query->EaName, query->EaNameLength)) {
        nfs3_attrs attrs;

        const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
            NfsV3Attributes.Length + sizeof(nfs3_attrs) - sizeof(CHAR);
        if (LengthRequired > RxContext->Info.LengthRemaining) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = LengthRequired;
            goto out;
        }

        create_nfs3_attrs(&attrs, NFS41GetFcbExtension(RxContext->pFcb));
#ifdef DEBUG_EA_QUERY
        print_nfs3_attrs(&attrs);
#endif

        info->NextEntryOffset = 0;
        info->Flags = 0;
        info->EaNameLength = (UCHAR)NfsV3Attributes.Length;
        info->EaValueLength = sizeof(nfs3_attrs);
        RtlCopyMemory(info->EaName, NfsV3Attributes.Buffer,
            NfsV3Attributes.Length);
        RtlCopyMemory(info->EaName + info->EaNameLength + 1, &attrs,
            sizeof(nfs3_attrs));
        RxContext->Info.LengthRemaining = LengthRequired;
        status = STATUS_SUCCESS;
        goto out;
    }

    if (AnsiStrEq(&NfsActOnLink, query->EaName, query->EaNameLength)) {

        const LONG LengthRequired = sizeof(FILE_FULL_EA_INFORMATION) +
            query->EaNameLength - sizeof(CHAR);
        if (LengthRequired > RxContext->Info.LengthRemaining) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = LengthRequired;
            goto out;
        }

        info->NextEntryOffset = 0;
        info->Flags = 0;
        info->EaNameLength = query->EaNameLength;
        info->EaValueLength = 0;
        RtlCopyMemory(info->EaName, query->EaName, query->EaNameLength);
        RxContext->Info.LengthRemaining = LengthRequired;
        status = STATUS_SUCCESS;
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_QueryEaInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_EAS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry = NULL;
    PFILE_GET_EA_INFORMATION query = (PFILE_GET_EA_INFORMATION)
            RxContext->CurrentIrpSp->Parameters.QueryEa.EaList;
    ULONG buflen = RxContext->CurrentIrpSp->Parameters.QueryEa.Length;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
            NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
            NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_EA_QUERY
    DbgEn();
    print_debug_header(RxContext);
    print_get_ea(1, query);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_queryea_args(RxContext);
    if (status) goto out;

    /* handle queries for cygwin EAs */
    status = QueryCygwinEA(RxContext, query,
        (PFILE_FULL_EA_INFORMATION)RxContext->Info.Buffer);
    if (status != STATUS_NONEXISTENT_EA_ENTRY)
        goto out;

    status = nfs41_UpcallCreate(NFS41_SYSOP_EA_GET, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->buf_len = buflen;
    entry->buf = RxContext->Info.Buffer;
    entry->u.QueryEa.EaList = query;
    entry->u.QueryEa.EaListLength = query == NULL ? 0 :
        RxContext->QueryEa.UserEaListLength;
    entry->u.QueryEa.EaIndex = RxContext->QueryEa.IndexSpecified ?
        RxContext->QueryEa.UserEaIndex : 0;
    entry->u.QueryEa.RestartScan = RxContext->QueryEa.RestartScan;
    entry->u.QueryEa.ReturnSingleEntry = RxContext->QueryEa.ReturnSingleEntry;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (entry->status == STATUS_SUCCESS) {
        switch (entry->u.QueryEa.Overflow) {
        case ERROR_INSUFFICIENT_BUFFER:
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        case ERROR_BUFFER_OVERFLOW:
            status = RxContext->IoStatusBlock.Status = STATUS_BUFFER_OVERFLOW;
            break;
        default:
            RxContext->IoStatusBlock.Status = STATUS_SUCCESS;
            break;
        }
        RxContext->InformationToReturn = entry->buf_len;
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getexattr.sops);
        InterlockedAdd64(&getexattr.size, entry->u.QueryEa.buf_len);
#endif
    } else {
        status = map_setea_error(entry->status);
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&getexattr.tops);
    InterlockedAdd64(&getexattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryEaInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, getexattr.tops, getexattr.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_EA_QUERY
    DbgEx();
#endif
    return status;
}
