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
    if (status) goto out;
    else tmp += *len;

    header_len = *len + 2 * sizeof(ULONG);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->buf_len, sizeof(ULONG));
    /* tmp += sizeof(ULONG); */
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_filequery: class=%d\n", entry->u.QueryFile.InfoClass);
#endif
out:
    return status;
}

NTSTATUS marshal_nfs41_fileset(
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
        2 * sizeof(ULONG) + entry->buf_len;
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.SetFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->buf, entry->buf_len);
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_fileset: filename='%wZ' class=%d\n",
        entry->filename, entry->u.SetFile.InfoClass);
#endif
out:
    return status;
}

void unmarshal_nfs41_setattr(
    nfs41_updowncall_entry *cur,
    PULONGLONG dest_buf,
    const unsigned char *restrict *restrict buf)
{
    RtlCopyMemory(dest_buf, *buf, sizeof(*dest_buf));
    *buf += sizeof(*dest_buf);
#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("unmarshal_nfs41_setattr: returned ChangeTime %llu\n", *dest_buf);
#endif
}

void unmarshal_nfs41_getattr(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    unmarshal_nfs41_attrget(cur, cur->buf, &cur->buf_len, buf, FALSE);
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
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
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

#ifdef DEBUG_FILE_QUERY
    DbgEn();
    print_debug_filedirquery_header(RxContext);
    DbgP("--> nfs41_QueryFileInformation, RxContext->Info.LengthRemaining=%ld\n",
        (long)RxContext->Info.LengthRemaining);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_dirquery_args(RxContext);
    if (status) {
        print_error("check_nfs41_dirquery_args failed.\n");
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
        break;
    default:
        print_error("nfs41_QueryFileInformation: unhandled class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_FILE_QUERY, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) {
        print_error("nfs41_UpcallCreate() failed, status=0x%lx\n",
            (long)status);
        goto out;
    }

    entry->u.QueryFile.InfoClass = InfoClass;
    entry->buf = RxContext->Info.Buffer;
    entry->buf_len = RxContext->Info.LengthRemaining;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn = entry->buf_len;
        print_error("entry->status == STATUS_BUFFER_TOO_SMALL\n");
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
#ifdef DEBUG_FILE_QUERY
        print_error("entry->status == STATUS_SUCCESS\n");
#endif
        BOOLEAN DeletePending = FALSE;
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getattr.sops);
        InterlockedAdd64(&getattr.size, entry->u.QueryFile.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->buf_len;
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
            break;
        default:
            print_error("Unhandled/unsupported InfoClass(%d)\n", (int)InfoClass);
        }
    } else {
        status = map_queryfile_error(entry->status);
        print_error("status(0x%lx) = map_queryfile_error(entry->status(0x%lx));\n",
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

NTSTATUS map_setfile_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_DIR_NOT_EMPTY:           return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_DIRECTORY_NOT_SUPPORTED: return STATUS_FILE_IS_A_DIRECTORY;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_NOT_SAME_DEVICE:         return STATUS_NOT_SAME_DEVICE;
    case ERROR_NOT_SUPPORTED:           return STATUS_NOT_IMPLEMENTED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_DISK_FULL:               return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED:     return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:          return STATUS_FILE_TOO_LARGE;
    case ERROR_INSUFFICIENT_BUFFER:     return STATUS_BUFFER_TOO_SMALL;
    case ERROR_MORE_DATA:               return STATUS_BUFFER_OVERFLOW;
    case ERROR_INTERNAL_ERROR:          return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_setfile_error: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_PARAMETER\n",
            (long)error);
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    }
}

static
NTSTATUS check_nfs41_setattr_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);

    if (pVNetRootContext->read_only) {
        print_error("check_nfs41_setattr_args: Read-only mount\n");
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }

    /* http://msdn.microsoft.com/en-us/library/ff469355(v=PROT.10).aspx
     * http://msdn.microsoft.com/en-us/library/ff469424(v=PROT.10).aspx
     * If Open.GrantedAccess does not contain FILE_WRITE_DATA, the operation
     * MUST be failed with STATUS_ACCESS_DENIED.
     */
    if (InfoClass == FileAllocationInformation ||
            InfoClass == FileEndOfFileInformation) {
        if (!(RxContext->pRelevantSrvOpen->DesiredAccess & FILE_WRITE_DATA)) {
            status = STATUS_ACCESS_DENIED;
            goto out;
        }
    }
    status = check_nfs41_dirquery_args(RxContext);
    if (status) goto out;

    switch (InfoClass) {
    case FileRenameInformation:
    {
        PFILE_RENAME_INFORMATION rinfo =
            (PFILE_RENAME_INFORMATION)RxContext->Info.Buffer;
        UNICODE_STRING dst = { (USHORT)rinfo->FileNameLength,
            (USHORT)rinfo->FileNameLength, rinfo->FileName };
#ifdef DEBUG_FILE_SET
        DbgP("Attempting to rename to '%wZ'\n", &dst);
#endif
        if (isFilenameTooLong(&dst, pVNetRootContext)) {
            status = STATUS_OBJECT_NAME_INVALID;
            goto out;
        }
        if (rinfo->RootDirectory) {
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        break;
    }
    case FileLinkInformation:
    {
        PFILE_LINK_INFORMATION linfo =
            (PFILE_LINK_INFORMATION)RxContext->Info.Buffer;
        UNICODE_STRING dst = { (USHORT)linfo->FileNameLength,
            (USHORT)linfo->FileNameLength, linfo->FileName };
#ifdef DEBUG_FILE_SET
        DbgP("Attempting to add link as '%wZ'\n", &dst);
#endif
        if (isFilenameTooLong(&dst, pVNetRootContext)) {
            status = STATUS_OBJECT_NAME_INVALID;
            goto out;
        }
        if (linfo->RootDirectory) {
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        break;
    }
    case FileDispositionInformation:
    {
        PFILE_DISPOSITION_INFORMATION dinfo =
            (PFILE_DISPOSITION_INFORMATION)RxContext->Info.Buffer;
        __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
        if (dinfo->DeleteFile && nfs41_fcb->DeletePending) {
            status = STATUS_DELETE_PENDING;
            goto out;
        }
        break;
    }
    case FileBasicInformation:
    case FileAllocationInformation:
    case FileEndOfFileInformation:
        break;
    default:
        print_error("nfs41_SetFileInformation: unhandled class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
    }

out:
    return status;
}

NTSTATUS nfs41_SetFileInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry = NULL;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;

#ifdef FORCE_POSIX_SEMANTICS_DELETE
    FILE_RENAME_INFORMATION rinfo;
#endif /* FORCE_POSIX_SEMANTICS_DELETE */
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

#ifdef DEBUG_FILE_SET
    DbgEn();
    print_debug_filedirquery_header(RxContext);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_setattr_args(RxContext);
    if (status) goto out;

    switch (InfoClass) {
    case FileDispositionInformation:
        {
            PFILE_DISPOSITION_INFORMATION dinfo =
                (PFILE_DISPOSITION_INFORMATION)RxContext->Info.Buffer;
            if (dinfo->DeleteFile) {
#ifdef FORCE_POSIX_SEMANTICS_DELETE
                /*
                 * Do POSIX-style delete here, i.e. what
                 * |FILE_DISPOSITION_INFORMATION_EX.Flags &
                 * FILE_DISPOSITION_POSIX_SEMANTICS| would do
                 */
                nfs41_fcb->DeletePending = TRUE;
                /*
                 * We can delete directories right away
                 * (NTFS allows deleting a dir which has open handles)
                 */
                if (nfs41_fcb->StandardInfo.Directory)
                    break;
                nfs41_fcb->StandardInfo.DeletePending = TRUE;
                if (RxContext->pFcb->OpenCount > 1) {
                    rinfo.ReplaceIfExists = 0;
                    rinfo.RootDirectory = INVALID_HANDLE_VALUE;
                    rinfo.FileNameLength = 0;
                    rinfo.FileName[0] = L'\0';
                    InfoClass = FileRenameInformation;
                    nfs41_fcb->Renamed = TRUE;
                    break;
                }
#else
                /* Do Win32 delete-on-close */
                /*
                 * We must make sure that this works and still returns errors
                 * to the caller, e.g. rm -Rf on a readonly dir must return
                 * an error.
                 *
                 * Example:
                 * ---- snip ----
                 * $ ksh93 -c 'mkdir d1 && touch d1/f1 && chmod -R a-w d1 &&
                 *      if rm -Rf d1 ; then echo "# Test failed" ; else
                 *      echo "# Test OK" ; fi'
                 * rm: cannot remove 'd1': Permission denied
                 * # Test OK
                s * ---- snip ----
                 */
                nfs41_fcb->DeletePending = TRUE;
                nfs41_fcb->StandardInfo.DeletePending = TRUE;
#endif /* FORCE_POSIX_SEMANTICS_DELETE */
            } else {
                /* section 4.3.3 of [FSBO]
                 * "file system behavior in the microsoft windows environment"
                 */
                if (nfs41_fcb->DeletePending) {
                    nfs41_fcb->DeletePending = 0;
                    nfs41_fcb->StandardInfo.DeletePending = 0;
                }
            }
            status = STATUS_SUCCESS;
            goto out;
        }
    case FileAllocationInformation:
        {
            PFILE_ALLOCATION_INFORMATION info =
                (PFILE_ALLOCATION_INFORMATION)RxContext->Info.Buffer;

            nfs41_fcb->StandardInfo.AllocationSize.QuadPart = info->AllocationSize.QuadPart;
            break;
        }
    case FileEndOfFileInformation:
        {
            PFILE_END_OF_FILE_INFORMATION info =
                (PFILE_END_OF_FILE_INFORMATION)RxContext->Info.Buffer;

            nfs41_fcb->StandardInfo.EndOfFile.QuadPart = info->EndOfFile.QuadPart;
            break;
        }
    case FileRenameInformation:
        {
            /* noop if filename and destination are the same */
            PFILE_RENAME_INFORMATION prinfo =
                (PFILE_RENAME_INFORMATION)RxContext->Info.Buffer;
            const UNICODE_STRING dst = { (USHORT)prinfo->FileNameLength,
                (USHORT)prinfo->FileNameLength, prinfo->FileName };
            if (RtlCompareUnicodeString(&dst,
                    SrvOpen->pAlreadyPrefixedName, FALSE) == 0) {
                status = STATUS_SUCCESS;
                goto out;
            }
        }
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_FILE_SET, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.SetFile.InfoClass = InfoClass;

#ifdef FORCE_POSIX_SEMANTICS_DELETE
    /* original irp has infoclass for remove but we need to rename instead,
     * thus we changed the local variable infoclass */
    if (RxContext->Info.FileInformationClass == FileDispositionInformation &&
            InfoClass == FileRenameInformation) {
        entry->buf = &rinfo;
        entry->buf_len = sizeof(rinfo);
    }
    else
#endif /* FORCE_POSIX_SEMANTICS_DELETE */
    {
        entry->buf = RxContext->Info.Buffer;
        entry->buf_len = RxContext->Info.Length;
    }
#ifdef ENABLE_TIMINGS
    InterlockedIncrement(&setattr.sops);
    InterlockedAdd64(&setattr.size, entry->u.SetFile.buf_len);
#endif

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_setfile_error(entry->status);
    if (!status) {
        if (!nfs41_fobx->deleg_type && entry->ChangeTime &&
                (SrvOpen->DesiredAccess &
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_fcb_list(RxContext->pFcb, entry->ChangeTime);
        nfs41_fcb->changeattr = entry->ChangeTime;
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setattr.tops);
    InterlockedAdd64(&setattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetFileInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, setattr.tops, setattr.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_FILE_SET
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_SetFileInformationAtCleanup(
      IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    DbgEn();
    status = nfs41_SetFileInformation(RxContext);
    DbgEx();
    return status;
}
