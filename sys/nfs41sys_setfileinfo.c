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
    if (status)
        goto out;
    tmp += *len;

    header_len = *len + unicode_filename_length_as_utf8(entry->filename) +
        2 * sizeof(ULONG) + entry->u.SetFile.buf_len;
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_fileset: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_filename_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    UPDOWNCALL_MEMCPY(tmp, &entry->u.SetFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    UPDOWNCALL_MEMCPY(tmp, &entry->u.SetFile.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    UPDOWNCALL_MEMCPY(tmp, entry->u.SetFile.buf, entry->u.SetFile.buf_len);
    if (entry->u.SetFile.InfoClass == FileRenameInformation) {
        PFILE_RENAME_INFORMATION fri = (PFILE_RENAME_INFORMATION)tmp;
#ifdef NFS41_DRIVER_STOMP_CYGWIN_SILLYRENAME_INVALID_UTF16_SEQUENCE_SUPPORT
        UNICODE_STRING fn = {
            .Buffer = fri->FileName,
            .Length = (USHORT)fri->FileNameLength,
            .MaximumLength = (USHORT)fri->FileNameLength
        };

        if (fn.Length > 0) {
            if (fn.Buffer[0] == L'\\')
                substitute_cygwin_sillyrename_unicode_path(&fn);
            else
                substitute_cygwin_sillyrename_unicode_filename(&fn);
        }
#endif /* NFS41_DRIVER_STOMP_CYGWIN_SILLYRENAME_INVALID_UTF16_SEQUENCE_SUPPORT */

        /*
         * We use %lu here for |ReplaceIfExists| because of
         * |FileRenameInformationEx| uses a ULONG flags field
         */
        DbgP("marshal_nfs41_fileset: "
            "FILE_RENAME_INFORMATION."
            "(ReplaceIfExists=%lu FileNameLength=%d FileName='%.*ls')\n",
            (unsigned long)fri->ReplaceIfExists,
            (int)fri->FileNameLength,
            (int)(fri->FileNameLength/sizeof(wchar_t)), fri->FileName);
    }
    else if (entry->u.SetFile.InfoClass == FileLinkInformation) {
        PFILE_LINK_INFORMATION fli = (PFILE_LINK_INFORMATION)tmp;
#ifdef NFS41_DRIVER_STOMP_CYGWIN_SILLYRENAME_INVALID_UTF16_SEQUENCE_SUPPORT
        UNICODE_STRING fn = {
            .Buffer = fli->FileName,
            .Length = (USHORT)fli->FileNameLength,
            .MaximumLength = (USHORT)fli->FileNameLength
        };

        if (fn.Length > 0) {
            if (fn.Buffer[0] == L'\\')
                substitute_cygwin_sillyrename_unicode_path(&fn);
            else
                substitute_cygwin_sillyrename_unicode_filename(&fn);
        }
#endif /* NFS41_DRIVER_STOMP_CYGWIN_SILLYRENAME_INVALID_UTF16_SEQUENCE_SUPPORT */

        DbgP("marshal_nfs41_fileset: "
            "FILE_LINK_INFORMATION.(FileNameLength=%d FileName='%.*ls')\n",
            (int)fli->FileNameLength,
            (int)(fli->FileNameLength/sizeof(wchar_t)), fli->FileName);
    }
    tmp += entry->u.SetFile.buf_len;

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_fileset: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_fileset: filename='%wZ' class=%d\n",
        entry->filename, entry->u.SetFile.InfoClass);
#endif
out:
    return status;
}

NTSTATUS unmarshal_nfs41_setattr(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    UPDOWNCALL_MEMCPY(&cur->ChangeTime, *buf, sizeof(cur->ChangeTime));
    *buf += sizeof(cur->ChangeTime);

#ifdef NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE
    if ((cur->u.SetFile.InfoClass == FileRenameInformation) ||
        (cur->u.SetFile.InfoClass == FileLinkInformation)) {
        UPDOWNCALL_MEMCPY(&cur->u.SetFile.linkrename_stale_dst.path_replaced,
            *buf, sizeof(cur->u.SetFile.linkrename_stale_dst.path_replaced));
        *buf += sizeof(cur->u.SetFile.linkrename_stale_dst.path_replaced);

        if (cur->u.SetFile.linkrename_stale_dst.path_replaced) {
            UPDOWNCALL_MEMCPY(&cur->u.SetFile.linkrename_stale_dst.path_len,
                *buf, sizeof(cur->u.SetFile.linkrename_stale_dst.path_len));
            *buf += sizeof(cur->u.SetFile.linkrename_stale_dst.path_len);

            UTF8_STRING stale_utf8filename = {
                .Length = (USHORT)
                    cur->u.SetFile.linkrename_stale_dst.path_len,
                .MaximumLength = (USHORT)
                    cur->u.SetFile.linkrename_stale_dst.path_len,
                .Buffer = (PCHAR)*buf
            };

            status = RtlUTF8StringToUnicodeString(
                &cur->u.SetFile.linkrename_stale_dst.path,
                &stale_utf8filename, TRUE);
            if (!NT_SUCCESS(status)) {
                goto out;
            }

            *buf += cur->u.SetFile.linkrename_stale_dst.path_len;

#ifdef WINDOWSBUG_WORKAROUND_RTLUTF8STRINGTOUNICODESTRING_READS_BEYOND_BUFFER
            /*
             * Windows bug: |RtlUTF8StringToUnicodeString()| can read beyond
             * the maximum size of the input buffer, which can cause "Blue
             * Screens" with Windows verifer. As workaround we add some
             * padding (|sizeof(void *)|), which we can safely skip here...
             */
            *buf += sizeof(void *);
#endif /* WINDOWSBUG_WORKAROUND_RTLUTF8STRINGTOUNICODESTRING_READS_BEYOND_BUFFER */
        }
    }
#endif /* NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE */

out:
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
    case ERROR_CALL_NOT_IMPLEMENTED:    return STATUS_NOT_IMPLEMENTED;
    case ERROR_NOT_SUPPORTED:           return STATUS_NOT_SUPPORTED;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_BUFFER_OVERFLOW:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_DISK_FULL:               return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED:     return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:          return STATUS_FILE_TOO_LARGE;
    case ERROR_INSUFFICIENT_BUFFER:     return STATUS_BUFFER_TOO_SMALL;
    case ERROR_MORE_DATA:               return STATUS_BUFFER_OVERFLOW;
    case ERROR_INVALID_NAME:            return STATUS_OBJECT_NAME_INVALID;
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
        print_error("check_nfs41_setattr_args: unhandled class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
    }

out:
    return status;
}

#ifdef NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE
VOID nfs41_mark_file_as_non_collapsible(
    PNET_ROOT netroot,
    PUNICODE_STRING nonc_filename)
{
    PFCB fcb;
    PNFS41_SRV_OPEN nfs41_srvopen;

    DbgP("nfs41_mark_file_as_non_collapsible: "
        "argument filename='%wZ'\n",
        nonc_filename);

    RxAcquireFcbTableLockExclusive(&netroot->FcbTable, TRUE);

    fcb = RxFcbTableLookupFcb(&netroot->FcbTable, nonc_filename);

    RxReleaseFcbTableLock(&netroot->FcbTable);

    if (fcb) {
        PLIST_ENTRY pSrvOpenListEntry;
        PSRV_OPEN srv_open;

        pSrvOpenListEntry = fcb->SrvOpenList.Flink;

        for (;;) {
            if (pSrvOpenListEntry == &fcb->SrvOpenList) {
                break;
            }

            srv_open = (PSRV_OPEN)
                CONTAINING_RECORD(pSrvOpenListEntry, SRV_OPEN, SrvOpenQLinks);
            nfs41_srvopen = NFS41GetSrvOpenExtension(srv_open);

            DbgP("nfs41_mark_file_as_non_collapsible: "
                "marking filename='%wZ'/fcb=0x%p/srv_open=0x%p as stale\n",
                nonc_filename, (void *)fcb, (void *)srv_open);

            nfs41_srvopen->stale = TRUE;

            pSrvOpenListEntry = pSrvOpenListEntry->Flink;
        }

        RxpDereferenceNetFcb(fcb);
    }
    else {
        DbgP("nfs41_mark_file_as_non_collapsible: "
            "nothing found for filename='%wZ'\n",
            nonc_filename);
    }
}
#endif /* NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE */

static
NTSTATUS nfs41_SetFileInformationImpl(
    IN OUT PRX_CONTEXT RxContext,
    nfs41_opcodes opcode)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry = NULL;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;

#ifdef FORCE_POSIX_SEMANTICS_DELETE
    FILE_RENAME_INFORMATION rinfo;
#endif /* FORCE_POSIX_SEMANTICS_DELETE */
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

    status = nfs41_UpcallCreate(opcode, &nfs41_srvopen->sec_ctx,
        pVNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.SetFile.InfoClass = InfoClass;

#ifdef FORCE_POSIX_SEMANTICS_DELETE
    /* original irp has infoclass for remove but we need to rename instead,
     * thus we changed the local variable infoclass */
    if (RxContext->Info.FileInformationClass == FileDispositionInformation &&
            InfoClass == FileRenameInformation) {
        entry->u.SetFile.buf = &rinfo;
        entry->u.SetFile.buf_len = sizeof(rinfo);
    }
    else
#endif /* FORCE_POSIX_SEMANTICS_DELETE */
    {
        entry->u.SetFile.buf = RxContext->Info.Buffer;
        entry->u.SetFile.buf_len = RxContext->Info.Length;
    }
#ifdef ENABLE_TIMINGS
    InterlockedIncrement(&setattr.sops);
    InterlockedAdd64(&setattr.size, entry->u.SetFile.buf_len);
#endif

#ifdef NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE
    if ((RxContext->Info.FileInformationClass == FileRenameInformation) ||
        (RxContext->Info.FileInformationClass == FileLinkInformation)) {
        entry->u.SetFile.linkrename_stale_dst.path_replaced = FALSE;
        entry->u.SetFile.linkrename_stale_dst.path.Buffer = NULL;
    }
#endif /* NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE */

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_setfile_error(entry->status);
    if (!status) {
        if ((!IS_NFS41_OPEN_DELEGATE_NONE(nfs41_srvopen->deleg_type)) &&
            entry->ChangeTime &&
            (SrvOpen->DesiredAccess &
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_fcb_list(RxContext->pFcb, entry->ChangeTime);
        nfs41_fcb->changeattr = entry->ChangeTime;

#ifdef NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE
        if ((RxContext->Info.FileInformationClass == FileRenameInformation) ||
            (RxContext->Info.FileInformationClass == FileLinkInformation)) {
            DbgP("nfs41_SetFileInformationImpl: "
                "finishig '%s' for filename='%wZ', "
                "linkrename_stale_dst.path_replaced=%d\n",
                ((RxContext->Info.FileInformationClass == FileLinkInformation)?
                    "FileLinkInformation":"FileRenameInformation"),
                entry->filename,
                (int)entry->u.SetFile.linkrename_stale_dst.path_replaced);

            if (entry->u.SetFile.linkrename_stale_dst.path_replaced) {
                DbgP("nfs41_SetFileInformationImpl: "
                    "linkrename_stale_dst.path_len=%d path='%wZ'\n",
                    (int)entry->u.SetFile.linkrename_stale_dst.path_len,
                    &entry->u.SetFile.linkrename_stale_dst.path);

                nfs41_mark_file_as_non_collapsible(
                    (PNET_ROOT)SrvOpen->pVNetRoot->pNetRoot,
                    &entry->u.SetFile.linkrename_stale_dst.path);

                status = STATUS_SUCCESS;
            }
        }
#endif /* NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE */
    }
out:
    if (entry) {
#ifdef NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE
        if ((entry->u.SetFile.InfoClass == FileRenameInformation) ||
            (entry->u.SetFile.InfoClass == FileLinkInformation)) {
            if (entry->u.SetFile.linkrename_stale_dst.path.Buffer != NULL) {
                RtlFreeUnicodeString(
                    &entry->u.SetFile.linkrename_stale_dst.path);
                entry->u.SetFile.linkrename_stale_dst.path.Buffer = NULL;
            }
        }
#endif /* NFS41_DRIVER_MARK_OVERWRITTEN_LINKRENAME_DST_PATH_SRVOPEN_AS_STALE */

        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setattr.tops);
    InterlockedAdd64(&setattr.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetFileInformationImpl delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, setattr.tops, setattr.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_FILE_SET
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_SetFileInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    return nfs41_SetFileInformationImpl(RxContext, NFS41_SYSOP_FILE_SET);
}

NTSTATUS nfs41_SetFileInformationAtCleanup(
      IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;

    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;

    /* Filter |MRxSetFileInfoAtCleanup()| by InfoClass */
    switch (InfoClass) {
        case FileEndOfFileInformation:
            /*
             * NFS server is in charge of managing the file size. Since
             * |nfs41_SetFileInformationAtCleanup()| is never used to
             * truncate a file we just make this as NO-OP here
             *
             * This also needs to be handled with care in cases multiple
             * machines access a file in a { lock-whole-file, append,
             * unlock-whole-file } manner, doing a set-file-size outside
             * the file lock causes data corruption in such cases.
             */
            DbgP("nfs41_SetFileInformationAtCleanup: "
                "FileEndOfFileInformation NOP\n");
            status = STATUS_SUCCESS;
            break;
        case FileBasicInformation:
            /* Timestamp updates */
            DbgP("nfs41_SetFileInformationAtCleanup: "
                "FileBasicInformation timestamp updates\n");
            status = nfs41_SetFileInformationImpl(RxContext,
                NFS41_SYSOP_FILE_SET_AT_CLEANUP);
            break;
        default:
            DbgP("nfs41_SetFileInformationAtCleanup: unknown InfoClass=%d\n",
                (int)InfoClass);
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    return status;
}
