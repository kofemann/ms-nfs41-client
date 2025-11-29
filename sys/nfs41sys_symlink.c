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
#include <stdbool.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"

#include "win_reparse.h"


NTSTATUS marshal_nfs41_symlink(
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

    header_len = *len + length_as_utf8(entry->filename);
    if (entry->opcode == NFS41_SYSOP_SYMLINK_SET)
        header_len += length_as_utf8(entry->u.Symlink.target);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = marshall_unicode_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    if (entry->opcode == NFS41_SYSOP_SYMLINK_SET) {
        status = marshall_unicode_as_utf8(&tmp, entry->u.Symlink.target);
        if (status) goto out;
    }

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_symlink: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    if (entry->opcode == NFS41_SYSOP_SYMLINK_SET) {
        DbgP("marshal_nfs41_symlink: "
            "SET: name '%wZ' symlink target '%wZ'\n",
            entry->filename,
            entry->u.Symlink.target);
    }
    else {
        DbgP("marshal_nfs41_symlink: "
            "GET: name '%wZ'\n",
            entry->filename);
    }
#endif /* DEBUG_MARSHAL_DETAIL */
out:
    return status;
}

void unmarshal_nfs41_get_symlink(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    RtlCopyMemory(&cur->u.Symlink.target->Length, *buf, sizeof(USHORT));
    *buf += sizeof(USHORT);
    if (cur->u.Symlink.target->Length >
            cur->u.Symlink.target->MaximumLength) {
        cur->status = STATUS_BUFFER_TOO_SMALL;
        return;
    }
    RtlCopyMemory(cur->u.Symlink.target->Buffer, *buf,
        cur->u.Symlink.target->Length);
    *buf += cur->u.Symlink.target->Length;
}

void unmarshal_nfs41_set_symlink(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    /* empty */
}

NTSTATUS map_symlink_errors(
    NTSTATUS status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_FILE_NOT_FOUND:      return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:      return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_INVALID_REPARSE_DATA: return STATUS_IO_REPARSE_DATA_INVALID;
    case ERROR_NOT_A_REPARSE_POINT: return STATUS_NOT_A_REPARSE_POINT;
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_DIR_NOT_EMPTY:       return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INSUFFICIENT_BUFFER: return STATUS_BUFFER_TOO_SMALL;
    case STATUS_BUFFER_TOO_SMALL:
    case ERROR_BUFFER_OVERFLOW:     return STATUS_BUFFER_OVERFLOW;
    case ERROR_DISK_FULL:           return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED: return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:      return STATUS_FILE_TOO_LARGE;
    case ERROR_TOO_MANY_LINKS:      return STATUS_TOO_MANY_LINKS;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_symlink_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

static
NTSTATUS check_nfs41_setsymlinkreparse_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull const PREPARSE_DATA_BUFFER Reparse =
        (const PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    const ULONG HeaderLen = REPARSE_DATA_BUFFER_HEADER_SIZE;

    /* access checks */
    if (VNetRootContext->read_only) {
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
    if (!(SrvOpen->DesiredAccess & (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES))) {
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    /* must have a filename longer than vnetroot name,
     * or it's trying to operate on the volume itself */
    if (is_root_directory(RxContext)) {
        status = STATUS_INVALID_PARAMETER;
        DbgP("check_nfs41_setsymlinkreparse_args: "
            "is_root_directory() == TRUE\n");
        goto out;
    }

    /* validate input buffer and length */
    if (!Reparse) {
        status = STATUS_INVALID_BUFFER_SIZE;
        DbgP("check_nfs41_setsymlinkreparse_args: Reparse == NULL\n");
        goto out;
    }

    if (FsCtl->InputBufferLength < HeaderLen ||
            FsCtl->InputBufferLength > MAXIMUM_REPARSE_DATA_BUFFER_SIZE) {
        DbgP("check_nfs41_setsymlinkreparse_args: "
            "InputBufferLength too small/large\n");
        status = STATUS_IO_REPARSE_DATA_INVALID;
        goto out;
    }
    if (FsCtl->InputBufferLength != HeaderLen + Reparse->ReparseDataLength) {
        status = STATUS_IO_REPARSE_DATA_INVALID;
        DbgP("check_nfs41_setsymlinkreparse_args: "
            "InputBufferLength != HeaderLen + ReparseDataLength\n");
        goto out;
    }

    /* validate reparse tag */
    if (!IsReparseTagValid(Reparse->ReparseTag)) {
        status = STATUS_IO_REPARSE_TAG_INVALID;
        DbgP("check_nfs41_setsymlinkreparse_args: "
            "IsReparseTagValid() failed\n");
        goto out;
    }
    if (Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        status = STATUS_IO_REPARSE_TAG_MISMATCH;
        DbgP("check_nfs41_setsymlinkreparse_args: "
            "Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK\n");
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_SetSymlinkReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    UNICODE_STRING TargetName;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull const PREPARSE_DATA_BUFFER Reparse =
        (const PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry = NULL;
    PWSTR prefixed_targetname = NULL;

#ifdef DEBUG_SYMLINK
    DbgEn();
    print_debug_header(RxContext);
    print_reparse_buffer(Reparse);
#endif

    DbgP("nfs41_SetSymlinkReparsePoint: ReparseTag: '%s'/0x%04lx\n",
        reparsetag2string(Reparse->ReparseTag),
        (long)Reparse->ReparseTag);

    status = check_nfs41_setsymlinkreparse_args(RxContext);
    if (status) {
        DbgP("nfs41_SetSymlinkReparsePoint: "
            "check_nfs41_setsymlinkreparse_args() failed, "
            "status=0x%lx\n",
                (long)status);
        goto out;
    }

    if (Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        status = IO_REPARSE_TAG_SYMLINK;
        DbgP("nfs41_SetSymlinkReparsePoint: "
            "Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK\n");
        goto out;
    }

    TargetName.MaximumLength = TargetName.Length =
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength;
    TargetName.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset/sizeof(WCHAR)];

    if (TargetName.Buffer[0] == L'.') {
        DbgP("nfs41_SetSymlinkReparsePoint: "
            "relative path TargetName='%wZ'\n",
            &TargetName);
    }
    else {
        DbgP("nfs41_SetSymlinkReparsePoint: "
            "absolute path TargetName='%wZ'\n",
            &TargetName);

        /* UNC path ? */
        if ((TargetName.Length > 8*sizeof(wchar_t)) &&
            (!memcmp(&TargetName.Buffer[0], L"\\??\\UNC\\",
            (8*sizeof(wchar_t))))) {

            /* Strip "\\??\\" prefix */
            TargetName.Buffer += 4;
            TargetName.MaximumLength = TargetName.Length =
                TargetName.Length-(4*sizeof(wchar_t));

            /*
             * Turn "UNC\" into "\\"
             * (userland daemon will convert the backslashes in UNC
             * path to slashes)
             */
            TargetName.Buffer += 2;
            TargetName.MaximumLength = TargetName.Length =
                TargetName.Length-(2*sizeof(wchar_t));
            TargetName.Buffer[0] = L'\\';

            DbgP("nfs41_SetSymlinkReparsePoint: "
                "UNC TargetName='%wZ'\n",
                &TargetName);
        }
        /* DEVICELETTR path ? */
        else if ((TargetName.Length >= 6*sizeof(wchar_t)) &&
            (!memcmp(&TargetName.Buffer[0], L"\\??\\",
            (4*sizeof(wchar_t)))) &&
            (TargetName.Buffer[5] == L':')) {
            wchar_t devletter;

            DbgP("nfs41_SetSymlinkReparsePoint: "
                "DEVLETTER TargetName='%wZ'\n",
                &TargetName);

            /* Strip "\\??\\" prefix */
            TargetName.Buffer += 4;
            TargetName.MaximumLength = TargetName.Length =
                TargetName.Length-(4*sizeof(wchar_t));

            if ((TargetName.Buffer[1] != L':') ||
                (TargetName.Buffer[2] != L'\\')) {
                status = STATUS_INVALID_PARAMETER;
                DbgP("nfs41_SetSymlinkReparsePoint: "
                    "DEVLETTER path '%wZ' should start with 'L:\\'\n",
                    &TargetName);
                goto out;
            }

            /* Get devletter and skip "L:\" "*/
            devletter = towlower(TargetName.Buffer[0]);
            TargetName.Buffer += 3;
            TargetName.MaximumLength = TargetName.Length =
                TargetName.Length-(3*sizeof(wchar_t));

            DbgP("nfs41_SetSymlinkReparsePoint: "
                "deviceletter='%C' path='%wZ'\n",
                devletter,
                &TargetName);

            size_t prefixed_targetname_len = 4096*sizeof(wchar_t);

            prefixed_targetname = RxAllocatePoolWithTag(NonPagedPoolNx,
                prefixed_targetname_len, NFS41_MM_POOLTAG);
            if (prefixed_targetname == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto out;
            }

            /*
             * Stuff Cygwin /cygdrive/<deviceletter>/ prefix in front
             * of path, userland daemon will convert the backslashes
             * to slashes
             */
            (void)_snwprintf(prefixed_targetname,
                prefixed_targetname_len, L"\\cygdrive\\%C\\%wZ",
                devletter,
                &TargetName);

            /* Put new buffer into target name */
            TargetName.MaximumLength = TargetName.Length =
                (USHORT)(wcslen(prefixed_targetname)*sizeof(wchar_t));
            TargetName.Buffer = prefixed_targetname;

            DbgP("nfs41_SetSymlinkReparsePoint: "
                "new TargetName='%wZ'\n",
                &TargetName);
        }
        else if ((TargetName.Length > 1*sizeof(wchar_t)) &&
            (
                (TargetName.Buffer[0] == L'\\') ||
                (TargetName.Buffer[0] == L'/') ||
                (TargetName.Buffer[0] == L':')
            )) {
            DbgP("nfs41_SetSymlinkReparsePoint: "
                "TargetName='%wZ' should not start "
                "with '/', '\\' or ':'\n",
                &TargetName);
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        else {
            DbgP("nfs41_SetSymlinkReparsePoint: "
                "relative symlink TargetName='%wZ'\n",
                &TargetName);
        }
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_SYMLINK_SET, &Fobx->sec_ctx,
        VNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Symlink.target = &TargetName;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_symlink_errors(entry->status);
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
    if (prefixed_targetname)
        RxFreePool(prefixed_targetname);

#ifdef DEBUG_SYMLINK
    DbgEx();
#endif
    return status;
}

static
NTSTATUS check_nfs41_getsymlinkreparse_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
        SymbolicLinkReparseBuffer.PathBuffer);

    /* ifs reparse tests expect STATUS_INVALID_PARAMETER,
     * but 'dir' passes a buffer here when querying symlinks
    if (FsCtl->pInputBuffer != NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    } */
    if (!FsCtl->pOutputBuffer) {
        status = STATUS_INVALID_USER_BUFFER;
        DbgP("check_nfs41_getsymlinkreparse_args: "
            "FsCtl->pOutputBuffer == NULL\n");
        goto out;
    }
    if (!BooleanFlagOn(RxContext->pFcb->Attributes,
            FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_NOT_A_REPARSE_POINT;
        DbgP("FILE_ATTRIBUTE_REPARSE_POINT is not set!\n");
        goto out;
    }

    if (FsCtl->OutputBufferLength < HeaderLen) {
        RxContext->InformationToReturn = HeaderLen;
        status = STATUS_BUFFER_TOO_SMALL;
        DbgP("check_nfs41_getsymlinkreparse_args: "
            "FsCtl->OutputBufferLength < HeaderLen\n");
        goto out;
    }
out:
    return status;
}

static
bool is_us_relative_path(UNICODE_STRING *restrict us)
{
    /* Match exactly "." (single dot) */
    if ((us->Length == (1*sizeof(wchar_t))) &&
        (us->Buffer[0] == L'.'))
        return true;

    /* Match exactly ".." (double dot) */
    if ((us->Length == (2*sizeof(wchar_t)) &&
        (!memcmp(&us->Buffer[0], L"..", (2*sizeof(wchar_t))))))
        return true;

    /* Match "..\..." */
    if ((us->Length >= (3*sizeof(wchar_t))) &&
        (!memcmp(&us->Buffer[0], L"..\\", (3*sizeof(wchar_t)))))
        return true;

    /* Match ".\..." */
    if ((us->Length >= (2*sizeof(wchar_t))) &&
        (!memcmp(&us->Buffer[0], L".\\", (2*sizeof(wchar_t)))))
        return true;

    /* Reject any absolute paths or similar stuff */
    if ((us->Length >= (1*sizeof(wchar_t)) &&
        (
            (us->Buffer[0] == L'\\') ||
            (us->Buffer[0] == L'/')
        ))) {
        return false;
    }

    /*
     * Reject paths like L: (':' is an illegal filesystem name
     * character, reserved for alternate data streams only)
     */
    if ((us->Length >= (2*sizeof(wchar_t)) &&
        (us->Buffer[1] == L':'))) {
        return false;
    }

    /*
     * Handle the case of symlink foo --> bar (and foo -->bar/baz),
     * e.g. symlinking one name to a file/dir in the same directory
     */
    return true;
}

static
bool is_us_unc_path(UNICODE_STRING *restrict us)
{
    if (!memcmp(&us->Buffer[0], L"\\\\", (2*sizeof(wchar_t))))
        return true;
    return false;
}

static
bool is_us_cygdrive_path(UNICODE_STRING *restrict us)
{
    /* Fixme: What about MSYS2 ? */

    /* "/cygdrive/l" == 11 characters */
    if ((us->Length >= (11*sizeof(wchar_t))) &&
        (!memcmp(&us->Buffer[0],
            L"\\cygdrive\\", (10*sizeof(wchar_t)))))
        return true;
    return false;
}

static
bool is_us_posixroot_path(UNICODE_STRING *restrict us)
{
    if ((us->Length >= (1*sizeof(wchar_t))) &&
        (!memcmp(&us->Buffer[0],
            L"\\", (1*sizeof(wchar_t)))))
        return true;
    return false;
}

NTSTATUS nfs41_GetSymlinkReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    UNICODE_STRING TargetName;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry = NULL;
    PWSTR targetname_buffer = NULL;

#ifdef DEBUG_SYMLINK
    DbgEn();
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_getsymlinkreparse_args(RxContext);
    if (status) {
        DbgP("nfs41_GetSymlinkReparsePoint: "
            "check_nfs41_getsymlinkreparse_args() failed, "
            "status=0x%lx\n",
                (long)status);
        goto out;
    }

    size_t targetname_buffer_len = 4096*sizeof(wchar_t);
    targetname_buffer = RxAllocatePoolWithTag(NonPagedPoolNx,
        targetname_buffer_len, NFS41_MM_POOLTAG);
    if (targetname_buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    TargetName.Buffer = targetname_buffer;
    TargetName.MaximumLength = (USHORT)targetname_buffer_len;

    status = nfs41_UpcallCreate(NFS41_SYSOP_SYMLINK_GET, &Fobx->sec_ctx,
        VNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Symlink.target = &TargetName;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_symlink_errors(entry->status);
    if (status == STATUS_SUCCESS) {
        /* fill in the output buffer */
        PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)
            FsCtl->pOutputBuffer;

        DbgP("nfs41_GetSymlinkReparsePoint: "
            "got TargetName='%wZ', len=%d\n",
            &TargetName, (int)TargetName.Length);

        /*
         * Cygwin: Pass-through for POSIX symlinks to /dev, e.g.
         * /dev/null, /dev/zero, /dev/stdin etc.
         * Otherwise code like
         * $ ln -s /dev/zero foo && ls -l foo && rm foo #
         * will fail.
         * We restrict this to /dev only, all other kind of POSIX
         * symlinks should be translated to Win32 symlink syntax
         */
        if (((TargetName.Length > 5*sizeof(wchar_t)) &&
            (!wcsncmp(TargetName.Buffer, L"/dev/", 5)))) {
            const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
                SymbolicLinkReparseBuffer.PathBuffer);

            DbgP("nfs41_GetSymlinkReparsePoint: "
                "Cygwin /dev/ symlink codepath\n");

            /* Copy data into FsCtl buffer  */
            (void)memcpy(((PBYTE)FsCtl->pOutputBuffer + HeaderLen),
                TargetName.Buffer, TargetName.Length);
            TargetName.Buffer =
                (PWCH)((PBYTE)FsCtl->pOutputBuffer + HeaderLen);

            DbgP("nfs41_GetSymlinkReparsePoint: "
                "Cygwin /dev/ symlink TargetName='%wZ'\n",
                &TargetName);

            Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
            Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
                REPARSE_DATA_BUFFER_HEADER_SIZE;
            Reparse->Reserved = 0;
            /* Cygwin wants |SYMLINK_FLAG_RELATIVE| for these symlinks */
            Reparse->SymbolicLinkReparseBuffer.Flags =
                SYMLINK_FLAG_RELATIVE;

            /* PrintName and SubstituteName point to the same string */
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength =
                TargetName.Length;
            Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.PrintNameLength =
                TargetName.Length;

            print_reparse_buffer(Reparse);

            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)HeaderLen + TargetName.Length;
            goto out;
        }

        /* POSIX slash to Win32 backslash */
        size_t i;
        for (i=0 ; i < TargetName.Length ; i++) {
            if (TargetName.Buffer[i] == L'/')
                TargetName.Buffer[i] = L'\\';
        }

        DbgP("nfs41_GetSymlinkReparsePoint: "
            "TargetName='%wZ' with '/'-->'\\' conversion\n",
            &TargetName);

        if (is_us_cygdrive_path(&TargetName)) {
            const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
                SymbolicLinkReparseBuffer.PathBuffer);

            DbgP("nfs41_GetSymlinkReparsePoint: /cygdrive/ codepath\n");

            wchar_t dosletter;
            dosletter = towupper(TargetName.Buffer[10]);
            TargetName.Buffer += 9;
            TargetName.MaximumLength = TargetName.Length =
                TargetName.Length-(9*sizeof(wchar_t));

            /* If we only have "L:" turn this into "L:\" */
            if (TargetName.Length == (2*sizeof(wchar_t))) {
                TargetName.MaximumLength = TargetName.Length =
                    TargetName.Length + (1*sizeof(wchar_t));
            }

            TargetName.Buffer[0] = dosletter;
            TargetName.Buffer[1] = L':';
            TargetName.Buffer[2] = L'\\';

            DbgP("nfs41_GetSymlinkReparsePoint: new TargetName='%wZ'\n",
                &TargetName);

            /* Copy data into FsCtl buffer  */
            PWCH outbuff = (PWCH)(((PBYTE)FsCtl->pOutputBuffer) + HeaderLen);
            (void)memcpy(outbuff, TargetName.Buffer, TargetName.Length);
            TargetName.Buffer = outbuff;

            DbgP("nfs41_GetSymlinkReparsePoint: new TargetName='%wZ'\n",
                &TargetName);

            Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
            Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
                REPARSE_DATA_BUFFER_HEADER_SIZE;
            Reparse->Reserved = 0;
            /* /cygwin/<devletter>/ are absolute paths */
#define CYGWIN_WANTS_SYMLINKFLAGRELATIVE_FOR_ABS_PATHS 1 /* FIXME: Why ? */

#ifdef CYGWIN_WANTS_SYMLINKFLAGRELATIVE_FOR_ABS_PATHS
            Reparse->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
#else
            Reparse->SymbolicLinkReparseBuffer.Flags = 0;
#endif

            /* PrintName and SubstituteName point to the same string */
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength =
                TargetName.Length;
            Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.PrintNameLength =
                TargetName.Length;

            print_reparse_buffer(Reparse);

            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)HeaderLen + TargetName.Length;
        }
        else if (is_us_unc_path(&TargetName)) {
            /*
             * FIXME: UNC paths should return
             * |IO_REPARSE_TAG_MOUNT_POINT|, but Cygwin does not
             * support |IO_REPARSE_TAG_MOUNT_POINT| for remote
             * filesystems.
             * Note that we if we switch this over to
             * |IO_REPARSE_TAG_MOUNT_POINT| we also have to teach
             * daemon/readdir.c&co that we have more than one type
             * of reparse tag
             */
            const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
                SymbolicLinkReparseBuffer.PathBuffer);

            DbgP("nfs41_GetSymlinkReparsePoint: UNC codepath\n");

            /* Copy data into FsCtl buffer  */
            PWCH outbuff = (PWCH)(((PBYTE)FsCtl->pOutputBuffer) + HeaderLen);
            (void)memcpy(outbuff, TargetName.Buffer, TargetName.Length);
            TargetName.Buffer = outbuff;


            DbgP("nfs41_GetSymlinkReparsePoint: "
                "new UNC TargetName='%wZ'\n",
                &TargetName);

            Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
            Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
            REPARSE_DATA_BUFFER_HEADER_SIZE;
            Reparse->Reserved = 0;
            /* UNC paths are absolute paths */
#ifdef CYGWIN_WANTS_SYMLINKFLAGRELATIVE_FOR_ABS_PATHS
            Reparse->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
#else
            Reparse->SymbolicLinkReparseBuffer.Flags = 0;
#endif

            /* PrintName and SubstituteName point to the same string */
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength =
                TargetName.Length;
            Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.PrintNameLength =
                TargetName.Length;

            print_reparse_buffer(Reparse);

            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)HeaderLen + TargetName.Length;
        }
        else if (is_us_relative_path(&TargetName)) {
            const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
                SymbolicLinkReparseBuffer.PathBuffer);

            DbgP("nfs41_GetSymlinkReparsePoint: relative symlink codepath\n");

            /* Copy data into FsCtl buffer  */
            (void)memcpy(((PBYTE)FsCtl->pOutputBuffer + HeaderLen),
                TargetName.Buffer, TargetName.Length);
            TargetName.Buffer =
                (PWCH)((PBYTE)FsCtl->pOutputBuffer + HeaderLen);

            DbgP("nfs41_GetSymlinkReparsePoint: "
                "new relative TargetName='%wZ'\n",
                &TargetName);

            Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
            Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
            REPARSE_DATA_BUFFER_HEADER_SIZE;
            Reparse->Reserved = 0;
            Reparse->SymbolicLinkReparseBuffer.Flags =
                SYMLINK_FLAG_RELATIVE;
            /* PrintName and SubstituteName point to the same string */
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength =
                TargetName.Length;
            Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.PrintNameLength =
                TargetName.Length;

            print_reparse_buffer(Reparse);

            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)HeaderLen + TargetName.Length;
        }
        else if (is_us_posixroot_path(&TargetName)) {
            const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
                SymbolicLinkReparseBuffer.PathBuffer);

            DbgP("nfs41_GetSymlinkReparsePoint: POSIX root symlink codepath\n");

            /*
             * Copy data into FsCtl buffer, using L"C:\\cygwin64"
             * as prefix
             */
            wchar_t *outbuff = (wchar_t *)
                ((PBYTE)FsCtl->pOutputBuffer + HeaderLen);
            size_t outbuff_len;
            if ((TargetName.Buffer[0] == L'\\') &&
                (TargetName.Length == (1*sizeof(wchar_t)))) {
                /*
                 * Special case "bar -> /", to avoid that the
                 * symlink target will be "//"
                 */
                TargetName.Length = 0;
            }
            (void)_snwprintf(outbuff,
                (FsCtl->OutputBufferLength-HeaderLen) / sizeof(wchar_t),
#ifdef _WIN64
                /* |TargetName| always starts with a backslash */
                L"C:\\cygwin64%wZ",
#else
                /* |TargetName| always starts with a backslash */
                L"C:\\cygwin%wZ",
#endif /* _WIN64 */
                &TargetName);
            outbuff_len = wcslen(outbuff);

            TargetName.Length =
                (USHORT)outbuff_len*sizeof(wchar_t);

            DbgP("nfs41_GetSymlinkReparsePoint: "
                "new posixroot TargetName='%wZ'\n",
                &TargetName);

            Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
            Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
            REPARSE_DATA_BUFFER_HEADER_SIZE;
            Reparse->Reserved = 0;
            Reparse->SymbolicLinkReparseBuffer.Flags =
                SYMLINK_FLAG_RELATIVE;
            /* PrintName and SubstituteName point to the same string */
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength =
                TargetName.Length;
            Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
            Reparse->SymbolicLinkReparseBuffer.PrintNameLength =
                TargetName.Length;

            print_reparse_buffer(Reparse);

            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)HeaderLen + TargetName.Length;
        }
        else {
            status = STATUS_IO_REPARSE_DATA_INVALID;
            DbgP("nfs41_GetSymlinkReparsePoint: "
                "cannot parse symlink data TargetName='%wZ'\n",
                &TargetName);
        }
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        const size_t sym_hdr_len =
            FIELD_OFFSET(REPARSE_DATA_BUFFER,
                MountPointReparseBuffer.PathBuffer);
        const size_t mnt_hdr_len =
            FIELD_OFFSET(REPARSE_DATA_BUFFER,
                SymbolicLinkReparseBuffer.PathBuffer);
        /*
         * We don't know whether we have to return
         * |IO_REPARSE_TAG_MOUNT_POINT| or |IO_REPARSE_TAG_SYMLINK|,
         * so we return a size which can fit both
         */
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
        RxContext->InformationToReturn =
            MAX(sym_hdr_len, mnt_hdr_len) + TargetName.Length;
    }

out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
    if (targetname_buffer)
        RxFreePool(targetname_buffer);

    FsRtlExitFileSystem();
#ifdef DEBUG_SYMLINK
    DbgEx();
#endif
    return status;
}
