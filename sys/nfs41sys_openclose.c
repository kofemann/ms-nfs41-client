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
#include <stdbool.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"

static
NTSTATUS nfs41_get_sec_ctx(
    IN enum _SECURITY_IMPERSONATION_LEVEL level,
    OUT PSECURITY_CLIENT_CONTEXT out_ctx)
{
    NTSTATUS status;
    SECURITY_SUBJECT_CONTEXT ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;

    SeCaptureSubjectContext(&ctx);
    sec_qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    sec_qos.ImpersonationLevel = level;
    sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    sec_qos.EffectiveOnly = 0;
    /*
     * Arg |ServerIsRemote| must be |FALSE|, otherwise processes
     * like Cygwin setup-x86_64.exe can fail during "Activation
     * Context" creation in
     * |SeCreateClientSecurityFromSubjectContext()| with
     * |STATUS_BAD_IMPERSONATION_LEVEL|
     */
    status = SeCreateClientSecurityFromSubjectContext(&ctx, &sec_qos,
        FALSE, out_ctx);
    if (status != STATUS_SUCCESS) {
        print_error("SeCreateClientSecurityFromSubjectContext "
            "failed with 0x%lx\n", (long)status);
    }
#ifdef DEBUG_SECURITY_TOKEN
    DbgP("Created client security token 0x%p\n", out_ctx->ClientToken);
#endif
    SeReleaseSubjectContext(&ctx);

    return status;
}

NTSTATUS marshal_nfs41_open(
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
        7 * sizeof(ULONG) +
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
        2 * sizeof(DWORD) +
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
        1 * sizeof(BOOLEAN) +
        2 * sizeof(HANDLE) +
        length_as_utf8(&entry->u.Open.symlink);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Open.isvolumemntpt,
        sizeof(entry->u.Open.isvolumemntpt));
    tmp += sizeof(entry->u.Open.isvolumemntpt);
    RtlCopyMemory(tmp, &entry->u.Open.access_mask,
        sizeof(entry->u.Open.access_mask));
    tmp += sizeof(entry->u.Open.access_mask);
    RtlCopyMemory(tmp, &entry->u.Open.access_mode,
        sizeof(entry->u.Open.access_mode));
    tmp += sizeof(entry->u.Open.access_mode);
    RtlCopyMemory(tmp, &entry->u.Open.attrs, sizeof(entry->u.Open.attrs));
    tmp += sizeof(entry->u.Open.attrs);
    RtlCopyMemory(tmp, &entry->u.Open.copts, sizeof(entry->u.Open.copts));
    tmp += sizeof(entry->u.Open.copts);
    RtlCopyMemory(tmp, &entry->u.Open.disp, sizeof(entry->u.Open.disp));
    tmp += sizeof(entry->u.Open.disp);
    RtlCopyMemory(tmp, &entry->u.Open.open_owner_id,
        sizeof(entry->u.Open.open_owner_id));
    tmp += sizeof(entry->u.Open.open_owner_id);
    RtlCopyMemory(tmp, &entry->u.Open.mode, sizeof(DWORD));
    tmp += sizeof(DWORD);
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    RtlCopyMemory(tmp, &entry->u.Open.owner_local_uid, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Open.owner_group_local_gid, sizeof(DWORD));
    tmp += sizeof(DWORD);
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
    RtlCopyMemory(tmp, &entry->u.Open.srv_open, sizeof(HANDLE));
    tmp += sizeof(HANDLE);
    status = marshall_unicode_as_utf8(&tmp, &entry->u.Open.symlink);
    if (status) goto out;

    __try {
        if (entry->u.Open.EaMdl) {
            entry->u.Open.EaBuffer =
                MmMapLockedPagesSpecifyCache(entry->u.Open.EaMdl,
                    UserMode, MmCached, NULL, FALSE,
                    NormalPagePriority|MdlMappingNoExecute);
            if (entry->u.Open.EaBuffer == NULL) {
                print_error("marshal_nfs41_open: "
                    "MmMapLockedPagesSpecifyCache() failed to "
                    "map pages\n");
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto out;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        print_error("marshal_nfs41_open: Call to "
            "MmMapLockedPagesSpecifyCache() failed "
            "due to exception 0x%lx\n", (long)GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Open.EaBuffer, sizeof(HANDLE));
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_open: name='%wZ' mask=0x%x access=0x%x attrs=0x%x "
         "opts=0x%x dispo=0x%x open_owner_id=0x%x mode=0%o "
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
         "owner_local_uid=%lu owner_group_local_gid=%lu "
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
         "srv_open=0x%p ea=0x%p\n",
         entry->filename, entry->u.Open.access_mask,
         entry->u.Open.access_mode, entry->u.Open.attrs, entry->u.Open.copts,
         entry->u.Open.disp, entry->u.Open.open_owner_id, entry->u.Open.mode,
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
         entry->u.Open.owner_local_uid,entry->u.Open.owner_group_local_gid,
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
         entry->u.Open.srv_open, entry->u.Open.EaBuffer);
#endif
out:
    return status;
}

NTSTATUS marshal_nfs41_close(
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

    header_len = *len + sizeof(BOOLEAN) + sizeof(HANDLE);
    if (entry->u.Close.remove)
        header_len += length_as_utf8(entry->filename) +
            sizeof(BOOLEAN);

    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Close.remove, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.Close.srv_open, sizeof(HANDLE));
    if (entry->u.Close.remove) {
        tmp += sizeof(HANDLE);
        status = marshall_unicode_as_utf8(&tmp, entry->filename);
        if (status) goto out;
        RtlCopyMemory(tmp, &entry->u.Close.renamed, sizeof(BOOLEAN));
    }
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_close: name='%wZ' remove=%d srv_open=0x%p renamed=%d\n",
        entry->filename->Length?entry->filename:&SLASH,
        entry->u.Close.remove, entry->u.Close.srv_open, entry->u.Close.renamed);
#endif
out:
    return status;
}

NTSTATUS unmarshal_nfs41_open(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        if (cur->u.Open.EaBuffer) {
            MmUnmapLockedPages(cur->u.Open.EaBuffer, cur->u.Open.EaMdl);
            cur->u.Open.EaBuffer = NULL;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        print_error("MmUnmapLockedPages thrown exception=0x%lx\n",
            (long)GetExceptionCode());
        status = cur->status = STATUS_ACCESS_VIOLATION;
        goto out;
    }

    RtlCopyMemory(&cur->u.Open.binfo, *buf, sizeof(FILE_BASIC_INFORMATION));
    *buf += sizeof(FILE_BASIC_INFORMATION);
    RtlCopyMemory(&cur->u.Open.sinfo, *buf, sizeof(FILE_STANDARD_INFORMATION));
    *buf += sizeof(FILE_STANDARD_INFORMATION);
    RtlCopyMemory(&cur->u.Open.fileid, *buf, sizeof(ULONGLONG));
    *buf += sizeof(ULONGLONG);
    RtlCopyMemory(&cur->u.Open.fsid_major, *buf, sizeof(ULONGLONG));
    *buf += sizeof(ULONGLONG);
    RtlCopyMemory(&cur->u.Open.fsid_minor, *buf, sizeof(ULONGLONG));
    *buf += sizeof(ULONGLONG);
    RtlCopyMemory(&cur->open_state, *buf, sizeof(HANDLE));
    *buf += sizeof(HANDLE);
    RtlCopyMemory(&cur->u.Open.mode, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    RtlCopyMemory(&cur->u.Open.owner_local_uid, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    RtlCopyMemory(&cur->u.Open.owner_group_local_gid, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
    RtlCopyMemory(&cur->ChangeTime, *buf, sizeof(ULONGLONG));
    *buf += sizeof(ULONGLONG);
    RtlCopyMemory(&cur->u.Open.deleg_type, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    if (cur->errno == ERROR_REPARSE) {
        RtlCopyMemory(&cur->u.Open.symlink_embedded, *buf, sizeof(BOOLEAN));
        *buf += sizeof(BOOLEAN);
        BYTE tmp_symlinktarget_type;
        RtlCopyMemory(&tmp_symlinktarget_type, *buf, sizeof(BYTE));
        cur->u.Open.symlinktarget_type = tmp_symlinktarget_type;
        *buf += sizeof(BYTE);
        RtlCopyMemory(&cur->u.Open.symlink.MaximumLength, *buf,
            sizeof(USHORT));
        *buf += sizeof(USHORT);
        cur->u.Open.symlink.Length = cur->u.Open.symlink.MaximumLength -
            sizeof(WCHAR);
        cur->u.Open.symlink.Buffer = RxAllocatePoolWithTag(NonPagedPoolNx,
            cur->u.Open.symlink.MaximumLength, NFS41_MM_POOLTAG);
        if (cur->u.Open.symlink.Buffer == NULL) {
            cur->status = STATUS_INSUFFICIENT_RESOURCES;
            status = STATUS_UNSUCCESSFUL;
            goto out;
        }
        RtlCopyMemory(cur->u.Open.symlink.Buffer, *buf,
            cur->u.Open.symlink.MaximumLength);
#ifdef DEBUG_MARSHAL_DETAIL
        DbgP("unmarshal_nfs41_open: ERROR_REPARSE -> '%wZ'\n", &cur->u.Open.symlink);
#endif
    }
#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("unmarshal_nfs41_open: "
        "open_state 0x%x fileid=0x%llx fsid=(0x%llx.0x%llx) mode 0%o "
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
        "owner_local_uid %u owner_group_local_gid %u "
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
        "changeattr %llu "
        "deleg_type %d\n",
        cur->open_state, cur->u.Open.fileid,
        cur->u.Open.fsid_major, cur->u.Open.fsid_minor,
        cur->u.Open.mode,
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
        cur->u.Open.owner_local_uid, cur->u.Open.owner_group_local_gid,
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
        cur->ChangeTime, cur->u.Open.deleg_type);
#endif /* DEBUG_MARSHAL_DETAIL */
out:
    return status;
}

static BOOLEAN isDataAccess(
    ACCESS_MASK mask)
{
    if (mask & (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA))
        return TRUE;
    return FALSE;
}

static BOOLEAN isOpen2Create(
    ULONG disposition)
{
    if (disposition == FILE_CREATE || disposition == FILE_OPEN_IF ||
            disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE)
        return TRUE;
    return FALSE;
}

static BOOLEAN isWriteOnlyDesiredAccess(PNT_CREATE_PARAMETERS params)
{
    if (((params->DesiredAccess & (FILE_EXECUTE|FILE_READ_DATA)) == 0) &&
        ((params->DesiredAccess & (FILE_WRITE_DATA|FILE_APPEND_DATA)) != 0)) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN isAttributeOnlyDesiredAccess(PNT_CREATE_PARAMETERS params)
{
    if ((params->DesiredAccess &
        ~(FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|SYNCHRONIZE)) == 0) {
        return TRUE;
    }
    return FALSE;
}

static BOOLEAN areOpenParamsValid(NT_CREATE_PARAMETERS *params)
{
    /* from ms-fsa page 52 */
    if ((params->CreateOptions & FILE_DELETE_ON_CLOSE) &&
            !(params->DesiredAccess & DELETE))
        return FALSE;
    if ((params->CreateOptions & FILE_DIRECTORY_FILE) &&
            (params->Disposition == FILE_SUPERSEDE ||
                params->Disposition == FILE_OVERWRITE ||
                params->Disposition == FILE_OVERWRITE_IF))
        return FALSE;
    if ((params->CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING) &&
            (params->DesiredAccess & FILE_APPEND_DATA) &&
            !(params->DesiredAccess & FILE_WRITE_DATA))
        return FALSE;
    /* from ms-fsa 3.1.5.1.1 page 56 */
    if ((params->CreateOptions & FILE_DIRECTORY_FILE) &&
            (params->FileAttributes & FILE_ATTRIBUTE_TEMPORARY))
        return FALSE;
    return TRUE;
}

static BOOLEAN isFileNameTheVolumeMountPoint(PUNICODE_STRING fileName,
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext) {
    /* Check whether this is the mount point for this volume */
    if ((fileName->Length == pVNetRootContext->MntPt.Length) &&
        (memcmp(fileName->Buffer,
            pVNetRootContext->MntPt.Buffer,
            pVNetRootContext->MntPt.Length) == 0)) {
        return TRUE;
    }
    return FALSE;
}

NTSTATUS map_open_errors(
    DWORD status,
    USHORT len)
{
    switch (status) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_ACCESS_DENIED:
        if (len > 0)                    return STATUS_ACCESS_DENIED;
        else                            return STATUS_SUCCESS;
    case ERROR_INVALID_REPARSE_DATA:
    case ERROR_INVALID_NAME:            return STATUS_OBJECT_NAME_INVALID;
    case ERROR_FILE_EXISTS:             return STATUS_OBJECT_NAME_COLLISION;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_FILENAME_EXCED_RANGE:    return STATUS_NAME_TOO_LONG;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_BAD_NETPATH:             return STATUS_BAD_NETWORK_PATH;
    case ERROR_SHARING_VIOLATION:       return STATUS_SHARING_VIOLATION;
    case ERROR_REPARSE:                 return STATUS_REPARSE;
    case ERROR_TOO_MANY_LINKS:          return STATUS_TOO_MANY_LINKS;
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    /* See |handle_open()| for |ERROR_DIRECTORY| */
    case ERROR_DIRECTORY:               return STATUS_NOT_A_DIRECTORY;
    /* See |handle_open()| for |ERROR_DIRECTORY_NOT_SUPPORTED| */
    case ERROR_DIRECTORY_NOT_SUPPORTED: return STATUS_FILE_IS_A_DIRECTORY;
    case ERROR_BAD_FILE_TYPE:           return STATUS_BAD_FILE_TYPE;
    case ERROR_DISK_FULL:               return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED:     return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:          return STATUS_FILE_TOO_LARGE;
    case ERROR_INTERNAL_ERROR:          return STATUS_INTERNAL_ERROR;
    default:
        print_error("[ERROR] nfs41_Create: upcall returned ERROR_0x%lx "
            "returning STATUS_INSUFFICIENT_RESOURCES\n",
            (long)status);
    case ERROR_OUTOFMEMORY:             return STATUS_INSUFFICIENT_RESOURCES;
    }
}

static DWORD map_disposition_to_create_retval(
    DWORD disposition,
    DWORD errno)
{
    switch(disposition) {
    case FILE_SUPERSEDE:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_SUPERSEDED;
    case FILE_CREATE:                       return FILE_CREATED;
    case FILE_OPEN:                         return FILE_OPENED;
    case FILE_OPEN_IF:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_OPENED;
    case FILE_OVERWRITE:                    return FILE_OVERWRITTEN;
    case FILE_OVERWRITE_IF:
        if (errno == ERROR_FILE_NOT_FOUND)  return FILE_CREATED;
        else                                return FILE_OVERWRITTEN;
    default:
        print_error("unknown disposition %d\n", disposition);
        return FILE_OPENED;
    }
}

static BOOLEAN create_should_pass_ea(
    IN PFILE_FULL_EA_INFORMATION ea,
    IN ULONG disposition)
{
    /* don't pass cygwin EAs */
    if (AnsiStrEq(&NfsV3Attributes, ea->EaName, ea->EaNameLength)
        || AnsiStrEq(&NfsActOnLink, ea->EaName, ea->EaNameLength)
        || AnsiStrEq(&NfsSymlinkTargetName, ea->EaName, ea->EaNameLength))
        return FALSE;
    /* only set EAs on file creation */
    return disposition == FILE_SUPERSEDE || disposition == FILE_CREATE
        || disposition == FILE_OPEN_IF || disposition == FILE_OVERWRITE
        || disposition == FILE_OVERWRITE_IF;
}

NTSTATUS check_nfs41_create_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNT_CREATE_PARAMETERS params = &RxContext->Create.NtCreateParameters;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull NFS41_FILE_FS_ATTRIBUTE_INFORMATION *FsAttrs =
        &pVNetRootContext->FsAttrs;
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PMRX_FCB Fcb = RxContext->pFcb;
    __notnull PNFS41_FCB nfs41_fcb = (PNFS41_FCB)Fcb->Context;
    PFILE_FULL_EA_INFORMATION ea = (PFILE_FULL_EA_INFORMATION)
        RxContext->CurrentIrp->AssociatedIrp.SystemBuffer;

    if (Fcb->pNetRoot->Type != NET_ROOT_DISK &&
            Fcb->pNetRoot->Type != NET_ROOT_WILD) {
        print_error("nfs41_Create: Unsupported NetRoot Type %u\n",
            Fcb->pNetRoot->Type);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (FlagOn(Fcb->FcbState, FCB_STATE_PAGING_FILE )) {
        print_error("FCB_STATE_PAGING_FILE not implemented\n");
        status = STATUS_NOT_IMPLEMENTED;
        goto out;
    }

    if (!pNetRootContext->mounts_init) {
        print_error("nfs41_Create: No valid session established\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    if (isStream(SrvOpen->pAlreadyPrefixedName)) {
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (pVNetRootContext->read_only &&
            (params->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA))) {
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }

    /* if FCB was marked for deletion and opened multiple times, as soon
     * as first close happen, FCB transitions into delete_pending state
     * no more opens allowed
     */
    if (Fcb->OpenCount && nfs41_fcb->DeletePending) {
        status = STATUS_DELETE_PENDING;
        goto out;
    }

    /* ms-fsa: 3.1.5.1.2.1 page 68 */
    if (Fcb->OpenCount && nfs41_fcb->StandardInfo.DeletePending &&
            !(params->ShareAccess & FILE_SHARE_DELETE) &&
                (params->DesiredAccess & (FILE_EXECUTE | FILE_READ_DATA |
                    FILE_WRITE_DATA | FILE_APPEND_DATA))) {
        status = STATUS_SHARING_VIOLATION;
        goto out;
    }

    /* rdbss seems miss this sharing_violation check */
    if (Fcb->OpenCount && params->Disposition == FILE_SUPERSEDE) {
        if ((!RxContext->CurrentIrpSp->FileObject->SharedRead &&
                (params->DesiredAccess & FILE_READ_DATA)) ||
            ((!RxContext->CurrentIrpSp->FileObject->SharedWrite &&
                (params->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                    FILE_WRITE_ATTRIBUTES))) ||
            (!RxContext->CurrentIrpSp->FileObject->SharedDelete &&
                (params->DesiredAccess & DELETE)))) {
            status = STATUS_SHARING_VIOLATION;
            goto out;
        }
    }
    if (isFilenameTooLong(SrvOpen->pAlreadyPrefixedName, pVNetRootContext)) {
        status = STATUS_OBJECT_NAME_INVALID;
        goto out;
    }

    /* We do not support oplocks (yet) */
    if (params->CreateOptions & FILE_OPEN_REQUIRING_OPLOCK) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (!areOpenParamsValid(params)) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    /* from ms-fsa 3.1.5.1.1 page 56 */
    if ((params->CreateOptions & FILE_DELETE_ON_CLOSE) &&
            (params->FileAttributes & FILE_ATTRIBUTE_READONLY)) {
        status = STATUS_CANNOT_DELETE;
        goto out;
    }

    if (ea) {
        /* ignore cygwin EAs when checking support and access */
        if (!AnsiStrEq(&NfsV3Attributes, ea->EaName, ea->EaNameLength) &&
            !AnsiStrEq(&NfsActOnLink, ea->EaName, ea->EaNameLength) &&
            !AnsiStrEq(&NfsSymlinkTargetName, ea->EaName, ea->EaNameLength)) {
            if (!(FsAttrs->FileSystemAttributes & FILE_SUPPORTS_EXTENDED_ATTRIBUTES)) {
                status = STATUS_EAS_NOT_SUPPORTED;
                goto out;
            }
        }
    } else if (RxContext->CurrentIrpSp->Parameters.Create.EaLength) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

out:
    return status;
}

NTSTATUS nfs41_Create(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry = NULL;
    PNT_CREATE_PARAMETERS params = &RxContext->Create.NtCreateParameters;
    PFILE_FULL_EA_INFORMATION ea = (PFILE_FULL_EA_INFORMATION)
        RxContext->CurrentIrp->AssociatedIrp.SystemBuffer;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PMRX_FCB Fcb = RxContext->pFcb;
    __notnull PNFS41_FCB nfs41_fcb = (PNFS41_FCB)Fcb->Context;
    PNFS41_FOBX nfs41_fobx = NULL;
    BOOLEAN oldDeletePending = nfs41_fcb->StandardInfo.DeletePending;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

    ASSERT( NodeType(SrvOpen) == RDBSS_NTC_SRVOPEN );

#ifdef DEBUG_OPEN
    DbgEn();
    print_debug_header(RxContext);
    print_nt_create_params(1, RxContext->Create.NtCreateParameters);
    // if (ea) print_ea_info(ea);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_create_args(RxContext);
    if (status) goto out;

    status = nfs41_UpcallCreate(NFS41_SYSOP_OPEN, NULL,
        pVNetRootContext->session, INVALID_HANDLE_VALUE,
        pNetRootContext->nfs41d_version,
        SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    /* Check whether this is the mount point for this volume */
    entry->u.Open.isvolumemntpt =
        isFileNameTheVolumeMountPoint(SrvOpen->pAlreadyPrefixedName,
            pVNetRootContext);

    entry->u.Open.access_mask = params->DesiredAccess;
    entry->u.Open.access_mode = params->ShareAccess;
    entry->u.Open.attrs = params->FileAttributes;
    if (!(params->CreateOptions & FILE_DIRECTORY_FILE))
        entry->u.Open.attrs |= FILE_ATTRIBUTE_ARCHIVE;
    entry->u.Open.disp = params->Disposition;
    entry->u.Open.copts = params->CreateOptions;
    entry->u.Open.srv_open = SrvOpen;
    /* treat the NfsActOnLink ea as FILE_OPEN_REPARSE_POINT */
    if ((ea && AnsiStrEq(&NfsActOnLink, ea->EaName, ea->EaNameLength)) ||
            (entry->u.Open.access_mask & DELETE))
        entry->u.Open.copts |= FILE_OPEN_REPARSE_POINT;
    if (isDataAccess(params->DesiredAccess) || isOpen2Create(params->Disposition))
        entry->u.Open.open_owner_id = InterlockedIncrement(&open_owner_id);
    // if we are creating a file check if nfsv3attributes were passed in
    if (params->Disposition != FILE_OPEN && params->Disposition != FILE_OVERWRITE) {
        bool is_dir;
        bool use_nfsv3attrsea_mode;

        is_dir = (params->CreateOptions & FILE_DIRECTORY_FILE)?true:false;

        /* Get default mode */
        if (is_dir) {
            entry->u.Open.mode = pVNetRootContext->dir_createmode.mode;
        }
        else {
            entry->u.Open.mode = pVNetRootContext->file_createmode.mode;
        }

        /* Prefer mode from NfsV3Attributes ? */
        use_nfsv3attrsea_mode = (is_dir?
            pVNetRootContext->dir_createmode.use_nfsv3attrsea_mode:
            pVNetRootContext->file_createmode.use_nfsv3attrsea_mode);

        /* Use mode from NfsV3Attributes */
        if (use_nfsv3attrsea_mode &&
            ea && AnsiStrEq(&NfsV3Attributes,
            ea->EaName, ea->EaNameLength)) {
            nfs3_attrs *attrs =
                (nfs3_attrs *)(ea->EaName + ea->EaNameLength + 1);

            entry->u.Open.mode = attrs->mode;
#ifdef DEBUG_OPEN
            DbgP("creating '%s' with EA mode 0%o\n",
                (is_dir?"dir":"file"),
                entry->u.Open.mode);
#endif
        }
        else {
#ifdef DEBUG_OPEN
            DbgP("creating '%s' with default mode 0%o\n",
                (is_dir?"dir":"file"),
                entry->u.Open.mode);
#endif
        }

        if (params->FileAttributes & FILE_ATTRIBUTE_READONLY) {
            entry->u.Open.mode &= ~0222;
            DbgP("FILE_ATTRIBUTE_READONLY set, using mode 0%o\n",
                entry->u.Open.mode);
        }
    }
    if (entry->u.Open.disp == FILE_CREATE && ea &&
            AnsiStrEq(&NfsSymlinkTargetName, ea->EaName, ea->EaNameLength)) {
        /* for a cygwin symlink, given as a unicode string */
        entry->u.Open.symlink.Buffer = (PWCH)(ea->EaName + ea->EaNameLength + 1);
        entry->u.Open.symlink.MaximumLength = entry->u.Open.symlink.Length = ea->EaValueLength;
    }
retry_on_link:
    if (ea && create_should_pass_ea(ea, params->Disposition)) {
        /* lock the extended attribute buffer for read access in user space */
        entry->u.Open.EaMdl = IoAllocateMdl(ea,
            RxContext->CurrentIrpSp->Parameters.Create.EaLength,
            FALSE, FALSE, NULL);
        if (entry->u.Open.EaMdl == NULL) {
            status = STATUS_INTERNAL_ERROR;
            goto out;
        }
#pragma warning( push )
/*
 * C28145: "The opaque MDL structure should not be modified by a
 * driver.", |MDL_MAPPING_CAN_FAIL| is the exception
 */
#pragma warning (disable : 28145)
        entry->u.Open.EaMdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;
#pragma warning( pop )
        MmProbeAndLockPages(entry->u.Open.EaMdl, KernelMode, IoModifyAccess);
    }

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);

    if (entry->u.Open.EaMdl) {
        MmUnlockPages(entry->u.Open.EaMdl);
        IoFreeMdl(entry->u.Open.EaMdl);
        entry->u.Open.EaMdl = NULL;
    }

    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (entry->status == NO_ERROR && entry->errno == ERROR_REPARSE) {
        /* symbolic link handling. when attempting to open a symlink when the
         * FILE_OPEN_REPARSE_POINT flag is not set, replace the filename with
         * the symlink target's by calling RxPrepareToReparseSymbolicLink()
         * and returning STATUS_REPARSE. the object manager will attempt to
         * open the new path, and return its handle for the original open */
        PRDBSS_DEVICE_OBJECT DeviceObject = RxContext->RxDeviceObject;
        PV_NET_ROOT VNetRoot = (PV_NET_ROOT)
            RxContext->pRelevantSrvOpen->pVNetRoot;
        PUNICODE_STRING VNetRootPrefix = &VNetRoot->PrefixEntry.Prefix;
        UNICODE_STRING AbsPath;
        PCHAR buf;
        BOOLEAN ReparseRequired;

        /*
         * Allocate the string for |RxPrepareToReparseSymbolicLink()|,
         * and format an absolute path
         * "DeviceName+VNetRootName+symlink" if the symlink is
         * device-relative, or just "symlink" if the input is an NT path
         * (which starts with "\??\", see above)
         */
        AbsPath.Length = 0;
        if (entry->u.Open.symlinktarget_type ==
            NFS41_SYMLINKTARGET_FILESYSTEM_ABSOLUTE) {
            AbsPath.Length += DeviceObject->DeviceName.Length +
                VNetRootPrefix->Length;
        }
        else if (entry->u.Open.symlinktarget_type ==
            NFS41_SYMLINKTARGET_NTPATH) {
        }
        else {
            DbgP("nfs41_Create: Unknown symlinktarget_type=%d\n",
                (int)entry->u.Open.symlinktarget_type);
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        AbsPath.Length += entry->u.Open.symlink.Length;
        AbsPath.MaximumLength = AbsPath.Length + sizeof(UNICODE_NULL);
        AbsPath.Buffer = RxAllocatePoolWithTag(NonPagedPoolNx,
            AbsPath.MaximumLength, NFS41_MM_POOLTAG);
        if (AbsPath.Buffer == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }

        buf = (PCHAR)AbsPath.Buffer;
        if (entry->u.Open.symlinktarget_type ==
            NFS41_SYMLINKTARGET_FILESYSTEM_ABSOLUTE) {
            RtlCopyMemory(buf, DeviceObject->DeviceName.Buffer,
                DeviceObject->DeviceName.Length);
            buf += DeviceObject->DeviceName.Length;
            RtlCopyMemory(buf, VNetRootPrefix->Buffer,
                VNetRootPrefix->Length);
            buf += VNetRootPrefix->Length;
        }

        RtlCopyMemory(buf, entry->u.Open.symlink.Buffer,
            entry->u.Open.symlink.Length);
        buf += entry->u.Open.symlink.Length;
        *(PWCHAR)buf = UNICODE_NULL;

        RxFreePool(entry->u.Open.symlink.Buffer);
        entry->u.Open.symlink.Buffer = NULL;

        status = RxPrepareToReparseSymbolicLink(RxContext,
            entry->u.Open.symlink_embedded, &AbsPath, TRUE, &ReparseRequired);

        DbgP("nfs41_Create: "
            "RxPrepareToReparseSymbolicLink(%u, '%wZ') returned "
            "ReparseRequired=%d, status=0x%lx, "
            "FileName is '%wZ'\n",
            entry->u.Open.symlink_embedded,
            &AbsPath,
            (int)ReparseRequired,
            (long)status,
            &RxContext->CurrentIrpSp->FileObject->FileName);

        if (status == STATUS_SUCCESS) {
            /* if a reparse is not required, reopen the link itself.  this
             * happens with operations on cygwin symlinks, where the reparse
             * flag is not set */
            if (!ReparseRequired) {
                entry->u.Open.symlink.Length = 0;
                entry->u.Open.copts |= FILE_OPEN_REPARSE_POINT;
                goto retry_on_link;
            }
            status = STATUS_REPARSE;
        }
        goto out;
    }

    status = map_open_errors(entry->status,
                SrvOpen->pAlreadyPrefixedName->Length);
    if (status) {
#ifdef DEBUG_OPEN
        print_open_error(1, status);
#endif
        goto out;
    }

    if (!RxIsFcbAcquiredExclusive(Fcb)) {
        ASSERT(!RxIsFcbAcquiredShared(Fcb));
        RxAcquireExclusiveFcbResourceInMRx(Fcb);
    }

    RxContext->pFobx = RxCreateNetFobx(RxContext, SrvOpen);
    if (RxContext->pFobx == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
#ifdef DEBUG_OPEN
    DbgP("nfs41_Create: created FOBX 0x%p\n", RxContext->pFobx);
#endif
    nfs41_fobx = (PNFS41_FOBX)(RxContext->pFobx)->Context;
    nfs41_fobx->nfs41_open_state = entry->open_state;
    if (nfs41_fobx->sec_ctx.ClientToken == NULL) {
        status = nfs41_get_sec_ctx(SecurityImpersonation, &nfs41_fobx->sec_ctx);
        if (status)
            goto out;
    }

    // we get attributes only for data access and file (not directories)
    if (Fcb->OpenCount == 0 ||
            (Fcb->OpenCount > 0 &&
                nfs41_fcb->changeattr != entry->ChangeTime)) {
        FCB_INIT_PACKET InitPacket;
        RX_FILE_TYPE StorageType = FileTypeNotYetKnown;
        RtlCopyMemory(&nfs41_fcb->BasicInfo, &entry->u.Open.binfo,
            sizeof(entry->u.Open.binfo));
        RtlCopyMemory(&nfs41_fcb->StandardInfo, &entry->u.Open.sinfo,
            sizeof(entry->u.Open.sinfo));
        nfs41_fcb->fileid = entry->u.Open.fileid;
        nfs41_fcb->fsid_major = entry->u.Open.fsid_major;
        nfs41_fcb->fsid_minor = entry->u.Open.fsid_minor;
        nfs41_fcb->mode = entry->u.Open.mode;
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
        nfs41_fcb->owner_local_uid = entry->u.Open.owner_local_uid;
        nfs41_fcb->owner_group_local_gid = entry->u.Open.owner_group_local_gid;
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
        nfs41_fcb->changeattr = entry->ChangeTime;
        if (((params->CreateOptions & FILE_DELETE_ON_CLOSE) &&
                !pVNetRootContext->read_only) || oldDeletePending)
            nfs41_fcb->StandardInfo.DeletePending = TRUE;

        if (Fcb->OpenCount == 0) {
            /* Init FCB attributes */
            RxFormInitPacket(InitPacket,
                &entry->u.Open.binfo.FileAttributes,
                &entry->u.Open.sinfo.NumberOfLinks,
                &entry->u.Open.binfo.CreationTime,
                &entry->u.Open.binfo.LastAccessTime,
                &entry->u.Open.binfo.LastWriteTime,
                &entry->u.Open.binfo.ChangeTime,
                &entry->u.Open.sinfo.AllocationSize,
                &entry->u.Open.sinfo.EndOfFile,
                &entry->u.Open.sinfo.EndOfFile);

            if (entry->u.Open.sinfo.Directory)
                StorageType = FileTypeDirectory;
            else
                StorageType = FileTypeFile;

            RxFinishFcbInitialization(Fcb,
                RDBSS_STORAGE_NTC(StorageType),
                &InitPacket);
        }
        else {
#ifndef NFS41_DRIVER_HACK_DISABLE_FCB_ATTR_UPDATE_ON_OPEN
            /*
             * NFS41_DRIVER_HACK_DISABLE_FCB_ATTR_UPDATE_ON_OPEN -
             * disable updating of FCB attributes for an already
             * opened FCB
             * This is a hack for now, until we can figure out how
             * to do this correctly (best guess is not to update FCB
             * attributes if the file is opened for writing, because
             * the kernel keeps updating the FCB data. The userland
             * is not affected by this, they get all information from
             * |nfs41_fcb->BasicInfo| and |nfs41_fcb->StandardInfo|).
             *
             * Without this hack
             * $ '/cygdrive/c/Program Files/Git/cmd/git' clone ... #
             * will fail with read errors.
             *
             */
            PFCB pFcb = (PFCB)RxContext->pFcb;

            /* Update FCB attributes */
            pFcb->Attributes = entry->u.Open.binfo.FileAttributes;
            pFcb->NumberOfLinks = entry->u.Open.sinfo.NumberOfLinks;
            pFcb->CreationTime = entry->u.Open.binfo.CreationTime;
            pFcb->LastAccessTime = entry->u.Open.binfo.LastAccessTime;
            pFcb->LastWriteTime = entry->u.Open.binfo.LastWriteTime;
            pFcb->LastChangeTime = entry->u.Open.binfo.ChangeTime;
            pFcb->ActualAllocationLength =
                entry->u.Open.sinfo.AllocationSize.QuadPart;
            pFcb->Header.AllocationSize =
                entry->u.Open.sinfo.AllocationSize;
            pFcb->Header.FileSize  = entry->u.Open.sinfo.EndOfFile;
            pFcb->Header.ValidDataLength =
                entry->u.Open.sinfo.EndOfFile;
#endif /* !NFS41_DRIVER_HACK_DISABLE_FCB_ATTR_UPDATE_ON_OPEN */
        }
    }
#ifdef DEBUG_OPEN
    else
        DbgP("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n");

    print_basic_info(1, &nfs41_fcb->BasicInfo);
    print_std_info(1, &nfs41_fcb->StandardInfo);
#endif

    /* aglo: 05/10/2012. it seems like always have to invalid the cache if the
     * file has been opened before and being opened again for data access.
     * If the file was opened before, RDBSS might have cached (unflushed) data
     * and by opening it again, we will not have the correct representation of
     * the file size and data content. fileio tests 208, 219, 221.
     */
    if (Fcb->OpenCount > 0 && (isDataAccess(params->DesiredAccess) ||
            nfs41_fcb->changeattr != entry->ChangeTime) &&
                !nfs41_fcb->StandardInfo.Directory) {
        ULONG flag = DISABLE_CACHING;
#ifdef DEBUG_OPEN
        DbgP("nfs41_Create: reopening (changed) file '%wZ'\n",
            SrvOpen->pAlreadyPrefixedName);
#endif
        RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);
    }

    if (!nfs41_fcb->StandardInfo.Directory &&
        isAttributeOnlyDesiredAccess(params)) {
        SrvOpen->Flags |= SRVOPEN_FLAG_NO_BUFFERING_STATE_CHANGE;
    }

    if (!nfs41_fcb->StandardInfo.Directory &&
            isDataAccess(params->DesiredAccess)) {
        nfs41_fobx->deleg_type = entry->u.Open.deleg_type;
#ifdef DEBUG_OPEN
        DbgP("nfs41_Create: received delegation %d\n", entry->u.Open.deleg_type);
#endif

        /* We always cache file size and file times locally */
        SrvOpen->BufferingFlags |=
            FCB_STATE_FILESIZECACHEING_ENABLED |
            FCB_STATE_FILETIMECACHEING_ENABLED;

        /*
         * We cannot have a file cached on a write-only handle,
         * so we have to set |SRVOPEN_FLAG_DONTUSE_WRITE_CACHING|
         * in this case.
         */
        if (isWriteOnlyDesiredAccess(params)) {
            SrvOpen->Flags |= SRVOPEN_FLAG_DONTUSE_WRITE_CACHING;
            DbgP("nfs41_Create: write-only handle for file '%wZ', "
                "setting SRVOPEN_FLAG_DONTUSE_WRITE_CACHING\n",
                SrvOpen->pAlreadyPrefixedName);
        }

        if (!(params->CreateOptions & FILE_WRITE_THROUGH) &&
                !pVNetRootContext->write_thru &&
                (entry->u.Open.deleg_type == 2 ||
                (params->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)))) {
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: enabling write buffering\n");
#endif
            SrvOpen->BufferingFlags |=
                (FCB_STATE_WRITECACHING_ENABLED |
                FCB_STATE_WRITEBUFFERING_ENABLED);
        } else if (params->CreateOptions & FILE_WRITE_THROUGH ||
                    pVNetRootContext->write_thru)
            nfs41_fobx->write_thru = TRUE;
        if (entry->u.Open.deleg_type >= 1 ||
                params->DesiredAccess & FILE_READ_DATA) {
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: enabling read buffering\n");
#endif
            SrvOpen->BufferingFlags |=
                (FCB_STATE_READBUFFERING_ENABLED |
                FCB_STATE_READCACHING_ENABLED);
        }
        nfs41_fobx->timebasedcoherency = pVNetRootContext->timebasedcoherency;
        if (pVNetRootContext->nocache ||
                (params->CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING)) {
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: disabling buffering\n");
#endif
            SrvOpen->BufferingFlags = FCB_STATE_DISABLE_LOCAL_BUFFERING;
            nfs41_fobx->nocache = TRUE;
        } else if (!entry->u.Open.deleg_type && !Fcb->OpenCount) {
            nfs41_fcb_list_entry *oentry;
#ifdef DEBUG_OPEN
            DbgP("nfs41_Create: received no delegations: srv_open=0x%p "
                "ctime=%llu\n", SrvOpen, entry->ChangeTime);
#endif
            oentry = nfs41_allocate_nfs41_fcb_list_entry();
            if (oentry == NULL) {
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto out;
            }
            oentry->fcb = RxContext->pFcb;
            oentry->nfs41_fobx = nfs41_fobx;
            oentry->session = pVNetRootContext->session;
            oentry->ChangeTime = entry->ChangeTime;
            oentry->skip = FALSE;
            nfs41_AddEntry(fcblistLock, openlist, oentry);
        }
    }

    if ((params->CreateOptions & FILE_DELETE_ON_CLOSE) &&
            !pVNetRootContext->read_only)
        nfs41_fcb->StandardInfo.DeletePending = TRUE;

    RxContext->Create.ReturnedCreateInformation =
        map_disposition_to_create_retval(params->Disposition, entry->errno);

    RxContext->pFobx->OffsetOfNextEaToReturn = 1;
    RxContext->CurrentIrp->IoStatus.Information =
        RxContext->Create.ReturnedCreateInformation;
    status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;

out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }

#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    if ((params->DesiredAccess & FILE_READ_DATA) ||
            (params->DesiredAccess & FILE_WRITE_DATA) ||
            (params->DesiredAccess & FILE_APPEND_DATA) ||
            (params->DesiredAccess & FILE_EXECUTE)) {
        InterlockedIncrement(&open.tops);
        InterlockedAdd64(&open.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Create open delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, open.tops, open.ticks);
#endif
    } else {
        InterlockedIncrement(&lookup.tops);
        InterlockedAdd64(&lookup.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Create lookup delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, lookup.tops, lookup.ticks);
#endif
    }
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_OPEN
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_CollapseOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_MORE_PROCESSING_REQUIRED;
    DbgEn();
    FsRtlEnterFileSystem();
    FsRtlExitFileSystem();
    DbgEx();
    return status;
}

NTSTATUS nfs41_ShouldTryToCollapseThisOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    if (RxContext->pRelevantSrvOpen == NULL)
        return STATUS_SUCCESS;
    else return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS map_close_errors(
    DWORD status)
{
    switch (status) {
    case NO_ERROR:              return STATUS_SUCCESS;
    case ERROR_FILE_NOT_FOUND:  return STATUS_NO_SUCH_FILE;
    case ERROR_NETNAME_DELETED: return STATUS_NETWORK_NAME_DELETED;
    case ERROR_DIR_NOT_EMPTY:   return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_FILE_INVALID:    return STATUS_FILE_INVALID;
    case ERROR_DISK_FULL:       return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED: return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:  return STATUS_FILE_TOO_LARGE;
    default:
        print_error("map_close_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INTERNAL_ERROR\n",
            (long)status);
    case ERROR_INTERNAL_ERROR:  return STATUS_INTERNAL_ERROR;
    }
}

NTSTATUS nfs41_CloseSrvOpen(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
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

#ifdef DEBUG_CLOSE
    DbgEn();
    print_debug_header(RxContext);
#endif
    FsRtlEnterFileSystem();

    if (!nfs41_fobx->deleg_type && !nfs41_fcb->StandardInfo.Directory &&
            !RxContext->pFcb->OpenCount) {
        nfs41_remove_fcb_entry(RxContext->pFcb);
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_CLOSE, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Close.srv_open = SrvOpen;
    if (nfs41_fcb->StandardInfo.DeletePending)
        nfs41_fcb->DeletePending = TRUE;
    if (!RxContext->pFcb->OpenCount ||
            (nfs41_fcb->StandardInfo.DeletePending &&
                nfs41_fcb->StandardInfo.Directory))
        entry->u.Close.remove = nfs41_fcb->StandardInfo.DeletePending;
    if (!RxContext->pFcb->OpenCount)
        entry->u.Close.renamed = nfs41_fcb->Renamed;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    /* map windows ERRORs to NTSTATUS */
    status = map_close_errors(entry->status);
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&close.tops);
    InterlockedAdd64(&close.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_CloseSrvOpen delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, close.tops, close.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_CLOSE
    DbgEx();
#endif
    return status;
}
