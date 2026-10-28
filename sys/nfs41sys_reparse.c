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
#include <wchar.h>
#include <stdbool.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"

#include "win_reparse.h"


NTSTATUS marshal_nfs41_reparse_get(
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

    header_len = *len;
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_reparse_get: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_reparse_get: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_reparse_get: name='%wZ'\n",
        entry->filename);
#endif /* DEBUG_MARSHAL_DETAIL */
out:
    return status;
}

void unmarshal_nfs41_get_reparse(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    USHORT len;
    (void)memcpy(&len, *buf, sizeof(len));
    *buf += sizeof(len);
    if (len > cur->u.GetReparse.reparsebufferlen) {
        cur->status = STATUS_BUFFER_TOO_SMALL;
        return;
    }
    (void)memcpy(cur->u.GetReparse.reparsebuffer, *buf, len);
    *buf += len;
    cur->u.GetReparse.reparsebufferlen = len;
}

NTSTATUS marshal_nfs41_reparse_set(
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

    header_len = *len;
    header_len += sizeof(USHORT) + entry->u.SetReparse.reparsebufferlen;
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_reparse_set: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    UPDOWNCALL_MEMCPY(tmp,
        &entry->u.SetReparse.reparsebufferlen, sizeof(USHORT));
    tmp += sizeof(USHORT);
    UPDOWNCALL_MEMCPY(tmp,
        entry->u.SetReparse.reparsebuffer,
        entry->u.SetReparse.reparsebufferlen);
    tmp += entry->u.SetReparse.reparsebufferlen;

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_reparse_set: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_reparse_set: name='%wZ'\n",
        entry->filename);
#endif /* DEBUG_MARSHAL_DETAIL */
out:
    return status;
}

void unmarshal_nfs41_set_reparse(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    /* empty */
}

NTSTATUS map_reparse_errors(
    NTSTATUS status)
{
    switch (status) {
    case NO_ERROR:                      return STATUS_SUCCESS;
    case ERROR_FILE_NOT_FOUND:          return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:          return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_INVALID_REPARSE_DATA:    return STATUS_IO_REPARSE_DATA_INVALID;
    case ERROR_NOT_A_REPARSE_POINT:     return STATUS_NOT_A_REPARSE_POINT;
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_DIR_NOT_EMPTY:           return STATUS_DIRECTORY_NOT_EMPTY;
    case ERROR_OUTOFMEMORY:             return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INSUFFICIENT_BUFFER:     return STATUS_BUFFER_TOO_SMALL;
    case STATUS_BUFFER_TOO_SMALL:
    case ERROR_BUFFER_OVERFLOW:         return STATUS_BUFFER_OVERFLOW;
    case ERROR_DISK_FULL:               return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED:     return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:          return STATUS_FILE_TOO_LARGE;
    case ERROR_TOO_MANY_LINKS:          return STATUS_TOO_MANY_LINKS;
    case ERROR_INTERNAL_ERROR:          return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_reparse_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

static
NTSTATUS check_nfs41_setreparse_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
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
    if ((SrvOpen->DesiredAccess & (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES)) == 0) {
        DbgP("check_nfs41_setreparse_args: "
            "(FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES) not set\n");
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    /*
     * Must have a filename longer than vnetroot name,
     * or it's trying to operate on the volume itself
     */
    if (is_root_directory(RxContext)) {
        status = STATUS_INVALID_PARAMETER;
        DbgP("check_nfs41_setreparse_args: "
            "is_root_directory() == TRUE\n");
        goto out;
    }

    /* validate input buffer and length */
    if (!Reparse) {
        status = STATUS_INVALID_BUFFER_SIZE;
        DbgP("check_nfs41_setreparse_args: Reparse == NULL\n");
        goto out;
    }

    if ((FsCtl->InputBufferLength < HeaderLen) ||
        (FsCtl->InputBufferLength > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)) {
        DbgP("check_nfs41_setreparse_args: "
            "InputBufferLength too small/large\n");
        status = STATUS_IO_REPARSE_DATA_INVALID;
        goto out;
    }
    if (FsCtl->InputBufferLength != (HeaderLen + Reparse->ReparseDataLength)) {
        status = STATUS_IO_REPARSE_DATA_INVALID;
        DbgP("check_nfs41_setreparse_args: "
            "InputBufferLength != (HeaderLen + ReparseDataLength)\n");
        goto out;
    }

    /* validate reparse tag */
    if (!IsReparseTagValid(Reparse->ReparseTag)) {
        status = STATUS_IO_REPARSE_TAG_INVALID;
        DbgP("check_nfs41_setreparse_args: "
            "IsReparseTagValid() failed\n");
        goto out;
    }

out:
    return status;
}

NTSTATUS nfs41_SetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull const PREPARSE_DATA_BUFFER Reparse =
        (const PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
    ULONG ReparseLen = FsCtl->InputBufferLength;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry = NULL;
    PWSTR prefixed_targetname = NULL;

#ifdef DEBUG_REPARSE
    DbgEn();
    print_debug_header(RxContext);
    print_reparse_buffer(Reparse);
#endif

    DbgP("nfs41_SetReparsePoint: ReparseTag: '%s'/0x%04lx\n",
        reparsetag2string(Reparse->ReparseTag),
        (long)Reparse->ReparseTag);

    status = check_nfs41_setreparse_args(RxContext);
    if (status) {
        DbgP("nfs41_SetReparsePoint: "
            "check_nfs41_setreparse_args() failed, "
            "status=0x%lx\n",
                (long)status);
        goto out;
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_REPARSE_SET, &nfs41_srvopen->sec_ctx,
        VNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    /* |ReparseLen| cannot be larger than |MAXIMUM_REPARSE_DATA_BUFFER_SIZE| */
    entry->u.SetReparse.reparsebufferlen = (USHORT)ReparseLen;
    entry->u.SetReparse.reparsebuffer = Reparse;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_reparse_errors(entry->status);
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
    if (prefixed_targetname)
        RxFreePool(prefixed_targetname);

#ifdef DEBUG_REPARSE
    DbgEx();
#endif
    return status;
}

static
NTSTATUS check_nfs41_getreparse_args(
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
    if (FsCtl->pOutputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        DbgP("check_nfs41_getreparse_args: "
            "FsCtl->pOutputBuffer == NULL\n");
        goto out;
    }
    if (!BooleanFlagOn(RxContext->pFcb->Attributes,
        FILE_ATTRIBUTE_REPARSE_POINT)) {
        status = STATUS_NOT_A_REPARSE_POINT;
        DbgP("check_nfs41_getreparse_args: "
            "FILE_ATTRIBUTE_REPARSE_POINT is not set!\n");
        goto out;
    }

    if (FsCtl->OutputBufferLength < HeaderLen) {
        RxContext->InformationToReturn = HeaderLen;
        status = STATUS_BUFFER_TOO_SMALL;
        DbgP("check_nfs41_getreparse_args: "
            "FsCtl->OutputBufferLength < HeaderLen\n");
        goto out;
    }
out:
    return status;

}

NTSTATUS nfs41_GetReparsePoint(IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry = NULL;
    PVOID new_buffer = NULL;
    USHORT new_buffer_len = MAXIMUM_REPARSE_DATA_BUFFER_SIZE;

#ifdef DEBUG_REPARSE
    DbgEn();
#endif /* DEBUG_REPARSE */

    FsRtlEnterFileSystem();

    status = check_nfs41_getreparse_args(RxContext);
    if (status) {
        DbgP("nfs41_GetReparsePoint: "
            "check_nfs41_getreparse_args() failed, "
            "status=0x%lx\n",
                (long)status);
    }

    new_buffer = RxAllocatePoolWithTag(NonPagedPoolNx,
        MAXIMUM_REPARSE_DATA_BUFFER_SIZE, NFS41_MM_REPARSE_BUFFER);
    if (new_buffer == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    (void)memset(new_buffer, 0, MAXIMUM_REPARSE_DATA_BUFFER_SIZE);

    status = nfs41_UpcallCreate(NFS41_SYSOP_REPARSE_GET, &nfs41_srvopen->sec_ctx,
        VNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.GetReparse.reparsebuffer = new_buffer;
    entry->u.GetReparse.reparsebufferlen = new_buffer_len;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }
    status = map_reparse_errors(entry->status);
    if (status)
        goto out;

    new_buffer_len = entry->u.GetReparse.reparsebufferlen;

    if (FsCtl->OutputBufferLength < new_buffer_len) {
        DbgP("nfs41_GetReparsePoint: "
            "FsCtl->OutputBufferLength too small\n");

        RxContext->InformationToReturn = new_buffer_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else {
        (void)memcpy(FsCtl->pOutputBuffer, new_buffer, new_buffer_len);
        RxContext->IoStatusBlock.Information = new_buffer_len;
    }

out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
    if (new_buffer) {
        RxFreePool(new_buffer);
    }

    FsRtlExitFileSystem();

#ifdef DEBUG_REPARSE
    DbgEx();
#endif /* DEBUG_REPARSE */

    return status;
}

void print_reparse_buffer(
    PREPARSE_DATA_BUFFER r)
{
    UNICODE_STRING name;
    DbgP("ReparseTag: 0x%lx\n", (long)r->ReparseTag);
    DbgP("ReparseDataLength: %u\n", (int)r->ReparseDataLength);
    DbgP("Reserved: %u\n", (int)r->Reserved);
    if (r->ReparseTag == IO_REPARSE_TAG_SYMLINK) {
        DbgP("IO_REPARSE_TAG_SYMLINK:\n");
        DbgP("SubstituteNameOffset: %u\n",
            r->SymbolicLinkReparseBuffer.SubstituteNameOffset);
        DbgP("SubstituteNameLength: %u\n",
            r->SymbolicLinkReparseBuffer.SubstituteNameLength);
        DbgP("PrintNameOffset: %u\n",
            r->SymbolicLinkReparseBuffer.PrintNameOffset);
        DbgP("PrintNameLength: %u\n",
            r->SymbolicLinkReparseBuffer.PrintNameLength);
        DbgP("Flags: 0x%lx\n",
            (long)r->SymbolicLinkReparseBuffer.Flags);

        name.Buffer = &r->SymbolicLinkReparseBuffer.PathBuffer[
            r->SymbolicLinkReparseBuffer.SubstituteNameOffset/sizeof(WCHAR)];
        name.MaximumLength = name.Length =
            r->SymbolicLinkReparseBuffer.SubstituteNameLength;
        DbgP("SubstituteName: '%wZ'\n", &name);

        name.Buffer = &r->SymbolicLinkReparseBuffer.PathBuffer[
            r->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];
        name.MaximumLength = name.Length =
            r->SymbolicLinkReparseBuffer.PrintNameLength;
            DbgP("PrintName: '%wZ'\n", &name);
    }
    else if (r->ReparseTag == IO_REPARSE_TAG_MOUNT_POINT) {
        DbgP("IO_REPARSE_TAG_MOUNT_POINT:\n");
        DbgP("SubstituteNameOffset: %u\n",
            r->MountPointReparseBuffer.SubstituteNameOffset);
        DbgP("SubstituteNameLength: %u\n",
            r->MountPointReparseBuffer.SubstituteNameLength);
        DbgP("PrintNameOffset: %u\n",
            r->MountPointReparseBuffer.PrintNameOffset);
        DbgP("PrintNameLength: %u\n",
            r->MountPointReparseBuffer.PrintNameLength);

        name.Buffer = &r->MountPointReparseBuffer.PathBuffer[
            r->MountPointReparseBuffer.SubstituteNameOffset/sizeof(WCHAR)];
        name.MaximumLength = name.Length =
            r->MountPointReparseBuffer.SubstituteNameLength;
        DbgP("SubstituteName: '%wZ'\n", &name);

        name.Buffer = &r->MountPointReparseBuffer.PathBuffer[
            r->MountPointReparseBuffer.PrintNameOffset/sizeof(WCHAR)];
        name.MaximumLength = name.Length =
            r->MountPointReparseBuffer.PrintNameLength;
            DbgP("PrintName: '%wZ'\n", &name);
    }
}
