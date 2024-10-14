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
    if (status) goto out;
    else tmp += *len;

    header_len = *len + sizeof(BOOLEAN) + length_as_utf8(entry->filename);
    if (entry->u.Symlink.set)
        header_len += length_as_utf8(entry->u.Symlink.target);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    status = marshall_unicode_as_utf8(&tmp, entry->filename);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Symlink.set, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    if (entry->u.Symlink.set) {
        status = marshall_unicode_as_utf8(&tmp, entry->u.Symlink.target);
        if (status) goto out;
    }
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_symlink: name '%wZ' symlink target '%wZ'\n",
         entry->filename,
         entry->u.Symlink.set?entry->u.Symlink.target : NULL);
#endif
out:
    return status;
}

void unmarshal_nfs41_symlink(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    if (cur->u.Symlink.set) return;

    RtlCopyMemory(&cur->u.Symlink.target->Length, *buf, sizeof(USHORT));
    *buf += sizeof(USHORT);
    if (cur->u.Symlink.target->Length >
            cur->u.Symlink.target->MaximumLength) {
        cur->status = STATUS_BUFFER_TOO_SMALL;
        return;
    }
    RtlCopyMemory(cur->u.Symlink.target->Buffer, *buf,
        cur->u.Symlink.target->Length);
    cur->u.Symlink.target->Length -= sizeof(UNICODE_NULL);
}

NTSTATUS map_symlink_errors(
    NTSTATUS status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_INVALID_REPARSE_DATA: return STATUS_IO_REPARSE_DATA_INVALID;
    case ERROR_NOT_A_REPARSE_POINT: return STATUS_NOT_A_REPARSE_POINT;
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_NOT_EMPTY:           return STATUS_DIRECTORY_NOT_EMPTY;
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

static void print_reparse_buffer(
    PREPARSE_DATA_BUFFER Reparse)
{
    UNICODE_STRING name;
    DbgP("ReparseTag:           %08X\n", Reparse->ReparseTag);
    DbgP("ReparseDataLength:    %8u\n", Reparse->ReparseDataLength);
    DbgP("Reserved:             %8u\n", Reparse->Reserved);
    DbgP("SubstituteNameOffset: %8u\n",
         Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset);
    DbgP("SubstituteNameLength: %8u\n",
         Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength);
    DbgP("PrintNameOffset:      %8u\n",
         Reparse->SymbolicLinkReparseBuffer.PrintNameOffset);
    DbgP("PrintNameLength:      %8u\n",
         Reparse->SymbolicLinkReparseBuffer.PrintNameLength);
    DbgP("Flags:                %08X\n",
         Reparse->SymbolicLinkReparseBuffer.Flags);

    name.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset/sizeof(WCHAR)];
    name.MaximumLength = name.Length =
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength;
    DbgP("SubstituteName:       '%wZ'\n", &name);

    name.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];
    name.MaximumLength = name.Length =
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength;
    DbgP("PrintName:            '%wZ'\n", &name);
}

static
NTSTATUS check_nfs41_setreparse_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
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
        goto out;
    }
    if (FsCtl->pOutputBuffer != NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    /* validate input buffer and length */
    if (!Reparse) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto out;
    }

    if (FsCtl->InputBufferLength < HeaderLen ||
            FsCtl->InputBufferLength > MAXIMUM_REPARSE_DATA_BUFFER_SIZE) {
        status = STATUS_IO_REPARSE_DATA_INVALID;
        goto out;
    }
    if (FsCtl->InputBufferLength != HeaderLen + Reparse->ReparseDataLength) {
        status = STATUS_IO_REPARSE_DATA_INVALID;
        goto out;
    }

    /* validate reparse tag */
    if (!IsReparseTagValid(Reparse->ReparseTag)) {
        status = STATUS_IO_REPARSE_TAG_INVALID;
        goto out;
    }
    if (Reparse->ReparseTag != IO_REPARSE_TAG_SYMLINK) {
        status = STATUS_IO_REPARSE_TAG_MISMATCH;
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_SetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    UNICODE_STRING TargetName;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)FsCtl->pInputBuffer;
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry;

#ifdef DEBUG_SYMLINK
    DbgEn();
    print_debug_header(RxContext);
    print_reparse_buffer(Reparse);
#endif
    status = check_nfs41_setreparse_args(RxContext);
    if (status) goto out;

    TargetName.MaximumLength = TargetName.Length =
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength;
    TargetName.Buffer = &Reparse->SymbolicLinkReparseBuffer.PathBuffer[
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset/sizeof(WCHAR)];

    status = nfs41_UpcallCreate(NFS41_SYMLINK, &Fobx->sec_ctx,
        VNetRootContext->session, Fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Symlink.target = &TargetName;
    entry->u.Symlink.set = TRUE;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) goto out;

    status = map_symlink_errors(entry->status);
    nfs41_UpcallDestroy(entry);
out:
#ifdef DEBUG_SYMLINK
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

    /* must have a filename longer than vnetroot name,
     * or it's trying to operate on the volume itself */
    if (is_root_directory(RxContext)) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    /* ifs reparse tests expect STATUS_INVALID_PARAMETER,
     * but 'dir' passes a buffer here when querying symlinks
    if (FsCtl->pInputBuffer != NULL) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    } */
    if (!FsCtl->pOutputBuffer) {
        status = STATUS_INVALID_USER_BUFFER;
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
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_GetReparsePoint(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status;
    UNICODE_STRING TargetName;
    XXCTL_LOWIO_COMPONENT *FsCtl = &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PNFS41_FOBX Fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    nfs41_updowncall_entry *entry;
    const USHORT HeaderLen = FIELD_OFFSET(REPARSE_DATA_BUFFER,
        SymbolicLinkReparseBuffer.PathBuffer);

#ifdef DEBUG_SYMLINK
    DbgEn();
#endif
    status = check_nfs41_getreparse_args(RxContext);
    if (status) goto out;

    TargetName.Buffer = (PWCH)((PBYTE)FsCtl->pOutputBuffer + HeaderLen);
    TargetName.MaximumLength = (USHORT)min(FsCtl->OutputBufferLength -
        HeaderLen, 0xFFFF);

    status = nfs41_UpcallCreate(NFS41_SYMLINK, &Fobx->sec_ctx,
        VNetRootContext->session, Fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Symlink.target = &TargetName;
    entry->u.Symlink.set = FALSE;

    status = nfs41_UpcallWaitForReply(entry, VNetRootContext->timeout);
    if (status) goto out;

    status = map_symlink_errors(entry->status);
    if (status == STATUS_SUCCESS) {
        /* fill in the output buffer */
        PREPARSE_DATA_BUFFER Reparse = (PREPARSE_DATA_BUFFER)
            FsCtl->pOutputBuffer;
        Reparse->ReparseTag = IO_REPARSE_TAG_SYMLINK;
        Reparse->ReparseDataLength = HeaderLen + TargetName.Length -
            REPARSE_DATA_BUFFER_HEADER_SIZE;
        Reparse->Reserved = 0;
        Reparse->SymbolicLinkReparseBuffer.Flags = SYMLINK_FLAG_RELATIVE;
        /* PrintName and SubstituteName point to the same string */
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameOffset = 0;
        Reparse->SymbolicLinkReparseBuffer.SubstituteNameLength =
            TargetName.Length;
        Reparse->SymbolicLinkReparseBuffer.PrintNameOffset = 0;
        Reparse->SymbolicLinkReparseBuffer.PrintNameLength = TargetName.Length;
        print_reparse_buffer(Reparse);

        RxContext->IoStatusBlock.Information =
            (ULONG_PTR)HeaderLen + TargetName.Length;
    } else if (status == STATUS_BUFFER_TOO_SMALL) {
        RxContext->InformationToReturn =
            (ULONG_PTR)HeaderLen + TargetName.Length;
    }
    nfs41_UpcallDestroy(entry);
out:
#ifdef DEBUG_SYMLINK
    DbgEx();
#endif
    return status;
}
