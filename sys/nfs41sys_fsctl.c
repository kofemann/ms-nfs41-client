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

static
NTSTATUS check_nfs41_queryallocatedranges_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
    const USHORT HeaderLen = sizeof(FILE_ALLOCATED_RANGE_BUFFER);

    if (!FsCtl->pOutputBuffer) {
        status = STATUS_INVALID_USER_BUFFER;
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

static
NTSTATUS nfs41_QueryAllocatedRanges(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    nfs41_updowncall_entry *entry = NULL;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PFILE_ALLOCATED_RANGE_BUFFER in_range_buffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)FsCtl->pInputBuffer;
    __notnull PFILE_ALLOCATED_RANGE_BUFFER out_range_buffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)FsCtl->pOutputBuffer;
    ULONG out_range_buffer_len = FsCtl->OutputBufferLength;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);

    DbgEn();

    RxContext->IoStatusBlock.Information = 0;

    status = check_nfs41_queryallocatedranges_args(RxContext);
    if (status)
        goto out;

    if (FsCtl->InputBufferLength <
        sizeof(FILE_ALLOCATED_RANGE_BUFFER)) {
        DbgP("nfs41_QueryAllocatedRanges: "
            "in_range_buffer to small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    DbgP("nfs41_QueryAllocatedRanges/REAL: "
        "in_range_buffer=(FileOffset=%lld,Length=%lld)\n",
        (long long)in_range_buffer->FileOffset.QuadPart,
        (long long)in_range_buffer->Length.QuadPart);

    status = nfs41_UpcallCreate(NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES,
        &nfs41_fobx->sec_ctx,
        pVNetRootContext->session,
        nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version,
        SrvOpen->pAlreadyPrefixedName,
        &entry);

    if (status)
        goto out;

    entry->u.QueryAllocatedRanges.inrange = *in_range_buffer;
    entry->u.QueryAllocatedRanges.BufferSize = out_range_buffer_len;

    /* lock the buffer for write access in user space */
    entry->u.QueryAllocatedRanges.BufferMdl = IoAllocateMdl(
        out_range_buffer,
        out_range_buffer_len,
        FALSE, FALSE, NULL);
    if (entry->u.QueryAllocatedRanges.BufferMdl == NULL) {
        status = STATUS_INTERNAL_ERROR;
        DbgP("nfs41_QueryAllocatedRanges: IoAllocateMdl() failed\n");
        goto out_free;
    }

#pragma warning( push )
/*
 * C28145: "The opaque MDL structure should not be modified by a
 * driver.", |MDL_MAPPING_CAN_FAIL| is the exception
 */
#pragma warning (disable : 28145)
    entry->u.QueryAllocatedRanges.BufferMdl->MdlFlags |=
        MDL_MAPPING_CAN_FAIL;
#pragma warning( pop )
    MmProbeAndLockPages(entry->u.QueryAllocatedRanges.BufferMdl,
        KernelMode,
        IoModifyAccess);

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        goto out;
    }

    if (entry->psec_ctx == &entry->sec_ctx) {
        SeDeleteClientSecurity(entry->psec_ctx);
    }
    entry->psec_ctx = NULL;

    if (!entry->status) {
        DbgP("nfs41_QueryAllocatedRanges: SUCCESS\n");
        RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information =
            (ULONG_PTR)entry->u.QueryAllocatedRanges.returned_size;
    }
    else {
        DbgP("nfs41_QueryAllocatedRanges: "
            "FAILURE, entry->status=0x%lx\n", entry->status);
        status = map_setfile_error(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }

out_free:
    if (entry) {
        if (entry->u.QueryAllocatedRanges.BufferMdl) {
            MmUnlockPages(entry->u.QueryAllocatedRanges.BufferMdl);
            IoFreeMdl(entry->u.QueryAllocatedRanges.BufferMdl);
            entry->u.QueryAllocatedRanges.BufferMdl = NULL;
        }

        nfs41_UpcallDestroy(entry);
    }

out:
    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_queryallocatedranges(
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

    header_len = *len + sizeof(FILE_ALLOCATED_RANGE_BUFFER) +
        sizeof(LONGLONG) +
        sizeof(HANDLE);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.QueryAllocatedRanges.inrange,
        sizeof(entry->u.QueryAllocatedRanges.inrange));
    tmp += sizeof(entry->u.QueryAllocatedRanges.inrange);
    RtlCopyMemory(tmp, &entry->u.QueryAllocatedRanges.BufferSize,
        sizeof(entry->u.QueryAllocatedRanges.BufferSize));
    tmp += sizeof(entry->u.QueryAllocatedRanges.BufferSize);

    __try {
        if (entry->u.QueryAllocatedRanges.BufferMdl) {
            entry->u.QueryAllocatedRanges.Buffer =
                MmMapLockedPagesSpecifyCache(
                    entry->u.QueryAllocatedRanges.BufferMdl,
                    UserMode, MmCached, NULL, FALSE,
                    NormalPagePriority|MdlMappingNoExecute);
            if (entry->u.QueryAllocatedRanges.Buffer == NULL) {
                print_error("marshal_nfs41_queryallocatedranges: "
                    "MmMapLockedPagesSpecifyCache() failed to "
                    "map pages\n");
                status = STATUS_INSUFFICIENT_RESOURCES;
                goto out;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        print_error("marshal_nfs41_queryallocatedranges: Call to "
            "MmMapLockedPagesSpecifyCache() failed "
            "due to exception 0x%lx\n", (long)GetExceptionCode());
        status = STATUS_ACCESS_VIOLATION;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryAllocatedRanges.Buffer,
        sizeof(HANDLE));
    *len = header_len;

    DbgP("marshal_nfs41_queryallocatedranges: name='%wZ' "
        "buffersize=0x%ld, buffer=0x%p\n",
         entry->filename,
         (long)entry->u.QueryAllocatedRanges.BufferSize,
         (void *)entry->u.QueryAllocatedRanges.Buffer);
out:
    return status;
}

NTSTATUS unmarshal_nfs41_queryallocatedranges(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        if (cur->u.QueryAllocatedRanges.Buffer)
            MmUnmapLockedPages(
                cur->u.QueryAllocatedRanges.Buffer,
                cur->u.QueryAllocatedRanges.BufferMdl);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        print_error("unmarshal_nfs41_queryallocatedranges: "
            "MmUnmapLockedPages thrown exception=0x%lx\n",
            (long)GetExceptionCode());
        status = cur->status = STATUS_ACCESS_VIOLATION;
        goto out;
    }

    RtlCopyMemory(&cur->u.QueryAllocatedRanges.returned_size,
        *buf, sizeof(ULONG));
    *buf += sizeof(ULONG);

    DbgP("unmarshal_nfs41_queryallocatedranges: "
        "queryallocatedranges.returned_size=%llu\n",
        cur->u.QueryAllocatedRanges.returned_size);

out:
    return status;
}

static
NTSTATUS nfs41_SetSparse(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PFILE_SET_SPARSE_BUFFER set_parse_buffer =
        (PFILE_SET_SPARSE_BUFFER)FsCtl->pInputBuffer;

    DbgEn();

    /*
     * Special case: No input buffer, so we treat this as if we got
     * |set_parse_buffer->SetSparse == TRUE|
     */
    if (FsCtl->InputBufferLength == 0) {
        /*
         * We treat all files on NFS as sparse files by default,
         * so setting the flag is just a (valid) NOP
         */
        DbgP("nfs41_SetSparse: "
            "SUCCESS: FsCtl->InputBufferLength==0, "
            "treating as SetSparse=TRUE for file '%wZ'\n",
            SrvOpen->pAlreadyPrefixedName);
        status = STATUS_SUCCESS;
        goto out;
    }

    if (FsCtl->InputBufferLength < sizeof(FILE_SET_SPARSE_BUFFER)) {
        DbgP("nfs41_SetSparse: Buffer too small\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (set_parse_buffer->SetSparse) {
        /*
         * We treat all files on NFS as sparse files by default,
         * so setting the flag is just a (valid) NOP
         */
        DbgP("nfs41_SetSparse: "
            "SUCCESS: SetSparse=TRUE for file '%wZ'\n",
            SrvOpen->pAlreadyPrefixedName);
        status = STATUS_SUCCESS;
    }
    else {
        /*
         * We cannot disable the sparse flag, as we treat all files
         * on NFS as sparse files
         */
        DbgP("nfs41_SetSparse: "
            "FAIL: Cannot set SetSparse=FALSE for file '%wZ'\n",
            SrvOpen->pAlreadyPrefixedName);
        status = STATUS_INVALID_PARAMETER;
    }

out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_FsCtl(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
#ifdef DEBUG_FSCTL
    DbgEn();
    print_debug_header(RxContext);
#endif
    const ULONG fscontrolcode =
        RxContext->LowIoContext.ParamsFor.FsCtl.FsControlCode;

    switch (fscontrolcode) {
    case FSCTL_SET_REPARSE_POINT:
        status = nfs41_SetReparsePoint(RxContext);
        break;
    case FSCTL_GET_REPARSE_POINT:
        status = nfs41_GetReparsePoint(RxContext);
        break;
    case FSCTL_QUERY_ALLOCATED_RANGES:
        status = nfs41_QueryAllocatedRanges(RxContext);
        break;
    case FSCTL_SET_SPARSE:
        status = nfs41_SetSparse(RxContext);
        break;
    default:
        break;
    }

#ifdef DEBUG_FSCTL
    const char *fsctl_str = fsctl2string(fscontrolcode);

    if (fsctl_str) {
        DbgP("nfs41_FsCtl: FsControlCode='%s', status=0x%lx\n",
            fsctl_str, (long)status);
    }
    else {
        DbgP("nfs41_FsCtl: FsControlCode=0x%lx, status=0x%lx\n",
            (unsigned long)fscontrolcode, (long)status);
    }
#endif /* DEBUG_FSCTL */

#ifdef DEBUG_FSCTL
    DbgEx();
#endif
    return status;
}
