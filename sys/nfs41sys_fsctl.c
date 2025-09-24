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
#include <ntddstor.h>
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
    __notnull PFILE_ALLOCATED_RANGE_BUFFER in_range_buffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)FsCtl->pInputBuffer;

    if (FsCtl->pInputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

    if (FsCtl->InputBufferLength <
        sizeof(FILE_ALLOCATED_RANGE_BUFFER)) {
        DbgP("check_nfs41_queryallocatedranges_args: "
            "in_range_buffer to small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    if ((in_range_buffer->FileOffset.QuadPart < 0LL) ||
        (in_range_buffer->Length.QuadPart < 0LL) ||
        (in_range_buffer->Length.QuadPart >
            (MAXLONGLONG - in_range_buffer->FileOffset.QuadPart))) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (FsCtl->pOutputBuffer == NULL) {
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
    if (status) {
        DbgP("nfs41_QueryAllocatedRanges: "
            "check_nfs41_queryallocatedranges_args() failed with status=0x%lx\n",
            (long)status);
        goto out;
    }

    DbgP("nfs41_QueryAllocatedRanges: "
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
        goto out;
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
        entry = NULL;
        goto out;
    }

    if (entry->status == NO_ERROR) {
        DbgP("nfs41_QueryAllocatedRanges: SUCCESS\n");

        if (entry->u.QueryAllocatedRanges.buffer_overflow) {
            DbgP("nfs41_QueryAllocatedRanges: buffer_overflow: "
                "need at least a buffer with %ld bytes\n",
                (long)entry->u.QueryAllocatedRanges.returned_size);
            status = RxContext->CurrentIrp->IoStatus.Status =
                STATUS_BUFFER_OVERFLOW;
            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)entry->u.QueryAllocatedRanges.returned_size;
        }
        else {
            status = RxContext->CurrentIrp->IoStatus.Status =
                STATUS_SUCCESS;
            RxContext->IoStatusBlock.Information =
                (ULONG_PTR)entry->u.QueryAllocatedRanges.returned_size;
        }
    }
    else {
        DbgP("nfs41_QueryAllocatedRanges: "
            "FAILURE, entry->status=0x%lx\n", entry->status);

        status = map_setfile_error(entry->status);

        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }

out:
    if (entry) {
        if (entry->u.QueryAllocatedRanges.BufferMdl) {
            MmUnlockPages(entry->u.QueryAllocatedRanges.BufferMdl);
            IoFreeMdl(entry->u.QueryAllocatedRanges.BufferMdl);
            entry->u.QueryAllocatedRanges.BufferMdl = NULL;
        }

        nfs41_UpcallDestroy(entry);
    }

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
        sizeof(ULONG) +
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
        if (cur->u.QueryAllocatedRanges.Buffer) {
            MmUnmapLockedPages(
                cur->u.QueryAllocatedRanges.Buffer,
                cur->u.QueryAllocatedRanges.BufferMdl);
            cur->u.QueryAllocatedRanges.Buffer = NULL;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        print_error("unmarshal_nfs41_queryallocatedranges: "
            "MmUnmapLockedPages thrown exception=0x%lx\n",
            (long)GetExceptionCode());
        status = cur->status = STATUS_ACCESS_VIOLATION;
        goto out;
    }

    RtlCopyMemory(&cur->u.QueryAllocatedRanges.buffer_overflow,
        *buf, sizeof(BOOLEAN));
    *buf += sizeof(BOOLEAN);
    RtlCopyMemory(&cur->u.QueryAllocatedRanges.returned_size,
        *buf, sizeof(ULONG));
    *buf += sizeof(ULONG);

    DbgP("unmarshal_nfs41_queryallocatedranges: "
        "buffer_overflow=%d returned_size=%llu\n",
        (int)cur->u.QueryAllocatedRanges.buffer_overflow,
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
     * We do not do any access checks here because ms-nfs41-client
     * files always have the |FILE_ATTRIBUTE_SPARSE_FILE| set.
     * This function is basically only a dummy which returns
     * |STATUS_SUCCESS| (if the correct are provided) to conform
     * sto the Win32 sparse file API.
     */

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

static
NTSTATUS check_nfs41_setzerodata_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);

    /* access checks */
    if (VNetRootContext->read_only) {
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
    if (!(SrvOpen->DesiredAccess &
        (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES))) {
        status = STATUS_ACCESS_DENIED;
        goto out;
    }
out:
    return status;
}

static
NTSTATUS nfs41_SetZeroData(
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
    __notnull PFILE_ZERO_DATA_INFORMATION setzerodatabuffer =
        (PFILE_ZERO_DATA_INFORMATION)FsCtl->pInputBuffer;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);

    DbgEn();

    RxContext->IoStatusBlock.Information = 0;

    status = check_nfs41_setzerodata_args(RxContext);
    if (status)
        goto out;

    if (FsCtl->pInputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

    if (FsCtl->InputBufferLength <
        sizeof(FILE_ZERO_DATA_INFORMATION)) {
        DbgP("nfs41_SetZeroData: "
            "buffer to small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    DbgP("nfs41_SetZeroData: "
        "setzerodatabuffer=(FileOffset=%lld,BeyondFinalZero=%lld)\n",
        (long long)setzerodatabuffer->FileOffset.QuadPart,
        (long long)setzerodatabuffer->BeyondFinalZero.QuadPart);

    /*
     * Disable caching because NFSv4.2 DEALLOCATE is basically a
     * "write" operation. AFAIK we should flush the cache and wait
     * for the kernel lazy writer (which |RxChangeBufferingState()|
     * AFAIK does) before doing the DEALLOCATE, to avoid that we
     * have outstanding writes in the kernel cache at the same
     * location where the DEALLOCATE should do it's work
     */
    ULONG flag = DISABLE_CACHING;
    DbgP("nfs41_SetZeroData: disableing caching for file '%wZ'\n",
        SrvOpen->pAlreadyPrefixedName);
    RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);

    status = nfs41_UpcallCreate(NFS41_SYSOP_FSCTL_SET_ZERO_DATA,
        &nfs41_fobx->sec_ctx,
        pVNetRootContext->session,
        nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version,
        SrvOpen->pAlreadyPrefixedName,
        &entry);

    if (status)
        goto out;

    entry->u.SetZeroData.setzerodata = *setzerodatabuffer;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (!entry->status) {
        DbgP("nfs41_SetZeroData: SUCCESS\n");
        RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = 0;
    }
    else {
        DbgP("nfs41_SetZeroData: "
            "FAILURE, entry->status=0x%lx\n", entry->status);
        status = map_setfile_error(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }

out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }

    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_setzerodata(
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

    header_len = *len + sizeof(FILE_ZERO_DATA_INFORMATION);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.SetZeroData.setzerodata,
        sizeof(entry->u.SetZeroData.setzerodata));
    tmp += sizeof(entry->u.SetZeroData.setzerodata);

    *len = header_len;

    DbgP("marshal_nfs41_setzerodata: name='%wZ'\n",
         entry->filename);
out:
    return status;
}

NTSTATUS unmarshal_nfs41_setzerodata(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlCopyMemory(&cur->ChangeTime, *buf, sizeof(ULONGLONG));
    DbgP("unmarshal_nfs41_setzerodata: returned ChangeTime %llu\n",
        cur->ChangeTime);

    return status;
}

static
NTSTATUS check_nfs41_duplicatedata_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);

    /* access checks */
    if (VNetRootContext->read_only) {
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
    if (!(SrvOpen->DesiredAccess &
        (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES))) {
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    if (nfs41_fcb->StandardInfo.Directory) {
        status = STATUS_FILE_IS_A_DIRECTORY;
        goto out;
    }
out:
    return status;
}

static
NTSTATUS nfs41_DuplicateData(
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
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);

    /*
     * Temporary store |FSCTL_DUPLICATE_EXTENTS_TO_FILE| data here, which
     * can be either |DUPLICATE_EXTENTS_DATA32| for 32bit processes on a
     * 64bit kernel, |DUPLICATE_EXTENTS_DATA| for 64bit processes on a
     * 64bit kernel, or |DUPLICATE_EXTENTS_DATA| for 32bit processes on
     * a 32bit kernel
     */
    struct {
        HANDLE      handle;
        LONGLONG    srcfileoffset;
        LONGLONG    destfileoffset;
        LONGLONG    bytecount;
    } dd;

    DbgEn();

    PFILE_OBJECT srcfo = NULL;
    LONGLONG io_delay;

    RxContext->IoStatusBlock.Information = 0;

    status = check_nfs41_duplicatedata_args(RxContext);
    if (status)
        goto out;

    if (FsCtl->pInputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

#if defined(_WIN64)
    if (IoIs32bitProcess(RxContext->CurrentIrp)) {
        if (FsCtl->InputBufferLength <
            sizeof(DUPLICATE_EXTENTS_DATA32)) {
            DbgP("nfs41_DuplicateData: "
                "buffer too small for DUPLICATE_EXTENTS_DATA32\n");
            status = STATUS_BUFFER_TOO_SMALL;
            goto out;
        }

        PDUPLICATE_EXTENTS_DATA32 ded32bit =
            (PDUPLICATE_EXTENTS_DATA32)FsCtl->pInputBuffer;

        dd.handle           = (HANDLE)ded32bit->FileHandle;
        dd.srcfileoffset    = ded32bit->SourceFileOffset.QuadPart;
        dd.destfileoffset   = ded32bit->TargetFileOffset.QuadPart;
        dd.bytecount        = ded32bit->ByteCount.QuadPart;
    }
    else
#endif /* defined(_WIN64) */
    {
        if (FsCtl->InputBufferLength <
            sizeof(DUPLICATE_EXTENTS_DATA)) {
            DbgP("nfs41_DuplicateData: "
                "buffer too small for DUPLICATE_EXTENTS_DATA\n");
            status = STATUS_BUFFER_TOO_SMALL;
            goto out;
        }

        PDUPLICATE_EXTENTS_DATA ded =
            (PDUPLICATE_EXTENTS_DATA)FsCtl->pInputBuffer;

        dd.handle           = ded->FileHandle;
        dd.srcfileoffset    = ded->SourceFileOffset.QuadPart;
        dd.destfileoffset   = ded->TargetFileOffset.QuadPart;
        dd.bytecount        = ded->ByteCount.QuadPart;
    }

    DbgP("nfs41_DuplicateData: "
        "dd=(handle=0x%p,"
        "srcfileoffset=%lld,"
        "destfileoffset=%lld,"
        "bytecount=%lld)\n",
        (void *)dd.handle,
        (long long)dd.srcfileoffset,
        (long long)dd.destfileoffset,
        (long long)dd.bytecount);

    if (dd.bytecount == 0LL) {
        status = STATUS_SUCCESS;
        goto out;
    }

    status = ObReferenceObjectByHandle(dd.handle,
        0,
        *IoFileObjectType,
        RxContext->CurrentIrp->RequestorMode,
        (void **)&srcfo,
        NULL);
    if (!NT_SUCCESS(status)) {
        DbgP("nfs41_DuplicateData: "
            "ObReferenceObjectByHandle returned 0x%lx\n",
            status);
        goto out;
    }

    DbgP("nfs41_DuplicateData: "
        "srcfo=0x%p srcfo->FileName='%wZ'\n",
        srcfo,
        srcfo->FileName);

    if (srcfo->DeviceObject !=
        RxContext->CurrentIrpSp->FileObject->DeviceObject) {
        DbgP("nfs41_DuplicateData: "
            "source and destination are on different volumes\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    PFCB srcfcb = srcfo->FsContext;
    PFOBX srcfox = srcfo->FsContext2;
    PNFS41_FCB nfs41_src_fcb = NFS41GetFcbExtension(srcfcb);
    PNFS41_FOBX nfs41_src_fobx = NFS41GetFobxExtension(srcfox);

    if (!nfs41_src_fcb) {
        DbgP("nfs41_DuplicateData: No nfs41_src_fcb\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (!nfs41_src_fobx) {
        DbgP("nfs41_DuplicateData: No nfs41_src_fobx\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (nfs41_src_fcb->StandardInfo.Directory) {
        DbgP("nfs41_DuplicateData: src is a dir\n");
        status = STATUS_FILE_IS_A_DIRECTORY;
        goto out;
    }

    IO_STATUS_BLOCK flushIoStatus;
    DbgP("nfs41_DuplicateData: flushing src file buffers\n");
    status = ZwFlushBuffersFile(dd.handle, &flushIoStatus);
    if (status) {
        if (status == STATUS_ACCESS_DENIED) {
            /*
             * |ZwFlushBuffersFile()| can fail if |dd.handle| was not opened
             * for write access
             */
            DbgP("nfs41_DuplicateData: "
                "ZwFlushBuffersFile() failed with STATUS_ACCESS_DENIED\n");
        }
        else {
            DbgP("nfs41_DuplicateData: "
                "ZwFlushBuffersFile() failed, status=0x%lx\n",
                (long)status);
            goto out;
        }
    }

    /*
     * Disable caching because NFSv4.2 CLONE is basically a
     * "write" operation. AFAIK we should flush the cache and wait
     * for the kernel lazy writer (which |RxChangeBufferingState()|
     * AFAIK does) before doing the CLONE, to avoid that we
     * have outstanding writes in the kernel cache at the same
     * location where the CLONE should do it's work
     */
    ULONG flag = DISABLE_CACHING;
    DbgP("nfs41_DuplicateData: disableing caching for file '%wZ'\n",
        SrvOpen->pAlreadyPrefixedName);
    RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);

    status = nfs41_UpcallCreate(NFS41_SYSOP_FSCTL_DUPLICATE_DATA,
        &nfs41_fobx->sec_ctx,
        pVNetRootContext->session,
        nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version,
        SrvOpen->pAlreadyPrefixedName,
        &entry);

    if (status)
        goto out;

    entry->u.DuplicateData.src_state = nfs41_src_fobx->nfs41_open_state;
    entry->u.DuplicateData.srcfileoffset = dd.srcfileoffset;
    entry->u.DuplicateData.destfileoffset = dd.destfileoffset;
    entry->u.DuplicateData.bytecount = dd.bytecount;

    /* Add extra timeout depending on file size */
    io_delay = pVNetRootContext->timeout +
        EXTRA_TIMEOUT_PER_BYTE(entry->u.DuplicateData.bytecount);

    status = nfs41_UpcallWaitForReply(entry, io_delay);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (!entry->status) {
        DbgP("nfs41_DuplicateData: SUCCESS\n");
        RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = 0;
    }
    else {
        DbgP("nfs41_DuplicateData: "
            "FAILURE, entry->status=0x%lx\n", entry->status);
        status = map_setfile_error(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }

out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }

    if (srcfo) {
        ObDereferenceObject(srcfo);
    }

    DbgEx();
    return status;
}

NTSTATUS marshal_nfs41_duplicatedata(
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

    header_len = *len +
        sizeof(void *) +
        3*sizeof(LONGLONG);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.DuplicateData.src_state,
        sizeof(entry->u.DuplicateData.src_state));
    tmp += sizeof(entry->u.DuplicateData.src_state);
    RtlCopyMemory(tmp, &entry->u.DuplicateData.srcfileoffset,
        sizeof(entry->u.DuplicateData.srcfileoffset));
    tmp += sizeof(entry->u.DuplicateData.srcfileoffset);
    RtlCopyMemory(tmp, &entry->u.DuplicateData.destfileoffset,
        sizeof(entry->u.DuplicateData.destfileoffset));
    tmp += sizeof(entry->u.DuplicateData.destfileoffset);
    RtlCopyMemory(tmp, &entry->u.DuplicateData.bytecount,
        sizeof(entry->u.DuplicateData.bytecount));
    tmp += sizeof(entry->u.DuplicateData.bytecount);
    *len = header_len;

    DbgP("marshal_nfs41_duplicatedata: name='%wZ'\n",
         entry->filename);
out:
    return status;
}

NTSTATUS unmarshal_nfs41_duplicatedata(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlCopyMemory(&cur->ChangeTime, *buf, sizeof(ULONGLONG));
    DbgP("unmarshal_nfs41_duplicatedata: returned ChangeTime %llu\n",
        cur->ChangeTime);

    return status;
}

/*
 * |offloadcontext_entry| - context to store |FSCTL_OFFLOAD_READ| token
 * information
 *
 * * Notes:
 * - These are stored in a global list, as |FSCTL_OFFLOAD_READ|+
 * |FSCTL_OFFLOAD_WRITE| is intended to work for intra-server and
 * inter-server copies, so |FSCTL_OFFLOAD_READ| might be done on one
 * filesystem but |FSCTL_OFFLOAD_WRITE| might be done on a different
 * one
 *
 * * FIXME:
 * - Is it legal if one user passes a token to another user, or
 * should this be prevented ?
 * - |offloadcontext_entry| lifetime is unkown. Right now we create
 * it via |FSCTL_OFFLOAD_READ| and remove it when the matching file gets
 * closed, but we ignore |FSCTL_OFFLOAD_READ_INPUT.TokenTimeToLive|
 */
typedef struct _offloadcontext_entry
{
    LIST_ENTRY              next;
    /*
     * r/w lock - shared access for |FSCTL_OFFLOAD_WRITE|, so one token can
     * be used for multiple parallel writes, exclusive access for file delete
     * (i.e. wait until all shared access before deleting the context)
     */
    ERESOURCE               resource;
    STORAGE_OFFLOAD_TOKEN   token;
    PNFS41_FOBX             src_fobx;
    ULONGLONG               src_fileoffset;
    ULONGLONG               src_length;
} offloadcontext_entry;


void nfs41_remove_offloadcontext_for_fobx(
    IN PMRX_FOBX pFobx)
{
    PLIST_ENTRY pEntry;
    offloadcontext_entry *cur, *found = NULL;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(pFobx);

    ExAcquireFastMutexUnsafe(&offloadcontextlist.lock);

    pEntry = offloadcontextlist.head.Flink;
    while (!IsListEmpty(&offloadcontextlist.head)) {
        cur = (offloadcontext_entry *)CONTAINING_RECORD(pEntry,
            offloadcontext_entry, next);
        if (cur->src_fobx == nfs41_fobx) {
            found = cur;
            break;
        }
        if (pEntry->Flink == &offloadcontextlist.head) {
            break;
        }
        pEntry = pEntry->Flink;
    }

    if (found) {
        DbgP("nfs41_remove_offloadcontext(pFobx=0x%p): "
            "removing found=0x%p\n",
            pFobx,
            found);

        /* Wait for any shared access in |nfs41_OffloadWrite()| to finish */
        (void)ExAcquireResourceExclusiveLite(&found->resource, TRUE);
        ExReleaseResourceLite(&found->resource);

        RemoveEntryList(&found->next);

        (void)ExDeleteResourceLite(&found->resource);
        RxFreePool(found);
    }
    else {
#ifdef DEBUG_FSCTL_OFFLOAD_READWRITE
        DbgP("nfs41_remove_offloadcontext(pFobx=0x%p): Nothing found.\n",
            pFobx);
#endif /* DEBUG_FSCTL_OFFLOAD_READWRITE */
    }

    ExReleaseFastMutexUnsafe(&offloadcontextlist.lock);
}

static
offloadcontext_entry *nfs41_find_offloadcontext_acquireshared(
    IN offloadcontext_entry *unvalidated_oce)
{
    PLIST_ENTRY pEntry;
    offloadcontext_entry *cur, *found = NULL;

    ExAcquireFastMutexUnsafe(&offloadcontextlist.lock);

    pEntry = offloadcontextlist.head.Flink;
    while (!IsListEmpty(&offloadcontextlist.head)) {
        cur = (offloadcontext_entry *)CONTAINING_RECORD(pEntry,
            offloadcontext_entry, next);
        if (cur == unvalidated_oce) {
            found = cur;
            break;
        }
        if (pEntry->Flink == &offloadcontextlist.head) {
            break;
        }
        pEntry = pEntry->Flink;
    }

    if (found) {
#ifdef DEBUG_FSCTL_OFFLOAD_READWRITE
        DbgP("nfs41_find_offloadcontext_acquireshared(unvalidated_oce=0x%p): "
            "found=0x%p\n",
            unvalidated_oce);
#endif /* DEBUG_FSCTL_OFFLOAD_READWRITE */

        (void)ExAcquireSharedStarveExclusive(&found->resource, TRUE);
        ExReleaseFastMutexUnsafe(&offloadcontextlist.lock);
        return found;
    }
    else {
        DbgP("nfs41_find_offloadcontext_acquireshared(unvalidated_oce=0x%p): "
            "Nothing found.\n",
            unvalidated_oce);
        ExReleaseFastMutexUnsafe(&offloadcontextlist.lock);
        return NULL;
    }
}

static
NTSTATUS nfs41_OffloadRead(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);

    DbgEn();

    RxContext->IoStatusBlock.Information = 0;

    if (FsCtl->pInputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

    if (FsCtl->pOutputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

    if (FsCtl->InputBufferLength < sizeof(FSCTL_OFFLOAD_READ_INPUT)) {
        DbgP("nfs41_OffloadRead: "
            "buffer too small for FSCTL_OFFLOAD_READ_INPUT\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }
    if (FsCtl->OutputBufferLength < sizeof(FSCTL_OFFLOAD_READ_OUTPUT)) {
        DbgP("nfs41_OffloadRead: "
            "buffer too small for FSCTL_OFFLOAD_READ_OUTPUT\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    if (nfs41_fcb->StandardInfo.Directory) {
        status = STATUS_FILE_IS_A_DIRECTORY;
        goto out;
    }

    PFSCTL_OFFLOAD_READ_INPUT ori =
        (PFSCTL_OFFLOAD_READ_INPUT)FsCtl->pInputBuffer;
    PFSCTL_OFFLOAD_READ_OUTPUT oro =
        (PFSCTL_OFFLOAD_READ_OUTPUT)FsCtl->pOutputBuffer;

    DbgP("nfs41_OffloadRead: "
        "ori->(Size=%lu, Flags=0x%lx, TokenTimeToLive=%lu, Reserved=%lu, "
        "FileOffset=%llu, CopyLength=%llu)\n",
        (unsigned long)ori->Size,
        (unsigned long)ori->Flags,
        (unsigned long)ori->TokenTimeToLive,
        (unsigned long)ori->Reserved,
        (unsigned long long)ori->FileOffset,
        (unsigned long long)ori->CopyLength);

    offloadcontext_entry *oce = RxAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(offloadcontext_entry), NFS41_MM_POOLTAG);
    if (oce == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    DbgP("nfs41_OffloadRead: oce=0x%p\n", oce);

    (void)ExInitializeResourceLite(&oce->resource);

    (void)memset(&oce->token, 0, sizeof(oce->token));
    /* Add safeguard to |TokenType| */
    oce->token.TokenType[0] = 'N';
    oce->token.TokenType[1] = 'F';
    oce->token.TokenType[2] = 'S';
    oce->token.TokenType[3] = '4';
    /* FIXME: What about the endianness of |TokenIdLength| ? */
    *((USHORT *)(&oce->token.TokenIdLength[0])) =
        STORAGE_OFFLOAD_TOKEN_ID_LENGTH;
    *((void **)(&oce->token.Token[0])) = oce;
    oce->src_fobx = nfs41_fobx;
    oce->src_fileoffset = ori->FileOffset;
    oce->src_length = ori->CopyLength;

    oro->Size = sizeof(FSCTL_OFFLOAD_READ_OUTPUT);
    oro->Flags = 0;
    oro->TransferLength = ori->CopyLength;
    (void)memcpy(&oro->Token[0], &oce->token, sizeof(oce->token));

    nfs41_AddEntry(offloadcontextlist.lock,
        offloadcontextlist, oce);

    RxContext->CurrentIrp->IoStatus.Status = status = STATUS_SUCCESS;
    RxContext->InformationToReturn = sizeof(FSCTL_OFFLOAD_READ_OUTPUT);

out:
    DbgEx();
    return status;
}

static
NTSTATUS check_nfs41_offload_write_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION VNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);

    /* access checks */
    if (VNetRootContext->read_only) {
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
    if (!(SrvOpen->DesiredAccess &
        (FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES))) {
        status = STATUS_ACCESS_DENIED;
        goto out;
    }

    if (nfs41_fcb->StandardInfo.Directory) {
        status = STATUS_FILE_IS_A_DIRECTORY;
        goto out;
    }
out:
    return status;
}

static
NTSTATUS nfs41_OffloadWrite(
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
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    offloadcontext_entry *src_oce = NULL;

    struct {
        LONGLONG    srcfileoffset;
        LONGLONG    destfileoffset;
        LONGLONG    bytecount;
    } dd;

    DbgEn();

    LONGLONG io_delay;
    RxContext->IoStatusBlock.Information = 0;

    status = check_nfs41_offload_write_args(RxContext);
    if (status)
        goto out;

    if (FsCtl->pInputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }
    if (FsCtl->pOutputBuffer == NULL) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }
    if (FsCtl->InputBufferLength < sizeof(FSCTL_OFFLOAD_WRITE_INPUT)) {
        DbgP("nfs41_OffloadWrite: "
            "buffer too small for FSCTL_OFFLOAD_WRITE_INPUT\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }
    if (FsCtl->OutputBufferLength < sizeof(FSCTL_OFFLOAD_WRITE_OUTPUT)) {
        DbgP("nfs41_OffloadWrite: "
            "buffer too small for FSCTL_OFFLOAD_WRITE_OUTPUT\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    PFSCTL_OFFLOAD_WRITE_INPUT owi =
        (PFSCTL_OFFLOAD_WRITE_INPUT)FsCtl->pInputBuffer;
    PFSCTL_OFFLOAD_WRITE_OUTPUT owo =
        (PFSCTL_OFFLOAD_WRITE_OUTPUT)FsCtl->pOutputBuffer;

    offloadcontext_entry *unvalidated_src_oce;

    /*
     * Peel |offloadcontext_entry| pointer from token...
     */
    unvalidated_src_oce =
        *((void **)(&(((STORAGE_OFFLOAD_TOKEN *)(&owi->Token[0]))->Token[0])));
#ifdef DEBUG_FSCTL_OFFLOAD_READWRITE
    DbgP("nfs41_OffloadWrite: "
        "unvalidated_src_oce=0x%p\n", unvalidated_src_oce);
#endif /* DEBUG_FSCTL_OFFLOAD_READWRITE */

    /*
     * ... and validate it (and take a shared lock if validation was
     * successful, so nobody can delete the context while we use it)!
     */
    src_oce = nfs41_find_offloadcontext_acquireshared(unvalidated_src_oce);
    if (src_oce == NULL) {
        DbgP("nfs41_OffloadWrite: "
            "nfs41_find_offloadcontext_acquireshared() failed\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    DbgP("nfs41_OffloadWrite: src_oce=0x%p\n", src_oce);

    /* Check safeguard... */
    if ((src_oce->token.TokenType[0] != 'N') ||
        (src_oce->token.TokenType[1] != 'F') ||
        (src_oce->token.TokenType[2] != 'S') ||
        (src_oce->token.TokenType[3] != '4')) {
        DbgP("nfs41_OffloadWrite: "
            "token in src_oce=0x%p not a 'NFS4' token\n",
            src_oce);
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    /*
     * FIXME: We should validate the length passed as
     * |FSCTL_OFFLOAD_READ_INPUT.CopyLength| here better, because it is
     * also used as some kind of access control to different parts of a
     * file
     */
    dd.srcfileoffset    = src_oce->src_fileoffset + owi->TransferOffset;
    dd.destfileoffset   = owi->FileOffset;
    dd.bytecount        = owi->CopyLength;

    DbgP("nfs41_OffloadWrite: "
        "dd=(srcfileoffset=%lld,"
        "destfileoffset=%lld,"
        "bytecount=%lld)\n",
        (long long)dd.srcfileoffset,
        (long long)dd.destfileoffset,
        (long long)dd.bytecount);

    if (dd.bytecount == 0LL) {
        status = STATUS_SUCCESS;
        goto out;
    }

    PNFS41_FOBX nfs41_src_fobx = src_oce->src_fobx;
    if (!nfs41_src_fobx) {
        DbgP("nfs41_OffloadWrite: No nfs41_src_fobx\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    /*
     * Disable caching because NFSv4.2 COPY is basically a
     * "write" operation. AFAIK we should flush the cache and wait
     * for the kernel lazy writer (which |RxChangeBufferingState()|
     * AFAIK does) before doing the COPY, to avoid that we
     * have outstanding writes in the kernel cache at the same
     * location where the COPY should do it's work
     */
    ULONG flag = DISABLE_CACHING;
    DbgP("nfs41_OffloadWrite: disableing caching for file '%wZ'\n",
        SrvOpen->pAlreadyPrefixedName);
    RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);

    status = nfs41_UpcallCreate(NFS41_SYSOP_FSCTL_OFFLOAD_DATACOPY,
        &nfs41_fobx->sec_ctx,
        pVNetRootContext->session,
        nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version,
        SrvOpen->pAlreadyPrefixedName,
        &entry);

    if (status)
        goto out;

    entry->u.DuplicateData.src_state = nfs41_src_fobx->nfs41_open_state;
    entry->u.DuplicateData.srcfileoffset = dd.srcfileoffset;
    entry->u.DuplicateData.destfileoffset = dd.destfileoffset;
    entry->u.DuplicateData.bytecount = dd.bytecount;

    /* Add extra timeout depending on file size */
    io_delay = pVNetRootContext->timeout +
        EXTRA_TIMEOUT_PER_BYTE(entry->u.DuplicateData.bytecount);

    status = nfs41_UpcallWaitForReply(entry, io_delay);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (!entry->status) {
        DbgP("nfs41_OffloadWrite: SUCCESS\n");

        owo->Size = sizeof(FSCTL_OFFLOAD_READ_OUTPUT);
        owo->Flags = 0;
        owo->LengthWritten = dd.bytecount;

        RxContext->CurrentIrp->IoStatus.Status = status = STATUS_SUCCESS;
        RxContext->InformationToReturn = sizeof(FSCTL_OFFLOAD_READ_OUTPUT);
    }
    else {
        DbgP("nfs41_OffloadWrite: "
            "FAILURE, entry->status=0x%lx\n", entry->status);
        status = map_setfile_error(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }

out:
    if (src_oce) {
        /* Release resource we obtained in shared mode */
        ExReleaseResourceLite(&src_oce->resource);
    }

    if (entry) {
        nfs41_UpcallDestroy(entry);
    }

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
    FsRtlEnterFileSystem();

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
    case FSCTL_SET_ZERO_DATA:
        status = nfs41_SetZeroData(RxContext);
        break;
    case FSCTL_DUPLICATE_EXTENTS_TO_FILE:
        status = nfs41_DuplicateData(RxContext);
        break;
    case FSCTL_OFFLOAD_READ:
        status = nfs41_OffloadRead(RxContext);
        break;
    case FSCTL_OFFLOAD_WRITE:
        status = nfs41_OffloadWrite(RxContext);
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

    FsRtlExitFileSystem();
#ifdef DEBUG_FSCTL
    DbgEx();
#endif
    return status;
}
