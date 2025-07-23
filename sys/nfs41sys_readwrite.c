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
#include "nfs41_np.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"
#include "nfs_ea.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"


static void print_readwrite_args(
    PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;

    print_debug_header(RxContext);
    DbgP("Byteoffset=0x%llx Bytecount=0x%llx Buffer=0x%p\n",
        (long long)LowIoContext->ParamsFor.ReadWrite.ByteOffset,
        (long long)LowIoContext->ParamsFor.ReadWrite.ByteCount,
        LowIoContext->ParamsFor.ReadWrite.Buffer);
}

NTSTATUS marshal_nfs41_rw(
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

    header_len = *len + sizeof(entry->buf_len) +
        sizeof(entry->u.ReadWrite.offset) + sizeof(HANDLE);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->buf_len, sizeof(entry->buf_len));
    tmp += sizeof(entry->buf_len);
    RtlCopyMemory(tmp, &entry->u.ReadWrite.offset,
        sizeof(entry->u.ReadWrite.offset));
    tmp += sizeof(entry->u.ReadWrite.offset);
    __try {
#pragma warning( push )
/*
 * C28145: "The opaque MDL structure should not be modified by a
 * driver.", |MDL_MAPPING_CAN_FAIL| is the exception
 */
#pragma warning (disable : 28145)
        entry->u.ReadWrite.MdlAddress->MdlFlags |= MDL_MAPPING_CAN_FAIL;
#pragma warning( pop )
        ULONG prio_writeflags = 0;

        /*
         * The userland daemon will only read from this memory for
         * "write" requests, so make it read-only
         */
        if (entry->opcode == NFS41_SYSOP_WRITE)
            prio_writeflags |= MdlMappingNoWrite;

        entry->buf =
            MmMapLockedPagesSpecifyCache(entry->u.ReadWrite.MdlAddress,
                UserMode, MmCached, NULL, FALSE,
                (NormalPagePriority|prio_writeflags));
        if (entry->buf == NULL) {
            print_error("marshal_nfs41_rw: "
                "MmMapLockedPagesSpecifyCache() failed to map pages\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("marshal_nfs41_rw: Call to "
            "MmMapLockedPagesSpecifyCache() failed due to "
            "exception 0x%lx\n", (long)code);
        status = STATUS_ACCESS_VIOLATION;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->buf, sizeof(HANDLE));
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL_RW
    DbgP("marshal_nfs41_rw: len=%lu offset=%llu "
        "MdlAddress=0x%p Userspace=0x%p\n",
        entry->buf_len, entry->u.ReadWrite.offset,
        entry->u.ReadWrite.MdlAddress, entry->buf);
#endif
out:
    return status;
}

NTSTATUS unmarshal_nfs41_rw(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;

    RtlCopyMemory(&cur->buf_len, *buf, sizeof(cur->buf_len));
    *buf += sizeof(cur->buf_len);
    RtlCopyMemory(&cur->ChangeTime, *buf, sizeof(ULONGLONG));
#ifdef DEBUG_MARSHAL_DETAIL_RW
    DbgP("unmarshal_nfs41_rw: returned len %lu ChangeTime %llu\n",
        cur->buf_len, cur->ChangeTime);
#endif
#if 1
    /* 08/27/2010: it looks like we really don't need to call
        * MmUnmapLockedPages() eventhough we called
        * MmMapLockedPagesSpecifyCache() as the MDL passed to us
        * is already locked.
        */
    __try {
        if (cur->buf) {
            MmUnmapLockedPages(cur->buf, cur->u.ReadWrite.MdlAddress);
            cur->buf = NULL;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("unmarshal_nfs41_rw: Call to MmUnmapLockedPages() "
            "failed due to exception 0x%0x\n", (long)code);
        status = STATUS_ACCESS_VIOLATION;
    }
#endif
    return status;
}

NTSTATUS map_readwrite_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:           return STATUS_ACCESS_DENIED;
    case ERROR_HANDLE_EOF:              return STATUS_END_OF_FILE;
    case ERROR_FILE_INVALID:            return STATUS_FILE_INVALID;
    case ERROR_INVALID_PARAMETER:       return STATUS_INVALID_PARAMETER;
    case ERROR_LOCK_VIOLATION:          return STATUS_FILE_LOCK_CONFLICT;
    case ERROR_NETWORK_ACCESS_DENIED:   return STATUS_NETWORK_ACCESS_DENIED;
    case ERROR_NETNAME_DELETED:         return STATUS_NETWORK_NAME_DELETED;
    case ERROR_DISK_FULL:               return STATUS_DISK_FULL;
    case ERROR_DISK_QUOTA_EXCEEDED:     return STATUS_DISK_QUOTA_EXCEEDED;
    case ERROR_FILE_TOO_LARGE:          return STATUS_FILE_TOO_LARGE;
    case ERROR_INTERNAL_ERROR:          return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_readwrite_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_NET_WRITE_FAULT\n",
            (long)status);
    case ERROR_NET_WRITE_FAULT:         return STATUS_NET_WRITE_FAULT;
    }
}

static NTSTATUS check_nfs41_read_args(
    IN PRX_CONTEXT RxContext)
{
    if (!RxContext->LowIoContext.ParamsFor.ReadWrite.Buffer)
        return STATUS_INVALID_USER_BUFFER;
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_Read(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry = NULL;
    BOOLEAN async = FALSE;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    LONGLONG io_delay;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_READ
    DbgEn();
    print_readwrite_args(RxContext);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_read_args(RxContext);
    if (status) goto out;

    status = nfs41_UpcallCreate(NFS41_SYSOP_READ, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.ReadWrite.MdlAddress = LowIoContext->ParamsFor.ReadWrite.Buffer;
    entry->buf_len = LowIoContext->ParamsFor.ReadWrite.ByteCount;
    entry->u.ReadWrite.offset = LowIoContext->ParamsFor.ReadWrite.ByteOffset;
    if (FlagOn(RxContext->CurrentIrpSp->FileObject->Flags,
            FO_SYNCHRONOUS_IO) == FALSE) {
        entry->u.ReadWrite.rxcontext = RxContext;
        async = entry->async_op = TRUE;
    }

    /* Add extra timeout depending on buffer size */
    io_delay = pVNetRootContext->timeout +
        EXTRA_TIMEOUT_PER_BYTE(entry->buf_len);
    status = nfs41_UpcallWaitForReply(entry, io_delay);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (async) {
#ifdef DEBUG_READ
        DbgP("This is asynchronous read, returning control back to the user\n");
#endif
        status = STATUS_PENDING;
        entry = NULL; /* |entry| will be freed once async call is done */
        goto out;
    }

    if (entry->status == NO_ERROR) {
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&read.sops);
        InterlockedAdd64(&read.size, entry->u.ReadWrite.len);
#endif
        status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = entry->buf_len;

        if ((!BooleanFlagOn(LowIoContext->ParamsFor.ReadWrite.Flags,
                LOWIO_READWRITEFLAG_PAGING_IO) &&
                (SrvOpen->DesiredAccess & FILE_READ_DATA) &&
                !pVNetRootContext->nocache && !nfs41_fobx->nocache &&
                !(SrvOpen->BufferingFlags &
                (FCB_STATE_READBUFFERING_ENABLED |
                 FCB_STATE_READCACHING_ENABLED)))) {
            enable_caching(SrvOpen, nfs41_fobx, nfs41_fcb->changeattr,
                pVNetRootContext->session);
        }
    } else {
        status = map_readwrite_errors(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&read.tops);
    InterlockedAdd64(&read.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Read delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart,
        read.tops, read.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_READ
    DbgEx();
#endif
    return status;
}

static NTSTATUS check_nfs41_write_args(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);

    if (!RxContext->LowIoContext.ParamsFor.ReadWrite.Buffer) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

    if (pVNetRootContext->read_only) {
        print_error("check_nfs41_write_args: Read-only mount\n");
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_Write(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry = NULL;
    BOOLEAN async = FALSE;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    DWORD io_delay;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_WRITE
    DbgEn();
    print_readwrite_args(RxContext);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_write_args(RxContext);
    if (status) goto out;

    status = nfs41_UpcallCreate(NFS41_SYSOP_WRITE, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.ReadWrite.MdlAddress = LowIoContext->ParamsFor.ReadWrite.Buffer;
    entry->buf_len = LowIoContext->ParamsFor.ReadWrite.ByteCount;
    entry->u.ReadWrite.offset = LowIoContext->ParamsFor.ReadWrite.ByteOffset;

    if (FlagOn(RxContext->CurrentIrpSp->FileObject->Flags,
            FO_SYNCHRONOUS_IO) == FALSE) {
        entry->u.ReadWrite.rxcontext = RxContext;
        async = entry->async_op = TRUE;
    }

    /* Add extra timeout depending on buffer size */
    io_delay = pVNetRootContext->timeout +
        EXTRA_TIMEOUT_PER_BYTE(entry->buf_len);
    status = nfs41_UpcallWaitForReply(entry, io_delay);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (async) {
#ifdef DEBUG_WRITE
        DbgP("This is asynchronous write, returning control back to the user\n");
#endif
        status = STATUS_PENDING;
        entry = NULL; /* |entry| will be freed once async call is done */
        goto out;
    }

    if (entry->status == NO_ERROR) {
        //update cached file attributes
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&write.sops);
        InterlockedAdd64(&write.size, entry->u.ReadWrite.len);
#endif
        status = RxContext->CurrentIrp->IoStatus.Status = STATUS_SUCCESS;
        RxContext->IoStatusBlock.Information = entry->buf_len;
        nfs41_fcb->changeattr = entry->ChangeTime;

        //re-enable write buffering
        if (!BooleanFlagOn(LowIoContext->ParamsFor.ReadWrite.Flags,
                LOWIO_READWRITEFLAG_PAGING_IO) &&
                (SrvOpen->DesiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA)) &&
                !pVNetRootContext->write_thru &&
                !pVNetRootContext->nocache &&
                !nfs41_fobx->write_thru && !nfs41_fobx->nocache &&
                !(SrvOpen->BufferingFlags &
                (FCB_STATE_WRITEBUFFERING_ENABLED |
                 FCB_STATE_WRITECACHING_ENABLED))) {
            enable_caching(SrvOpen, nfs41_fobx, nfs41_fcb->changeattr,
                pVNetRootContext->session);
        } else if (!nfs41_fobx->deleg_type)
            nfs41_update_fcb_list(RxContext->pFcb, entry->ChangeTime);

    } else {
        status = map_readwrite_errors(entry->status);
        RxContext->CurrentIrp->IoStatus.Status = status;
        RxContext->IoStatusBlock.Information = 0;
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&write.tops);
    InterlockedAdd64(&write.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Write delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart,
        write.tops, write.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_WRITE
    DbgEx();
#endif
    return status;
}

ULONG nfs41_ExtendForCache(
    IN OUT PRX_CONTEXT RxContext,
    IN PLARGE_INTEGER pNewFileSize,
    OUT PLARGE_INTEGER pNewAllocationSize)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
#ifdef DEBUG_CACHE
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    DbgEn();
    print_debug_header(RxContext);
    DbgP("input: bytecount=0x%lx filesize=0x%llx allocsize=0x%llx\n",
        (long)LowIoContext->ParamsFor.ReadWrite.ByteCount,
        (long long)pNewFileSize->QuadPart,
        (long long)pNewAllocationSize->QuadPart);
#endif
    FsRtlEnterFileSystem();

    pNewAllocationSize->QuadPart = pNewFileSize->QuadPart;
    nfs41_fcb->StandardInfo.AllocationSize.QuadPart =
        pNewAllocationSize->QuadPart;
    nfs41_fcb->StandardInfo.EndOfFile.QuadPart = pNewFileSize->QuadPart;
#ifdef DEBUG_CACHE
    DbgP("newfilesize=0x%llx newallocationsize=0x%llx\n",
        (long long)pNewFileSize->QuadPart,
        (long long)pNewAllocationSize->QuadPart);
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_CACHE
    DbgEx();
#endif
    return status;
}
