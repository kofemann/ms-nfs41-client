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


NTSTATUS marshal_nfs41_lock(
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

    header_len = *len + 2 * sizeof(LONGLONG) + 2 * sizeof(BOOLEAN);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Lock.offset, sizeof(LONGLONG));
    tmp += sizeof(LONGLONG);
    RtlCopyMemory(tmp, &entry->u.Lock.length, sizeof(LONGLONG));
    tmp += sizeof(LONGLONG);
    RtlCopyMemory(tmp, &entry->u.Lock.exclusive, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.Lock.blocking, sizeof(BOOLEAN));
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_lock: "
        "offset=0x%llx length=0x%llx exclusive=%u "
        "blocking=%u\n",
        (long long)entry->u.Lock.offset,
        (long long)entry->u.Lock.length,
        entry->u.Lock.exclusive, entry->u.Lock.blocking);
#endif
out:
    return status;
}

NTSTATUS marshal_nfs41_unlock(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;
    PLOWIO_LOCK_LIST lock;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status) goto out;
    else tmp += *len;

    header_len = *len + sizeof(ULONG) +
        (size_t)entry->u.Unlock.count * 2 * sizeof(LONGLONG);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.Unlock.count, sizeof(ULONG));
    tmp += sizeof(ULONG);

    lock = &entry->u.Unlock.locks;
    while (lock) {
        RtlCopyMemory(tmp, &lock->ByteOffset, sizeof(LONGLONG));
        tmp += sizeof(LONGLONG);
        RtlCopyMemory(tmp, &lock->Length, sizeof(LONGLONG));
        tmp += sizeof(LONGLONG);
        lock = lock->Next;
    }
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_unlock: count=%u\n", entry->u.Unlock.count);
#endif
out:
    return status;
}

NTSTATUS nfs41_IsLockRealizable(
    IN OUT PMRX_FCB pFcb,
    IN PLARGE_INTEGER  ByteOffset,
    IN PLARGE_INTEGER  Length,
    IN ULONG  LowIoLockFlags)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_LOCK
    DbgEn();
    DbgP("offset 0x%llx, length 0x%llx, exclusive=%u, blocking=%u\n",
        (long long)ByteOffset->QuadPart,
        (long long)Length->QuadPart,
        BooleanFlagOn(LowIoLockFlags, SL_EXCLUSIVE_LOCK),
        !BooleanFlagOn(LowIoLockFlags, SL_FAIL_IMMEDIATELY));
#endif

    /* NFS lock operations with length=0 MUST fail with NFS4ERR_INVAL */
    if (Length->QuadPart == 0)
        status = STATUS_NOT_SUPPORTED;

#ifdef DEBUG_LOCK
    DbgEx();
#endif
    return status;
}

NTSTATUS map_lock_errors(
    DWORD status)
{
    switch (status) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_LOCK_FAILED:         return STATUS_LOCK_NOT_GRANTED;
    case ERROR_NOT_LOCKED:          return STATUS_RANGE_NOT_LOCKED;
    case ERROR_ATOMIC_LOCKS_NOT_SUPPORTED: return STATUS_UNSUCCESSFUL;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_SHARING_VIOLATION:   return STATUS_SHARING_VIOLATION;
    case ERROR_FILE_INVALID:        return STATUS_FILE_INVALID;
    /* if we return ERROR_INVALID_PARAMETER, Windows translates that to
     * success!! */
    case ERROR_INVALID_PARAMETER:   return STATUS_LOCK_NOT_GRANTED;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_lock_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

static void print_lock_args(
    PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    const ULONG flags = LowIoContext->ParamsFor.Locks.Flags;
    print_debug_header(RxContext);
    DbgP("offset 0x%llx, length 0x%llx, exclusive=%u, blocking=%u\n",
        (long long)LowIoContext->ParamsFor.Locks.ByteOffset,
        (long long)LowIoContext->ParamsFor.Locks.Length,
        BooleanFlagOn(flags, SL_EXCLUSIVE_LOCK),
        !BooleanFlagOn(flags, SL_FAIL_IMMEDIATELY));
}


/* use exponential backoff between polls for blocking locks */
#define MSEC_TO_RELATIVE_WAIT   (-10000)
#define MIN_LOCK_POLL_WAIT      (500 * MSEC_TO_RELATIVE_WAIT) /* 500ms */
#define MAX_LOCK_POLL_WAIT      (30000 * MSEC_TO_RELATIVE_WAIT) /* 30s */

static void denied_lock_backoff(
    IN OUT PLARGE_INTEGER delay)
{
    if (delay->QuadPart == 0)
        delay->QuadPart = MIN_LOCK_POLL_WAIT;
    else
        delay->QuadPart <<= 1;

    if (delay->QuadPart < MAX_LOCK_POLL_WAIT)
        delay->QuadPart = MAX_LOCK_POLL_WAIT;
}

NTSTATUS nfs41_Lock(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    const ULONG flags = LowIoContext->ParamsFor.Locks.Flags;
    LARGE_INTEGER poll_delay = {0};
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

    poll_delay.QuadPart = 0;

#ifdef DEBUG_LOCK
    DbgEn();
    print_lock_args(RxContext);
#endif

/*  RxReleaseFcbResourceForThreadInMRx(RxContext, RxContext->pFcb,
        LowIoContext->ResourceThreadId); */

    status = nfs41_UpcallCreate(NFS41_LOCK, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Lock.offset = LowIoContext->ParamsFor.Locks.ByteOffset;
    entry->u.Lock.length = LowIoContext->ParamsFor.Locks.Length;
    entry->u.Lock.exclusive = BooleanFlagOn(flags, SL_EXCLUSIVE_LOCK);
    entry->u.Lock.blocking = !BooleanFlagOn(flags, SL_FAIL_IMMEDIATELY);

retry_upcall:
    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) goto out;

    /* blocking locks keep trying until it succeeds */
    if (entry->status == ERROR_LOCK_FAILED && entry->u.Lock.blocking) {
        denied_lock_backoff(&poll_delay);
        DbgP("returned ERROR_LOCK_FAILED; retrying in %llums\n",
            poll_delay.QuadPart / MSEC_TO_RELATIVE_WAIT);
        KeDelayExecutionThread(KernelMode, FALSE, &poll_delay);
        entry->state = NFS41_WAITING_FOR_UPCALL;
        goto retry_upcall;
    }

    status = map_lock_errors(entry->status);
    RxContext->CurrentIrp->IoStatus.Status = status;

    nfs41_UpcallDestroy(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&lock.tops);
    InterlockedAdd64(&lock.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Lock delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart,
        lock.tops, lock.ticks);
#endif
#endif
#ifdef DEBUG_LOCK
    DbgEx();
#endif
    return status;
}

static void print_unlock_args(
    PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    print_debug_header(RxContext);
    if (LowIoContext->Operation == LOWIO_OP_UNLOCK_MULTIPLE) {
        PLOWIO_LOCK_LIST lock = LowIoContext->ParamsFor.Locks.LockList;
        DbgP("LOWIO_OP_UNLOCK_MULTIPLE:");
        while (lock) {
            DbgP(" (offset=%llu, length=%llu)", lock->ByteOffset, lock->Length);
            lock = lock->Next;
        }
        DbgP("\n");
    } else {
        DbgP("LOWIO_OP_UNLOCK: offset=%llu, length=%llu\n",
            LowIoContext->ParamsFor.Locks.ByteOffset,
            LowIoContext->ParamsFor.Locks.Length);
    }
}

__inline ULONG unlock_list_count(
    PLOWIO_LOCK_LIST lock)
{
    ULONG count = 0;
    while (lock) {
        count++;
        lock = lock->Next;
    }
    return count;
}

NTSTATUS nfs41_Unlock(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    PLOWIO_CONTEXT LowIoContext  = &RxContext->LowIoContext;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif
#ifdef DEBUG_LOCK
    DbgEn();
    print_lock_args(RxContext);
#endif

/*  RxReleaseFcbResourceForThreadInMRx(RxContext, RxContext->pFcb,
        LowIoContext->ResourceThreadId); */

    status = nfs41_UpcallCreate(NFS41_UNLOCK, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    if (LowIoContext->Operation == LOWIO_OP_UNLOCK_MULTIPLE) {
        entry->u.Unlock.count = unlock_list_count(
            LowIoContext->ParamsFor.Locks.LockList);
        RtlCopyMemory(&entry->u.Unlock.locks,
            LowIoContext->ParamsFor.Locks.LockList,
            sizeof(LOWIO_LOCK_LIST));
    } else {
        entry->u.Unlock.count = 1;
        entry->u.Unlock.locks.ByteOffset =
            LowIoContext->ParamsFor.Locks.ByteOffset;
        entry->u.Unlock.locks.Length =
            LowIoContext->ParamsFor.Locks.Length;
    }

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) goto out;

    status = map_lock_errors(entry->status);
    RxContext->CurrentIrp->IoStatus.Status = status;
    nfs41_UpcallDestroy(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&unlock.tops);
    InterlockedAdd64(&unlock.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_Unlock delta = %d op=%d sum=%d\n", t2.QuadPart - t1.QuadPart,
        unlock.tops, unlock.ticks);
#endif
#endif
#ifdef DEBUG_LOCK
    DbgEx();
#endif
    return status;
}
