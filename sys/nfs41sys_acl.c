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
#include <stdbool.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"


NTSTATUS marshal_nfs41_getacl(
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

    header_len = *len + sizeof(SECURITY_INFORMATION);
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_getacl: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp,
        &entry->u.Acl.query_secinfo, sizeof(SECURITY_INFORMATION));
    tmp += sizeof(SECURITY_INFORMATION);

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_getacl: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_getacl: class=0x%x\n",
        (int)entry->u.Acl.query_secinfo);
#endif
out:
    return status;
}

NTSTATUS marshal_nfs41_setacl(
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

    header_len = *len + sizeof(SECURITY_INFORMATION) +
        sizeof(ULONG) + entry->u.Acl.buf_len;
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_setacl: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp,
        &entry->u.Acl.query_secinfo, sizeof(SECURITY_INFORMATION));
    tmp += sizeof(SECURITY_INFORMATION);
    RtlCopyMemory(tmp, &entry->u.Acl.buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->u.Acl.buf, entry->u.Acl.buf_len);
    tmp += entry->u.Acl.buf_len;

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_setacl: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_setacl: class=0x%x sec_desc_len=%lu\n",
         (int)entry->u.Acl.query_secinfo, (long)entry->u.Acl.buf_len);
#endif
out:
    return status;
}

NTSTATUS unmarshal_nfs41_getacl(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD buf_len;

    RtlCopyMemory(&buf_len, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    cur->u.Acl.buf = RxAllocatePoolWithTag(NonPagedPoolNx,
        buf_len, NFS41_MM_POOLTAG_ACL);
    if (cur->u.Acl.buf == NULL) {
        cur->status = status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(cur->u.Acl.buf, *buf, buf_len);
    *buf += buf_len;
    if (buf_len > cur->u.Acl.buf_len)
        cur->status = STATUS_BUFFER_TOO_SMALL;
    cur->u.Acl.buf_len = buf_len;

out:
    return status;
}

NTSTATUS map_query_acl_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                  return STATUS_SUCCESS;
    case ERROR_CALL_NOT_IMPLEMENTED:return STATUS_NOT_IMPLEMENTED;
    case ERROR_NOT_SUPPORTED:       return STATUS_NOT_SUPPORTED;
    case ERROR_NONE_MAPPED:         return STATUS_NONE_MAPPED;
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_FILE_NOT_FOUND:      return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_query_acl_error: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)error);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

static
NTSTATUS check_nfs41_getacl_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (RxContext->CurrentIrp->UserBuffer == NULL &&
            RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length) {
        DbgP("check_nfs41_getacl_args: "
            "RxContext->CurrentIrp->UserBuffer == NULL\n");
        status = STATUS_INVALID_USER_BUFFER;
    }
    return status;
}

NTSTATUS nfs41_QuerySecurityInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry = NULL;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    SECURITY_INFORMATION secinfo =
        RxContext->CurrentIrpSp->Parameters.QuerySecurity.SecurityInformation;
    ULONG querysecuritylength =
        RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length;
    bool aclcache_locked = false;

#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_ACL_QUERY
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(secinfo);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_getacl_args(RxContext);
    if (status) goto out;

    ExAcquireFastMutexUnsafe(&nfs41_fcb->aclcache.lock);
    aclcache_locked = true;

    if (nfs41_fcb->aclcache.data && nfs41_fcb->aclcache.data_len) {
        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);
#ifdef DEBUG_ACL_QUERY
        DbgP("CurrentTime 0x%llx Saved Acl time 0x%llx\n",
            (long long)current_time.QuadPart,
            (long long)nfs41_fcb->aclcache.time.QuadPart);
#endif
        if ((current_time.QuadPart - nfs41_fcb->aclcache.time.QuadPart)
            <= (10*10000000)) {
            if (querysecuritylength < nfs41_fcb->aclcache.data_len) {
                status = STATUS_BUFFER_OVERFLOW;
                RxContext->InformationToReturn = nfs41_fcb->aclcache.data_len;

                DbgP("nfs41_QuerySecurityInformation: "
                    "STATUS_BUFFER_OVERFLOW for cached entry, "
                    "got %lu, need %lu\n",
                    (unsigned long)querysecuritylength,
                    (unsigned long)nfs41_fcb->aclcache.data_len);
                goto out;
            }

            /* Check whether the cached info have all the info we need */
            if ((nfs41_fcb->aclcache.secinfo & secinfo) == secinfo) {
                PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
                    RxContext->CurrentIrp->UserBuffer;
                RtlCopyMemory(sec_desc, nfs41_fcb->aclcache.data,
                    nfs41_fcb->aclcache.data_len);
                RxContext->IoStatusBlock.Information =
                    RxContext->InformationToReturn =
                        nfs41_fcb->aclcache.data_len;
                RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;
#ifdef ENABLE_TIMINGS
                InterlockedIncrement(&getacl.sops);
                InterlockedAdd64(&getacl.size, nfs41_fcb->aclcache.data_len);
#endif

                DbgP("nfs41_QuerySecurityInformation: using cached ACL info\n");
                goto out;
            }
            else {
                DbgP("nfs41_QuerySecurityInformation: "
                    "cache misses requested info, "
                    "acl_secinfo=0x%lx, secinfo=0x%lx\n",
                    (unsigned long)nfs41_fcb->aclcache.secinfo,
                    (unsigned long)secinfo);
            }
        }
        else {
            DbgP("nfs41_QuerySecurityInformation: acl cache expired, "
                "current_time=%llu, nfs41_fcb->aclcache.time=%llu\n",
                current_time.QuadPart, nfs41_fcb->aclcache.time.QuadPart);
        }

        if (nfs41_fcb->aclcache.data) {
            RxFreePool(nfs41_fcb->aclcache.data);
            nfs41_fcb->aclcache.data = NULL;
            nfs41_fcb->aclcache.data_len = 0;
            nfs41_fcb->aclcache.secinfo = 0;
            nfs41_fcb->aclcache.time.QuadPart = 0LL;
        }
        DbgP("nfs41_QuerySecurityInformation: cached ACL info invalidated\n");
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_ACL_QUERY, &nfs41_srvopen->sec_ctx,
        pVNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Acl.query_secinfo = secinfo;
    /* we can't provide RxContext->CurrentIrp->UserBuffer to the upcall thread
     * because it becomes an invalid pointer with that execution context
     */
    entry->u.Acl.buf_len = querysecuritylength;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        DbgP("nfs41_QuerySecurityInformation: "
            "STATUS_BUFFER_OVERFLOW for entry, "
            "got %lu, need %lu\n",
            (unsigned long)querysecuritylength,
            (unsigned long)entry->u.Acl.buf_len);
        status = STATUS_BUFFER_OVERFLOW;
        RxContext->InformationToReturn = entry->u.Acl.buf_len;

        if (entry->u.Acl.buf) {
            RxFreePool(entry->u.Acl.buf);
            entry->u.Acl.buf = NULL;
        }
    } else if (entry->status == STATUS_SUCCESS) {
        /*
         * Free previous ACL data. This can happen if two concurrent
         * requests are executed for the same file
         */
        if (nfs41_fcb->aclcache.data) {
            RxFreePool(nfs41_fcb->aclcache.data);
            nfs41_fcb->aclcache.data = NULL;
            nfs41_fcb->aclcache.data_len = 0;
            nfs41_fcb->aclcache.secinfo = 0;
            nfs41_fcb->aclcache.time.QuadPart = 0LL;
        }

        nfs41_fcb->aclcache.data = entry->u.Acl.buf;
        nfs41_fcb->aclcache.data_len = entry->u.Acl.buf_len;
        nfs41_fcb->aclcache.secinfo = entry->u.Acl.query_secinfo;
        entry->u.Acl.buf = NULL;
        KeQuerySystemTime(&nfs41_fcb->aclcache.time);

        PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
            RxContext->CurrentIrp->UserBuffer;
        RtlCopyMemory(sec_desc, nfs41_fcb->aclcache.data,
            nfs41_fcb->aclcache.data_len);
        RxContext->IoStatusBlock.Information =
            RxContext->InformationToReturn = nfs41_fcb->aclcache.data_len;
        RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;

#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getacl.sops);
        InterlockedAdd64(&getacl.size, entry->u.Acl.buf_len);
#endif
    } else {
        status = map_query_acl_error(entry->status);

        if (entry->u.Acl.buf) {
            RxFreePool(entry->u.Acl.buf);
            entry->u.Acl.buf = NULL;
        }
    }

out:
    if (aclcache_locked) {
        ExReleaseFastMutexUnsafe(&nfs41_fcb->aclcache.lock);
    }

    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    /* only count getacl that we made an upcall for */
    if (status == STATUS_BUFFER_OVERFLOW) {
        InterlockedIncrement(&getacl.tops);
        InterlockedAdd64(&getacl.ticks, t2.QuadPart - t1.QuadPart);
    }
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QuerySecurityInformation: delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, getacl.tops, getacl.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_ACL_QUERY
    DbgEx();
#endif
    return status;
}

static
NTSTATUS check_nfs41_setacl_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);

    if (pVNetRootContext->read_only) {
        print_error("check_nfs41_setacl_args: Read-only mount\n");
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_SetSecurityInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry = NULL;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PSECURITY_DESCRIPTOR sec_desc =
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityDescriptor;
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    SECURITY_INFORMATION secinfo =
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityInformation;

#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_ACL_SET
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(secinfo);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_setacl_args(RxContext);
    if (status) goto out;

    /* check that ACL is present */
    if (secinfo & DACL_SECURITY_INFORMATION) {
        PACL acl;
        BOOLEAN present, dacl_default;
        status = RtlGetDaclSecurityDescriptor(sec_desc, &present, &acl,
                    &dacl_default);
        if (status) {
            DbgP("RtlGetDaclSecurityDescriptor failed status=0x%lx\n",
                (long)status);
            goto out;
        }
        if (present == FALSE) {
            DbgP("NO ACL present\n");
            goto out;
        }
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_ACL_SET, &nfs41_srvopen->sec_ctx,
        pVNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Acl.query_secinfo = secinfo;
    entry->u.Acl.buf = sec_desc;
    entry->u.Acl.buf_len = RtlLengthSecurityDescriptor(sec_desc);
#ifdef ENABLE_TIMINGS
    InterlockedIncrement(&setacl.sops);
    InterlockedAdd64(&setacl.size, entry->u.Acl.buf_len);
#endif

    /*
     * Invalidate cached ACL info
     * (we do not try to fill the cache afte a |NFS41_SYSOP_ACL_SET|
     * because it is typically not read after that)
     */
    ExAcquireFastMutexUnsafe(&nfs41_fcb->aclcache.lock);
    if (nfs41_fcb->aclcache.data) {
        RxFreePool(nfs41_fcb->aclcache.data);
        nfs41_fcb->aclcache.data = NULL;
        nfs41_fcb->aclcache.data_len = 0;
        nfs41_fcb->aclcache.secinfo = 0;
        nfs41_fcb->aclcache.time.QuadPart = 0LL;
    }
    ExReleaseFastMutexUnsafe(&nfs41_fcb->aclcache.lock);

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    status = map_query_acl_error(entry->status);
    if (!status) {
        if ((IS_NFS41_OPEN_DELEGATE_NONE(nfs41_srvopen->deleg_type)) &&
            entry->ChangeTime &&
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
    InterlockedIncrement(&setacl.tops);
    InterlockedAdd64(&setacl.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetSecurityInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, setacl.tops, setacl.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_ACL_SET
    DbgEx();
#endif
    return status;
}
