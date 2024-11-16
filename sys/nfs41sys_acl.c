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
    if (status) goto out;
    else tmp += *len;

    header_len = *len + sizeof(SECURITY_INFORMATION);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Acl.query, sizeof(SECURITY_INFORMATION));
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_getacl: class=0x%x\n", (int)entry->u.Acl.query);
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
    if (status) goto out;
    else tmp += *len;

    header_len = *len + sizeof(SECURITY_INFORMATION) +
        sizeof(ULONG) + entry->buf_len;
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.Acl.query, sizeof(SECURITY_INFORMATION));
    tmp += sizeof(SECURITY_INFORMATION);
    RtlCopyMemory(tmp, &entry->buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, entry->buf, entry->buf_len);
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_setacl: class=0x%x sec_desc_len=%lu\n",
         (int)entry->u.Acl.query, (long)entry->buf_len);
#endif
out:
    return status;
}

NTSTATUS unmarshal_nfs41_getacl(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;
    DWORD buf_len;

    RtlCopyMemory(&buf_len, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    cur->buf = RxAllocatePoolWithTag(NonPagedPoolNx,
        buf_len, NFS41_MM_POOLTAG_ACL);
    if (cur->buf == NULL) {
        cur->status = status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlCopyMemory(cur->buf, *buf, buf_len);
    if (buf_len > cur->buf_len)
        cur->status = STATUS_BUFFER_TOO_SMALL;
    cur->buf_len = buf_len;

out:
    return status;
}

NTSTATUS map_query_acl_error(
    DWORD error)
{
    switch (error) {
    case NO_ERROR:                  return STATUS_SUCCESS;
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
    SECURITY_INFORMATION info_class =
        RxContext->CurrentIrpSp->Parameters.QuerySecurity.SecurityInformation;

    /* we don't support sacls */
    if (info_class == SACL_SECURITY_INFORMATION ||
            info_class == LABEL_SECURITY_INFORMATION) {
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }
    if (RxContext->CurrentIrp->UserBuffer == NULL &&
            RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length)
        status = STATUS_INVALID_USER_BUFFER;
out:
    return status;
}

NTSTATUS nfs41_QuerySecurityInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    SECURITY_INFORMATION info_class =
        RxContext->CurrentIrpSp->Parameters.QuerySecurity.SecurityInformation;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_ACL_QUERY
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(info_class);
#endif

    status = check_nfs41_getacl_args(RxContext);
    if (status) goto out;

    if (nfs41_fobx->acl && nfs41_fobx->acl_len) {
        LARGE_INTEGER current_time;
        KeQuerySystemTime(&current_time);
#ifdef DEBUG_ACL_QUERY
        DbgP("CurrentTime 0x%llx Saved Acl time 0x%llx\n",
            (long long)current_time.QuadPart,
            (long long)nfs41_fobx->time.QuadPart);
#endif
        if (current_time.QuadPart - nfs41_fobx->time.QuadPart <= 20*1000) {
            PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
                RxContext->CurrentIrp->UserBuffer;
            RtlCopyMemory(sec_desc, nfs41_fobx->acl, nfs41_fobx->acl_len);
            RxContext->IoStatusBlock.Information =
                RxContext->InformationToReturn = nfs41_fobx->acl_len;
            RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;
#ifdef ENABLE_TIMINGS
            InterlockedIncrement(&getacl.sops);
            InterlockedAdd64(&getacl.size, nfs41_fobx->acl_len);
#endif
        } else status = 1;
        RxFreePool(nfs41_fobx->acl);
        nfs41_fobx->acl = NULL;
        nfs41_fobx->acl_len = 0;
        if (!status)
            goto out;
    }

    status = nfs41_UpcallCreate(NFS41_SYSOP_ACL_QUERY, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Acl.query = info_class;
    /* we can't provide RxContext->CurrentIrp->UserBuffer to the upcall thread
     * because it becomes an invalid pointer with that execution context
     */
    entry->buf_len = RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) goto out;

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
#ifdef DEBUG_ACL_QUERY
        DbgP("nfs41_QuerySecurityInformation: provided buffer size=%d but we "
             "need %lu\n",
             RxContext->CurrentIrpSp->Parameters.QuerySecurity.Length,
             entry->buf_len);
#endif
        status = STATUS_BUFFER_OVERFLOW;
        RxContext->InformationToReturn = entry->buf_len;

        /* Save ACL buffer */
        nfs41_fobx->acl = entry->buf;
        nfs41_fobx->acl_len = entry->buf_len;
        KeQuerySystemTime(&nfs41_fobx->time);
    } else if (entry->status == STATUS_SUCCESS) {
        PSECURITY_DESCRIPTOR sec_desc = (PSECURITY_DESCRIPTOR)
            RxContext->CurrentIrp->UserBuffer;
        RtlCopyMemory(sec_desc, entry->buf, entry->buf_len);
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&getacl.sops);
        InterlockedAdd64(&getacl.size, entry->u.Acl.buf_len);
#endif
        RxFreePool(entry->buf);
        entry->buf = NULL;
        nfs41_fobx->acl = NULL;
        nfs41_fobx->acl_len = 0;
        RxContext->IoStatusBlock.Information = RxContext->InformationToReturn =
            entry->buf_len;
        RxContext->IoStatusBlock.Status = status = STATUS_SUCCESS;
    } else {
        status = map_query_acl_error(entry->status);
    }
    nfs41_UpcallDestroy(entry);
out:
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
    SECURITY_INFORMATION info_class =
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityInformation;

    if (pVNetRootContext->read_only) {
        print_error("check_nfs41_setacl_args: Read-only mount\n");
        status = STATUS_MEDIA_WRITE_PROTECTED;
        goto out;
    }
    /* we don't support sacls */
    if (info_class == SACL_SECURITY_INFORMATION  ||
            info_class == LABEL_SECURITY_INFORMATION) {
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }
out:
    return status;
}

NTSTATUS nfs41_SetSecurityInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    nfs41_updowncall_entry *entry;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PSECURITY_DESCRIPTOR sec_desc =
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityDescriptor;
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    SECURITY_INFORMATION info_class =
        RxContext->CurrentIrpSp->Parameters.SetSecurity.SecurityInformation;
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_ACL_SET
    DbgEn();
    print_debug_header(RxContext);
    print_acl_args(info_class);
#endif

    status = check_nfs41_setacl_args(RxContext);
    if (status) goto out;

    /* check that ACL is present */
    if (info_class & DACL_SECURITY_INFORMATION) {
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

    status = nfs41_UpcallCreate(NFS41_SYSOP_ACL_SET, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Acl.query = info_class;
    entry->buf = sec_desc;
    entry->buf_len = RtlLengthSecurityDescriptor(sec_desc);
#ifdef ENABLE_TIMINGS
    InterlockedIncrement(&setacl.sops);
    InterlockedAdd64(&setacl.size, entry->u.Acl.buf_len);
#endif

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) goto out;

    status = map_query_acl_error(entry->status);
    if (!status) {
        if (!nfs41_fobx->deleg_type && entry->ChangeTime &&
                (SrvOpen->DesiredAccess &
                (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)))
            nfs41_update_fcb_list(RxContext->pFcb, entry->ChangeTime);
        nfs41_fcb->changeattr = entry->ChangeTime;
    }
    nfs41_UpcallDestroy(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&setacl.tops);
    InterlockedAdd64(&setacl.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_SetSecurityInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, setacl.tops, setacl.ticks);
#endif
#endif
#ifdef DEBUG_ACL_SET
    DbgEx();
#endif
    return status;
}
