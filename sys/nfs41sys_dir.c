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

NTSTATUS marshal_nfs41_dirquery(
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

    header_len = *len + 2 * sizeof(ULONG) + sizeof(HANDLE) +
        length_as_utf8(entry->u.QueryFile.filter) + 3 * sizeof(BOOLEAN);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlCopyMemory(tmp, &entry->u.QueryFile.InfoClass, sizeof(ULONG));
    tmp += sizeof(ULONG);
    RtlCopyMemory(tmp, &entry->buf_len, sizeof(ULONG));
    tmp += sizeof(ULONG);
    status = marshall_unicode_as_utf8(&tmp, entry->u.QueryFile.filter);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.QueryFile.initial_query, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryFile.restart_scan, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    RtlCopyMemory(tmp, &entry->u.QueryFile.return_single, sizeof(BOOLEAN));
    tmp += sizeof(BOOLEAN);
    __try {
        entry->u.QueryFile.mdl_buf =
            MmMapLockedPagesSpecifyCache(entry->u.QueryFile.mdl,
                UserMode, MmCached, NULL, TRUE,
                NormalPagePriority|MdlMappingNoExecute);
        if (entry->u.QueryFile.mdl_buf == NULL) {
            print_error("marshal_nfs41_dirquery: "
                "MmMapLockedPagesSpecifyCache() failed to map pages\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("marshal_nfs41_dirquery: Call to "
            "MmMapLockedPagesSpecifyCache() failed "
            "due to exception 0x%x\n", (int)code);
        status = STATUS_ACCESS_VIOLATION;
        goto out;
    }
    RtlCopyMemory(tmp, &entry->u.QueryFile.mdl_buf, sizeof(HANDLE));
    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_dirquery: filter='%wZ' class=%d len=%d "
         "1st\\restart\\single=%d\\%d\\%d\n", entry->u.QueryFile.filter,
         entry->u.QueryFile.InfoClass, entry->buf_len,
         entry->u.QueryFile.initial_query, entry->u.QueryFile.restart_scan,
         entry->u.QueryFile.return_single);
#endif
out:
    return status;
}

NTSTATUS unmarshal_nfs41_dirquery(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG buf_len;

    RtlCopyMemory(&buf_len, *buf, sizeof(ULONG));
#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("unmarshal_nfs41_dirquery: reply size %d\n", buf_len);
#endif
    *buf += sizeof(ULONG);
    __try {
        MmUnmapLockedPages(cur->u.QueryFile.mdl_buf, cur->u.QueryFile.mdl);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("MmUnmapLockedPages thrown exception=0x%0x\n", code);
        status = STATUS_ACCESS_VIOLATION;
    }
    if (buf_len > cur->buf_len)
        cur->status = STATUS_BUFFER_TOO_SMALL;
    cur->buf_len = buf_len;

    return status;
}

static void print_debug_filedirquery_header(
    PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = '%s'\n",
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext),
        print_file_information_class(RxContext->Info.FileInformationClass));
}

static void print_querydir_args(
    PRX_CONTEXT RxContext)
{
    print_debug_filedirquery_header(RxContext);
    DbgP("Filter='%wZ', Index=%d, Restart/Single/Specified/Init=%d/%d/%d/%d\n",
        &RxContext->pFobx->UnicodeQueryTemplate,
        RxContext->QueryDirectory.FileIndex,
        RxContext->QueryDirectory.RestartScan,
        RxContext->QueryDirectory.ReturnSingleEntry,
        RxContext->QueryDirectory.IndexSpecified,
        RxContext->QueryDirectory.InitialQuery);
}

NTSTATUS map_querydir_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_BUFFER_OVERFLOW:     return STATUS_BUFFER_OVERFLOW;
    case ERROR_FILE_NOT_FOUND:      return STATUS_NO_SUCH_FILE;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_NO_MORE_FILES:       return STATUS_NO_MORE_FILES;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_FILENAME_EXCED_RANGE: return STATUS_NAME_TOO_LONG;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_querydir_errors: "
            "failed to map windows ERROR_0x%x to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n", status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

NTSTATUS check_nfs41_dirquery_args(
    IN PRX_CONTEXT RxContext)
{
    if (RxContext->Info.Buffer == NULL)
        return STATUS_INVALID_USER_BUFFER;
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_QueryDirectory(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry;
    FILE_INFORMATION_CLASS InfoClass = RxContext->Info.FileInformationClass;
    PUNICODE_STRING Filter = &RxContext->pFobx->UnicodeQueryTemplate;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(RxContext->pFobx);
#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_DIR_QUERY
    DbgEn();
    print_querydir_args(RxContext);
#endif

    status = check_nfs41_dirquery_args(RxContext);
    if (status) goto out;

    switch (InfoClass) {
    /* classes handled in readdir_copy_entry() and readdir_size_for_entry() */
    case FileNamesInformation:
    case FileDirectoryInformation:
    case FileFullDirectoryInformation:
    case FileIdFullDirectoryInformation:
    case FileBothDirectoryInformation:
    case FileIdBothDirectoryInformation:
        break;
    default:
        print_error("nfs41_QueryDirectory: unhandled dir query class %d\n",
            InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }
    status = nfs41_UpcallCreate(NFS41_DIR_QUERY, &nfs41_fobx->sec_ctx,
        pVNetRootContext->session, nfs41_fobx->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.QueryFile.InfoClass = InfoClass;
    entry->buf_len = RxContext->Info.LengthRemaining;
    entry->buf = RxContext->Info.Buffer;
    entry->u.QueryFile.mdl = IoAllocateMdl(RxContext->Info.Buffer,
        RxContext->Info.LengthRemaining, FALSE, FALSE, NULL);
    if (entry->u.QueryFile.mdl == NULL) {
        status = STATUS_INTERNAL_ERROR;
        nfs41_UpcallDestroy(entry);
        goto out;
    }
#pragma warning( push )
/*
 * C28145: "The opaque MDL structure should not be modified by a
 * driver.", |MDL_MAPPING_CAN_FAIL| is the exception
 */
#pragma warning (disable : 28145)
    entry->u.QueryFile.mdl->MdlFlags |= MDL_MAPPING_CAN_FAIL;
#pragma warning( pop )

    MmProbeAndLockPages(entry->u.QueryFile.mdl, KernelMode, IoModifyAccess);

    entry->u.QueryFile.filter = Filter;
    entry->u.QueryFile.initial_query = RxContext->QueryDirectory.InitialQuery;
    entry->u.QueryFile.restart_scan = RxContext->QueryDirectory.RestartScan;
    entry->u.QueryFile.return_single = RxContext->QueryDirectory.ReturnSingleEntry;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) goto out;
    MmUnlockPages(entry->u.QueryFile.mdl);

    if (entry->status == STATUS_BUFFER_TOO_SMALL) {
        DbgP("nfs41_QueryDirectory: buffer too small provided %d need %lu\n",
            RxContext->Info.LengthRemaining, entry->buf_len);
        RxContext->InformationToReturn = entry->buf_len;
        status = STATUS_BUFFER_TOO_SMALL;
    } else if (entry->status == STATUS_SUCCESS) {
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&readdir.sops);
        InterlockedAdd64(&readdir.size, entry->u.QueryFile.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->buf_len;
        status = STATUS_SUCCESS;
    } else if ((entry->status == STATUS_ACCESS_VIOLATION) ||
        (entry->status == STATUS_INSUFFICIENT_RESOURCES)) {
        DbgP("nfs41_QueryDirectory: internal error: entry->status=0x%x\n",
            (int)entry->status);
        status = STATUS_INSUFFICIENT_RESOURCES;
    } else {
        /* map windows ERRORs to NTSTATUS */
        status = map_querydir_errors(entry->status);
    }
    IoFreeMdl(entry->u.QueryFile.mdl);
    nfs41_UpcallDestroy(entry);
out:
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&readdir.tops);
    InterlockedAdd64(&readdir.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryDirectory delta = %d ops=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, readdir.tops, readdir.ticks);
#endif
#endif
#ifdef DEBUG_DIR_QUERY
    DbgEx();
#endif
    return status;
}
