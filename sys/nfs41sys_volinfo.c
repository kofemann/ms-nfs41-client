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

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"


NTSTATUS marshal_nfs41_volume(
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

    header_len = *len + sizeof(FS_INFORMATION_CLASS);
    if (header_len > buf_len) {
        DbgP("marshal_nfs41_volume: "
            "upcall buffer too small: header_len(=%ld) > buf_len(=%ld)\n",
            (long)header_len, (long)buf_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    UPDOWNCALL_MEMCPY(tmp, &entry->u.Volume.query, sizeof(FS_INFORMATION_CLASS));
    tmp += sizeof(FS_INFORMATION_CLASS);

    *len = (ULONG)(tmp - buf);
    if (*len != header_len) {
        DbgP("marshal_nfs41_volume: *len(=%ld) != header_len(=%ld)\n",
            (long)*len, (long)header_len);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_volume: class=%d\n", entry->u.Volume.query);
#endif
out:
    return status;
}

void unmarshal_nfs41_volume(
    nfs41_updowncall_entry *cur,
    const unsigned char *restrict *restrict buf)
{
    unmarshal_nfs41_attrget(cur,
        cur->u.Volume.buf, &cur->u.Volume.buf_len, buf, TRUE);
}

static void print_queryvolume_args(
    PRX_CONTEXT RxContext)
{
    print_debug_header(RxContext);
    DbgP("FileName='%wZ', InfoClass = '%s' BufferLen = %d\n",
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext),
        print_fs_information_class(RxContext->Info.FileInformationClass),
        RxContext->Info.LengthRemaining);
}

NTSTATUS map_volume_errors(
    DWORD status)
{
    switch (status) {
    case ERROR_ACCESS_DENIED:       return STATUS_ACCESS_DENIED;
    case ERROR_VC_DISCONNECTED:     return STATUS_CONNECTION_DISCONNECTED;
    case ERROR_NETNAME_DELETED:     return STATUS_NETWORK_NAME_DELETED;
    case ERROR_INVALID_PARAMETER:   return STATUS_INVALID_PARAMETER;
    case ERROR_OUTOFMEMORY:         return STATUS_INSUFFICIENT_RESOURCES;
    case ERROR_INTERNAL_ERROR:      return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_volume_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INVALID_NETWORK_RESPONSE\n",
            (long)status);
    case ERROR_BAD_NET_RESP:        return STATUS_INVALID_NETWORK_RESPONSE;
    }
}

#ifdef NFS41_DRIVER_VOLUME_QUERY_CACHE
static
PNFS41_VOLUME_QUERY_CACHE_FSID_ENTRY find_volume_query_cache_fsid_entry(
    PNFS41_V_NET_ROOT_EXTENSION vnetroot,
    ULONGLONG fsid_major,
    ULONGLONG fsid_minor)
{
    PLIST_ENTRY list_entry;

    for (list_entry = vnetroot->volumequerycache.entries.Flink;
         list_entry != &vnetroot->volumequerycache.entries;
         list_entry = list_entry->Flink) {
        PNFS41_VOLUME_QUERY_CACHE_FSID_ENTRY cache_entry = CONTAINING_RECORD(
            list_entry, NFS41_VOLUME_QUERY_CACHE_FSID_ENTRY, next);

        if ((cache_entry->fsid_major == fsid_major) &&
            (cache_entry->fsid_minor == fsid_minor))
            return cache_entry;
    }
    return NULL;
}

static
bool volume_query_cache_lookup(
    PNFS41_V_NET_ROOT_EXTENSION vnetroot,
    PNFS41_FCB fcb,
    FS_INFORMATION_CLASS info_class,
    PVOID buffer,
    ULONG buffer_size,
    PULONG copied_size,
    PNTSTATUS status)
{
    PNFS41_VOLUME_QUERY_CACHE_FSID_ENTRY cache_entry;
    PNFS41_VOLUME_QUERY_CACHE_VALUE value;
    ULONGLONG now = KeQueryInterruptTime();
    size_t copy_size;
    bool found = false;

    ExAcquireFastMutexUnsafe(&vnetroot->volumequerycache.lock);
    cache_entry = find_volume_query_cache_fsid_entry(vnetroot,
        fcb->fsid_major, fcb->fsid_minor);
    if (cache_entry == NULL)
        goto out;

    value = &cache_entry->values[info_class];
    if (value->data == NULL)
        goto out;

    if (now >= value->time_to_live) {
        DbgP("volume_query_cache_lookup: cache entry expired: "
            "fsid=(major=0x%llx,minor=0x%llx) infoclass=%d "
            "size=%lld ttl=%lld\n",
            (long long)fcb->fsid_major, (long long)fcb->fsid_minor,
            (int)info_class,
            (long long)value->size,
            (long long)value->time_to_live);
        RxFreePool(value->data);
        value->data = NULL;
        value->size = 0;
        value->time_to_live = 0;
        goto out;
    }

    copy_size = min(value->size, (size_t)buffer_size);
    if (copy_size != 0)
        (void)memcpy(buffer, value->data, copy_size);
    *copied_size = (ULONG)copy_size;
    *status = (copy_size == value->size) ?
        STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW;

    DbgP("volume_query_cache_lookup: cache used: "
        "fsid=(major=0x%llx,minor=0x%llx) infoclass=%d "
        "size=%lld ttl=%lld\n",
         (long long)fcb->fsid_major, (long long)fcb->fsid_minor,
         (int)info_class,
         (long long)value->size, (long long)value->time_to_live);
    found = true;
out:
    ExReleaseFastMutexUnsafe(&vnetroot->volumequerycache.lock);
    return found;
}

static
void volume_query_cache_store(
    PNFS41_V_NET_ROOT_EXTENSION vnetroot,
    PNFS41_FCB fcb,
    FS_INFORMATION_CLASS info_class,
    PVOID data,
    size_t size)
{
    PNFS41_VOLUME_QUERY_CACHE_FSID_ENTRY cache_entry;
    PVOID new_data;

    new_data = RxAllocatePoolWithTag(NonPagedPoolNx, size,
        NFS41_MM_VOLUME_CACHE);
    if (new_data == NULL)
        return;
    (void)memcpy(new_data, data, size);

    ExAcquireFastMutexUnsafe(&vnetroot->volumequerycache.lock);

    cache_entry = find_volume_query_cache_fsid_entry(vnetroot,
        fcb->fsid_major, fcb->fsid_minor);

    /* No entry for this fsid ? Then create one... */
    if (cache_entry == NULL) {
        cache_entry = RxAllocatePoolWithTag(NonPagedPoolNx,
            sizeof(NFS41_VOLUME_QUERY_CACHE_FSID_ENTRY), NFS41_MM_VOLUME_CACHE);
        if (cache_entry == NULL) {
            RxFreePool(new_data);
            goto out;
        }

        (void)memset(cache_entry, 0, sizeof(NFS41_VOLUME_QUERY_CACHE_FSID_ENTRY));
        cache_entry->fsid_major = fcb->fsid_major;
        cache_entry->fsid_minor = fcb->fsid_minor;

        InsertTailList(&vnetroot->volumequerycache.entries, &cache_entry->next);
    }

    /*
     * Remove any data which might have appeared while we made the
     * daemon upcall (e.g. >= two parallel lookups) ...
     */
    if (cache_entry->values[info_class].data != NULL)
        RxFreePool(cache_entry->values[info_class].data);

    cache_entry->values[info_class].data = new_data;
    cache_entry->values[info_class].size = size;
    cache_entry->values[info_class].time_to_live = KeQueryInterruptTime() +
        NFS41_VOLUME_QUERY_CACHE_TTL_SECONDS * 10ULL * 1000ULL * 1000ULL;

out:
    ExReleaseFastMutexUnsafe(&vnetroot->volumequerycache.lock);
}
#endif /* NFS41_DRIVER_VOLUME_QUERY_CACHE */

NTSTATUS nfs41_QueryVolumeInformation(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    nfs41_updowncall_entry *entry = NULL;
    ULONG RemainingLength = RxContext->Info.LengthRemaining, SizeUsed;
    FS_INFORMATION_CLASS InfoClass = RxContext->Info.FsInformationClass;
    __notnull PMRX_SRV_OPEN SrvOpen = RxContext->pRelevantSrvOpen;
    __notnull PNFS41_SRV_OPEN nfs41_srvopen = NFS41GetSrvOpenExtension(SrvOpen);
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(SrvOpen->pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(SrvOpen->pVNetRoot->pNetRoot);
#ifdef NFS41_DRIVER_VOLUME_QUERY_CACHE
    __notnull PNFS41_FCB nfs41_fcb = NFS41GetFcbExtension(RxContext->pFcb);
    ULONG cached_size = 0;
#endif /* NFS41_DRIVER_VOLUME_QUERY_CACHE */

#ifdef ENABLE_TIMINGS
    LARGE_INTEGER t1, t2;
    t1 = KeQueryPerformanceCounter(NULL);
#endif

#ifdef DEBUG_VOLUME_QUERY
    DbgEn();
    print_queryvolume_args(RxContext);
#endif
    FsRtlEnterFileSystem();

    status = check_nfs41_dirquery_args(RxContext);
    if (status) goto out;

    RtlZeroMemory(RxContext->Info.Buffer, RxContext->Info.LengthRemaining);

    switch (InfoClass) {
    case FileFsDeviceInformation:
    {
        PFILE_FS_DEVICE_INFORMATION pDevInfo = RxContext->Info.Buffer;

        SizeUsed = sizeof(FILE_FS_DEVICE_INFORMATION);
        if (RemainingLength < SizeUsed) {
            status = STATUS_BUFFER_TOO_SMALL;
            RxContext->InformationToReturn = SizeUsed;
            goto out;
        }
        pDevInfo->DeviceType = RxContext->pFcb->pNetRoot->DeviceType;
        pDevInfo->Characteristics = FILE_REMOTE_DEVICE | FILE_DEVICE_IS_MOUNTED;
        RxContext->Info.LengthRemaining -= SizeUsed;
        status = STATUS_SUCCESS;
        goto out;
    }

    case FileFsAttributeInformation:
    case FileFsSizeInformation:
    case FileFsFullSizeInformation:
    case FileFsSectorSizeInformation:
    case FileFsVolumeInformation:
        break;

    default:
        print_error("nfs41_QueryVolumeInformation: unhandled class %d\n", InfoClass);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }
#ifdef NFS41_DRIVER_VOLUME_QUERY_CACHE
    if (volume_query_cache_lookup(pVNetRootContext, nfs41_fcb, InfoClass,
            RxContext->Info.Buffer, RxContext->Info.LengthRemaining,
            &cached_size, &status)) {
        RxContext->Info.LengthRemaining -= cached_size;
        goto out;
    }
#endif /* NFS41_DRIVER_VOLUME_QUERY_CACHE */

    status = nfs41_UpcallCreate(NFS41_SYSOP_VOLUME_QUERY, &nfs41_srvopen->sec_ctx,
        pVNetRootContext->session, nfs41_srvopen->nfs41_open_state,
        pNetRootContext->nfs41d_version, SrvOpen->pAlreadyPrefixedName, &entry);
    if (status) goto out;

    entry->u.Volume.query = InfoClass;
    entry->u.Volume.buf = RxContext->Info.Buffer;
    entry->u.Volume.buf_len = RxContext->Info.LengthRemaining;

    status = nfs41_UpcallWaitForReply(entry, pVNetRootContext->timeout);
    if (status) {
        /* Timeout - |nfs41_downcall()| will free |entry|+contents */
        entry = NULL;
        goto out;
    }

    if (entry->status == STATUS_BUFFER_OVERFLOW) {
        /*
         * Supplied buffer was too small, so we copied only part of
         * the data into the buffer
         */
        status = STATUS_BUFFER_OVERFLOW;
    }
    else if (entry->status == STATUS_SUCCESS) {
#ifdef ENABLE_TIMINGS
        InterlockedIncrement(&volume.sops);
        InterlockedAdd64(&volume.size, entry->u.Volume.buf_len);
#endif
        RxContext->Info.LengthRemaining -= entry->u.Volume.buf_len;
#ifdef NFS41_DRIVER_VOLUME_QUERY_CACHE
        /*
         * We must only cache on |STATUS_SUCCESS| but NOT if we got a
         * |STATUS_BUFFER_OVERFLOW|!
         */
        volume_query_cache_store(pVNetRootContext, nfs41_fcb, InfoClass,
            RxContext->Info.Buffer, entry->u.Volume.buf_len);
#endif /* NFS41_DRIVER_VOLUME_QUERY_CACHE */
        status = STATUS_SUCCESS;
    } else {
        status = map_volume_errors(entry->status);
    }
out:
    if (entry) {
        nfs41_UpcallDestroy(entry);
    }
#ifdef ENABLE_TIMINGS
    t2 = KeQueryPerformanceCounter(NULL);
    InterlockedIncrement(&volume.tops);
    InterlockedAdd64(&volume.ticks, t2.QuadPart - t1.QuadPart);
#ifdef ENABLE_INDV_TIMINGS
    DbgP("nfs41_QueryVolumeInformation delta = %d op=%d sum=%d\n",
        t2.QuadPart - t1.QuadPart, volume.tops, volume.ticks);
#endif
#endif
    FsRtlExitFileSystem();
#ifdef DEBUG_VOLUME_QUERY
    DbgEx();
#endif
    return status;
}
