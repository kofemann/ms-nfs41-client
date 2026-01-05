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

#ifndef _NFS41SYS_UTIL_H_
#define _NFS41SYS_UTIL_H_ 1

#include "nfs41_build_features.h"

#include <stdbool.h>

static INLINE BOOL AnsiStrEq(
    IN const ANSI_STRING *lhs,
    IN const CHAR *rhs,
    IN const UCHAR rhs_len)
{
    return lhs->Length == rhs_len &&
        RtlCompareMemory(lhs->Buffer, rhs, rhs_len) == rhs_len;
}

/* convert strings from unicode -> ansi during marshalling to
 * save space in the upcall buffers and avoid extra copies */
static INLINE ULONG length_as_utf8(
    PCUNICODE_STRING str)
{
    ULONG ActualCount = 0;
    RtlUnicodeToUTF8N(NULL, 0xffff, &ActualCount, str->Buffer, str->Length);
    /* Length of length field + string length + '\0'*/
    return sizeof(USHORT) + ActualCount + 1;
}

/* Prototypes */
BOOLEAN isFilenameTooLong(
    PUNICODE_STRING name,
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext);
BOOLEAN is_root_directory(
    PRX_CONTEXT RxContext);
NTSTATUS nfs41_ProbeAndLockKernelPages(
    __inout PMDL    MemoryDescriptorList,
    __in    LOCK_OPERATION  Operation);
NTSTATUS nfs41_UnlockKernelPages(
    __inout PMDL    MemoryDescriptorList);
NTSTATUS nfs41_MapLockedPagesInNfsDaemonAddressSpace(
    __inout PVOID               *outbuf,
    __in    PMDL                MemoryDescriptorList,
    __in    MEMORY_CACHING_TYPE CacheType,
    __in    ULONG               Priority);
NTSTATUS nfs41_UnmapLockedKernelPagesInNfsDaemonAddressSpace(
    __in PVOID BaseAddress,
    __in PMDL  MemoryDescriptorList);
PQUERY_ON_CREATE_ECP_CONTEXT get_queryoncreateecpcontext(
    __in PIRP Irp);
_Success_(return == true) bool
get_primarygroup_id(
    _Out_writes_bytes_(MAX_SID_BUFFER_SIZE) SID *restrict ret_sid);
void qocec_file_stat_information(
    OUT QUERY_ON_CREATE_FILE_STAT_INFORMATION *restrict qocfsi,
    IN const NFS41_FCB *restrict nfs41_fcb);
#ifdef NFS41_DRIVER_WSL_SUPPORT
void qocec_file_stat_lx_information(
    OUT QUERY_ON_CREATE_FILE_LX_INFORMATION *restrict qocflxi,
    IN const NFS41_FCB *restrict nfs41_fcb,
    IN const NFS41_V_NET_ROOT_EXTENSION *restrict pVNetRootContext);
#endif /* NFS41_DRIVER_WSL_SUPPORT */

#endif /* !_NFS41SYS_UTIL_H_ */
