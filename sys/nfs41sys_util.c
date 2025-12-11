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

#include <Ntstrsafe.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"


BOOLEAN isFilenameTooLong(
    PUNICODE_STRING name,
    PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext)
{
    NFS41_FILE_FS_ATTRIBUTE_INFORMATION *attrs = &pVNetRootContext->FsAttrs;
    LONG len = attrs->MaximumComponentNameLength, count = 1, i;
    PWCH p = name->Buffer;
    for (i = 0; i < name->Length / 2; i++) {
        if (p[0] == L'\\') count = 1;
        else {
            if (p[0] == L'\0') return FALSE;
            if (count > len) return TRUE;
            count++;
        }
        p++;
    }
    return FALSE;
}

BOOLEAN isStream(
    PUNICODE_STRING name)
{
    LONG i;
    PWCH p = name->Buffer;
    for (i = 0; i < name->Length / 2; i++) {
        if (p[0] == L':') return TRUE;
        else if (p[0] == L'\0') return FALSE;
        p++;
    }
    return FALSE;
}

BOOLEAN is_root_directory(
    PRX_CONTEXT RxContext)
{
    __notnull PV_NET_ROOT VNetRoot = (PV_NET_ROOT)
        RxContext->pRelevantSrvOpen->pVNetRoot;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(RxContext->pRelevantSrvOpen->pVNetRoot);

    /* calculate the root directory's length, including vnetroot prefix,
     * mount path, and a trailing \ */
    const USHORT RootPathLen = VNetRoot->PrefixEntry.Prefix.Length +
            pVNetRootContext->MntPt.Length + sizeof(WCHAR);

    return RxContext->CurrentIrpSp->FileObject->FileName.Length <= RootPathLen;
}

NTSTATUS nfs41_ProbeAndLockKernelPages(
    __inout PMDL    MemoryDescriptorList,
    __in    LOCK_OPERATION  Operation)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        MmProbeAndLockPages(MemoryDescriptorList, KernelMode, Operation);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("nfs41_ProbeAndLockKernelPages: Call to "
            "MmMapLockedPagesSpecifyCache() failed "
            "due to exception 0x%lx\n", (long)code);
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

NTSTATUS nfs41_UnlockKernelPages(
    __inout PMDL    MemoryDescriptorList)
{
    NTSTATUS status = STATUS_SUCCESS;
    MmUnlockPages(MemoryDescriptorList);
    return status;
}

NTSTATUS nfs41_MapLockedPagesInNfsDaemonAddressSpace(
    __inout PVOID               *outbuf,
    __in    PMDL                MemoryDescriptorList,
    __in    MEMORY_CACHING_TYPE CacheType,
    __in    ULONG               Priority)
{
    NTSTATUS status = STATUS_SUCCESS;

    *outbuf = NULL;

    __try {
        *outbuf =
            MmMapLockedPagesSpecifyCache(MemoryDescriptorList,
                UserMode, CacheType, NULL, FALSE, Priority);
        if (*outbuf == NULL)
            status = STATUS_INSUFFICIENT_RESOURCES;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("nfs41_MapLockedPagesInNfsDaemonAddressSpace: "
            "Call to MmMapLockedPagesSpecifyCache() failed "
            "due to exception 0x%lx\n", (long)code);
        status = STATUS_ACCESS_VIOLATION;
        goto out;
    }

out:
    return status;
}

NTSTATUS nfs41_UnmapLockedKernelPagesInNfsDaemonAddressSpace(
    __in PVOID BaseAddress,
    __in PMDL  MemoryDescriptorList)
{
    NTSTATUS status = STATUS_SUCCESS;

    __try {
        MmUnmapLockedPages(BaseAddress, MemoryDescriptorList);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("nfs41_UnmapLockedKernelPagesInNfsDaemonAddressSpace: "
            "MmUnmapLockedPages() thrown exception=0x%lx\n",
            (long)code);
        status = STATUS_ACCESS_VIOLATION;
    }

    return status;
}

PQUERY_ON_CREATE_ECP_CONTEXT get_queryoncreateecpcontext(
    __in PIRP Irp)
{
    NTSTATUS status;
    PECP_LIST ecpList = NULL;
    PVOID ecpContext = NULL;

    status = FsRtlGetEcpListFromIrp(Irp, &ecpList);

    if ((!NT_SUCCESS(status)) || (ecpList == NULL)) {
        return NULL;
    }

    status = FsRtlFindExtraCreateParameter(
        ecpList,
        &GUID_ECP_QUERY_ON_CREATE,
        &ecpContext,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        return NULL;
    }

    return (PQUERY_ON_CREATE_ECP_CONTEXT)ecpContext;
}

_Success_(return == true) bool
get_primarygroup_id(
    _Out_writes_bytes_(SID_BUF_SIZE) SID *restrict ret_sid)
{
    PACCESS_TOKEN token = NULL;
    PVOID infoBuffer = NULL;
    NTSTATUS status;
    bool retval;

    BOOLEAN copyOnOpen = FALSE;
    BOOLEAN effectiveOnly = FALSE;
    SECURITY_IMPERSONATION_LEVEL impLevel;
    token = PsReferenceImpersonationToken(PsGetCurrentThread(),
        &copyOnOpen, &effectiveOnly, &impLevel);
    if (token == NULL) {
        token = PsReferencePrimaryToken(PsGetCurrentProcess());
        if (token == NULL) {
            DbgP("get_primarygroup_id: Failed to get token\n");
            return false;
        }
    }

    status = SeQueryInformationToken(token,
        TokenPrimaryGroup, &infoBuffer);
    if (!NT_SUCCESS(status) || (infoBuffer == NULL)) {
        DbgPrint("get_primarygroup_id: "
            "SeQueryInformationToken(TokenPrimaryGroup) failed: 0x%lx\n",
            (long)status);
        retval = false;
        goto out_cleanup_sequeryinfotok;
    }

    TOKEN_PRIMARY_GROUP *primaryGroup = (TOKEN_PRIMARY_GROUP *)infoBuffer;
    if ((primaryGroup == NULL) || (primaryGroup->PrimaryGroup == NULL)) {
        DbgP("get_primarygroup_id: "
            "primaryGroup or PrimaryGroup SID is NULL\n");
        retval = false;
        goto out_cleanup_sequeryinfotok;
    }

    ULONG sidLength = RtlLengthSid(primaryGroup->PrimaryGroup);
    if ((sidLength == 0UL) || (sidLength > SID_BUF_SIZE)) {
        DbgP("get_primarygroup_id: "
            "SID length (%lu) invalid or too large for buffer (%u)\n",
            sidLength, (unsigned)SID_BUF_SIZE);
        retval = false;
        goto out_cleanup_sequeryinfotok;
    }

    (void)memcpy(ret_sid, primaryGroup->PrimaryGroup, sidLength);
    retval = true;

out_cleanup_sequeryinfotok:
    if (infoBuffer) {
        ExFreePool(infoBuffer);
    }

    if (token) {
        ObDereferenceObject(token);
    }

    return retval;
}

void qocec_file_stat_information(
    OUT QUERY_ON_CREATE_FILE_STAT_INFORMATION *restrict qocfsi,
    IN const NFS41_FCB *restrict nfs41_fcb)
{
    DbgP("qocec_file_stat_information: "
        "qocfsi=0x%p, nfs41_fcb=0x%p\n",
        qocfsi, nfs41_fcb);

    qocfsi->FileId.QuadPart = nfs41_fcb->fileid;
    qocfsi->CreationTime    = nfs41_fcb->BasicInfo.CreationTime;
    qocfsi->LastAccessTime  = nfs41_fcb->BasicInfo.LastAccessTime;
    qocfsi->LastWriteTime   = nfs41_fcb->BasicInfo.LastWriteTime;
    qocfsi->ChangeTime      = nfs41_fcb->BasicInfo.ChangeTime;
    qocfsi->AllocationSize  = nfs41_fcb->StandardInfo.AllocationSize;
    qocfsi->EndOfFile       = nfs41_fcb->StandardInfo.EndOfFile;
    qocfsi->FileAttributes  = nfs41_fcb->BasicInfo.FileAttributes;
    if (nfs41_fcb->BasicInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
        qocfsi->ReparseTag = IO_REPARSE_TAG_SYMLINK;
    }
    else {
        qocfsi->ReparseTag = 0;
    }
    qocfsi->NumberOfLinks   = nfs41_fcb->StandardInfo.NumberOfLinks;
}

#ifdef NFS41_DRIVER_WSL_SUPPORT
/*
 * Note: Kernel module |qocec_file_stat_lx_information()| and userland
 * daemon |nfs_to_stat_lx_info()| should be kept in sync!
 */
void qocec_file_stat_lx_information(
    OUT QUERY_ON_CREATE_FILE_LX_INFORMATION *restrict qocflxi,
    IN const NFS41_FCB *restrict nfs41_fcb,
    IN const NFS41_V_NET_ROOT_EXTENSION *restrict pVNetRootContext)
{
    ULONG fsattrs;

    DbgP("qocec_file_stat_lx_information: "
        "qocflxi=0x%p, nfs41_fcb=0x%p, pVNetRootContext=0x%p\n",
        qocflxi, nfs41_fcb, pVNetRootContext);

    qocflxi->EffectiveAccess =
        GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ; /* FIXME */
    qocflxi->LxFlags =
        LX_FILE_METADATA_HAS_UID |
        LX_FILE_METADATA_HAS_GID |
        LX_FILE_METADATA_HAS_MODE;

    qocflxi->LxUid = nfs41_fcb->owner_local_uid;
    qocflxi->LxGid = nfs41_fcb->owner_group_local_gid;

    qocflxi->LxMode = 0UL;

/* NFSv4 Mode bits from "daemon/nfs41_const.h" */
#define MODE4_SUID 0x800    /* set user id on execution     */
#define MODE4_SGID 0x400    /* set group id on execution    */
#define MODE4_SVTX 0x200    /* save text even after use     */
#define MODE4_RUSR 0x100    /* read permission: owner       */
#define MODE4_WUSR 0x080    /* write permission: owner      */
#define MODE4_XUSR 0x040    /* execute permission: owner    */
#define MODE4_RGRP 0x020    /* read permission: group       */
#define MODE4_WGRP 0x010    /* write permission: group      */
#define MODE4_XGRP 0x008    /* execute permission: group    */
#define MODE4_ROTH 0x004    /* read permission: other       */
#define MODE4_WOTH 0x002    /* write permission: other      */
#define MODE4_XOTH 0x001    /* execute permission: other    */

/* FIXME: This should go into a new header in include/ */
#define LX_MODE_S_IFMT      0xF000 /* file type mask */
#define LX_MODE_S_IFREG     0x8000 /* regular */
#define LX_MODE_S_IFDIR     0x4000 /* directory */
#define LX_MODE_S_IFCHR     0x2000 /* character special */
#define LX_MODE_S_IFIFO     0x1000 /* pipe */
#define LX_MODE_S_IREAD     0x0100 /* read permission, owner */
#define LX_MODE_S_IWRITE    0x0080 /* write permission, owner */
#define LX_MODE_S_IEXEC     0x0040 /* execute/search permission, owner */

    /*
     * Symlinks are handled via
     * |QUERY_ON_CREATE_FILE_STAT_INFORMATION.ReparseTag|
     */
    if (nfs41_fcb->StandardInfo.Directory)
        qocflxi->LxMode |= LX_MODE_S_IFDIR;
    else
        qocflxi->LxMode |= LX_MODE_S_IFREG;

    if (nfs41_fcb->mode & MODE4_RUSR)
        qocflxi->LxMode |= LX_MODE_S_IREAD;
    if (nfs41_fcb->mode & MODE4_WUSR)
        qocflxi->LxMode |= LX_MODE_S_IWRITE;
    if (nfs41_fcb->mode & MODE4_XUSR)
        qocflxi->LxMode |= LX_MODE_S_IEXEC;

    fsattrs = pVNetRootContext->FsAttrs.FileSystemAttributes;
    if (fsattrs & FILE_CASE_SENSITIVE_SEARCH)
        qocflxi->LxMode |= LX_FILE_CASE_SENSITIVE_DIR;

    /* FIXME: We should support devices */
    qocflxi->LxDeviceIdMajor = 0;
    qocflxi->LxDeviceIdMinor = 0;
}
#endif /* NFS41_DRIVER_WSL_SUPPORT */
