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

#define MINIRDR__NAME MRxNFS41

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


#include <rx.h>

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include <stdio.h>
#include <stdarg.h>
#include <ntstrsafe.h>
#include <winerror.h>

#include "win_reparse.h"

//#define INCLUDE_TIMESTAMPS

ULONG __cdecl DbgP(IN PCCH fmt, ...)
{
    CHAR msg[512];
    va_list args;
    NTSTATUS status;

    va_start(args, fmt);
    ASSERT(fmt != NULL);
    status = RtlStringCbVPrintfA(msg, sizeof(msg), fmt, args);
    if (NT_SUCCESS(status) || (status == STATUS_BUFFER_OVERFLOW)) {
#ifdef INCLUDE_TIMESTAMPS
        LARGE_INTEGER timestamp, local_time;
        TIME_FIELDS time_fields;

        KeQuerySystemTime(&timestamp);
        ExSystemTimeToLocalTime(&timestamp,&local_time);
        RtlTimeToTimeFields(&local_time, &time_fields);

        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[%04x].[%02u:%02u:%02u.%u] %s",
            PsGetCurrentProcessShortDebugId(),
            time_fields.Hour, time_fields.Minute, time_fields.Second,
            time_fields.Milliseconds, msg);
#else
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[%04x] %s", PsGetCurrentProcessShortDebugId(), msg);
#endif
    }
    else {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[%04x] DbgP: RtlStringCbVPrintfA() failed, status=0x%lx",
            PsGetCurrentProcessShortDebugId(), (long)status);
    }
    va_end(args);

    return 0;
}

ULONG __cdecl print_error(IN PCCH fmt, ...)
{
    CHAR msg[512];
    va_list args;
    NTSTATUS status;

    va_start(args, fmt);
    ASSERT(fmt != NULL);
    status = RtlStringCbVPrintfA(msg, sizeof(msg), fmt, args);
    if (NT_SUCCESS(status) || (status == STATUS_BUFFER_OVERFLOW)) {
#ifdef INCLUDE_TIMESTAMPS
        LARGE_INTEGER timestamp, local_time;
        TIME_FIELDS time_fields;

        KeQuerySystemTime(&timestamp);
        ExSystemTimeToLocalTime(&timestamp,&local_time);
        RtlTimeToTimeFields(&local_time, &time_fields);

        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[%04x].[%02u:%02u:%02u.%u] %s",
            PsGetCurrentProcessShortDebugId(),
            time_fields.Hour, time_fields.Minute, time_fields.Second,
            time_fields.Milliseconds, msg);
#else
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[%04x] %s", PsGetCurrentProcessShortDebugId(), msg);
#endif /* INCLUDE_TIMESTAMPS */
    }
    else {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "[%04x] print_error: RtlStringCbVPrintfA() failed, status=0x%lx",
            PsGetCurrentProcessShortDebugId(), (long)status);
    }

    va_end(args);

    return 0;
}

void print_hexbuf(const char *title, unsigned char *buf, int len)
{
    int j, k;
    LARGE_INTEGER timestamp, local_time;
    TIME_FIELDS time_fields;

    KeQuerySystemTime(&timestamp);
    ExSystemTimeToLocalTime(&timestamp,&local_time);
    RtlTimeToTimeFields(&local_time, &time_fields);

    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
        "[%04x].[%02u:%02u:%02u.%u] %s\n",
        PsGetCurrentProcessShortDebugId(),
        time_fields.Hour, time_fields.Minute, time_fields.Second,
        time_fields.Milliseconds, title);
    for(j = 0, k = 0; j < len; j++, k++) {
        DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL,
            "%02x ", buf[j]);
        if (((k+1) % 30 == 0 && k > 0))
            DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "\n");
    }
    DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_ERROR_LEVEL, "\n");
}

void print_ioctl(int op)
{
    switch(op) {
        case IRP_MJ_FILE_SYSTEM_CONTROL:
            DbgP("IRP_MJ_FILE_SYSTEM_CONTROL\n");
            break;
        case IRP_MJ_DEVICE_CONTROL:
            DbgP("IRP_MJ_DEVICE_CONTROL\n");
            break;
        case IRP_MJ_INTERNAL_DEVICE_CONTROL:
            DbgP("IRP_MJ_INTERNAL_DEVICE_CONTROL\n");
            break;
        default:
            DbgP("UNKNOWN MJ IRP %d\n", op);
    };
}

void print_fs_ioctl(int op)
{
    switch(op) {
        case IOCTL_NFS41_INVALCACHE:
            DbgP("IOCTL_NFS41_INVALCACHE\n");
            break;
        case IOCTL_NFS41_READ:
            DbgP("IOCTL_NFS41_UPCALL\n");
            break;
        case IOCTL_NFS41_WRITE:
            DbgP("IOCTL_NFS41_DOWNCALL\n");
            break;
        case IOCTL_NFS41_ADDCONN:
            DbgP("IOCTL_NFS41_ADDCONN\n");
            break;
        case IOCTL_NFS41_DELCONN:
            DbgP("IOCTL_NFS41_DELCONN\n");
            break;
        case IOCTL_NFS41_GETSTATE:
            DbgP("IOCTL_NFS41_GETSTATE\n");
            break;
        case IOCTL_NFS41_START:
            DbgP("IOCTL_NFS41_START\n");
            break;
        case IOCTL_NFS41_STOP:
            DbgP("IOCTL_NFS41_STOP\n");
            break;
        default:
            DbgP("UNKNOWN FS IOCTL %d\n", op);
    };
}

void print_driver_state(int state)
{
    switch (state) {
        case NFS41_START_DRIVER_STARTABLE:
            DbgP("NFS41_START_DRIVER_STARTABLE\n");
            break;
        case NFS41_START_DRIVER_STOPPED:
            DbgP("NFS41_START_DRIVER_STOPPED\n");
            break;
        case NFS41_START_DRIVER_START_IN_PROGRESS:
            DbgP("NFS41_START_DRIVER_START_IN_PROGRESS\n");
            break;
        case NFS41_START_DRIVER_STARTED:
            DbgP("NFS41_START_DRIVER_STARTED\n");
            break;
        default:
            DbgP("UNKNOWN DRIVER STATE %d\n", state);
    };

}

void print_basic_info(int on, PFILE_BASIC_INFORMATION info)
{
    if (!on) return;
    DbgP("BASIC_INFO: "
        "Create=0x%llx Access=0x%llx Write=0x%llx Change=0x%llx Attr=0x%x\n",
        (long long)info->CreationTime.QuadPart,
        (long long)info->LastAccessTime.QuadPart,
        (long long)info->LastWriteTime.QuadPart,
        (long long)info->ChangeTime.QuadPart,
        (int)info->FileAttributes);
}
void print_std_info(int on, PFILE_STANDARD_INFORMATION info)
{
    if (!on) return;
    DbgP("STD_INFO: "
        "Type='%s' #Links=%d Alloc=0x%llx EOF=0x%llx Delete=%d\n",
        info->Directory?"DIR":"FILE", info->NumberOfLinks,
        (long long)info->AllocationSize.QuadPart,
        (long long)info->EndOfFile.QuadPart,
        info->DeletePending);
}

void print_ea_info(PFILE_FULL_EA_INFORMATION info)
{
    DbgP("FULL_EA_INFO: NextOffset=%d Flags=0x%x EaNameLength=%d "
        "ExValueLength=0x%x EaName='%s'\n",
        info->NextEntryOffset, info->Flags,
        info->EaNameLength, info->EaValueLength, info->EaName);
#if DEBUG_EAINFO_DETAILS
    if (info->EaValueLength)
        print_hexbuf("eavalue",
            (unsigned char *)info->EaName + info->EaNameLength + 1,
            info->EaValueLength);
#endif /* DEBUG_EAINFO_DETAILS */
}

void print_get_ea(int on, PFILE_GET_EA_INFORMATION info)
{
    if (!on || !info) return;
    DbgP("GET_EA_INFO: NextOffset=%d EaNameLength=%d EaName='%s'\n",
        info->NextEntryOffset, info->EaNameLength, info->EaName);
}

VOID print_srv_call(IN PMRX_SRV_CALL p)
{
    DbgP("PMRX_SRV_CALL 0x%p\n", p);
#if 0
    DbgP("\tNodeReferenceCount %ld\n", p->NodeReferenceCount);
    //DbgP("Context 0x%p\n", p->Context);
    //DbgP("Context2 0x%p\n", p->Context2);
    //DbgP("pSrvCallName '%wZ'\n", p->pSrvCallName);
    //DbgP("pPrincipalName '%wZ'\n", p->pPrincipalName);
    //DbgP("PDomainName '%wZ'\n", p->pDomainName);
    //DbgP("Flags %08lx\n", p->Flags);
    //DbgP("MaximumNumberOfCloseDelayedFiles %ld\n",
    //    p->MaximumNumberOfCloseDelayedFiles);
    //DbgP("Status %ld\n", p->Status);
    DbgP("*****************\n");
#endif
}

VOID print_net_root(IN PMRX_NET_ROOT p)
{
    DbgP("PMRX_NET_ROOT 0x%p\n", p);
#if 0
    DbgP("\tNodeReferenceCount %ld\n", p->NodeReferenceCount);
    DbgP("\tpSrvCall 0x%p\n", p->pSrvCall);
    //DbgP("Context 0x%p\n", p->Context);
    //DbgP("Context2 0x%p\n", p->Context2);
    //DbgP("Flags 0x%08lx\n", p->Flags);
    DbgP("\tNumberOfFcbs %ld\n", p->NumberOfFcbs);
    DbgP("\tNumberofSrvOpens %ld\n", p->NumberOfSrvOpens);
    //DbgP("MRxNetRootState %ld\n", p->MRxNetRootState);
    //DbgP("Type %ld\n", p->Type);
    //DbgP("DeviceType %ld\n", p->DeviceType);
    //DbgP("pNetRootName '%wZ'\n", p->pNetRootName);
    //DbgP("InnerNamePrefix '%wZ'\n", &p->InnerNamePrefix);
    DbgP("*****************\n");
#endif
}

VOID print_v_net_root(IN PMRX_V_NET_ROOT p)
{
    DbgP("PMRX_V_NET_ROOT 0x%p\n", p);
#if 0
    DbgP("\tNodeReferenceCount %ld\n", p->NodeReferenceCount);
    DbgP("\tpNetRoot 0x%p\n", p->pNetRoot);
    //DbgP("Context 0x%p\n", p->Context);
    //DbgP("Context2 0x%p\n", p->Context2);
    //DbgP("Flags 0x%08lx\n", p->Flags);
    DbgP("\tNumberofOpens %ld\n", p->NumberOfOpens);
    DbgP("\tNumberofFobxs %ld\n", p->NumberOfFobxs);
    //DbgP("LogonId\n");
    //DbgP("pUserDomainName '%wZ'\n", p->pUserDomainName);
    //DbgP("pUserName '%wZ'\n", p->pUserName);
    //DbgP("pPassword '%wZ'\n", p->pPassword);
    //DbgP("SessionId %ld\n", p->SessionId);
    //DbgP("ConstructionStatus 0x%08lx\n", p->ConstructionStatus);
    //DbgP("IsExplicitConnection %d\n", p->IsExplicitConnection);
    DbgP("*****************\n");
#endif
}

void print_file_object(int on, PFILE_OBJECT file)
{
    if (!on) return;
    DbgP("FsContext 0x%p FsContext2 0x%p\n",
        file->FsContext, file->FsContext2);
    DbgP("DeletePending %d ReadAccess %d WriteAccess %d DeleteAccess %d\n",
        file->DeletePending, file->WriteAccess, file->DeleteAccess);
    DbgP("SharedRead %d SharedWrite %d SharedDelete %d Flags 0x%x\n",
        file->SharedRead, file->SharedWrite, file->SharedDelete,
        file->Flags);
}

void print_fo_all(int on, PRX_CONTEXT c)
{
    if (!on) return;
    if (c->pFcb && c->pRelevantSrvOpen)
        DbgP("OpenCount %d FCB 0x%p SRV 0x%p FOBX 0x%p VNET 0x%p NET 0x%p\n",
            c->pFcb->OpenCount, c->pFcb, c->pRelevantSrvOpen, c->pFobx,
            c->pRelevantSrvOpen->pVNetRoot, c->pFcb->pNetRoot);
}

VOID print_fcb(int on, IN PMRX_FCB p)
{
    if (!on) return;
    DbgP("PMRX_FCB 0x%p OpenCount %d\n", p, p->OpenCount);
#if 0
    DbgP("\tNodeReferenceCount %ld\n", p->NodeReferenceCount);
    DbgP("\tpNetRoot 0x%p\n", p->pNetRoot);
    //DbgP("Context 0x%p\n", p->Context);
    //DbgP("Context2 0x%p\n", p->Context2);
    //DbgP("FcbState %ld\n", p->FcbState);
    //DbgP("UncleanCount %ld\n", p->UncleanCount);
    //DbgP("UncachedUncleanCount %ld\n", p->UncachedUncleanCount);
    DbgP("\tOpenCount %ld\n", p->OpenCount);
    //DbgP("OutstandingLockOperationsCount %ld\n",
    //    p->OutstandingLockOperationsCount);
    //DbgP("ActualAllocationLength %ull\n", p->ActualAllocationLength);
    //DbgP("Attributes %ld\n", p->Attributes);
    //DbgP("IsFileWritten %d\n", p->IsFileWritten);
    //DbgP("fShouldBeOrphaned %d\n", p->fShouldBeOrphaned);
    //DbgP("fMiniInited %ld\n", p->fMiniInited);
    //DbgP("CachedNetRootType %c\n", p->CachedNetRootType);
    //DbgP("SrvOpenList\n");
    //DbgP("SrvOpenListVersion %ld\n", p->SrvOpenListVersion);
    DbgP("*****************\n");
#endif
}

VOID print_srv_open(int on, IN PMRX_SRV_OPEN p)
{
    if (!on) return;
    DbgP("PMRX_SRV_OPEN 0x%p\n", p);
#if 0
    DbgP("\tNodeReferenceCount %ld\n", p->NodeReferenceCount);
    DbgP("\tpFcb 0x%p\n", p->pFcb);
    DbgP("\tpVNetRoot 0x%p\n", p->pVNetRoot);
    //DbgP("Context 0x%p\n", p->Context);
    //DbgP("Context2 0x%p\n", p->Context2);
    //DbgP("Flags 0x%08lx\n", p->Flags);
    //DbgP("pAlreadyPrefixedName '%wZ'\n", p->pAlreadyPrefixedName);
    //DbgP("UncleanFobxCount %ld\n", p->UncleanFobxCount);
    DbgP("\tOpenCount %ld\n", p->OpenCount);
    //DbgP("Key 0x%p\n", p->Key);
    //DbgP("DesiredAccess\n");
    //DbgP("ShareAccess %ld\n", p->ShareAccess);
    //DbgP("CreateOptions %ld\n", p->CreateOptions);
    //DbgP("BufferingFlags %ld\n", p->BufferingFlags);
    //DbgP("ulFileSizeVersion %ld\n", p->ulFileSizeVersion);
    //DbgP("SrvOpenQLinks\n");
    DbgP("*****************\n");
#endif
}

VOID print_fobx(int on, IN PMRX_FOBX p)
{
    if (!on) return;
    DbgP("PMRX_FOBX 0x%p\n", p);
#if 0
    DbgP("\tNodeReferenceCount %ld\n", p->NodeReferenceCount);
    DbgP("\tpSrvOpen 0x%p\n", p->pSrvOpen);
    DbgP("\tAssociatedFileObject 0x%p\n", p->AssociatedFileObject);
    //DbgP("Context 0x%p\n", p->Context);
    //DbgP("Context2 0x%p\n", p->Context2);
    //DbgP("Flags 0x%08lx\n", p->Flags);
    DbgP("*****************\n");
#endif
}

VOID print_irp_flags(int on, PIRP irp)
{
    if (!on) return;
    if (irp->Flags)
        DbgP("IRP FLAGS: "
            "0x%x "
            "'%s' '%s' '%s' '%s' "
            "'%s' '%s' '%s' '%s' "
            "'%s' '%s' '%s' '%s' '%s' '%s'\n",
            irp->Flags,
            (irp->Flags & IRP_NOCACHE)?"NOCACHE":"",
            (irp->Flags & IRP_PAGING_IO)?"PAGING_IO":"",
            (irp->Flags & IRP_MOUNT_COMPLETION)?"MOUNT":"",
            (irp->Flags & IRP_SYNCHRONOUS_API)?"SYNC":"",
            (irp->Flags & IRP_ASSOCIATED_IRP)?"ASSOC_IPR":"",
            (irp->Flags & IRP_BUFFERED_IO)?"BUFFERED":"",
            (irp->Flags & IRP_DEALLOCATE_BUFFER)?"DEALLOC_BUF":"",
            (irp->Flags & IRP_INPUT_OPERATION)?"INPUT_OP":"",
            (irp->Flags & IRP_SYNCHRONOUS_PAGING_IO)?"SYNC_PAGIN_IO":"",
            (irp->Flags & IRP_CREATE_OPERATION)?"CREATE_OP":"",
            (irp->Flags & IRP_READ_OPERATION)?"READ_OP":"",
            (irp->Flags & IRP_WRITE_OPERATION)?"WRITE_OP":"",
            (irp->Flags & IRP_CLOSE_OPERATION)?"CLOSE_OP":"",
            (irp->Flags & IRP_DEFER_IO_COMPLETION)?"DEFER_IO":"");
}

void print_irps_flags(int on, PIO_STACK_LOCATION irps)
{
    if (!on) return;
    if (irps->Flags)
        DbgP("IRPSP FLAGS 0x%x '%s' '%s' '%s' '%s'\n", irps->Flags,
            (irps->Flags & SL_CASE_SENSITIVE)?"CASE_SENSITIVE":"",
            (irps->Flags & SL_OPEN_PAGING_FILE)?"PAGING_FILE":"",
            (irps->Flags & SL_FORCE_ACCESS_CHECK)?"ACCESS_CHECK":"",
            (irps->Flags & SL_OPEN_TARGET_DIRECTORY)?"TARGET_DIR":"");
}
void print_nt_create_params(int on, NT_CREATE_PARAMETERS params)
{
    if (!on) return;
    if (params.FileAttributes)
        DbgP("File attributes 0x%x: "
            "'%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' "
            "'%s' '%s' '%s' '%s' '%s'\n",
            params.FileAttributes,
            (params.FileAttributes & FILE_ATTRIBUTE_TEMPORARY)?"TEMPFILE ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_READONLY)?"READONLY ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_HIDDEN)?"HIDDEN ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_SYSTEM)?"SYSTEM ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_ARCHIVE)?"ARCHIVE ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_DIRECTORY)?"DIR ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_DEVICE)?"DEVICE ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_NORMAL)?"NORMAL ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)?"SPARSE_FILE ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)?"REPARSE_POINT ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_COMPRESSED)?"COMPRESSED ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)?"NOT INDEXED ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED)?"ENCRYPTED ":"",
            (params.FileAttributes & FILE_ATTRIBUTE_VIRTUAL)?"VIRTUAL":"");

    if (params.Disposition  == FILE_SUPERSEDE)
        DbgP("Create Dispositions: FILE_SUPERSEDE\n");
    if (params.Disposition == FILE_CREATE)
        DbgP("Create Dispositions: FILE_CREATE\n");
    if (params.Disposition == FILE_OPEN)
        DbgP("Create Dispositions: FILE_OPEN\n");
    if (params.Disposition == FILE_OPEN_IF)
        DbgP("Create Dispositions: FILE_OPEN_IF\n");
    if (params.Disposition == FILE_OVERWRITE)
        DbgP("Create Dispositions: FILE_OVERWRITE\n");
    if (params.Disposition == FILE_OVERWRITE_IF)
        DbgP("Create Dispositions: FILE_OVERWRITE_IF\n");

    DbgP("Create Attributes: "
        "0x%x "
        "'%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' "
        "'%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s'\n",
        params.CreateOptions,
        (params.CreateOptions & FILE_DIRECTORY_FILE)?"DIRFILE":"",
        (params.CreateOptions & FILE_NON_DIRECTORY_FILE)?"FILE":"",
        (params.CreateOptions & FILE_DELETE_ON_CLOSE)?"DELETE_ON_CLOSE":"",
        (params.CreateOptions & FILE_WRITE_THROUGH)?"WRITE_THROUGH":"",
        (params.CreateOptions & FILE_SEQUENTIAL_ONLY)?"SEQUENTIAL":"",
        (params.CreateOptions & FILE_RANDOM_ACCESS)?"RANDOM":"",
        (params.CreateOptions & FILE_NO_INTERMEDIATE_BUFFERING)?"NO_BUFFERING":"",
        (params.CreateOptions & FILE_SYNCHRONOUS_IO_ALERT)?"SYNC_ALERT":"",
        (params.CreateOptions & FILE_SYNCHRONOUS_IO_NONALERT)?"SYNC_NOALERT":"",
        (params.CreateOptions & FILE_CREATE_TREE_CONNECTION)?"CREATE_TREE_CONN":"",
        (params.CreateOptions & FILE_COMPLETE_IF_OPLOCKED)?"OPLOCKED":"",
        (params.CreateOptions & FILE_NO_EA_KNOWLEDGE)?"NO_EA":"",
        (params.CreateOptions & FILE_OPEN_REPARSE_POINT)?"OPEN_REPARSE":"",
        (params.CreateOptions & FILE_OPEN_BY_FILE_ID)?"BY_ID":"",
        (params.CreateOptions & FILE_OPEN_FOR_BACKUP_INTENT)?"4_BACKUP":"",
        (params.CreateOptions & FILE_OPEN_REQUIRING_OPLOCK)?"REQUIRING_OPLOCK":"",
        (params.CreateOptions & FILE_DISALLOW_EXCLUSIVE)?"DISALLOW_EXCLUSIVE":"",
        (params.CreateOptions & FILE_RESERVE_OPFILTER)?"OPFILTER":"");

    DbgP("Share Access: '%s' '%s' '%s'\n",
        (params.ShareAccess & FILE_SHARE_READ)?"READ":"",
        (params.ShareAccess & FILE_SHARE_WRITE)?"WRITE":"",
        (params.ShareAccess & FILE_SHARE_DELETE)?"DELETE":"");

    DbgP("Desired Access: "
        "0x%x '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s' '%s'\n",
        params.DesiredAccess,
        (params.DesiredAccess & FILE_READ_DATA)?"READ":"",
        (params.DesiredAccess & STANDARD_RIGHTS_READ)?"READ_ACL":"",
        (params.DesiredAccess & FILE_READ_ATTRIBUTES)?"GETATTR":"",
        (params.DesiredAccess & FILE_READ_EA)?"READ_EA":"",
        (params.DesiredAccess & FILE_WRITE_DATA)?"WRITE":"",
        (params.DesiredAccess & FILE_WRITE_ATTRIBUTES)?"SETATTR":"",
        (params.DesiredAccess & FILE_WRITE_EA)?"WRITE_EA":"",
        (params.DesiredAccess & FILE_APPEND_DATA)?"APPEND":"",
        (params.DesiredAccess & FILE_EXECUTE)?"EXEC":"",
        (params.DesiredAccess & FILE_LIST_DIRECTORY)?"LSDIR":"",
        (params.DesiredAccess & FILE_TRAVERSE)?"TRAVERSE":"",
        (params.DesiredAccess & FILE_LIST_DIRECTORY)?"LSDIR":"",
        (params.DesiredAccess & DELETE)?"DELETE":"",
        (params.DesiredAccess & READ_CONTROL)?"READ_CONTROL":"",
        (params.DesiredAccess & WRITE_DAC)?"WRITE_DAC":"",
        (params.DesiredAccess & WRITE_OWNER)?"WRITE_OWNER":"",
        (params.DesiredAccess & SYNCHRONIZE)?"SYNCHRONIZE":"");
}

const char *print_file_information_class(int fic)
{
    switch(fic) {
#define FIC_TO_STRLITERAL(e) case e: return #e;
        FIC_TO_STRLITERAL(FileDirectoryInformation)
        FIC_TO_STRLITERAL(FileFullDirectoryInformation)
        FIC_TO_STRLITERAL(FileBothDirectoryInformation)
        FIC_TO_STRLITERAL(FileBasicInformation)
        FIC_TO_STRLITERAL(FileStandardInformation)
        FIC_TO_STRLITERAL(FileInternalInformation)
        FIC_TO_STRLITERAL(FileEaInformation)
        FIC_TO_STRLITERAL(FileAccessInformation)
        FIC_TO_STRLITERAL(FileNameInformation)
        FIC_TO_STRLITERAL(FileRenameInformation)
        FIC_TO_STRLITERAL(FileLinkInformation)
        FIC_TO_STRLITERAL(FileNamesInformation)
        FIC_TO_STRLITERAL(FileDispositionInformation)
        FIC_TO_STRLITERAL(FilePositionInformation)
        FIC_TO_STRLITERAL(FileFullEaInformation)
        FIC_TO_STRLITERAL(FileModeInformation)
        FIC_TO_STRLITERAL(FileAlignmentInformation)
        FIC_TO_STRLITERAL(FileAllInformation)
        FIC_TO_STRLITERAL(FileAllocationInformation)
        FIC_TO_STRLITERAL(FileEndOfFileInformation)
        FIC_TO_STRLITERAL(FileAlternateNameInformation)
        FIC_TO_STRLITERAL(FileStreamInformation)
        FIC_TO_STRLITERAL(FilePipeInformation)
        FIC_TO_STRLITERAL(FilePipeLocalInformation)
        FIC_TO_STRLITERAL(FilePipeRemoteInformation)
        FIC_TO_STRLITERAL(FileMailslotQueryInformation)
        FIC_TO_STRLITERAL(FileMailslotSetInformation)
        FIC_TO_STRLITERAL(FileCompressionInformation)
        FIC_TO_STRLITERAL(FileObjectIdInformation)
        FIC_TO_STRLITERAL(FileCompletionInformation)
        FIC_TO_STRLITERAL(FileMoveClusterInformation)
        FIC_TO_STRLITERAL(FileQuotaInformation)
        FIC_TO_STRLITERAL(FileReparsePointInformation)
        FIC_TO_STRLITERAL(FileNetworkOpenInformation)
        FIC_TO_STRLITERAL(FileAttributeTagInformation)
        FIC_TO_STRLITERAL(FileTrackingInformation)
        FIC_TO_STRLITERAL(FileIdBothDirectoryInformation)
        FIC_TO_STRLITERAL(FileIdFullDirectoryInformation)
        FIC_TO_STRLITERAL(FileValidDataLengthInformation)
        FIC_TO_STRLITERAL(FileShortNameInformation)
        FIC_TO_STRLITERAL(FileIoCompletionNotificationInformation)
        FIC_TO_STRLITERAL(FileIoStatusBlockRangeInformation)
        FIC_TO_STRLITERAL(FileIoPriorityHintInformation)
        FIC_TO_STRLITERAL(FileSfioReserveInformation)
        FIC_TO_STRLITERAL(FileSfioVolumeInformation)
        FIC_TO_STRLITERAL(FileHardLinkInformation)
        FIC_TO_STRLITERAL(FileProcessIdsUsingFileInformation)
        FIC_TO_STRLITERAL(FileNormalizedNameInformation)
        FIC_TO_STRLITERAL(FileNetworkPhysicalNameInformation)
        FIC_TO_STRLITERAL(FileIdGlobalTxDirectoryInformation)
        FIC_TO_STRLITERAL(FileIsRemoteDeviceInformation)
        FIC_TO_STRLITERAL(FileUnusedInformation)
        FIC_TO_STRLITERAL(FileNumaNodeInformation)
        FIC_TO_STRLITERAL(FileStandardLinkInformation)
        FIC_TO_STRLITERAL(FileRemoteProtocolInformation)
        FIC_TO_STRLITERAL(FileRenameInformationBypassAccessCheck)
        FIC_TO_STRLITERAL(FileLinkInformationBypassAccessCheck)
        FIC_TO_STRLITERAL(FileVolumeNameInformation)
        FIC_TO_STRLITERAL(FileIdInformation)
        FIC_TO_STRLITERAL(FileIdExtdDirectoryInformation)
        FIC_TO_STRLITERAL(FileReplaceCompletionInformation)
        FIC_TO_STRLITERAL(FileHardLinkFullIdInformation)
        FIC_TO_STRLITERAL(FileIdExtdBothDirectoryInformation)
        FIC_TO_STRLITERAL(FileDispositionInformationEx)
        FIC_TO_STRLITERAL(FileRenameInformationEx)
        FIC_TO_STRLITERAL(FileRenameInformationExBypassAccessCheck)
        FIC_TO_STRLITERAL(FileDesiredStorageClassInformation)
        FIC_TO_STRLITERAL(FileStatInformation)
        FIC_TO_STRLITERAL(FileMemoryPartitionInformation)
        FIC_TO_STRLITERAL(FileStatLxInformation)
        FIC_TO_STRLITERAL(FileCaseSensitiveInformation)
        FIC_TO_STRLITERAL(FileLinkInformationEx)
        FIC_TO_STRLITERAL(FileLinkInformationExBypassAccessCheck)
        FIC_TO_STRLITERAL(FileStorageReserveIdInformation)
        FIC_TO_STRLITERAL(FileCaseSensitiveInformationForceAccessCheck)
    }
    return "<unknown FILE_INFORMATION_CLASS>";
}

const char *print_fs_information_class(int InfoClass)
{
#define FSIC_TO_STRLITERAL(e) case e: return #e;
    switch (InfoClass) {
        FSIC_TO_STRLITERAL(FileFsVolumeInformation)
        FSIC_TO_STRLITERAL(FileFsLabelInformation)
        FSIC_TO_STRLITERAL(FileFsSizeInformation)
        FSIC_TO_STRLITERAL(FileFsDeviceInformation)
        FSIC_TO_STRLITERAL(FileFsAttributeInformation)
        FSIC_TO_STRLITERAL(FileFsControlInformation)
        FSIC_TO_STRLITERAL(FileFsFullSizeInformation)
        FSIC_TO_STRLITERAL(FileFsObjectIdInformation)
        FSIC_TO_STRLITERAL(FileFsDriverPathInformation)
        FSIC_TO_STRLITERAL(FileFsVolumeFlagsInformation)
        FSIC_TO_STRLITERAL(FileFsSectorSizeInformation)
        FSIC_TO_STRLITERAL(FileFsDataCopyInformation)
        FSIC_TO_STRLITERAL(FileFsMetadataSizeInformation)
        FSIC_TO_STRLITERAL(FileFsFullSizeInformationEx)
    }
    return "<unknown FS_INFORMATION_CLASS>";
}

void print_caching_level(int on, ULONG flag, PUNICODE_STRING name)
{
    if (!on) return;
    switch(flag) {
        case 0:
            DbgP("enable_caching: DISABLE_CACHING '%wZ'\n", name);
            break;
        case 1:
            DbgP("enable_caching: ENABLE_READ_CACHING '%wZ'\n", name);
            break;
        case 2:
            DbgP("enable_caching: ENABLE_WRITE_CACHING '%wZ'\n", name);
            break;
        case 3:
            DbgP("enable_caching: ENABLE_READWRITE_CACHING '%wZ'\n", name);
            break;
    }
}

const char *opcode2string(int opcode)
{
    switch(opcode) {
    case NFS41_SYSOP_SHUTDOWN: return "NFS41_SYSOP_SHUTDOWN";
    case NFS41_SYSOP_MOUNT: return "NFS41_SYSOP_MOUNT";
    case NFS41_SYSOP_UNMOUNT: return "NFS41_SYSOP_UNMOUNT";
    case NFS41_SYSOP_OPEN: return "NFS41_SYSOP_OPEN";
    case NFS41_SYSOP_CLOSE: return "NFS41_SYSOP_CLOSE";
    case NFS41_SYSOP_READ: return "NFS41_SYSOP_READ";
    case NFS41_SYSOP_WRITE: return "NFS41_SYSOP_WRITE";
    case NFS41_SYSOP_LOCK: return "NFS41_SYSOP_LOCK";
    case NFS41_SYSOP_UNLOCK: return "NFS41_SYSOP_UNLOCK";
    case NFS41_SYSOP_DIR_QUERY: return "NFS41_SYSOP_DIR_QUERY";
    case NFS41_SYSOP_FILE_QUERY: return "NFS41_SYSOP_FILE_QUERY";
    case NFS41_SYSOP_FILE_SET: return "NFS41_SYSOP_FILE_SET";
    case NFS41_SYSOP_EA_SET: return "NFS41_SYSOP_EA_SET";
    case NFS41_SYSOP_EA_GET: return "NFS41_SYSOP_EA_GET";
    case NFS41_SYSOP_SYMLINK_GET: return "NFS41_SYSOP_SYMLINK_GET";
    case NFS41_SYSOP_SYMLINK_SET: return "NFS41_SYSOP_SYMLINK_SET";
    case NFS41_SYSOP_VOLUME_QUERY: return "NFS41_SYSOP_VOLUME_QUERY";
    case NFS41_SYSOP_ACL_QUERY: return "NFS41_SYSOP_ACL_QUERY";
    case NFS41_SYSOP_ACL_SET: return "NFS41_SYSOP_ACL_SET";
    case NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES: return "NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES";
    case NFS41_SYSOP_FSCTL_SET_ZERO_DATA: return "NFS41_SYSOP_FSCTL_SET_ZERO_DATA";
    case NFS41_SYSOP_FSCTL_DUPLICATE_DATA: return "NFS41_SYSOP_FSCTL_DUPLICATE_DATA";
    case NFS41_SYSOP_FSCTL_OFFLOAD_DATACOPY:
        return "NFS41_SYSOP_FSCTL_OFFLOAD_DATACOPY";
    default: return "UNKNOWN";
    }
}

void print_acl_args(
    SECURITY_INFORMATION info)
{
    DbgP("Security query: '%s' '%s' '%s'\n",
        (info & OWNER_SECURITY_INFORMATION)?"OWNER":"",
        (info & GROUP_SECURITY_INFORMATION)?"GROUP":"",
        (info & DACL_SECURITY_INFORMATION)?"DACL":"",
        (info & SACL_SECURITY_INFORMATION)?"SACL":"");
}

void print_open_error(int on, int status)
{
    if (!on) return;
    switch (status) {
    case STATUS_ACCESS_DENIED:
        DbgP("[ERROR] nfs41_Create: STATUS_ACCESS_DENIED\n");
        break;
    case STATUS_NETWORK_ACCESS_DENIED:
        DbgP("[ERROR] nfs41_Create: STATUS_NETWORK_ACCESS_DENIED\n");
        break;
    case STATUS_OBJECT_NAME_INVALID:
        DbgP("[ERROR] nfs41_Create: STATUS_OBJECT_NAME_INVALID\n");
        break;
    case STATUS_OBJECT_NAME_COLLISION:
        DbgP("[ERROR] nfs41_Create: STATUS_OBJECT_NAME_COLLISION\n");
        break;
    case STATUS_FILE_INVALID:
        DbgP("[ERROR] nfs41_Create: STATUS_FILE_INVALID\n");
        break;
    case STATUS_OBJECT_NAME_NOT_FOUND:
        DbgP("[ERROR] nfs41_Create: STATUS_OBJECT_NAME_NOT_FOUND\n");
        break;
    case STATUS_NAME_TOO_LONG:
        DbgP("[ERROR] nfs41_Create: STATUS_NAME_TOO_LONG\n");
        break;
    case STATUS_OBJECT_PATH_NOT_FOUND:
        DbgP("[ERROR] nfs41_Create: STATUS_OBJECT_PATH_NOT_FOUND\n");
        break;
    case STATUS_BAD_NETWORK_PATH:
        DbgP("[ERROR] nfs41_Create: STATUS_BAD_NETWORK_PATH\n");
        break;
    case STATUS_SHARING_VIOLATION:
        DbgP("[ERROR] nfs41_Create: STATUS_SHARING_VIOLATION\n");
        break;
    case ERROR_REPARSE:
        DbgP("[ERROR] nfs41_Create: STATUS_REPARSE\n");
        break;
    case ERROR_TOO_MANY_LINKS:
        DbgP("[ERROR] nfs41_Create: STATUS_TOO_MANY_LINKS\n");
        break;
    case ERROR_DIRECTORY_NOT_SUPPORTED:
        DbgP("[ERROR] nfs41_Create: STATUS_FILE_IS_A_DIRECTORY\n");
        break;
    case ERROR_DIRECTORY:
        DbgP("[ERROR] nfs41_Create: STATUS_NOT_A_DIRECTORY\n");
        break;
    case ERROR_BAD_FILE_TYPE:
        DbgP("[ERROR] nfs41_Create: STATUS_BAD_FILE_TYPE\n");
        break;
    default:
        DbgP("[ERROR] nfs41_Create: STATUS_INSUFFICIENT_RESOURCES\n");
        break;
    }
}

void print_wait_status(int on, const char *prefix, NTSTATUS status,
    const char *opcode, PVOID entry, LONGLONG xid)
{
    if (!on) return;
    switch (status) {
    case STATUS_SUCCESS:
        if (opcode)
            DbgP("'%s' Got a wakeup call, finishing '%s' entry=0x%p xid=%lld\n",
                prefix, opcode, entry, xid);
        else
            DbgP("'%s' Got a wakeup call\n", prefix);
        break;
    case STATUS_USER_APC:
        DbgP("'%s' KeWaitForSingleObject returned STATUS_USER_APC\n", prefix);
        break;
    case STATUS_ALERTED:
        DbgP("'%s' KeWaitForSingleObject returned STATUS_ALERTED\n", prefix);
        break;
    default:
        DbgP("'%s' KeWaitForSingleObject returned %d\n", prefix, status);
    }
}
/* This is taken from toaster/func.  Rumor says this should be replaced
 * with a WMI interface???
 */
ULONG
dprintk(
    IN PCHAR func,
    IN ULONG flags,
    IN PCHAR format,
    ...)
{
    #define     TEMP_BUFFER_SIZE        1024
    va_list    list;
    CHAR      debugMessageBuffer[TEMP_BUFFER_SIZE];
    NTSTATUS status, rv = STATUS_SUCCESS;

    va_start(list, format);

    if (format)
    {
        //
        // Use the safe string function, RtlStringCbVPrintfA, instead of _vsnprintf.
        // RtlStringCbVPrintfA NULL terminates the output buffer even if the message
        // is longer than the buffer. This prevents malicious code from compromising
        // the security of the system.
        //
        status = RtlStringCbVPrintfA(debugMessageBuffer, sizeof(debugMessageBuffer),
                                    format, list);

        if (!(NT_SUCCESS(status) || (status == STATUS_BUFFER_OVERFLOW)))
            rv = DbgPrintEx(PNFS_FLTR_ID, DPFLTR_MASK | flags,
                            "RtlStringCbVPrintfA failed 0x%lx \n",
                            (long)status);
        else
            rv = DbgPrintEx(PNFS_FLTR_ID, DPFLTR_MASK | flags, "'%s'    '%s': '%s'\n",
                    PNFS_TRACE_TAG, func, debugMessageBuffer);
    }
    va_end(list);

    return rv;
}

const char *fsctl2string(ULONG fscontrolcode)
{
#define CASE_SYM2STR_RET(x) case (x): return #x ; break;
    switch(fscontrolcode) {
#ifdef FSCTL_ADD_OVERLAY
        CASE_SYM2STR_RET(FSCTL_ADD_OVERLAY)
#endif /* FSCTL_ADD_OVERLAY */
#ifdef FSCTL_ADVANCE_FILE_ID
        CASE_SYM2STR_RET(FSCTL_ADVANCE_FILE_ID)
#endif /* FSCTL_ADVANCE_FILE_ID */
#ifdef FSCTL_ALLOW_EXTENDED_DASD_IO
        CASE_SYM2STR_RET(FSCTL_ALLOW_EXTENDED_DASD_IO)
#endif /* FSCTL_ALLOW_EXTENDED_DASD_IO */
#ifdef FSCTL_CLEAN_VOLUME_METADATA
        CASE_SYM2STR_RET(FSCTL_CLEAN_VOLUME_METADATA)
#endif /* FSCTL_CLEAN_VOLUME_METADATA */
#ifdef FSCTL_CORRUPTION_HANDLING
        CASE_SYM2STR_RET(FSCTL_CORRUPTION_HANDLING)
#endif /* FSCTL_CORRUPTION_HANDLING */
#ifdef FSCTL_CREATE_OR_GET_OBJECT_ID
        CASE_SYM2STR_RET(FSCTL_CREATE_OR_GET_OBJECT_ID)
#endif /* FSCTL_CREATE_OR_GET_OBJECT_ID */
#ifdef FSCTL_CREATE_USN_JOURNAL
        CASE_SYM2STR_RET(FSCTL_CREATE_USN_JOURNAL)
#endif /* FSCTL_CREATE_USN_JOURNAL */
#ifdef FSCTL_CSC_INTERNAL
        CASE_SYM2STR_RET(FSCTL_CSC_INTERNAL)
#endif /* FSCTL_CSC_INTERNAL */
#ifdef FSCTL_CSV_CONTROL
        CASE_SYM2STR_RET(FSCTL_CSV_CONTROL)
#endif /* FSCTL_CSV_CONTROL */
#ifdef FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT
        CASE_SYM2STR_RET(FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT)
#endif /* FSCTL_CSV_GET_VOLUME_NAME_FOR_VOLUME_MOUNT_POINT */
#ifdef FSCTL_CSV_GET_VOLUME_PATH_NAME
        CASE_SYM2STR_RET(FSCTL_CSV_GET_VOLUME_PATH_NAME)
#endif /* FSCTL_CSV_GET_VOLUME_PATH_NAME */
#ifdef FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME
        CASE_SYM2STR_RET(FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME)
#endif /* FSCTL_CSV_GET_VOLUME_PATH_NAMES_FOR_VOLUME_NAME */
#ifdef FSCTL_CSV_H_BREAKING_SYNC_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_CSV_H_BREAKING_SYNC_TUNNEL_REQUEST)
#endif /* FSCTL_CSV_H_BREAKING_SYNC_TUNNEL_REQUEST */
#ifdef FSCTL_CSV_INTERNAL
        CASE_SYM2STR_RET(FSCTL_CSV_INTERNAL)
#endif /* FSCTL_CSV_INTERNAL */
#ifdef FSCTL_CSV_MGMT_LOCK
        CASE_SYM2STR_RET(FSCTL_CSV_MGMT_LOCK)
#endif /* FSCTL_CSV_MGMT_LOCK */
#ifdef FSCTL_CSV_QUERY_DOWN_LEVEL_FILE_SYSTEM_CHARACTERISTICS
        CASE_SYM2STR_RET(FSCTL_CSV_QUERY_DOWN_LEVEL_FILE_SYSTEM_CHARACTERISTICS)
#endif /* FSCTL_CSV_QUERY_DOWN_LEVEL_FILE_SYSTEM_CHARACTERISTICS */
#ifdef FSCTL_CSV_QUERY_VETO_FILE_DIRECT_IO
        CASE_SYM2STR_RET(FSCTL_CSV_QUERY_VETO_FILE_DIRECT_IO)
#endif /* FSCTL_CSV_QUERY_VETO_FILE_DIRECT_IO */
#ifdef FSCTL_CSV_SYNC_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_CSV_SYNC_TUNNEL_REQUEST)
#endif /* FSCTL_CSV_SYNC_TUNNEL_REQUEST */
#ifdef FSCTL_CSV_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_CSV_TUNNEL_REQUEST)
#endif /* FSCTL_CSV_TUNNEL_REQUEST */
#ifdef FSCTL_DELETE_CORRUPTED_REFS_CONTAINER
        CASE_SYM2STR_RET(FSCTL_DELETE_CORRUPTED_REFS_CONTAINER)
#endif /* FSCTL_DELETE_CORRUPTED_REFS_CONTAINER */
#ifdef FSCTL_DELETE_EXTERNAL_BACKING
        CASE_SYM2STR_RET(FSCTL_DELETE_EXTERNAL_BACKING)
#endif /* FSCTL_DELETE_EXTERNAL_BACKING */
#ifdef FSCTL_DELETE_OBJECT_ID
        CASE_SYM2STR_RET(FSCTL_DELETE_OBJECT_ID)
#endif /* FSCTL_DELETE_OBJECT_ID */
#ifdef FSCTL_DELETE_REPARSE_POINT
        CASE_SYM2STR_RET(FSCTL_DELETE_REPARSE_POINT)
#endif /* FSCTL_DELETE_REPARSE_POINT */
#ifdef FSCTL_DELETE_USN_JOURNAL
        CASE_SYM2STR_RET(FSCTL_DELETE_USN_JOURNAL)
#endif /* FSCTL_DELETE_USN_JOURNAL */
#ifdef FSCTL_DFSR_SET_GHOST_HANDLE_STATE
        CASE_SYM2STR_RET(FSCTL_DFSR_SET_GHOST_HANDLE_STATE)
#endif /* FSCTL_DFSR_SET_GHOST_HANDLE_STATE */
#ifdef FSCTL_DISABLE_LOCAL_BUFFERING
        CASE_SYM2STR_RET(FSCTL_DISABLE_LOCAL_BUFFERING)
#endif /* FSCTL_DISABLE_LOCAL_BUFFERING */
#ifdef FSCTL_DISMOUNT_VOLUME
        CASE_SYM2STR_RET(FSCTL_DISMOUNT_VOLUME)
#endif /* FSCTL_DISMOUNT_VOLUME */
#ifdef FSCTL_DUPLICATE_EXTENTS_TO_FILE
        CASE_SYM2STR_RET(FSCTL_DUPLICATE_EXTENTS_TO_FILE)
#endif /* FSCTL_DUPLICATE_EXTENTS_TO_FILE */
#ifdef FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX
        CASE_SYM2STR_RET(FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX)
#endif /* FSCTL_DUPLICATE_EXTENTS_TO_FILE_EX */
#ifdef FSCTL_ENABLE_PER_IO_FLAGS
        CASE_SYM2STR_RET(FSCTL_ENABLE_PER_IO_FLAGS)
#endif /* FSCTL_ENABLE_PER_IO_FLAGS */
#ifdef FSCTL_ENABLE_UPGRADE
        CASE_SYM2STR_RET(FSCTL_ENABLE_UPGRADE)
#endif /* FSCTL_ENABLE_UPGRADE */
#ifdef FSCTL_ENCRYPTION_FSCTL_IO
        CASE_SYM2STR_RET(FSCTL_ENCRYPTION_FSCTL_IO)
#endif /* FSCTL_ENCRYPTION_FSCTL_IO */
#ifdef FSCTL_ENCRYPTION_KEY_CONTROL
        CASE_SYM2STR_RET(FSCTL_ENCRYPTION_KEY_CONTROL)
#endif /* FSCTL_ENCRYPTION_KEY_CONTROL */
#ifdef FSCTL_ENUM_EXTERNAL_BACKING
        CASE_SYM2STR_RET(FSCTL_ENUM_EXTERNAL_BACKING)
#endif /* FSCTL_ENUM_EXTERNAL_BACKING */
#ifdef FSCTL_ENUM_OVERLAY
        CASE_SYM2STR_RET(FSCTL_ENUM_OVERLAY)
#endif /* FSCTL_ENUM_OVERLAY */
#ifdef FSCTL_ENUM_USN_DATA
        CASE_SYM2STR_RET(FSCTL_ENUM_USN_DATA)
#endif /* FSCTL_ENUM_USN_DATA */
#ifdef FSCTL_EXTEND_VOLUME
        CASE_SYM2STR_RET(FSCTL_EXTEND_VOLUME)
#endif /* FSCTL_EXTEND_VOLUME */
#ifdef FSCTL_FILESYSTEM_GET_STATISTICS
        CASE_SYM2STR_RET(FSCTL_FILESYSTEM_GET_STATISTICS)
#endif /* FSCTL_FILESYSTEM_GET_STATISTICS */
#ifdef FSCTL_FILESYSTEM_GET_STATISTICS_EX
        CASE_SYM2STR_RET(FSCTL_FILESYSTEM_GET_STATISTICS_EX)
#endif /* FSCTL_FILESYSTEM_GET_STATISTICS_EX */
#ifdef FSCTL_FILE_LEVEL_TRIM
        CASE_SYM2STR_RET(FSCTL_FILE_LEVEL_TRIM)
#endif /* FSCTL_FILE_LEVEL_TRIM */
#ifdef FSCTL_FILE_PREFETCH
        CASE_SYM2STR_RET(FSCTL_FILE_PREFETCH)
#endif /* FSCTL_FILE_PREFETCH */
#ifdef FSCTL_FILE_TYPE_NOTIFICATION
        CASE_SYM2STR_RET(FSCTL_FILE_TYPE_NOTIFICATION)
#endif /* FSCTL_FILE_TYPE_NOTIFICATION */
#ifdef FSCTL_FIND_FILES_BY_SID
        CASE_SYM2STR_RET(FSCTL_FIND_FILES_BY_SID)
#endif /* FSCTL_FIND_FILES_BY_SID */
#ifdef FSCTL_GET_BOOT_AREA_INFO
        CASE_SYM2STR_RET(FSCTL_GET_BOOT_AREA_INFO)
#endif /* FSCTL_GET_BOOT_AREA_INFO */
#ifdef FSCTL_GET_COMPRESSION
        CASE_SYM2STR_RET(FSCTL_GET_COMPRESSION)
#endif /* FSCTL_GET_COMPRESSION */
#ifdef FSCTL_GET_EXTERNAL_BACKING
        CASE_SYM2STR_RET(FSCTL_GET_EXTERNAL_BACKING)
#endif /* FSCTL_GET_EXTERNAL_BACKING */
#ifdef FSCTL_GET_INTEGRITY_INFORMATION
        CASE_SYM2STR_RET(FSCTL_GET_INTEGRITY_INFORMATION)
#endif /* FSCTL_GET_INTEGRITY_INFORMATION */
#ifdef FSCTL_GET_NTFS_FILE_RECORD
        CASE_SYM2STR_RET(FSCTL_GET_NTFS_FILE_RECORD)
#endif /* FSCTL_GET_NTFS_FILE_RECORD */
#ifdef FSCTL_GET_NTFS_VOLUME_DATA
        CASE_SYM2STR_RET(FSCTL_GET_NTFS_VOLUME_DATA)
#endif /* FSCTL_GET_NTFS_VOLUME_DATA */
#ifdef FSCTL_GET_OBJECT_ID
        CASE_SYM2STR_RET(FSCTL_GET_OBJECT_ID)
#endif /* FSCTL_GET_OBJECT_ID */
#ifdef FSCTL_GET_REFS_VOLUME_DATA
        CASE_SYM2STR_RET(FSCTL_GET_REFS_VOLUME_DATA)
#endif /* FSCTL_GET_REFS_VOLUME_DATA */
#ifdef FSCTL_GET_REPAIR
        CASE_SYM2STR_RET(FSCTL_GET_REPAIR)
#endif /* FSCTL_GET_REPAIR */
#ifdef FSCTL_GET_REPARSE_POINT
        CASE_SYM2STR_RET(FSCTL_GET_REPARSE_POINT)
#endif /* FSCTL_GET_REPARSE_POINT */
#ifdef FSCTL_GET_RETRIEVAL_POINTERS
        CASE_SYM2STR_RET(FSCTL_GET_RETRIEVAL_POINTERS)
#endif /* FSCTL_GET_RETRIEVAL_POINTERS */
#ifdef FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT
        CASE_SYM2STR_RET(FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT)
#endif /* FSCTL_GET_RETRIEVAL_POINTERS_AND_REFCOUNT */
#ifdef FSCTL_GET_RETRIEVAL_POINTER_BASE
        CASE_SYM2STR_RET(FSCTL_GET_RETRIEVAL_POINTER_BASE)
#endif /* FSCTL_GET_RETRIEVAL_POINTER_BASE */
#ifdef FSCTL_GET_RETRIEVAL_POINTER_COUNT
        CASE_SYM2STR_RET(FSCTL_GET_RETRIEVAL_POINTER_COUNT)
#endif /* FSCTL_GET_RETRIEVAL_POINTER_COUNT */
#ifdef FSCTL_GET_VOLUME_BITMAP
        CASE_SYM2STR_RET(FSCTL_GET_VOLUME_BITMAP)
#endif /* FSCTL_GET_VOLUME_BITMAP */
#ifdef FSCTL_GET_WOF_VERSION
        CASE_SYM2STR_RET(FSCTL_GET_WOF_VERSION)
#endif /* FSCTL_GET_WOF_VERSION */
#ifdef FSCTL_GHOST_FILE_EXTENTS
        CASE_SYM2STR_RET(FSCTL_GHOST_FILE_EXTENTS)
#endif /* FSCTL_GHOST_FILE_EXTENTS */
#ifdef FSCTL_HCS_ASYNC_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_HCS_ASYNC_TUNNEL_REQUEST)
#endif /* FSCTL_HCS_ASYNC_TUNNEL_REQUEST */
#ifdef FSCTL_HCS_SYNC_NO_WRITE_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_HCS_SYNC_NO_WRITE_TUNNEL_REQUEST)
#endif /* FSCTL_HCS_SYNC_NO_WRITE_TUNNEL_REQUEST */
#ifdef FSCTL_HCS_SYNC_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_HCS_SYNC_TUNNEL_REQUEST)
#endif /* FSCTL_HCS_SYNC_TUNNEL_REQUEST */
#ifdef FSCTL_INITIATE_FILE_METADATA_OPTIMIZATION
        CASE_SYM2STR_RET(FSCTL_INITIATE_FILE_METADATA_OPTIMIZATION)
#endif /* FSCTL_INITIATE_FILE_METADATA_OPTIMIZATION */
#ifdef FSCTL_INITIATE_REPAIR
        CASE_SYM2STR_RET(FSCTL_INITIATE_REPAIR)
#endif /* FSCTL_INITIATE_REPAIR */
#ifdef FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF
        CASE_SYM2STR_RET(FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF)
#endif /* FSCTL_INTEGRITY_FLAG_CHECKSUM_ENFORCEMENT_OFF */
#ifdef FSCTL_INVALIDATE_VOLUMES
        CASE_SYM2STR_RET(FSCTL_INVALIDATE_VOLUMES)
#endif /* FSCTL_INVALIDATE_VOLUMES */
#ifdef FSCTL_IS_CSV_FILE
        CASE_SYM2STR_RET(FSCTL_IS_CSV_FILE)
#endif /* FSCTL_IS_CSV_FILE */
#ifdef FSCTL_IS_FILE_ON_CSV_VOLUME
        CASE_SYM2STR_RET(FSCTL_IS_FILE_ON_CSV_VOLUME)
#endif /* FSCTL_IS_FILE_ON_CSV_VOLUME */
#ifdef FSCTL_IS_PATHNAME_VALID
        CASE_SYM2STR_RET(FSCTL_IS_PATHNAME_VALID)
#endif /* FSCTL_IS_PATHNAME_VALID */
#ifdef FSCTL_IS_VOLUME_DIRTY
        CASE_SYM2STR_RET(FSCTL_IS_VOLUME_DIRTY)
#endif /* FSCTL_IS_VOLUME_DIRTY */
#ifdef FSCTL_IS_VOLUME_MOUNTED
        CASE_SYM2STR_RET(FSCTL_IS_VOLUME_MOUNTED)
#endif /* FSCTL_IS_VOLUME_MOUNTED */
#ifdef FSCTL_IS_VOLUME_OWNED_BYCSVFS
        CASE_SYM2STR_RET(FSCTL_IS_VOLUME_OWNED_BYCSVFS)
#endif /* FSCTL_IS_VOLUME_OWNED_BYCSVFS */
#ifdef FSCTL_LOCK_VOLUME
        CASE_SYM2STR_RET(FSCTL_LOCK_VOLUME)
#endif /* FSCTL_LOCK_VOLUME */
#ifdef FSCTL_LOOKUP_STREAM_FROM_CLUSTER
        CASE_SYM2STR_RET(FSCTL_LOOKUP_STREAM_FROM_CLUSTER)
#endif /* FSCTL_LOOKUP_STREAM_FROM_CLUSTER */
#ifdef FSCTL_MAKE_MEDIA_COMPATIBLE
        CASE_SYM2STR_RET(FSCTL_MAKE_MEDIA_COMPATIBLE)
#endif /* FSCTL_MAKE_MEDIA_COMPATIBLE */
#ifdef FSCTL_MARK_AS_SYSTEM_HIVE
        CASE_SYM2STR_RET(FSCTL_MARK_AS_SYSTEM_HIVE)
#endif /* FSCTL_MARK_AS_SYSTEM_HIVE */
#ifdef FSCTL_MARK_HANDLE
        CASE_SYM2STR_RET(FSCTL_MARK_HANDLE)
#endif /* FSCTL_MARK_HANDLE */
#ifdef FSCTL_MARK_VOLUME_DIRTY
        CASE_SYM2STR_RET(FSCTL_MARK_VOLUME_DIRTY)
#endif /* FSCTL_MARK_VOLUME_DIRTY */
#ifdef FSCTL_MOVE_FILE
        CASE_SYM2STR_RET(FSCTL_MOVE_FILE)
#endif /* FSCTL_MOVE_FILE */
#ifdef FSCTL_NOTIFY_DATA_CHANGE
        CASE_SYM2STR_RET(FSCTL_NOTIFY_DATA_CHANGE)
#endif /* FSCTL_NOTIFY_DATA_CHANGE */
#ifdef FSCTL_NOTIFY_STORAGE_SPACE_ALLOCATION
        CASE_SYM2STR_RET(FSCTL_NOTIFY_STORAGE_SPACE_ALLOCATION)
#endif /* FSCTL_NOTIFY_STORAGE_SPACE_ALLOCATION */
#ifdef FSCTL_OFFLOAD_READ
        CASE_SYM2STR_RET(FSCTL_OFFLOAD_READ)
#endif /* FSCTL_OFFLOAD_READ */
#ifdef FSCTL_OFFLOAD_WRITE
        CASE_SYM2STR_RET(FSCTL_OFFLOAD_WRITE)
#endif /* FSCTL_OFFLOAD_WRITE */
#ifdef FSCTL_OPBATCH_ACK_CLOSE_PENDING
        CASE_SYM2STR_RET(FSCTL_OPBATCH_ACK_CLOSE_PENDING)
#endif /* FSCTL_OPBATCH_ACK_CLOSE_PENDING */
#ifdef FSCTL_OPLOCK_BREAK_ACKNOWLEDGE
        CASE_SYM2STR_RET(FSCTL_OPLOCK_BREAK_ACKNOWLEDGE)
#endif /* FSCTL_OPLOCK_BREAK_ACKNOWLEDGE */
#ifdef FSCTL_OPLOCK_BREAK_ACK_NO_2
        CASE_SYM2STR_RET(FSCTL_OPLOCK_BREAK_ACK_NO_2)
#endif /* FSCTL_OPLOCK_BREAK_ACK_NO_2 */
#ifdef FSCTL_OPLOCK_BREAK_NOTIFY
        CASE_SYM2STR_RET(FSCTL_OPLOCK_BREAK_NOTIFY)
#endif /* FSCTL_OPLOCK_BREAK_NOTIFY */
#ifdef FSCTL_QUERY_ALLOCATED_RANGES
        CASE_SYM2STR_RET(FSCTL_QUERY_ALLOCATED_RANGES)
#endif /* FSCTL_QUERY_ALLOCATED_RANGES */
#ifdef FSCTL_QUERY_ASYNC_DUPLICATE_EXTENTS_STATUS
        CASE_SYM2STR_RET(FSCTL_QUERY_ASYNC_DUPLICATE_EXTENTS_STATUS)
#endif /* FSCTL_QUERY_ASYNC_DUPLICATE_EXTENTS_STATUS */
#ifdef FSCTL_QUERY_BAD_RANGES
        CASE_SYM2STR_RET(FSCTL_QUERY_BAD_RANGES)
#endif /* FSCTL_QUERY_BAD_RANGES */
#ifdef FSCTL_QUERY_DEPENDENT_VOLUME
        CASE_SYM2STR_RET(FSCTL_QUERY_DEPENDENT_VOLUME)
#endif /* FSCTL_QUERY_DEPENDENT_VOLUME */
#ifdef FSCTL_QUERY_DIRECT_ACCESS_EXTENTS
        CASE_SYM2STR_RET(FSCTL_QUERY_DIRECT_ACCESS_EXTENTS)
#endif /* FSCTL_QUERY_DIRECT_ACCESS_EXTENTS */
#ifdef FSCTL_QUERY_DIRECT_IMAGE_ORIGINAL_BASE
        CASE_SYM2STR_RET(FSCTL_QUERY_DIRECT_IMAGE_ORIGINAL_BASE)
#endif /* FSCTL_QUERY_DIRECT_IMAGE_ORIGINAL_BASE */
#ifdef FSCTL_QUERY_EXTENT_READ_CACHE_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_EXTENT_READ_CACHE_INFO)
#endif /* FSCTL_QUERY_EXTENT_READ_CACHE_INFO */
#ifdef FSCTL_QUERY_FAT_BPB
        CASE_SYM2STR_RET(FSCTL_QUERY_FAT_BPB)
#endif /* FSCTL_QUERY_FAT_BPB */
#ifdef FSCTL_QUERY_FILE_LAYOUT
        CASE_SYM2STR_RET(FSCTL_QUERY_FILE_LAYOUT)
#endif /* FSCTL_QUERY_FILE_LAYOUT */
#ifdef FSCTL_QUERY_FILE_METADATA_OPTIMIZATION
        CASE_SYM2STR_RET(FSCTL_QUERY_FILE_METADATA_OPTIMIZATION)
#endif /* FSCTL_QUERY_FILE_METADATA_OPTIMIZATION */
#ifdef FSCTL_QUERY_FILE_REGIONS
        CASE_SYM2STR_RET(FSCTL_QUERY_FILE_REGIONS)
#endif /* FSCTL_QUERY_FILE_REGIONS */
#ifdef FSCTL_QUERY_FILE_SYSTEM_RECOGNITION
        CASE_SYM2STR_RET(FSCTL_QUERY_FILE_SYSTEM_RECOGNITION)
#endif /* FSCTL_QUERY_FILE_SYSTEM_RECOGNITION */
#ifdef FSCTL_QUERY_GHOSTED_FILE_EXTENTS
        CASE_SYM2STR_RET(FSCTL_QUERY_GHOSTED_FILE_EXTENTS)
#endif /* FSCTL_QUERY_GHOSTED_FILE_EXTENTS */
#ifdef FSCTL_QUERY_ON_DISK_VOLUME_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_ON_DISK_VOLUME_INFO)
#endif /* FSCTL_QUERY_ON_DISK_VOLUME_INFO */
#ifdef FSCTL_QUERY_PAGEFILE_ENCRYPTION
        CASE_SYM2STR_RET(FSCTL_QUERY_PAGEFILE_ENCRYPTION)
#endif /* FSCTL_QUERY_PAGEFILE_ENCRYPTION */
#ifdef FSCTL_QUERY_PERSISTENT_VOLUME_STATE
        CASE_SYM2STR_RET(FSCTL_QUERY_PERSISTENT_VOLUME_STATE)
#endif /* FSCTL_QUERY_PERSISTENT_VOLUME_STATE */
#ifdef FSCTL_QUERY_REFS_SMR_VOLUME_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_REFS_SMR_VOLUME_INFO)
#endif /* FSCTL_QUERY_REFS_SMR_VOLUME_INFO */
#ifdef FSCTL_QUERY_REFS_VOLUME_COUNTER_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_REFS_VOLUME_COUNTER_INFO)
#endif /* FSCTL_QUERY_REFS_VOLUME_COUNTER_INFO */
#ifdef FSCTL_QUERY_REGION_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_REGION_INFO)
#endif /* FSCTL_QUERY_REGION_INFO */
#ifdef FSCTL_QUERY_REGION_INFO_INPUT_VERSION
        CASE_SYM2STR_RET(FSCTL_QUERY_REGION_INFO_INPUT_VERSION)
#endif /* FSCTL_QUERY_REGION_INFO_INPUT_VERSION */
#ifdef FSCTL_QUERY_REGION_INFO_OUTPUT_VERSION
        CASE_SYM2STR_RET(FSCTL_QUERY_REGION_INFO_OUTPUT_VERSION)
#endif /* FSCTL_QUERY_REGION_INFO_OUTPUT_VERSION */
#ifdef FSCTL_QUERY_RETRIEVAL_POINTERS
        CASE_SYM2STR_RET(FSCTL_QUERY_RETRIEVAL_POINTERS)
#endif /* FSCTL_QUERY_RETRIEVAL_POINTERS */
#ifdef FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT
        CASE_SYM2STR_RET(FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT)
#endif /* FSCTL_QUERY_SHARED_VIRTUAL_DISK_SUPPORT */
#ifdef FSCTL_QUERY_SPARING_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_SPARING_INFO)
#endif /* FSCTL_QUERY_SPARING_INFO */
#ifdef FSCTL_QUERY_STORAGE_CLASSES
        CASE_SYM2STR_RET(FSCTL_QUERY_STORAGE_CLASSES)
#endif /* FSCTL_QUERY_STORAGE_CLASSES */
#ifdef FSCTL_QUERY_STORAGE_CLASSES_OUTPUT_VERSION
        CASE_SYM2STR_RET(FSCTL_QUERY_STORAGE_CLASSES_OUTPUT_VERSION)
#endif /* FSCTL_QUERY_STORAGE_CLASSES_OUTPUT_VERSION */
#ifdef FSCTL_QUERY_USN_JOURNAL
        CASE_SYM2STR_RET(FSCTL_QUERY_USN_JOURNAL)
#endif /* FSCTL_QUERY_USN_JOURNAL */
#ifdef FSCTL_QUERY_VOLUME_CONTAINER_STATE
        CASE_SYM2STR_RET(FSCTL_QUERY_VOLUME_CONTAINER_STATE)
#endif /* FSCTL_QUERY_VOLUME_CONTAINER_STATE */
#ifdef FSCTL_QUERY_VOLUME_NUMA_INFO
        CASE_SYM2STR_RET(FSCTL_QUERY_VOLUME_NUMA_INFO)
#endif /* FSCTL_QUERY_VOLUME_NUMA_INFO */
#ifdef FSCTL_READ_FILE_USN_DATA
        CASE_SYM2STR_RET(FSCTL_READ_FILE_USN_DATA)
#endif /* FSCTL_READ_FILE_USN_DATA */
#ifdef FSCTL_READ_FROM_PLEX
        CASE_SYM2STR_RET(FSCTL_READ_FROM_PLEX)
#endif /* FSCTL_READ_FROM_PLEX */
#ifdef FSCTL_READ_RAW_ENCRYPTED
        CASE_SYM2STR_RET(FSCTL_READ_RAW_ENCRYPTED)
#endif /* FSCTL_READ_RAW_ENCRYPTED */
#ifdef FSCTL_READ_UNPRIVILEGED_USN_JOURNAL
        CASE_SYM2STR_RET(FSCTL_READ_UNPRIVILEGED_USN_JOURNAL)
#endif /* FSCTL_READ_UNPRIVILEGED_USN_JOURNAL */
#ifdef FSCTL_READ_USN_JOURNAL
        CASE_SYM2STR_RET(FSCTL_READ_USN_JOURNAL)
#endif /* FSCTL_READ_USN_JOURNAL */
#ifdef FSCTL_REARRANGE_FILE
        CASE_SYM2STR_RET(FSCTL_REARRANGE_FILE)
#endif /* FSCTL_REARRANGE_FILE */
#ifdef FSCTL_RECALL_FILE
        CASE_SYM2STR_RET(FSCTL_RECALL_FILE)
#endif /* FSCTL_RECALL_FILE */
#ifdef FSCTL_REFS_DEALLOCATE_RANGES
        CASE_SYM2STR_RET(FSCTL_REFS_DEALLOCATE_RANGES)
#endif /* FSCTL_REFS_DEALLOCATE_RANGES */
#ifdef FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT
        CASE_SYM2STR_RET(FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT)
#endif /* FSCTL_REFS_STREAM_SNAPSHOT_MANAGEMENT */
#ifdef FSCTL_REMOVE_OVERLAY
        CASE_SYM2STR_RET(FSCTL_REMOVE_OVERLAY)
#endif /* FSCTL_REMOVE_OVERLAY */
#ifdef FSCTL_REPAIR_COPIES
        CASE_SYM2STR_RET(FSCTL_REPAIR_COPIES)
#endif /* FSCTL_REPAIR_COPIES */
#ifdef FSCTL_REQUEST_BATCH_OPLOCK
        CASE_SYM2STR_RET(FSCTL_REQUEST_BATCH_OPLOCK)
#endif /* FSCTL_REQUEST_BATCH_OPLOCK */
#ifdef FSCTL_REQUEST_FILTER_OPLOCK
        CASE_SYM2STR_RET(FSCTL_REQUEST_FILTER_OPLOCK)
#endif /* FSCTL_REQUEST_FILTER_OPLOCK */
#ifdef FSCTL_REQUEST_OPLOCK
        CASE_SYM2STR_RET(FSCTL_REQUEST_OPLOCK)
#endif /* FSCTL_REQUEST_OPLOCK */
#ifdef FSCTL_REQUEST_OPLOCK_LEVEL_1
        CASE_SYM2STR_RET(FSCTL_REQUEST_OPLOCK_LEVEL_1)
#endif /* FSCTL_REQUEST_OPLOCK_LEVEL_1 */
#ifdef FSCTL_REQUEST_OPLOCK_LEVEL_2
        CASE_SYM2STR_RET(FSCTL_REQUEST_OPLOCK_LEVEL_2)
#endif /* FSCTL_REQUEST_OPLOCK_LEVEL_2 */
#ifdef FSCTL_RESET_VOLUME_ALLOCATION_HINTS
        CASE_SYM2STR_RET(FSCTL_RESET_VOLUME_ALLOCATION_HINTS)
#endif /* FSCTL_RESET_VOLUME_ALLOCATION_HINTS */
#ifdef FSCTL_RKF_INTERNAL
        CASE_SYM2STR_RET(FSCTL_RKF_INTERNAL)
#endif /* FSCTL_RKF_INTERNAL */
#ifdef FSCTL_SCRUB_DATA
        CASE_SYM2STR_RET(FSCTL_SCRUB_DATA)
#endif /* FSCTL_SCRUB_DATA */
#ifdef FSCTL_SCRUB_UNDISCOVERABLE_ID
        CASE_SYM2STR_RET(FSCTL_SCRUB_UNDISCOVERABLE_ID)
#endif /* FSCTL_SCRUB_UNDISCOVERABLE_ID */
#ifdef FSCTL_SD_GLOBAL_CHANGE
        CASE_SYM2STR_RET(FSCTL_SD_GLOBAL_CHANGE)
#endif /* FSCTL_SD_GLOBAL_CHANGE */
#ifdef FSCTL_SECURITY_ID_CHECK
        CASE_SYM2STR_RET(FSCTL_SECURITY_ID_CHECK)
#endif /* FSCTL_SECURITY_ID_CHECK */
#ifdef FSCTL_SET_COMPRESSION
        CASE_SYM2STR_RET(FSCTL_SET_COMPRESSION)
#endif /* FSCTL_SET_COMPRESSION */
#ifdef FSCTL_SET_DAX_ALLOC_ALIGNMENT_HINT
        CASE_SYM2STR_RET(FSCTL_SET_DAX_ALLOC_ALIGNMENT_HINT)
#endif /* FSCTL_SET_DAX_ALLOC_ALIGNMENT_HINT */
#ifdef FSCTL_SET_DEFECT_MANAGEMENT
        CASE_SYM2STR_RET(FSCTL_SET_DEFECT_MANAGEMENT)
#endif /* FSCTL_SET_DEFECT_MANAGEMENT */
#ifdef FSCTL_SET_ENCRYPTION
        CASE_SYM2STR_RET(FSCTL_SET_ENCRYPTION)
#endif /* FSCTL_SET_ENCRYPTION */
#ifdef FSCTL_SET_EXTERNAL_BACKING
        CASE_SYM2STR_RET(FSCTL_SET_EXTERNAL_BACKING)
#endif /* FSCTL_SET_EXTERNAL_BACKING */
#ifdef FSCTL_SET_INTEGRITY_INFORMATION
        CASE_SYM2STR_RET(FSCTL_SET_INTEGRITY_INFORMATION)
#endif /* FSCTL_SET_INTEGRITY_INFORMATION */
#ifdef FSCTL_SET_INTEGRITY_INFORMATION_EX
        CASE_SYM2STR_RET(FSCTL_SET_INTEGRITY_INFORMATION_EX)
#endif /* FSCTL_SET_INTEGRITY_INFORMATION_EX */
#ifdef FSCTL_SET_LAYER_ROOT
        CASE_SYM2STR_RET(FSCTL_SET_LAYER_ROOT)
#endif /* FSCTL_SET_LAYER_ROOT */
#ifdef FSCTL_SET_OBJECT_ID
        CASE_SYM2STR_RET(FSCTL_SET_OBJECT_ID)
#endif /* FSCTL_SET_OBJECT_ID */
#ifdef FSCTL_SET_OBJECT_ID_EXTENDED
        CASE_SYM2STR_RET(FSCTL_SET_OBJECT_ID_EXTENDED)
#endif /* FSCTL_SET_OBJECT_ID_EXTENDED */
#ifdef FSCTL_SET_PERSISTENT_VOLUME_STATE
        CASE_SYM2STR_RET(FSCTL_SET_PERSISTENT_VOLUME_STATE)
#endif /* FSCTL_SET_PERSISTENT_VOLUME_STATE */
#ifdef FSCTL_SET_PURGE_FAILURE_MODE
        CASE_SYM2STR_RET(FSCTL_SET_PURGE_FAILURE_MODE)
#endif /* FSCTL_SET_PURGE_FAILURE_MODE */
#ifdef FSCTL_SET_REFS_FILE_STRICTLY_SEQUENTIAL
        CASE_SYM2STR_RET(FSCTL_SET_REFS_FILE_STRICTLY_SEQUENTIAL)
#endif /* FSCTL_SET_REFS_FILE_STRICTLY_SEQUENTIAL */
#ifdef FSCTL_SET_REFS_SMR_VOLUME_GC_PARAMETERS
        CASE_SYM2STR_RET(FSCTL_SET_REFS_SMR_VOLUME_GC_PARAMETERS)
#endif /* FSCTL_SET_REFS_SMR_VOLUME_GC_PARAMETERS */
#ifdef FSCTL_SET_REPAIR
        CASE_SYM2STR_RET(FSCTL_SET_REPAIR)
#endif /* FSCTL_SET_REPAIR */
#ifdef FSCTL_SET_REPARSE_POINT
        CASE_SYM2STR_RET(FSCTL_SET_REPARSE_POINT)
#endif /* FSCTL_SET_REPARSE_POINT */
#ifdef FSCTL_SET_REPARSE_POINT_EX
        CASE_SYM2STR_RET(FSCTL_SET_REPARSE_POINT_EX)
#endif /* FSCTL_SET_REPARSE_POINT_EX */
#ifdef FSCTL_SET_SHORT_NAME_BEHAVIOR
        CASE_SYM2STR_RET(FSCTL_SET_SHORT_NAME_BEHAVIOR)
#endif /* FSCTL_SET_SHORT_NAME_BEHAVIOR */
#ifdef FSCTL_SET_SPARSE
        CASE_SYM2STR_RET(FSCTL_SET_SPARSE)
#endif /* FSCTL_SET_SPARSE */
#ifdef FSCTL_SET_VOLUME_COMPRESSION_STATE
        CASE_SYM2STR_RET(FSCTL_SET_VOLUME_COMPRESSION_STATE)
#endif /* FSCTL_SET_VOLUME_COMPRESSION_STATE */
#ifdef FSCTL_SET_ZERO_DATA
        CASE_SYM2STR_RET(FSCTL_SET_ZERO_DATA)
#endif /* FSCTL_SET_ZERO_DATA */
#ifdef FSCTL_SET_ZERO_ON_DEALLOCATION
        CASE_SYM2STR_RET(FSCTL_SET_ZERO_ON_DEALLOCATION)
#endif /* FSCTL_SET_ZERO_ON_DEALLOCATION */
#ifdef FSCTL_SHRINK_VOLUME
        CASE_SYM2STR_RET(FSCTL_SHRINK_VOLUME)
#endif /* FSCTL_SHRINK_VOLUME */
#ifdef FSCTL_SHUFFLE_FILE
        CASE_SYM2STR_RET(FSCTL_SHUFFLE_FILE)
#endif /* FSCTL_SHUFFLE_FILE */
#ifdef FSCTL_SIS_COPYFILE
        CASE_SYM2STR_RET(FSCTL_SIS_COPYFILE)
#endif /* FSCTL_SIS_COPYFILE */
#ifdef FSCTL_SIS_LINK_FILES
        CASE_SYM2STR_RET(FSCTL_SIS_LINK_FILES)
#endif /* FSCTL_SIS_LINK_FILES */
#ifdef FSCTL_SMB_SHARE_FLUSH_AND_PURGE
        CASE_SYM2STR_RET(FSCTL_SMB_SHARE_FLUSH_AND_PURGE)
#endif /* FSCTL_SMB_SHARE_FLUSH_AND_PURGE */
#ifdef FSCTL_SPARSE_OVERALLOCATE
        CASE_SYM2STR_RET(FSCTL_SPARSE_OVERALLOCATE)
#endif /* FSCTL_SPARSE_OVERALLOCATE */
#ifdef FSCTL_SSDI_STORAGE_REQUEST
        CASE_SYM2STR_RET(FSCTL_SSDI_STORAGE_REQUEST)
#endif /* FSCTL_SSDI_STORAGE_REQUEST */
#ifdef FSCTL_START_VIRTUALIZATION_INSTANCE_EX
        CASE_SYM2STR_RET(FSCTL_START_VIRTUALIZATION_INSTANCE_EX)
#endif /* FSCTL_START_VIRTUALIZATION_INSTANCE_EX */
#ifdef FSCTL_STORAGE_QOS_CONTROL
        CASE_SYM2STR_RET(FSCTL_STORAGE_QOS_CONTROL)
#endif /* FSCTL_STORAGE_QOS_CONTROL */
#ifdef FSCTL_STREAMS_ASSOCIATE_ID
        CASE_SYM2STR_RET(FSCTL_STREAMS_ASSOCIATE_ID)
#endif /* FSCTL_STREAMS_ASSOCIATE_ID */
#ifdef FSCTL_STREAMS_QUERY_ID
        CASE_SYM2STR_RET(FSCTL_STREAMS_QUERY_ID)
#endif /* FSCTL_STREAMS_QUERY_ID */
#ifdef FSCTL_STREAMS_QUERY_PARAMETERS
        CASE_SYM2STR_RET(FSCTL_STREAMS_QUERY_PARAMETERS)
#endif /* FSCTL_STREAMS_QUERY_PARAMETERS */
#ifdef FSCTL_SUSPEND_OVERLAY
        CASE_SYM2STR_RET(FSCTL_SUSPEND_OVERLAY)
#endif /* FSCTL_SUSPEND_OVERLAY */
#ifdef FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST)
#endif /* FSCTL_SVHDX_ASYNC_TUNNEL_REQUEST */
#ifdef FSCTL_SVHDX_SET_INITIATOR_INFORMATION
        CASE_SYM2STR_RET(FSCTL_SVHDX_SET_INITIATOR_INFORMATION)
#endif /* FSCTL_SVHDX_SET_INITIATOR_INFORMATION */
#ifdef FSCTL_SVHDX_SYNC_TUNNEL_REQUEST
        CASE_SYM2STR_RET(FSCTL_SVHDX_SYNC_TUNNEL_REQUEST)
#endif /* FSCTL_SVHDX_SYNC_TUNNEL_REQUEST */
#ifdef FSCTL_TXFS_CREATE_MINIVERSION
        CASE_SYM2STR_RET(FSCTL_TXFS_CREATE_MINIVERSION)
#endif /* FSCTL_TXFS_CREATE_MINIVERSION */
#ifdef FSCTL_TXFS_CREATE_SECONDARY_RM
        CASE_SYM2STR_RET(FSCTL_TXFS_CREATE_SECONDARY_RM)
#endif /* FSCTL_TXFS_CREATE_SECONDARY_RM */
#ifdef FSCTL_TXFS_GET_METADATA_INFO
        CASE_SYM2STR_RET(FSCTL_TXFS_GET_METADATA_INFO)
#endif /* FSCTL_TXFS_GET_METADATA_INFO */
#ifdef FSCTL_TXFS_GET_TRANSACTED_VERSION
        CASE_SYM2STR_RET(FSCTL_TXFS_GET_TRANSACTED_VERSION)
#endif /* FSCTL_TXFS_GET_TRANSACTED_VERSION */
#ifdef FSCTL_TXFS_LIST_TRANSACTIONS
        CASE_SYM2STR_RET(FSCTL_TXFS_LIST_TRANSACTIONS)
#endif /* FSCTL_TXFS_LIST_TRANSACTIONS */
#ifdef FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES
        CASE_SYM2STR_RET(FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES)
#endif /* FSCTL_TXFS_LIST_TRANSACTION_LOCKED_FILES */
#ifdef FSCTL_TXFS_MODIFY_RM
        CASE_SYM2STR_RET(FSCTL_TXFS_MODIFY_RM)
#endif /* FSCTL_TXFS_MODIFY_RM */
#ifdef FSCTL_TXFS_QUERY_RM_INFORMATION
        CASE_SYM2STR_RET(FSCTL_TXFS_QUERY_RM_INFORMATION)
#endif /* FSCTL_TXFS_QUERY_RM_INFORMATION */
#ifdef FSCTL_TXFS_READ_BACKUP_INFORMATION
        CASE_SYM2STR_RET(FSCTL_TXFS_READ_BACKUP_INFORMATION)
#endif /* FSCTL_TXFS_READ_BACKUP_INFORMATION */
#ifdef FSCTL_TXFS_READ_BACKUP_INFORMATION2
        CASE_SYM2STR_RET(FSCTL_TXFS_READ_BACKUP_INFORMATION2)
#endif /* FSCTL_TXFS_READ_BACKUP_INFORMATION2 */
#ifdef FSCTL_TXFS_ROLLFORWARD_REDO
        CASE_SYM2STR_RET(FSCTL_TXFS_ROLLFORWARD_REDO)
#endif /* FSCTL_TXFS_ROLLFORWARD_REDO */
#ifdef FSCTL_TXFS_ROLLFORWARD_UNDO
        CASE_SYM2STR_RET(FSCTL_TXFS_ROLLFORWARD_UNDO)
#endif /* FSCTL_TXFS_ROLLFORWARD_UNDO */
#ifdef FSCTL_TXFS_SAVEPOINT_INFORMATION
        CASE_SYM2STR_RET(FSCTL_TXFS_SAVEPOINT_INFORMATION)
#endif /* FSCTL_TXFS_SAVEPOINT_INFORMATION */
#ifdef FSCTL_TXFS_SHUTDOWN_RM
        CASE_SYM2STR_RET(FSCTL_TXFS_SHUTDOWN_RM)
#endif /* FSCTL_TXFS_SHUTDOWN_RM */
#ifdef FSCTL_TXFS_START_RM
        CASE_SYM2STR_RET(FSCTL_TXFS_START_RM)
#endif /* FSCTL_TXFS_START_RM */
#ifdef FSCTL_TXFS_TRANSACTION_ACTIVE
        CASE_SYM2STR_RET(FSCTL_TXFS_TRANSACTION_ACTIVE)
#endif /* FSCTL_TXFS_TRANSACTION_ACTIVE */
#ifdef FSCTL_TXFS_WRITE_BACKUP_INFORMATION
        CASE_SYM2STR_RET(FSCTL_TXFS_WRITE_BACKUP_INFORMATION)
#endif /* FSCTL_TXFS_WRITE_BACKUP_INFORMATION */
#ifdef FSCTL_TXFS_WRITE_BACKUP_INFORMATION2
        CASE_SYM2STR_RET(FSCTL_TXFS_WRITE_BACKUP_INFORMATION2)
#endif /* FSCTL_TXFS_WRITE_BACKUP_INFORMATION2 */
#ifdef FSCTL_UNLOCK_VOLUME
        CASE_SYM2STR_RET(FSCTL_UNLOCK_VOLUME)
#endif /* FSCTL_UNLOCK_VOLUME */
#ifdef FSCTL_UNMAP_SPACE
        CASE_SYM2STR_RET(FSCTL_UNMAP_SPACE)
#endif /* FSCTL_UNMAP_SPACE */
#ifdef FSCTL_UPDATE_OVERLAY
        CASE_SYM2STR_RET(FSCTL_UPDATE_OVERLAY)
#endif /* FSCTL_UPDATE_OVERLAY */
#ifdef FSCTL_USN_TRACK_MODIFIED_RANGES
        CASE_SYM2STR_RET(FSCTL_USN_TRACK_MODIFIED_RANGES)
#endif /* FSCTL_USN_TRACK_MODIFIED_RANGES */
#ifdef FSCTL_VIRTUAL_STORAGE_PASSTHROUGH
        CASE_SYM2STR_RET(FSCTL_VIRTUAL_STORAGE_PASSTHROUGH)
#endif /* FSCTL_VIRTUAL_STORAGE_PASSTHROUGH */
#ifdef FSCTL_VIRTUAL_STORAGE_QUERY_PROPERTY
        CASE_SYM2STR_RET(FSCTL_VIRTUAL_STORAGE_QUERY_PROPERTY)
#endif /* FSCTL_VIRTUAL_STORAGE_QUERY_PROPERTY */
#ifdef FSCTL_VIRTUAL_STORAGE_SET_BEHAVIOR
        CASE_SYM2STR_RET(FSCTL_VIRTUAL_STORAGE_SET_BEHAVIOR)
#endif /* FSCTL_VIRTUAL_STORAGE_SET_BEHAVIOR */
#ifdef FSCTL_WAIT_FOR_REPAIR
        CASE_SYM2STR_RET(FSCTL_WAIT_FOR_REPAIR)
#endif /* FSCTL_WAIT_FOR_REPAIR */
#ifdef FSCTL_WRITE_RAW_ENCRYPTED
        CASE_SYM2STR_RET(FSCTL_WRITE_RAW_ENCRYPTED)
#endif /* FSCTL_WRITE_RAW_ENCRYPTED */
#ifdef FSCTL_WRITE_USN_CLOSE_RECORD
        CASE_SYM2STR_RET(FSCTL_WRITE_USN_CLOSE_RECORD)
#endif /* FSCTL_WRITE_USN_CLOSE_RECORD */
#ifdef FSCTL_WRITE_USN_REASON
        CASE_SYM2STR_RET(FSCTL_WRITE_USN_REASON)
#endif /* FSCTL_WRITE_USN_REASON */
        default:
            return NULL;
            break;
    }

    /* not reached */
}

const char *reparsetag2string(ULONG tag)
{
#define REPARSETAG2STR_RET(x) case (x): return #x ; break
    switch(tag) {
        REPARSETAG2STR_RET(IO_REPARSE_TAG_MOUNT_POINT);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_HSM);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_DRIVE_EXTENDER);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_HSM2);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_SIS);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WIM);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CSV);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_DFS);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_FILTER_MANAGER);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_SYMLINK);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_IIS_CACHE);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_DFSR);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_DEDUP);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_APPXSTRM);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_NFS);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_FILE_PLACEHOLDER);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_DFM);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WOF);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WCI);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WCI_1);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_GLOBAL_REPARSE);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_1);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_2);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_3);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_4);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_5);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_6);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_7);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_8);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_9);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_A);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_B);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_C);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_D);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_E);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_CLOUD_F);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_APPEXECLINK);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_PROJFS);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_LX_SYMLINK);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_STORAGE_SYNC);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_STORAGE_SYNC_FOLDER);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WCI_TOMBSTONE);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_UNHANDLED);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_ONEDRIVE);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_PROJFS_TOMBSTONE);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_AF_UNIX);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_LX_FIFO);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_LX_CHR);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_LX_BLK);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WCI_LINK);
        REPARSETAG2STR_RET(IO_REPARSE_TAG_WCI_LINK_1);
        default:
            return "<unknown reparse tag>";
            break;
    }

    /* not reached */
}


#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
void print_lookasidelist_stat(const char *label, PNPAGED_LOOKASIDE_LIST ll)
{
    DbgP("#### lookasidelist stat '%s': "
        "{ TotalAllocates=%ld, AllocateMisses=%ld, FreeMisses=%ld, Depth=%ld, MaximumDepth=%ld\n",
        label,
        (long)ll->L.TotalAllocates,
        (long)ll->L.AllocateMisses,
        (long)ll->L.FreeMisses,
        (long)ll->L.Depth,
        (long)ll->L.MaximumDepth);
}
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */

void print_debug_header(
    PRX_CONTEXT RxContext)
{
    PIO_STACK_LOCATION IrpSp = RxContext->CurrentIrpSp;

    if (IrpSp) {
        DbgP("FileOject=0x%p name='%wZ' access r=%d,w=%d,d=%d share r=%d,w=%d,d=%d\n",
            IrpSp->FileObject, &IrpSp->FileObject->FileName,
            IrpSp->FileObject->ReadAccess, IrpSp->FileObject->WriteAccess,
            IrpSp->FileObject->DeleteAccess, IrpSp->FileObject->SharedRead,
            IrpSp->FileObject->SharedWrite, IrpSp->FileObject->SharedDelete);
        print_file_object(0, IrpSp->FileObject);
        print_irps_flags(0, RxContext->CurrentIrpSp);
    } else
        DbgP("Couldn't print FileObject IrpSp is NULL\n");

    print_fo_all(1, RxContext);
    if (RxContext->CurrentIrp)
        print_irp_flags(0, RxContext->CurrentIrp);
}
