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
#include "nfs41_np.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"
#include "nfs_ea.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"

/*
 * In order to cooperate with other network providers,
 * we only claim paths of the format '\\server\nfs4\path' or
 * '\\server\pubnfs4\path'
 */
DECLARE_CONST_UNICODE_STRING(NfsPrefix, L"\\nfs4");
DECLARE_CONST_UNICODE_STRING(PubNfsPrefix, L"\\pubnfs4");
DECLARE_CONST_UNICODE_STRING(AUTH_SYS_NAME, L"sys");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5_NAME, L"krb5");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5I_NAME, L"krb5i");
DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5P_NAME, L"krb5p");
DECLARE_CONST_UNICODE_STRING(SLASH, L"\\");
DECLARE_CONST_UNICODE_STRING(EMPTY_STRING, L"");

DECLARE_CONST_ANSI_STRING(NfsV3Attributes, EA_NFSV3ATTRIBUTES);
DECLARE_CONST_ANSI_STRING(NfsSymlinkTargetName, EA_NFSSYMLINKTARGETNAME);
DECLARE_CONST_ANSI_STRING(NfsActOnLink, EA_NFSACTONLINK);

#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
NPAGED_LOOKASIDE_LIST updowncall_entry_upcall_lookasidelist;
NPAGED_LOOKASIDE_LIST updowncall_entry_downcall_lookasidelist;
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
#ifdef USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM
NPAGED_LOOKASIDE_LIST fcblistentry_lookasidelist;
#endif /* USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM */

#ifdef ENABLE_TIMINGS
nfs41_timings lookup;
nfs41_timings readdir;
nfs41_timings open;
nfs41_timings close;
nfs41_timings getattr;
nfs41_timings setattr;
nfs41_timings getacl;
nfs41_timings setacl;
nfs41_timings volume;
nfs41_timings read;
nfs41_timings write;
nfs41_timings lock;
nfs41_timings unlock;
nfs41_timings setexattr;
nfs41_timings getexattr;
#endif /* ENABLE_TIMINGS */

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD nfs41_driver_unload;
_Dispatch_type_(IRP_MJ_CREATE) \
    _Dispatch_type_(IRP_MJ_CREATE_NAMED_PIPE) \
    DRIVER_DISPATCH(nfs41_FsdDispatch);

struct _MINIRDR_DISPATCH nfs41_ops;
PRDBSS_DEVICE_OBJECT nfs41_dev;


KEVENT upcallEvent;
FAST_MUTEX upcallLock, downcallLock, fcblistLock;
FAST_MUTEX openOwnerLock;

LONGLONG xid = 0;
LONG open_owner_id = 1;


#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
const LUID SystemLuid = SYSTEM_LUID;
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */

/* |unix_time_diff| - needed to convert windows time to unix */
LARGE_INTEGER unix_time_diff;


nfs41_init_driver_state nfs41_init_state = NFS41_INIT_DRIVER_STARTABLE;
nfs41_start_driver_state nfs41_start_state = NFS41_START_DRIVER_STARTABLE;

nfs41_fcb_list_entry *nfs41_allocate_nfs41_fcb_list_entry(void)
{
    nfs41_fcb_list_entry *e;
#ifdef USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM
    e = ExAllocateFromNPagedLookasideList(
        &fcblistentry_lookasidelist);

#else
    e = RxAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(nfs41_fcb_list_entry),
        NFS41_MM_POOLTAG_OPEN);
#endif /* USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM */

    return e;
}

void nfs41_free_nfs41_fcb_list_entry(nfs41_fcb_list_entry *entry)
{
#ifdef USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM
    ExFreeToNPagedLookasideList(&fcblistentry_lookasidelist,
        entry);
#else
    RxFreePool(entry);
#endif /* USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM */
}

NTSTATUS marshall_unicode_as_utf8(
    IN OUT unsigned char **pos,
    IN PCUNICODE_STRING str)
{
    ANSI_STRING ansi;
    ULONG ActualCount;
    NTSTATUS status;

    if (str->Length == 0) {
        status = STATUS_SUCCESS;
        ActualCount = 0;
        ansi.MaximumLength = 1;
        goto out_copy;
    }

    /* query the number of bytes required for the utf8 encoding */
    status = RtlUnicodeToUTF8N(NULL, 0xffff,
        &ActualCount, str->Buffer, str->Length);
    if (status) {
        print_error("RtlUnicodeToUTF8N('%wZ') failed with 0x%08X\n",
            str, status);
        goto out;
    }

    /* convert the string directly into the upcall buffer */
    ansi.Buffer = (PCHAR)*pos + sizeof(ansi.MaximumLength);
    ansi.MaximumLength = (USHORT)ActualCount + sizeof(UNICODE_NULL);
    status = RtlUnicodeToUTF8N(ansi.Buffer, ansi.MaximumLength,
        &ActualCount, str->Buffer, str->Length);
    if (status) {
        print_error("RtlUnicodeToUTF8N(%hu, '%wZ', %hu) failed with 0x%08X\n",
            ansi.MaximumLength, str, str->Length, status);
        goto out;
    }

out_copy:
    RtlCopyMemory(*pos, &ansi.MaximumLength, sizeof(ansi.MaximumLength));
    *pos += sizeof(ansi.MaximumLength);
    (*pos)[ActualCount] = '\0';
    *pos += ansi.MaximumLength;
out:
    return status;
}

NTSTATUS marshal_nfs41_header(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    header_len = sizeof(entry->version) + sizeof(entry->xid) +
        sizeof(entry->opcode) + 2 * sizeof(HANDLE);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    else
        *len = header_len;
    RtlCopyMemory(tmp, &entry->version, sizeof(entry->version));
    tmp += sizeof(entry->version);
    RtlCopyMemory(tmp, &entry->xid, sizeof(entry->xid));
    tmp += sizeof(entry->xid);
    RtlCopyMemory(tmp, &entry->opcode, sizeof(entry->opcode));
    tmp += sizeof(entry->opcode);
    RtlCopyMemory(tmp, &entry->session, sizeof(HANDLE));
    tmp += sizeof(HANDLE);
    RtlCopyMemory(tmp, &entry->open_state, sizeof(HANDLE));
    tmp += sizeof(HANDLE);

    /*
     * gisburn: FIXME: For currently unknown reasons we need to
     * validate |entry->filename|+it's contents, because a heavily
     * stressed system somehow sometimes causes garbage there
     */
    if (MmIsAddressValid(entry->filename) &&
        (entry->filename != NULL) &&
        MmIsAddressValid(entry->filename->Buffer)) {
#ifdef DEBUG_MARSHAL_HEADER
        DbgP("[upcall header] xid=%lld opcode='%s' filename='%wZ' version=%d "
            "session=0x%p open_state=0x%x\n", entry->xid,
            ENTRY_OPCODE2STRING(entry), entry->filename,
            entry->version, entry->session, entry->open_state);
#endif /* DEBUG_MARSHAL_HEADER */
    }
    else {
        DbgP("[upcall header] Invalid filename 0x%p\n", entry);
        status = STATUS_INTERNAL_ERROR;
    }
out:
    return status;
}

NTSTATUS marshal_nfs41_shutdown(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    return marshal_nfs41_header(entry, buf, buf_len, len);
}

NTSTATUS nfs41_invalidate_cache(
    IN PRX_CONTEXT RxContext)
{
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    unsigned char *buf = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    ULONG flag = DISABLE_CACHING;
    PMRX_SRV_OPEN srv_open;
    NTSTATUS status;

    RtlCopyMemory(&srv_open, buf, sizeof(HANDLE));
#ifdef DEBUG_INVALIDATE_CACHE
    DbgP("nfs41_invalidate_cache: received srv_open=0x%p '%wZ'\n",
        srv_open, srv_open->pAlreadyPrefixedName);
#endif
    if (MmIsAddressValid(srv_open)) {
        RxIndicateChangeOfBufferingStateForSrvOpen(
            srv_open->pFcb->pNetRoot->pSrvCall, srv_open,
            srv_open->Key, ULongToPtr(flag));
        status = STATUS_SUCCESS;
    }
    else {
        print_error("nfs41_invalidate_cache: "
            "invalid ptr srv_open=0x%p file='%wZ'\n",
            srv_open, srv_open->pAlreadyPrefixedName);
        status = STATUS_INVALID_HANDLE;
    }

    return status;
}

NTSTATUS nfs41_shutdown_daemon(
    DWORD version)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry = NULL;

    DbgEn();
    status = nfs41_UpcallCreate(NFS41_SYSOP_SHUTDOWN, NULL, INVALID_HANDLE_VALUE,
        INVALID_HANDLE_VALUE, version, NULL, &entry);
    if (status) goto out;

    status = nfs41_UpcallWaitForReply(entry, UPCALL_TIMEOUT_DEFAULT);
    if (entry->psec_ctx == &entry->sec_ctx) {
        SeDeleteClientSecurity(entry->psec_ctx);
    }
    entry->psec_ctx = NULL;
    if (status) goto out;

    nfs41_UpcallDestroy(entry);
out:
    DbgEx();
    return status;
}

NTSTATUS SharedMemoryInit(
    OUT PHANDLE phSection)
{
    NTSTATUS status;
    HANDLE hSection;
    UNICODE_STRING SectionName;
    SECURITY_DESCRIPTOR SecurityDesc;
    OBJECT_ATTRIBUTES SectionAttrs;
    LARGE_INTEGER nSectionSize;

    DbgEn();

    RtlInitUnicodeString(&SectionName, NFS41_SHARED_MEMORY_NAME);

    /* XXX: setting dacl=NULL grants access to everyone */
    status = RtlCreateSecurityDescriptor(&SecurityDesc,
        SECURITY_DESCRIPTOR_REVISION);
    if (status) {
        print_error("RtlCreateSecurityDescriptor() failed with %08X\n", status);
        goto out;
    }
    status = RtlSetDaclSecurityDescriptor(&SecurityDesc, TRUE, NULL, FALSE);
    if (status) {
        print_error("RtlSetDaclSecurityDescriptor() failed with %08X\n", status);
        goto out;
    }

    InitializeObjectAttributes(&SectionAttrs, &SectionName,
        0, NULL, &SecurityDesc);

    nSectionSize.QuadPart = sizeof(NFS41NP_SHARED_MEMORY);

    status = ZwCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE,
        &SectionAttrs, &nSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    switch (status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_OBJECT_NAME_COLLISION:
        DbgP("section already created; returning success\n");
        status = STATUS_SUCCESS;
        goto out;
    default:
        DbgP("ZwCreateSection failed with %08X\n", status);
        goto out;
    }
out:
    DbgEx();
    return status;
}

NTSTATUS SharedMemoryFree(
    IN HANDLE hSection)
{
    NTSTATUS status;
    DbgEn();
    status = ZwClose(hSection);
    DbgEx();
    return status;
}

NTSTATUS nfs41_Start(
    IN OUT PRX_CONTEXT RxContext,
    IN OUT PRDBSS_DEVICE_OBJECT dev)
{
    NTSTATUS status;
    NFS41GetDeviceExtension(RxContext, DevExt);

    DbgEn();

    status = SharedMemoryInit(&DevExt->SharedMemorySection);
    if (status) {
        print_error("InitSharedMemory failed with %08X\n", status);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    InterlockedCompareExchange((PLONG)&nfs41_start_state,
        NFS41_START_DRIVER_STARTED,
        NFS41_START_DRIVER_START_IN_PROGRESS);
out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_Stop(
    IN OUT PRX_CONTEXT RxContext,
    IN OUT PRDBSS_DEVICE_OBJECT dev)
{
    NTSTATUS status;
    NFS41GetDeviceExtension(RxContext, DevExt);
    DbgEn();
    status = SharedMemoryFree(DevExt->SharedMemorySection);
    DbgEx();
    return status;
}

#ifdef ENABLE_TIMINGS
static void print_op_stat(
    const char *op_str,
    nfs41_timings *time, BOOLEAN clear)
{
    DbgP("%-9s: num_ops=%-10d delta_ticks=%-10d size=%-10d\n", op_str,
        time->tops, time->tops ? time->ticks/time->tops : 0,
        time->sops ? time->size/time->sops : 0);
    if (clear) {
        time->tops = 0;
        time->ticks = 0;
        time->size = 0;
        time->sops = 0;
    }
}
#endif

NTSTATUS nfs41_DevFcbXXXControlFile(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    UCHAR op = RxContext->MajorFunction;
    PLOWIO_CONTEXT io_ctx = &RxContext->LowIoContext;
    ULONG fsop = io_ctx->ParamsFor.FsCtl.FsControlCode, state;
    ULONG in_len = io_ctx->ParamsFor.IoCtl.InputBufferLength;
    DWORD *buf = io_ctx->ParamsFor.IoCtl.pInputBuffer;
    NFS41GetDeviceExtension(RxContext, DevExt);
    DWORD nfs41d_version = 0;

    //DbgEn();

    //print_ioctl(op);
    switch(op) {
    case IRP_MJ_FILE_SYSTEM_CONTROL:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    case IRP_MJ_DEVICE_CONTROL:
    case IRP_MJ_INTERNAL_DEVICE_CONTROL:
        //print_fs_ioctl(fsop);
        switch (fsop) {
        case IOCTL_NFS41_INVALCACHE:
            status = nfs41_invalidate_cache(RxContext);
            break;
        case IOCTL_NFS41_READ:
            status = nfs41_upcall(RxContext);
            break;
        case IOCTL_NFS41_WRITE:
            status = nfs41_downcall(RxContext);
            break;
        case IOCTL_NFS41_ADDCONN:
            status = nfs41_CreateConnection(RxContext, &RxContext->PostRequest);
            break;
        case IOCTL_NFS41_DELCONN:
            if (RxContext->RxDeviceObject->NumberOfActiveFcbs > 0) {
                DbgP("device has open handles %d\n",
                    RxContext->RxDeviceObject->NumberOfActiveFcbs);
                status = STATUS_REDIRECTOR_HAS_OPEN_HANDLES;
                break;
            }
            status = nfs41_DeleteConnection(RxContext, &RxContext->PostRequest);
            break;
        case IOCTL_NFS41_GETSTATE:
            state = RDR_NULL_STATE;

            if (io_ctx->ParamsFor.IoCtl.OutputBufferLength >= sizeof(ULONG)) {
                // map the states to control app's equivalents
                print_driver_state(nfs41_start_state);
                switch (nfs41_start_state) {
                case NFS41_START_DRIVER_STARTABLE:
                case NFS41_START_DRIVER_STOPPED:
                    state = RDR_STOPPED;
                    break;
                case NFS41_START_DRIVER_START_IN_PROGRESS:
                    state = RDR_STARTING;
                    break;
                case NFS41_START_DRIVER_STARTED:
                    state = RDR_STARTED;
                    break;
                }
                *(ULONG *)io_ctx->ParamsFor.IoCtl.pOutputBuffer = state;
                RxContext->InformationToReturn = sizeof(ULONG);
                status = STATUS_SUCCESS;
            } else
                status = STATUS_INVALID_PARAMETER;
            break;
        case IOCTL_NFS41_START:
            print_driver_state(nfs41_start_state);
            if (in_len >= sizeof(DWORD)) {
                RtlCopyMemory(&nfs41d_version, buf, sizeof(DWORD));
                DbgP("NFS41 Daemon sent start request with version %d\n",
                    nfs41d_version);
                DbgP("Currently used NFS41 Daemon version is %d\n",
                    DevExt->nfs41d_version);
                DevExt->nfs41d_version = nfs41d_version;
            }
            switch(nfs41_start_state) {
            case NFS41_START_DRIVER_STARTABLE:
                (nfs41_start_driver_state)InterlockedCompareExchange(
                              (PLONG)&nfs41_start_state,
                              NFS41_START_DRIVER_START_IN_PROGRESS,
                              NFS41_START_DRIVER_STARTABLE);
                    //lack of break is intentional
            case NFS41_START_DRIVER_START_IN_PROGRESS:
                status = RxStartMinirdr(RxContext, &RxContext->PostRequest);
                if (status == STATUS_REDIRECTOR_STARTED) {
                    DbgP("redirector started\n");
                    status = STATUS_SUCCESS;
                } else if (status == STATUS_PENDING &&
                            RxContext->PostRequest == TRUE) {
                    DbgP("RxStartMinirdr pending 0x%08lx\n", status);
                    status = STATUS_MORE_PROCESSING_REQUIRED;
                }
                break;
            case NFS41_START_DRIVER_STARTED:
                status = STATUS_SUCCESS;
                break;
            default:
                status = STATUS_INVALID_PARAMETER;
            }
            break;
        case IOCTL_NFS41_STOP:
            if (nfs41_start_state == NFS41_START_DRIVER_STARTED)
                nfs41_shutdown_daemon(DevExt->nfs41d_version);
            if (RxContext->RxDeviceObject->NumberOfActiveFcbs > 0) {
                DbgP("device has open handles %d\n",
                    RxContext->RxDeviceObject->NumberOfActiveFcbs);
                status = STATUS_REDIRECTOR_HAS_OPEN_HANDLES;
                break;
            }

            state = (nfs41_start_driver_state)InterlockedCompareExchange(
                        (PLONG)&nfs41_start_state,
                        NFS41_START_DRIVER_STARTABLE,
                        NFS41_START_DRIVER_STARTED);

            status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
            DbgP("RxStopMinirdr status 0x%08lx\n", status);
            if (status == STATUS_PENDING && RxContext->PostRequest == TRUE )
                status = STATUS_MORE_PROCESSING_REQUIRED;
            break;
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
        };
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
    };

    //DbgEx();
    return status;
}

NTSTATUS _nfs41_CreateSrvCall(
    PMRX_SRVCALL_CALLBACK_CONTEXT pCallbackContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PMRX_SRVCALL_CALLBACK_CONTEXT SCCBC = pCallbackContext;
    PMRX_SRV_CALL pSrvCall;
    PMRX_SRVCALLDOWN_STRUCTURE SrvCalldownStructure =
        (PMRX_SRVCALLDOWN_STRUCTURE)(SCCBC->SrvCalldownStructure);
    PNFS41_SERVER_ENTRY pServerEntry = NULL;

#ifdef DEBUG_MOUNT
    DbgEn();
#endif

    pSrvCall = SrvCalldownStructure->SrvCall;

    ASSERT( pSrvCall );
    ASSERT( NodeType(pSrvCall) == RDBSS_NTC_SRVCALL );
    // print_srv_call(pSrvCall);

    // validate the server name with the test name of 'pnfs'
#ifdef DEBUG_MOUNT
    DbgP("SrvCall: Connection Name Length: %d '%wZ'\n",
        pSrvCall->pSrvCallName->Length, pSrvCall->pSrvCallName);
#endif

    if (pSrvCall->pSrvCallName->Length > SERVER_NAME_BUFFER_SIZE) {
        print_error("Server name '%wZ' too long for server entry (max %u)\n",
            pSrvCall->pSrvCallName, SERVER_NAME_BUFFER_SIZE);
        status = STATUS_NAME_TOO_LONG;
        goto out;
    }

    /* Let's create our own representation of the server */
    pServerEntry = (PNFS41_SERVER_ENTRY)RxAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(NFS41_SERVER_ENTRY), NFS41_MM_POOLTAG);
    if (pServerEntry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    RtlZeroMemory(pServerEntry, sizeof(NFS41_SERVER_ENTRY));

    pServerEntry->Name.Buffer = pServerEntry->NameBuffer;
    pServerEntry->Name.Length = pSrvCall->pSrvCallName->Length;
    pServerEntry->Name.MaximumLength = SERVER_NAME_BUFFER_SIZE;
    RtlCopyMemory(pServerEntry->Name.Buffer, pSrvCall->pSrvCallName->Buffer,
        pServerEntry->Name.Length);

    pCallbackContext->RecommunicateContext = pServerEntry;
    InterlockedExchangePointer(&pServerEntry->pRdbssSrvCall, pSrvCall);

out:
    SCCBC->Status = status;
    SrvCalldownStructure->CallBack(SCCBC);

#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_CreateSrvCall(
    PMRX_SRV_CALL pSrvCall,
    PMRX_SRVCALL_CALLBACK_CONTEXT pCallbackContext)
{
    NTSTATUS status;

    ASSERT( pSrvCall );
    ASSERT( NodeType(pSrvCall) == RDBSS_NTC_SRVCALL );

    if (IoGetCurrentProcess() == RxGetRDBSSProcess()) {
        DbgP("executing with RDBSS context\n");
        status = _nfs41_CreateSrvCall(pCallbackContext);
    } else {
        status = RxDispatchToWorkerThread(nfs41_dev, DelayedWorkQueue,
           (PRX_WORKERTHREAD_ROUTINE)_nfs41_CreateSrvCall, pCallbackContext);
        if (status != STATUS_SUCCESS) {
            print_error("RxDispatchToWorkerThread returned status 0x%08lx\n",
                status);
            pCallbackContext->Status = status;
            pCallbackContext->SrvCalldownStructure->CallBack(pCallbackContext);
            status = STATUS_PENDING;
        }
    }
    /* RDBSS expects MRxCreateSrvCall to return STATUS_PENDING */
    if (status == STATUS_SUCCESS)
        status = STATUS_PENDING;

    return status;
}

NTSTATUS nfs41_SrvCallWinnerNotify(
    IN OUT PMRX_SRV_CALL pSrvCall,
    IN BOOLEAN ThisMinirdrIsTheWinner,
    IN OUT PVOID pSrvCallContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_SERVER_ENTRY pServerEntry;

    pServerEntry = (PNFS41_SERVER_ENTRY)pSrvCallContext;

    if (!ThisMinirdrIsTheWinner) {
        ASSERT(1);
        goto out;
    }

    pSrvCall->Context = pServerEntry;
out:
    return status;
}

VOID nfs41_remove_fcb_entry(
    PMRX_FCB fcb)
{
    PLIST_ENTRY pEntry;
    nfs41_fcb_list_entry *cur;
    ExAcquireFastMutex(&fcblistLock);

    pEntry = openlist.head.Flink;
    while (!IsListEmpty(&openlist.head)) {
        cur = (nfs41_fcb_list_entry *)CONTAINING_RECORD(pEntry,
                nfs41_fcb_list_entry, next);
        if (cur->fcb == fcb) {
#ifdef DEBUG_CLOSE
            DbgP("nfs41_remove_fcb_entry: Found match for fcb=0x%p\n", fcb);
#endif
            RemoveEntryList(pEntry);
            nfs41_free_nfs41_fcb_list_entry(cur);
            break;
        }
        if (pEntry->Flink == &openlist.head) {
#ifdef DEBUG_CLOSE
            DbgP("nfs41_remove_fcb_entry: reached EOL looking "
                "for fcb 0x%p\n", fcb);
#endif
            break;
        }
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&fcblistLock);
}

static
VOID nfs41_invalidate_fobx_entry(
    IN OUT PMRX_FOBX pFobx)
{
    PLIST_ENTRY pEntry;
    nfs41_fcb_list_entry *cur;
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(pFobx);

    ExAcquireFastMutex(&fcblistLock);

    pEntry = openlist.head.Flink;
    while (!IsListEmpty(&openlist.head)) {
        cur = (nfs41_fcb_list_entry *)CONTAINING_RECORD(pEntry,
                nfs41_fcb_list_entry, next);
        if (cur->nfs41_fobx == nfs41_fobx) {
#ifdef DEBUG_CLOSE
            DbgP("nfs41_invalidate_fobx_entry: Found match for fobx=0x%p\n", fobx);
#endif
            cur->nfs41_fobx = NULL;
            break;
        }
        if (pEntry->Flink == &openlist.head) {
#ifdef DEBUG_CLOSE
            DbgP("nfs41_invalidate_fobx_entry: reached EOL looking "
                "for fobx 0x%p\n", fobx);
#endif
            break;
        }
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&fcblistLock);
}

NTSTATUS nfs41_Flush(
    IN OUT PRX_CONTEXT RxContext)
{
    DbgP("nfs41_Flush: FileName='%wZ'\n",
        GET_ALREADY_PREFIXED_NAME_FROM_CONTEXT(RxContext));

    return STATUS_SUCCESS;
}

NTSTATUS nfs41_DeallocateForFcb(
    IN OUT PMRX_FCB pFcb)
{
    nfs41_remove_fcb_entry(pFcb);
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_DeallocateForFobx(
    IN OUT PMRX_FOBX pFobx)
{
    __notnull PNFS41_FOBX nfs41_fobx = NFS41GetFobxExtension(pFobx);

    nfs41_invalidate_fobx_entry(pFobx);

    if (nfs41_fobx->acl) {
        RxFreePool(nfs41_fobx->acl);
        nfs41_fobx->acl = NULL;
    }

    if (nfs41_fobx->sec_ctx.ClientToken) {
        SeDeleteClientSecurity(&nfs41_fobx->sec_ctx);
        nfs41_fobx->sec_ctx.ClientToken = NULL;
    }

    return STATUS_SUCCESS;
}

VOID nfs41_update_fcb_list(
    PMRX_FCB fcb,
    ULONGLONG ChangeTime)
{
    PLIST_ENTRY pEntry;
    nfs41_fcb_list_entry *cur;
    ExAcquireFastMutex(&fcblistLock);
    pEntry = openlist.head.Flink;
    while (!IsListEmpty(&openlist.head)) {
        cur = (nfs41_fcb_list_entry *)CONTAINING_RECORD(pEntry,
                nfs41_fcb_list_entry, next);
        if (cur->fcb == fcb &&
                cur->ChangeTime != ChangeTime) {
#if defined(DEBUG_FILE_SET) || defined(DEBUG_ACL_SET) || \
    defined(DEBUG_WRITE) || defined(DEBUG_EA_SET)
            DbgP("nfs41_update_fcb_list: Found match for fcb 0x%p: "
                "updating %llu to %llu\n",
                fcb, cur->ChangeTime, ChangeTime);
#endif
            cur->ChangeTime = ChangeTime;
            break;
        }
        /* place an upcall for this srv_open */
        if (pEntry->Flink == &openlist.head) {
#if defined(DEBUG_FILE_SET) || defined(DEBUG_ACL_SET) || \
    defined(DEBUG_WRITE) || defined(DEBUG_EA_SET)
            DbgP("nfs41_update_fcb_list: reached EOL loooking for "
                "fcb=0x%p\n", fcb);
#endif
            break;
        }
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&fcblistLock);
}

NTSTATUS nfs41_IsValidDirectory (
    IN OUT PRX_CONTEXT RxContext,
    IN PUNICODE_STRING DirectoryName)
{
    return STATUS_SUCCESS;
}

NTSTATUS nfs41_ComputeNewBufferingState(
    IN OUT PMRX_SRV_OPEN pSrvOpen,
    IN PVOID pMRxContext,
    OUT ULONG *pNewBufferingState)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG flag = PtrToUlong(pMRxContext);
#ifdef DEBUG_TIME_BASED_COHERENCY
    ULONG oldFlags = pSrvOpen->BufferingFlags;
#endif

    switch(flag) {
    case DISABLE_CACHING:
        if (pSrvOpen->BufferingFlags &
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED))
            pSrvOpen->BufferingFlags &=
                ~(FCB_STATE_READBUFFERING_ENABLED |
                  FCB_STATE_READCACHING_ENABLED);
        if (pSrvOpen->BufferingFlags &
            (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED))
            pSrvOpen->BufferingFlags &=
                ~(FCB_STATE_WRITECACHING_ENABLED |
                  FCB_STATE_WRITEBUFFERING_ENABLED);
        pSrvOpen->BufferingFlags |= FCB_STATE_DISABLE_LOCAL_BUFFERING;
        break;
    case ENABLE_READ_CACHING:
        pSrvOpen->BufferingFlags |=
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED);
        break;
    case ENABLE_WRITE_CACHING:
        pSrvOpen->BufferingFlags |=
            (FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
        break;
    case ENABLE_READWRITE_CACHING:
        pSrvOpen->BufferingFlags =
            (FCB_STATE_READBUFFERING_ENABLED | FCB_STATE_READCACHING_ENABLED |
            FCB_STATE_WRITECACHING_ENABLED | FCB_STATE_WRITEBUFFERING_ENABLED);
    }
#ifdef DEBUG_TIME_BASED_COHERENCY
    DbgP("nfs41_ComputeNewBufferingState: '%wZ' pSrvOpen 0x%p Old %08x New %08x\n",
         pSrvOpen->pAlreadyPrefixedName, pSrvOpen, oldFlags,
         pSrvOpen->BufferingFlags);
    *pNewBufferingState = pSrvOpen->BufferingFlags;
#endif
    return status;
}

void enable_caching(
    PMRX_SRV_OPEN SrvOpen,
    PNFS41_FOBX nfs41_fobx,
    ULONGLONG ChangeTime,
    HANDLE session)
{
    ULONG flag = 0;
    PLIST_ENTRY pEntry;
    nfs41_fcb_list_entry *cur;
    BOOLEAN found = FALSE;

    if (SrvOpen->DesiredAccess & FILE_READ_DATA)
        flag = ENABLE_READ_CACHING;
    if ((SrvOpen->DesiredAccess & FILE_WRITE_DATA) &&
            !nfs41_fobx->write_thru)
        flag = ENABLE_WRITE_CACHING;
    if ((SrvOpen->DesiredAccess & FILE_READ_DATA) &&
            (SrvOpen->DesiredAccess & FILE_WRITE_DATA) &&
            !nfs41_fobx->write_thru)
        flag = ENABLE_READWRITE_CACHING;

#if defined(DEBUG_TIME_BASED_COHERENCY) || \
        defined(DEBUG_WRITE) || defined(DEBUG_READ)
    print_caching_level(1, flag, SrvOpen->pAlreadyPrefixedName);
#endif

    if (!flag)
        return;

    RxChangeBufferingState((PSRV_OPEN)SrvOpen, ULongToPtr(flag), 1);

    ExAcquireFastMutex(&fcblistLock);
    pEntry = openlist.head.Flink;
    while (!IsListEmpty(&openlist.head)) {
        cur = (nfs41_fcb_list_entry *)CONTAINING_RECORD(pEntry,
                nfs41_fcb_list_entry, next);
        if (cur->fcb == SrvOpen->pFcb) {
#ifdef DEBUG_TIME_BASED_COHERENCY
            DbgP("enable_caching: Looked&Found match for fcb=0x%p '%wZ'\n",
                SrvOpen->pFcb, SrvOpen->pAlreadyPrefixedName);
#endif
            cur->skip = FALSE;
            found = TRUE;
            break;
        }
        if (pEntry->Flink == &openlist.head) {
#ifdef DEBUG_TIME_BASED_COHERENCY
            DbgP("enable_caching: reached EOL looking for fcb=0x%p '%wZ'\n",
                SrvOpen->pFcb, SrvOpen->pAlreadyPrefixedName);
#endif
            break;
        }
        pEntry = pEntry->Flink;
    }
    if (!found && nfs41_fobx->deleg_type) {
        nfs41_fcb_list_entry *oentry;
#ifdef DEBUG_TIME_BASED_COHERENCY
        DbgP("enable_caching: delegation recalled: srv_open=0x%p\n", SrvOpen);
#endif
        oentry = nfs41_allocate_nfs41_fcb_list_entry();
        if (oentry == NULL)
            goto out_release_fcblistlock;
        oentry->fcb = SrvOpen->pFcb;
        oentry->session = session;
        oentry->nfs41_fobx = nfs41_fobx;
        oentry->ChangeTime = ChangeTime;
        oentry->skip = FALSE;
        InsertTailList(&openlist.head, &oentry->next);
        nfs41_fobx->deleg_type = 0;
    }
out_release_fcblistlock:
    ExReleaseFastMutex(&fcblistLock);
}

NTSTATUS nfs41_CompleteBufferingStateChangeRequest(
    IN OUT PRX_CONTEXT RxContext,
    IN OUT PMRX_SRV_OPEN SrvOpen,
    IN PVOID pContext)
{
    return STATUS_SUCCESS;
}

/* |nfs41_FsdDispatch()| - must be public symbol */
NTSTATUS nfs41_FsdDispatch(
    IN PDEVICE_OBJECT dev,
    IN PIRP Irp)
{
#ifdef DEBUG_FSDDISPATCH
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
#endif
    NTSTATUS status;

#ifdef DEBUG_FSDDISPATCH
    DbgEn();
    DbgP("CURRENT IRP = %d.%d\n", IrpSp->MajorFunction, IrpSp->MinorFunction);
    if(IrpSp->FileObject)
        DbgP("FileOject 0x%p Filename '%wZ'\n", IrpSp->FileObject,
                &IrpSp->FileObject->FileName);
#endif

    if (dev != (PDEVICE_OBJECT)nfs41_dev) {
        print_error("*** not ours ***\n");
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT );
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto out;
    }

    status = RxFsdDispatch((PRDBSS_DEVICE_OBJECT)dev,Irp);
    /* AGLO: 08/05/2009 - looks like RxFsdDispatch frees IrpSp */

out:
#ifdef DEBUG_FSDDISPATCH
    DbgP("IoStatus status = 0x%lx info = 0x%x\n",
        (long)Irp->IoStatus.Status,
        (int)Irp->IoStatus.Information);
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_Unimplemented(
    PRX_CONTEXT RxContext)
{
    return STATUS_NOT_IMPLEMENTED;
}

NTSTATUS nfs41_AreFilesAliased(
    PFCB a,
    PFCB b)
{
    DbgP("nfs41_AreFilesAliased: a=0x%p b=0x%p\n",
        (void *)a, (void *)b);
    return STATUS_NOT_IMPLEMENTED;
}

static
NTSTATUS nfs41_init_ops(void)
{
    DbgEn();

    ZeroAndInitializeNodeType(&nfs41_ops, RDBSS_NTC_MINIRDR_DISPATCH,
        sizeof(MINIRDR_DISPATCH));

#define FIXME_WORKAROUND_FOR_WIN10_SCAVENGER_CRASH 1
#ifdef FIXME_WORKAROUND_FOR_WIN10_SCAVENGER_CRASH
    /*
     * gisburn: Ugly workaround for crash in Win10 scavenger code
     * with a stack trace like this:
     * -- snip --
     * nt!KeBugCheckEx
     * nt!KiBugCheckDispatch+0x69
     * nt!KiFastFailDispatch+0xd0
     * nt!KiRaiseSecurityCheckFailure+0x31d (TrapFrame @ fffffe0b`41ca0900)
     * nfs41_driver!RtlFailFast(void)+0x5 (Inline Function @ fffff801`41ba47dd) [onecore\external\ifskit\inc\wdm.h @ 11545]
     * nfs41_driver!FatalListEntryError(void)+0x5 (Inline Function @ fffff801`41ba47dd) [onecore\external\ifskit\inc\wdm.h @ 11778]
     * nfs41_driver!RemoveEntryList(void)+0x33 (Inline Function @ fffff801`41ba47dd) [onecore\external\ifskit\inc\wdm.h @ 11811]
     * nfs41_driver!RxpUndoScavengerFinalizationMarking(void * Instance = 0xffffca8f`b8f537d0)+0xad [base\fs\rdr2\rxce\scavengr.c @ 1154]
     * nfs41_driver!RxScavengerFinalizeEntries(struct _RDBSS_DEVICE_OBJECT * RxDeviceObject = <Value unavailable error>)+0x407 [base\fs\rdr2\rxce\scavengr.c @ 1710]
     * nfs41_driver!RxScavengerTimerRoutine(void * Context = 0xffffca8f`bb0d4060)+0x87 [base\fs\rdr2\rxce\scavengr.c @ 1826]
     * nfs41_driver!RxpWorkerThreadDispatcher(struct _RX_WORK_QUEUE_ * pWorkQueue = 0xfffff801`41b99240, union _LARGE_INTEGER * pWaitInterval = 0x00000000`00000000)+0xbb [base\fs\rdr2\rxce\rxworkq.c @ 1343]
     * nfs41_driver!RxBootstrapWorkerThreadDispatcher(struct _RX_WORK_QUEUE_ * pWorkQueue = <Value unavailable error>)+0xb [base\fs\rdr2\rxce\rxworkq.c @ 1469]
     * nt!PspSystemThreadStartup+0x55
     * nt!KiStartSystemThread+0x28
     * -- snip --
     *
     * As workaround we "disable" the scavenger by only running it
     * every 128 years, until then we should have found a fix.
     */
    nfs41_ops.ScavengerTimeout = 3600UL*24*365*128;
#endif /* FIXME_WORKAROUND_FOR_WIN10_SCAVENGER_CRASH */

    nfs41_ops.MRxFlags = (RDBSS_MANAGE_NET_ROOT_EXTENSION |
                            RDBSS_MANAGE_V_NET_ROOT_EXTENSION |
                            RDBSS_MANAGE_FCB_EXTENSION |
                            RDBSS_MANAGE_FOBX_EXTENSION);

    nfs41_ops.MRxSrvCallSize  = 0; // srvcall extension is not handled in rdbss
    nfs41_ops.MRxNetRootSize  = sizeof(NFS41_NETROOT_EXTENSION);
    nfs41_ops.MRxVNetRootSize = sizeof(NFS41_V_NET_ROOT_EXTENSION);
    nfs41_ops.MRxFcbSize      = sizeof(NFS41_FCB);
    nfs41_ops.MRxFobxSize     = sizeof(NFS41_FOBX);

    // Mini redirector cancel routine

    nfs41_ops.MRxCancel = NULL;

    //
    // Mini redirector Start/Stop. Each mini-rdr can be started or stopped
    // while the others continue to operate.
    //

    nfs41_ops.MRxStart                = (PMRX_CALLDOWN_CTX)nfs41_Start;
    nfs41_ops.MRxStop                 = (PMRX_CALLDOWN_CTX)nfs41_Stop;
    nfs41_ops.MRxDevFcbXXXControlFile =
        (PMRX_CALLDOWN)nfs41_DevFcbXXXControlFile;

    //
    // Mini redirector name resolution
    //

    nfs41_ops.MRxCreateSrvCall       =
        (PMRX_CREATE_SRVCALL)nfs41_CreateSrvCall;
    nfs41_ops.MRxSrvCallWinnerNotify =
        (PMRX_SRVCALL_WINNER_NOTIFY)nfs41_SrvCallWinnerNotify;
    nfs41_ops.MRxCreateVNetRoot      =
        (PMRX_CREATE_V_NET_ROOT)nfs41_CreateVNetRoot;
    nfs41_ops.MRxExtractNetRootName  =
        (PMRX_EXTRACT_NETROOT_NAME)nfs41_ExtractNetRootName;
    nfs41_ops.MRxFinalizeSrvCall     =
        (PMRX_FINALIZE_SRVCALL_CALLDOWN)nfs41_FinalizeSrvCall;
    nfs41_ops.MRxFinalizeNetRoot     =
        (PMRX_FINALIZE_NET_ROOT_CALLDOWN)nfs41_FinalizeNetRoot;
    nfs41_ops.MRxFinalizeVNetRoot    =
        (PMRX_FINALIZE_V_NET_ROOT_CALLDOWN)nfs41_FinalizeVNetRoot;

    //
    // File System Object Creation/Deletion
    //

    nfs41_ops.MRxCreate            =
        (PMRX_CALLDOWN)nfs41_Create;
    nfs41_ops.MRxCollapseOpen      =
        (PMRX_CALLDOWN)nfs41_CollapseOpen;
    nfs41_ops.MRxShouldTryToCollapseThisOpen =
        (PMRX_CALLDOWN)nfs41_ShouldTryToCollapseThisOpen;
    nfs41_ops.MRxExtendForCache    =
        (PMRX_EXTENDFILE_CALLDOWN)nfs41_ExtendForCache;
    nfs41_ops.MRxExtendForNonCache =
        (PMRX_EXTENDFILE_CALLDOWN)nfs41_ExtendForCache;
    nfs41_ops.MRxCloseSrvOpen      =
        (PMRX_CALLDOWN)nfs41_CloseSrvOpen;
    nfs41_ops.MRxFlush             =
        (PMRX_CALLDOWN)nfs41_Flush;
    nfs41_ops.MRxDeallocateForFcb  =
        (PMRX_DEALLOCATE_FOR_FCB)nfs41_DeallocateForFcb;
    nfs41_ops.MRxDeallocateForFobx =
        (PMRX_DEALLOCATE_FOR_FOBX)nfs41_DeallocateForFobx;
    nfs41_ops.MRxIsLockRealizable  =
        (PMRX_IS_LOCK_REALIZABLE)nfs41_IsLockRealizable;

    //
    // File System Objects query/Set
    //

    nfs41_ops.MRxQueryDirectory       =
        (PMRX_CALLDOWN)nfs41_QueryDirectory;
    nfs41_ops.MRxQueryVolumeInfo      =
        (PMRX_CALLDOWN)nfs41_QueryVolumeInformation;
    nfs41_ops.MRxSetVolumeInfo        =
        (PMRX_CALLDOWN)nfs41_Unimplemented;
    nfs41_ops.MRxQueryEaInfo          =
        (PMRX_CALLDOWN)nfs41_QueryEaInformation;
    nfs41_ops.MRxSetEaInfo            =
        (PMRX_CALLDOWN)nfs41_SetEaInformation;
    nfs41_ops.MRxQuerySdInfo          =
        (PMRX_CALLDOWN)nfs41_QuerySecurityInformation;
    nfs41_ops.MRxSetSdInfo            =
        (PMRX_CALLDOWN)nfs41_SetSecurityInformation;
    nfs41_ops.MRxQueryFileInfo        =
        (PMRX_CALLDOWN)nfs41_QueryFileInformation;
    nfs41_ops.MRxSetFileInfo          =
        (PMRX_CALLDOWN)nfs41_SetFileInformation;
    nfs41_ops.MRxQueryQuotaInfo       =
        (PMRX_CALLDOWN)nfs41_Unimplemented;
    nfs41_ops.MRxSetQuotaInfo         =
        (PMRX_CALLDOWN)nfs41_Unimplemented;

    //
    // Buffering state change
    //

    nfs41_ops.MRxComputeNewBufferingState =
        (PMRX_COMPUTE_NEW_BUFFERING_STATE)nfs41_ComputeNewBufferingState;

    //
    // File System Object I/O
    //

    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_READ]            =
        (PMRX_CALLDOWN)nfs41_Read;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_WRITE]           =
        (PMRX_CALLDOWN)nfs41_Write;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_SHAREDLOCK]      =
        (PMRX_CALLDOWN)nfs41_Lock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_EXCLUSIVELOCK]   =
        (PMRX_CALLDOWN)nfs41_Lock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_UNLOCK]          =
        (PMRX_CALLDOWN)nfs41_Unlock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_UNLOCK_MULTIPLE] =
        (PMRX_CALLDOWN)nfs41_Unlock;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_FSCTL]           =
        (PMRX_CALLDOWN)nfs41_FsCtl;
    nfs41_ops.MRxLowIOSubmit[LOWIO_OP_IOCTL]           =
        (PMRX_CALLDOWN)nfs41_IoCtl;

    //
    // Miscellanous
    //

    nfs41_ops.MRxCompleteBufferingStateChangeRequest =
        (PMRX_CHANGE_BUFFERING_STATE_CALLDOWN)nfs41_CompleteBufferingStateChangeRequest;
    nfs41_ops.MRxIsValidDirectory =
        (PMRX_CHKDIR_CALLDOWN)nfs41_IsValidDirectory;

    nfs41_ops.MRxTruncate =
        (PMRX_CALLDOWN)nfs41_Unimplemented;
    nfs41_ops.MRxZeroExtend =
        (PMRX_CALLDOWN)nfs41_Unimplemented;
    nfs41_ops.MRxAreFilesAliased =
        (PMRX_CHKFCB_CALLDOWN)nfs41_AreFilesAliased;

    DbgR();
    return(STATUS_SUCCESS);
}

KSTART_ROUTINE fcbopen_main;

VOID fcbopen_main(PVOID ctx)
{
    NTSTATUS status;
    LARGE_INTEGER timeout;

//    DbgEn();
    timeout.QuadPart = RELATIVE(SECONDS(30));
    while(1) {
        PLIST_ENTRY pEntry;
        nfs41_fcb_list_entry *cur;
        status = KeDelayExecutionThread(KernelMode, TRUE, &timeout);
        ExAcquireFastMutex(&fcblistLock);
        pEntry = openlist.head.Flink;
        while (!IsListEmpty(&openlist.head)) {
            PNFS41_NETROOT_EXTENSION pNetRootContext;
            nfs41_updowncall_entry *entry = NULL;
            FILE_BASIC_INFORMATION binfo;
            PNFS41_FCB nfs41_fcb;
            cur = (nfs41_fcb_list_entry *)CONTAINING_RECORD(pEntry,
                    nfs41_fcb_list_entry, next);

#ifdef DEBUG_TIME_BASED_COHERENCY
            DbgP("fcbopen_main: Checking attributes for fcb=0x%p "
                "change_time=%llu skipping=%d\n", cur->fcb,
                cur->ChangeTime, cur->skip);
#endif
            if (cur->skip) goto out;

            /*
             * This can only happen if |nfs41_DeallocateForFobx()|
             * was called
             */
            if ((!cur->nfs41_fobx) || (!cur->nfs41_fobx->sec_ctx.ClientToken))
                goto out;

            if (!cur->nfs41_fobx->timebasedcoherency) {
#ifdef DEBUG_TIME_BASED_COHERENCY
                DbgP("fcbopen_main: timebasedcoherency disabled for "
                    "fcb=0x%p, nfs41_fobx=0x%p\n", cur->fcb, cur->nfs41_fobx);
#endif
                goto out;
            }

            pNetRootContext =
                NFS41GetNetRootExtension(cur->fcb->pNetRoot);
            /* place an upcall for this srv_open */
            status = nfs41_UpcallCreate(
                NFS41_SYSOP_FILE_QUERY_TIME_BASED_COHERENCY,
                &cur->nfs41_fobx->sec_ctx, cur->session,
                cur->nfs41_fobx->nfs41_open_state,
                pNetRootContext->nfs41d_version, NULL, &entry);
            if (status) goto out;

            entry->u.QueryFile.InfoClass = FileBasicInformation;
            entry->buf = &binfo;
            entry->buf_len = sizeof(binfo);

            status = nfs41_UpcallWaitForReply(entry, UPCALL_TIMEOUT_DEFAULT);
            if (status) goto out;

            if (cur->ChangeTime != entry->ChangeTime) {
                ULONG flag = DISABLE_CACHING;
                PMRX_SRV_OPEN srv_open;
                PLIST_ENTRY psrvEntry;
#ifdef DEBUG_TIME_BASED_COHERENCY
                DbgP("fcbopen_main: old ctime=%llu new_ctime=%llu\n",
                    cur->ChangeTime, entry->ChangeTime);
#endif
                cur->ChangeTime = entry->ChangeTime;
                cur->skip = TRUE;
                psrvEntry = &cur->fcb->SrvOpenList;
                psrvEntry = psrvEntry->Flink;
                while (!IsListEmpty(&cur->fcb->SrvOpenList)) {
                    srv_open = (PMRX_SRV_OPEN)CONTAINING_RECORD(psrvEntry,
                            MRX_SRV_OPEN, SrvOpenQLinks);
                    if (srv_open->DesiredAccess &
                            (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA)) {
#ifdef DEBUG_TIME_BASED_COHERENCY
                        DbgP("fcbopen_main: ************ Invalidate the cache '%wZ'"
                             "************\n", srv_open->pAlreadyPrefixedName);
#endif
                        RxIndicateChangeOfBufferingStateForSrvOpen(
                            cur->fcb->pNetRoot->pSrvCall, srv_open,
                            srv_open->Key, ULongToPtr(flag));
                    }
                    if (psrvEntry->Flink == &cur->fcb->SrvOpenList) {
#ifdef DEBUG_TIME_BASED_COHERENCY
                        DbgP("fcbopen_main: reached end of srvopen for fcb 0x%p\n",
                            cur->fcb);
#endif
                        break;
                    }
                    psrvEntry = psrvEntry->Flink;
                };
            }
            nfs41_fcb = (PNFS41_FCB)cur->fcb->Context;
            nfs41_fcb->changeattr = entry->ChangeTime;
out:
            nfs41_UpcallDestroy(entry);
            entry = NULL;
            if (pEntry->Flink == &openlist.head) {
#ifdef DEBUG_TIME_BASED_COHERENCY
                DbgP("fcbopen_main: reached end of the fcb list\n");
#endif
                break;
            }
            pEntry = pEntry->Flink;
        }
        ExReleaseFastMutex(&fcblistLock);
    }
//    DbgEx();
}

/* Main driver entry point, must be public symbol */
NTSTATUS DriverEntry(
    IN PDRIVER_OBJECT drv,
    IN PUNICODE_STRING path)
{
    NTSTATUS status;
    ULONG flags = 0, i;
    UNICODE_STRING dev_name, user_dev_name;
    PNFS41_DEVICE_EXTENSION dev_exts;
    TIME_FIELDS jan_1_1970 = {1970, 1, 1, 0, 0, 0, 0, 0};
    ACCESS_MASK mask = 0;
    OBJECT_ATTRIBUTES oattrs;

    DbgEn();

    status = RxDriverEntry(drv, path);
    if (status != STATUS_SUCCESS) {
        print_error("RxDriverEntry failed: 0x%08lx\n", status);
        goto out;
    }

    RtlInitUnicodeString(&dev_name, NFS41_DEVICE_NAME);
    SetFlag(flags, RX_REGISTERMINI_FLAG_DONT_PROVIDE_MAILSLOTS);

    status = nfs41_init_ops();
    if (status != STATUS_SUCCESS) {
        print_error("nfs41_init_ops failed to initialize dispatch table\n");
        goto out;
    }

    DbgP("calling RxRegisterMinirdr\n");
    status = RxRegisterMinirdr(&nfs41_dev, drv, &nfs41_ops, flags, &dev_name,
                sizeof(NFS41_DEVICE_EXTENSION),
                FILE_DEVICE_NETWORK_FILE_SYSTEM, FILE_REMOTE_DEVICE);
    if (status != STATUS_SUCCESS) {
        print_error("RxRegisterMinirdr failed: 0x%08lx\n", status);
        goto out;
    }
    nfs41_dev->Flags |= DO_BUFFERED_IO;

    dev_exts = (PNFS41_DEVICE_EXTENSION)
        ((PBYTE)(nfs41_dev) + sizeof(RDBSS_DEVICE_OBJECT));

    RxDefineNode(dev_exts, NFS41_DEVICE_EXTENSION);
    dev_exts->DeviceObject = nfs41_dev;
    nfs41_create_volume_info((PFILE_FS_VOLUME_INFORMATION)dev_exts->VolAttrs,
        &dev_exts->VolAttrsLen);

    RtlInitUnicodeString(&user_dev_name, NFS41_SHADOW_DEVICE_NAME);
    DbgP("calling IoCreateSymbolicLink '%wZ' '%wZ'\n", &user_dev_name, &dev_name);
    status = IoCreateSymbolicLink(&user_dev_name, &dev_name);
    if (status != STATUS_SUCCESS) {
        print_error("Device name IoCreateSymbolicLink failed: 0x%08lx\n", status);
        goto out_unregister;
    }

    KeInitializeEvent(&upcallEvent, SynchronizationEvent, FALSE );
    ExInitializeFastMutex(&upcallLock);
    ExInitializeFastMutex(&downcallLock);
    ExInitializeFastMutex(&openOwnerLock);
    ExInitializeFastMutex(&fcblistLock);
    InitializeListHead(&upcall.head);
    InitializeListHead(&downcall.head);
    InitializeListHead(&openlist.head);
#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
    /*
     * The |Depth| parameter is unfortunately ignored in Win10,
     * otherwise we could use |MmQuerySystemSize()| to scale the
     * lookasidelists
     */
    ExInitializeNPagedLookasideList(
        &updowncall_entry_upcall_lookasidelist, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(nfs41_updowncall_entry),
        NFS41_MM_POOLTAG_UP, 0);
    ExInitializeNPagedLookasideList(
        &updowncall_entry_downcall_lookasidelist, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(nfs41_updowncall_entry),
        NFS41_MM_POOLTAG_DOWN, 0);
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
#ifdef USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM
    /*
     * The |Depth| parameter is unfortunately ignored in Win10,
     * otherwise we could use |MmQuerySystemSize()| to scale the
     * lookasidelists
     */
    ExInitializeNPagedLookasideList(
        &fcblistentry_lookasidelist, NULL, NULL,
        POOL_NX_ALLOCATION, sizeof(nfs41_fcb_list_entry),
        NFS41_MM_POOLTAG_OPEN, 0);
#endif /* USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM */
    InitializeObjectAttributes(&oattrs, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&dev_exts->openlistHandle, mask,
        &oattrs, NULL, NULL, &fcbopen_main, NULL);
    if (status != STATUS_SUCCESS)
        goto out_unregister;

    drv->DriverUnload = nfs41_driver_unload;

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv->MajorFunction[i] = (PDRIVER_DISPATCH)nfs41_FsdDispatch;

    RtlTimeFieldsToTime(&jan_1_1970, &unix_time_diff);

out_unregister:
    if (status != STATUS_SUCCESS)
        RxUnregisterMinirdr(nfs41_dev);
out:
    DbgEx();
    return status;
}

/* |nfs41_driver_unload()| - must be public symbol */
VOID nfs41_driver_unload(IN PDRIVER_OBJECT drv)
{
    PRX_CONTEXT RxContext;
    NTSTATUS    status;
    UNICODE_STRING dev_name, pipe_name;

    DbgEn();

    RxContext = RxCreateRxContext(NULL, nfs41_dev, RX_CONTEXT_FLAG_IN_FSP);
    if (RxContext == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto unload;
    }
    status = RxStopMinirdr(RxContext, &RxContext->PostRequest);
    RxDereferenceAndDeleteRxContext(RxContext);

unload:
    RtlInitUnicodeString(&dev_name, NFS41_SHADOW_DEVICE_NAME);
    status = IoDeleteSymbolicLink(&dev_name);
    if (status != STATUS_SUCCESS) {
        print_error("couldn't delete device symbolic link\n");
    }
    RtlInitUnicodeString(&pipe_name, NFS41_SHADOW_PIPE_NAME);
    status = IoDeleteSymbolicLink(&pipe_name);
    if (status != STATUS_SUCCESS) {
        print_error("couldn't delete pipe symbolic link\n");
    }
    RxUnload(drv);

    DbgP("driver unloaded 0x%p\n", drv);
    DbgR();
}
