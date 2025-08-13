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
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"


static
nfs41_updowncall_entry *nfs41_upcall_allocate_updowncall_entry(void)
{
    nfs41_updowncall_entry *e;
#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
    e = ExAllocateFromNPagedLookasideList(
        &updowncall_entry_upcall_lookasidelist);

#ifdef LOOKASIDELISTS_STATS
    volatile static long cnt = 0;
    if ((cnt++ % 100) == 0) {
        print_lookasidelist_stat("updowncall_entry_upcall",
            &updowncall_entry_upcall_lookasidelist);
    }
#endif /* LOOKASIDELISTS_STATS */
#else
    e = RxAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(nfs41_updowncall_entry),
        NFS41_MM_POOLTAG_UP);
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */

    return e;
}

static
void nfs41_upcall_free_updowncall_entry(nfs41_updowncall_entry *entry)
{
#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
    ExFreeToNPagedLookasideList(&updowncall_entry_upcall_lookasidelist,
        entry);
#else
    RxFreePool(entry);
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
}

#ifndef USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM
static
nfs41_updowncall_entry *nfs41_downcall_allocate_updowncall_entry(void)
{
    nfs41_updowncall_entry *e;
#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
    e = ExAllocateFromNPagedLookasideList(
        &updowncall_entry_downcall_lookasidelist);

#ifdef LOOKASIDELISTS_STATS
    volatile static long cnt = 0;
    if ((cnt++ % 100) == 0) {
        print_lookasidelist_stat("updowncall_entry_downcall",
            &updowncall_entry_downcall_lookasidelist);
    }
#endif /* LOOKASIDELISTS_STATS */
#else
    e = RxAllocatePoolWithTag(NonPagedPoolNx,
        sizeof(nfs41_updowncall_entry),
        NFS41_MM_POOLTAG_DOWN);
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
    return e;
}

static
void nfs41_downcall_free_updowncall_entry(nfs41_updowncall_entry *entry)
{
#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
    ExFreeToNPagedLookasideList(&updowncall_entry_downcall_lookasidelist,
        entry);
#else
    RxFreePool(entry);
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
}
#endif /* !USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM */

static void unmarshal_nfs41_header(
    nfs41_updowncall_entry *tmp,
    unsigned char **buf)
{
    RtlCopyMemory(&tmp->xid, *buf, sizeof(tmp->xid));
    *buf += sizeof(tmp->xid);
    RtlCopyMemory(&tmp->opcode, *buf, sizeof(tmp->opcode));
    *buf += sizeof(tmp->opcode);
    RtlCopyMemory(&tmp->status, *buf, sizeof(tmp->status));
    *buf += sizeof(tmp->status);
    RtlCopyMemory(&tmp->errno, *buf, sizeof(tmp->errno));
    *buf += sizeof(tmp->errno);
#ifdef DEBUG_MARSHAL_HEADER
    DbgP("[downcall header] "
        "xid=%lld opcode='%s' status=0x%lx errno=%d\n",
        tmp->xid,
        ENTRY_OPCODE2STRING(tmp), (long)tmp->status, tmp->errno);
#endif
}

void unmarshal_nfs41_attrget(
    nfs41_updowncall_entry *cur,
    PVOID attr_value,
    ULONG *attr_len,
    unsigned char **buf,
    BOOL copy_partial)
{
    ULONG buf_len;
    RtlCopyMemory(&buf_len, *buf, sizeof(ULONG));
    if (copy_partial) {
        if (buf_len > *attr_len) {
            cur->status = STATUS_BUFFER_OVERFLOW;
            buf_len = *attr_len;
        }
    }
    else {
        if (buf_len > *attr_len) {
            cur->status = STATUS_BUFFER_TOO_SMALL;
            return;
        }
    }

    *buf += sizeof(ULONG);
    *attr_len = buf_len;
    RtlCopyMemory(attr_value, *buf, buf_len);
    *buf += buf_len;
}

NTSTATUS handle_upcall(
    IN PRX_CONTEXT RxContext,
    IN nfs41_updowncall_entry *entry,
    OUT ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    ULONG cbOut = LowIoContext->ParamsFor.IoCtl.OutputBufferLength;
    unsigned char *pbOut = LowIoContext->ParamsFor.IoCtl.pOutputBuffer;

#ifdef NFS41_DRIVER_STABILITY_HACKS
    /*
     * Workaround for random crashes like this while compiling
     * the "gcc" compiler with a highly-parallel build.
     * Stack trace usually looks like this:
     * ---- snip ----
     * nt!SeTokenCanImpersonate+0x47
     * nt!PsImpersonateClient+0x126
     * nt!SeImpersonateClientEx+0x35
     * nfs41_driver!handle_upcall+0x59 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41_driver.c @ 1367]
     * nfs41_driver!nfs41_upcall+0xe7 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41_driver.c @ 1578]
     * nfs41_driver!nfs41_DevFcbXXXControlFile+0x128 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41_driver.c @ 2418]
     * nfs41_driver!RxXXXControlFileCallthru+0x76 [base\fs\rdr2\rdbss\ntdevfcb.c @ 130]
     * nfs41_driver!RxCommonDevFCBIoCtl+0x58 [base\fs\rdr2\rdbss\ntdevfcb.c @ 491]
     * nfs41_driver!RxFsdCommonDispatch+0x442 [base\fs\rdr2\rdbss\ntfsd.c @ 848]
     * nfs41_driver!RxFsdDispatch+0xfd [base\fs\rdr2\rdbss\ntfsd.c @ 442]
     * nfs41_driver!nfs41_FsdDispatch+0x67 [C:\cygwin64\home\roland_mainz\work\msnfs41_uidmapping\ms-nfs41-client\sys\nfs41_driver.c @ 6863]
     * nt!IofCallDriver+0x55
     * mup!MupiCallUncProvider+0xb8
     * mup!MupStateMachine+0x59
     * mup!MupFsdIrpPassThrough+0x17e
     * nt!IofCallDriver+0x55
     * FLTMGR!FltpDispatch+0xd6
     * nt!IofCallDriver+0x55
     * nt!IopSynchronousServiceTail+0x34c
     * nt!IopXxxControlFile+0xd13
     * nt!NtDeviceIoControlFile+0x56
     * nt!KiSystemServiceCopyEnd+0x25
     * ntdll!NtDeviceIoControlFile+0x14
     * KERNELBASE!DeviceIoControl+0x6b
     * KERNEL32!DeviceIoControlImplementation+0x81
     * nfsd_debug+0xc7b14
     * nfsd_debug+0xc79fb
     * nfsd_debug+0x171e80
     * KERNEL32!BaseThreadInitThunk+0x14
     * ntdll!RtlUserThreadStart+0x21
     * ---- snip ----
     */
    __try {
        status = SeImpersonateClientEx(entry->psec_ctx, NULL);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        NTSTATUS code;
        code = GetExceptionCode();
        print_error("handle_upcall: Call to SeImpersonateClientEx() "
            "failed due to exception 0x%lx\n", (long)code);
        status = STATUS_INTERNAL_ERROR;
    }
#else
    status = SeImpersonateClientEx(entry->psec_ctx, NULL);
#endif /* NFS41_DRIVER_STABILITY_HACKS */
    if (status != STATUS_SUCCESS) {
        print_error("handle_upcall: "
            "SeImpersonateClientEx() failed 0x%lx\n", (long)status);
        goto out;
    }

    switch(entry->opcode) {
    case NFS41_SYSOP_SHUTDOWN:
        status = marshal_nfs41_shutdown(entry, pbOut, cbOut, len);
        (void)KeSetEvent(&entry->cond, IO_NFS41FS_INCREMENT, FALSE);
        break;
    case NFS41_SYSOP_MOUNT:
        status = marshal_nfs41_mount(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_UNMOUNT:
        status = marshal_nfs41_unmount(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_OPEN:
        status = marshal_nfs41_open(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_READ:
        status = marshal_nfs41_rw(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_WRITE:
        status = marshal_nfs41_rw(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_LOCK:
        status = marshal_nfs41_lock(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_UNLOCK:
        status = marshal_nfs41_unlock(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_CLOSE:
        status = marshal_nfs41_close(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_DIR_QUERY:
        status = marshal_nfs41_dirquery(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_FILE_QUERY:
    case NFS41_SYSOP_FILE_QUERY_TIME_BASED_COHERENCY:
        status = marshal_nfs41_filequery(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_FILE_SET:
        status = marshal_nfs41_fileset(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_EA_SET:
        status = marshal_nfs41_easet(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_EA_GET:
        status = marshal_nfs41_eaget(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_SYMLINK_GET:
    case NFS41_SYSOP_SYMLINK_SET:
        status = marshal_nfs41_symlink(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_VOLUME_QUERY:
        status = marshal_nfs41_volume(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_ACL_QUERY:
        status = marshal_nfs41_getacl(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_ACL_SET:
        status = marshal_nfs41_setacl(entry, pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES:
        status = marshal_nfs41_queryallocatedranges(entry,
            pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_FSCTL_SET_ZERO_DATA:
        status = marshal_nfs41_setzerodata(entry,
            pbOut, cbOut, len);
        break;
    case NFS41_SYSOP_FSCTL_DUPLICATE_DATA:
        status = marshal_nfs41_duplicatedata(entry,
            pbOut, cbOut, len);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        print_error("Unknown nfs41 ops %d\n", entry->opcode);
    }

    // if (status == STATUS_SUCCESS)
    //     print_hexbuf("upcall buffer", pbOut, *len);

out:
    return status;
}

NTSTATUS nfs41_UpcallCreate(
    IN DWORD opcode,
    IN PSECURITY_CLIENT_CONTEXT clnt_sec_ctx,
    IN HANDLE session,
    IN HANDLE open_state,
    IN DWORD version,
    IN PUNICODE_STRING filename,
    OUT nfs41_updowncall_entry **entry_out)
{
    NTSTATUS status = STATUS_SUCCESS;
    nfs41_updowncall_entry *entry;
    SECURITY_SUBJECT_CONTEXT sec_ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;

    entry = nfs41_upcall_allocate_updowncall_entry();
    if (entry == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }

    RtlZeroMemory(entry, sizeof(nfs41_updowncall_entry));
    entry->xid = InterlockedIncrement64(&xid);
    entry->opcode = opcode;
    entry->state = NFS41_WAITING_FOR_UPCALL;
    entry->session = session;
    entry->open_state = open_state;
    entry->version = version;
    if (filename && filename->Length) entry->filename = filename;
    else if (filename && !filename->Length) entry->filename = (PUNICODE_STRING)&SLASH;
    else entry->filename = (PUNICODE_STRING)&EMPTY_STRING;
    /*XXX KeInitializeEvent will bugcheck under verifier if allocated
     * from PagedPool? */
    KeInitializeEvent(&entry->cond, SynchronizationEvent, FALSE);
    ExInitializeFastMutex(&entry->lock);

    if (clnt_sec_ctx == NULL) {
        SeCaptureSubjectContext(&sec_ctx);
        sec_qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
        sec_qos.ImpersonationLevel = SecurityImpersonation;
        sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
        sec_qos.EffectiveOnly = 0;
        entry->psec_ctx = &entry->sec_ctx;
        /*
         * Arg |ServerIsRemote| must be |FALSE|, otherwise processes
         * like Cygwin setup-x86_64.exe can fail during "Activation
         * Context" creation in
         * |SeCreateClientSecurityFromSubjectContext()| with
         * |STATUS_BAD_IMPERSONATION_LEVEL|
         */
        status = SeCreateClientSecurityFromSubjectContext(&sec_ctx, &sec_qos,
                    FALSE, entry->psec_ctx);
        if (status != STATUS_SUCCESS) {
            print_error("nfs41_UpcallCreate: "
                "SeCreateClientSecurityFromSubjectContext() "
                "failed with 0x%lx\n",
                (long)status);
            nfs41_upcall_free_updowncall_entry(entry);
            entry = NULL;
        }

        SeReleaseSubjectContext(&sec_ctx);
    } else {
        entry->psec_ctx = clnt_sec_ctx;
    }

    if (entry && entry->psec_ctx) {
        /*
         * Refcount client token (as |entry->psec_ctx_clienttoken|)
         * during lifetime of this |updowncall_entry| to avoid
         * crashes during |SeImpersonateClientEx()| if the
         * calling client thread exits.
         */
        entry->psec_ctx_clienttoken = entry->psec_ctx->ClientToken;
        ObReferenceObject(entry->psec_ctx_clienttoken);
    }

    if (entry) {
        /* Clear fields used for memory mappings */
        switch(entry->opcode) {
            case NFS41_SYSOP_WRITE:
            case NFS41_SYSOP_READ:
                entry->buf = NULL;
                break;
            case NFS41_SYSOP_DIR_QUERY:
                entry->u.QueryFile.mdl_buf = NULL;
                entry->u.QueryFile.mdl = NULL;
                break;
            case NFS41_SYSOP_OPEN:
                entry->u.Open.EaBuffer = NULL;
                entry->u.Open.EaMdl = NULL;
                break;
            case NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES:
                entry->u.QueryAllocatedRanges.Buffer = NULL;
                entry->u.QueryAllocatedRanges.BufferMdl = NULL;
                break;
        }
    }

    *entry_out = entry;
out:
    return status;
}

void nfs41_UpcallDestroy(nfs41_updowncall_entry *entry)
{
    if (!entry)
        return;

    /*
     * Free resources which might otherwise be leaked
     * FIXME: Does not work yet, the |NFS41_SYSOP_READ| codepath crashes in
     * |MmUnmapLockedPages()| when
     * $ verifier /standard /driver nfs41_driver.sys # is active
     */
#ifdef XXDISABLED_FOR_NOWXX /*defined(_DEBUG) */
    switch(entry->opcode) {
        case NFS41_SYSOP_WRITE:
        case NFS41_SYSOP_READ:
            if (entry->buf) {
                DbgP("nfs41_UpcallDestroy: NFS41_SYSOP_RW mapping leak\n");
                MmUnmapLockedPages(entry->buf, entry->u.ReadWrite.MdlAddress);
                entry->buf = NULL;
            }
            break;
        case NFS41_SYSOP_DIR_QUERY:
            if (entry->u.QueryFile.mdl) {
                DbgP("nfs41_UpcallDestroy: "
                    "NFS41_SYSOP_DIR_QUERY mapping leak\n");
                MmUnmapLockedPages(entry->u.QueryFile.mdl_buf,
                    entry->u.QueryFile.mdl);
                IoFreeMdl(entry->u.QueryFile.mdl);
                entry->u.QueryFile.mdl_buf = NULL;
                entry->u.QueryFile.mdl = NULL;
            }
            break;
        case NFS41_SYSOP_OPEN:
            if (entry->u.Open.EaMdl) {
                DbgP("nfs41_UpcallDestroy: NFS41_SYSOP_OPEN mapping leak\n");
                MmUnmapLockedPages(entry->u.Open.EaBuffer,
                    entry->u.Open.EaMdl);
                IoFreeMdl(entry->u.Open.EaMdl);
                entry->u.Open.EaBuffer = NULL;
                entry->u.Open.EaMdl = NULL;
            }
            break;
        case NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES:
            if (entry->u.QueryAllocatedRanges.BufferMdl) {
                DbgP("nfs41_UpcallDestroy: "
                    "NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES mapping leak\n");
                MmUnmapLockedPages(
                    entry->u.QueryAllocatedRanges.Buffer,
                    entry->u.QueryAllocatedRanges.BufferMdl);
                IoFreeMdl(entry->u.QueryAllocatedRanges.BufferMdl);
                entry->u.QueryAllocatedRanges.Buffer = NULL;
                entry->u.QueryAllocatedRanges.BufferMdl = NULL;
            }
            break;
    }
#endif /* _DEBUG */

    if (entry->psec_ctx_clienttoken) {
        ObDereferenceObject(entry->psec_ctx_clienttoken);
    }

    if (entry->psec_ctx == &entry->sec_ctx) {
        SeDeleteClientSecurity(entry->psec_ctx);
    }
    entry->psec_ctx = NULL;

    nfs41_upcall_free_updowncall_entry(entry);
}


NTSTATUS nfs41_UpcallWaitForReply(
    IN nfs41_updowncall_entry *entry,
    IN LONGLONG secs)
{
    NTSTATUS status = STATUS_SUCCESS;

    FsRtlEnterFileSystem();

    nfs41_AddEntry(upcallLock, upcall, entry);
    (void)KeSetEvent(&upcallEvent, IO_NFS41FS_INCREMENT, FALSE);

    if (entry->async_op)
        goto out;

    LARGE_INTEGER timeout;
    timeout.QuadPart = RELATIVE(SECONDS(secs));
retry_wait:
    status = KeWaitForSingleObject(&entry->cond, Executive,
                UserMode, FALSE, &timeout);

    if (status == STATUS_TIMEOUT)
            status = STATUS_NETWORK_UNREACHABLE;

    print_wait_status(0, "[downcall]", status,
        ENTRY_OPCODE2STRING(entry), entry,
        (entry?entry->xid:-1LL));

    switch(status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_USER_APC:
    case STATUS_ALERTED:
        DbgP("nfs41_UpcallWaitForReply: KeWaitForSingleObject() "
            "returned status(=0x%lx), "
            "retry waiting for '%s' entry=0x%p xid=%lld\n",
            (long)status,
            ENTRY_OPCODE2STRING(entry),
            entry,
            (entry?entry->xid:-1LL));
        if (entry) {
            goto retry_wait;
        }
        /* fall-through */
    default:
        ExAcquireFastMutex(&entry->lock);
        if (entry->state == NFS41_DONE_PROCESSING) {
            ExReleaseFastMutex(&entry->lock);
            break;
        }
        DbgP("[upcall] abandoning '%s' entry=0x%p xid=%lld\n",
            ENTRY_OPCODE2STRING(entry),
            entry,
            (entry?entry->xid:-1LL));
        entry->state = NFS41_NOT_WAITING;
        ExReleaseFastMutex(&entry->lock);
        goto out;
    }
    nfs41_RemoveEntry(downcallLock, entry);

out:
    FsRtlExitFileSystem();

    return status;
}

NTSTATUS nfs41_upcall(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG len = 0;
    PLIST_ENTRY pEntry = NULL;

process_upcall:
    nfs41_RemoveFirst(upcallLock, upcall, pEntry);
    if (pEntry) {
        nfs41_updowncall_entry *entry;

        entry = (nfs41_updowncall_entry *)CONTAINING_RECORD(pEntry,
                    nfs41_updowncall_entry, next);
        ExAcquireFastMutex(&entry->lock);
        nfs41_AddEntry(downcallLock, downcall, entry);
        status = handle_upcall(RxContext, entry, &len);
        if (status == STATUS_SUCCESS &&
                entry->state == NFS41_WAITING_FOR_UPCALL)
            entry->state = NFS41_WAITING_FOR_DOWNCALL;
        ExReleaseFastMutex(&entry->lock);
        if (status) {
            entry->status = status;
            (void)KeSetEvent(&entry->cond, IO_NFS41FS_INCREMENT, FALSE);
            RxContext->InformationToReturn = 0;
        } else
            RxContext->InformationToReturn = len;
    }
    else {
        status = KeWaitForSingleObject(&upcallEvent, Executive, UserMode, TRUE,
            (PLARGE_INTEGER) NULL);
        print_wait_status(0, "[upcall]", status, NULL, NULL, 0);
        switch (status) {
            case STATUS_SUCCESS:
                goto process_upcall;
            case STATUS_USER_APC:
            case STATUS_ALERTED:
                DbgP("nfs41_upcall: KeWaitForSingleObject() "
                    "returned status(=0x%lx)\n",
                    (long)status);
                goto out;
            default:
                DbgP("nfs41_upcall: KeWaitForSingleObject() "
                    "returned UNEXPECTED status(=0x%lx)\n",
                    (long)status);
                goto out;
        }
    }
out:
    return status;
}

NTSTATUS nfs41_downcall(
    IN PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
#ifdef DEBUG_PRINT_DOWNCALL_HEXBUF
    ULONG in_len = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
#endif /* DEBUG_PRINT_DOWNCALL_HEXBUF */
    unsigned char *buf = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    PLIST_ENTRY pEntry;
    nfs41_updowncall_entry *tmp, *cur= NULL;
    BOOLEAN found = 0;

#ifdef DEBUG_PRINT_DOWNCALL_HEXBUF
    print_hexbuf("downcall buffer", buf, in_len);
#endif /* DEBUG_PRINT_DOWNCALL_HEXBUF */

#ifdef USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM
    nfs41_updowncall_entry stacktmp; /* rename this to |header_tmp| */

    tmp = &stacktmp;
#else
    tmp = nfs41_downcall_allocate_updowncall_entry();
    if (tmp == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
#endif /* USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM */

    unmarshal_nfs41_header(tmp, &buf);

    ExAcquireFastMutex(&downcallLock);
    pEntry = &downcall.head;
    pEntry = pEntry->Flink;
    while (pEntry != NULL) {
        cur = (nfs41_updowncall_entry *)CONTAINING_RECORD(pEntry,
                nfs41_updowncall_entry, next);
        if (cur->xid == tmp->xid) {
            found = 1;
            break;
        }
        if (pEntry->Flink == &downcall.head)
            break;
        pEntry = pEntry->Flink;
    }
    ExReleaseFastMutex(&downcallLock);
    SeStopImpersonatingClient();
    if (!found) {
        print_error("Didn't find xid=%lld entry\n", tmp->xid);
        status = STATUS_NOT_FOUND;
        goto out_free;
    }

    ExAcquireFastMutex(&cur->lock);
    if (cur->state == NFS41_NOT_WAITING) {
        DbgP("[downcall] Nobody is waiting for this request!!!\n");
        switch(cur->opcode) {
        case NFS41_SYSOP_WRITE:
        case NFS41_SYSOP_READ:
            if (cur->buf) {
                MmUnmapLockedPages(cur->buf, cur->u.ReadWrite.MdlAddress);
                cur->buf = NULL;
            }
            break;
        case NFS41_SYSOP_DIR_QUERY:
            if (cur->u.QueryFile.mdl) {
                MmUnmapLockedPages(cur->u.QueryFile.mdl_buf,
                    cur->u.QueryFile.mdl);
                IoFreeMdl(cur->u.QueryFile.mdl);
                cur->u.QueryFile.mdl_buf = NULL;
                cur->u.QueryFile.mdl = NULL;
            }
            break;
        case NFS41_SYSOP_OPEN:
            if (cur->u.Open.EaMdl) {
                MmUnmapLockedPages(cur->u.Open.EaBuffer,
                    cur->u.Open.EaMdl);
                IoFreeMdl(cur->u.Open.EaMdl);
                cur->u.Open.EaBuffer = NULL;
                cur->u.Open.EaMdl = NULL;
            }
            break;
        case NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES:
            if (cur->u.QueryAllocatedRanges.BufferMdl) {
                MmUnmapLockedPages(
                    cur->u.QueryAllocatedRanges.Buffer,
                    cur->u.QueryAllocatedRanges.BufferMdl);
                IoFreeMdl(cur->u.QueryAllocatedRanges.BufferMdl);
                cur->u.QueryAllocatedRanges.Buffer = NULL;
                cur->u.QueryAllocatedRanges.BufferMdl = NULL;
            }
            break;
        }
        ExReleaseFastMutex(&cur->lock);
        nfs41_RemoveEntry(downcallLock, cur);
        nfs41_UpcallDestroy(cur);
        status = STATUS_UNSUCCESSFUL;
        goto out_free;
    }
    cur->state = NFS41_DONE_PROCESSING;
    cur->status = tmp->status;
    cur->errno = tmp->errno;
    status = STATUS_SUCCESS;

    if (!tmp->status) {
        switch (tmp->opcode) {
        case NFS41_SYSOP_MOUNT:
            unmarshal_nfs41_mount(cur, &buf);
            break;
        case NFS41_SYSOP_WRITE:
        case NFS41_SYSOP_READ:
            status = unmarshal_nfs41_rw(cur, &buf);
            break;
        case NFS41_SYSOP_OPEN:
            status = unmarshal_nfs41_open(cur, &buf);
            break;
        case NFS41_SYSOP_DIR_QUERY:
            status = unmarshal_nfs41_dirquery(cur, &buf);
            break;
        case NFS41_SYSOP_FILE_QUERY:
        case NFS41_SYSOP_FILE_QUERY_TIME_BASED_COHERENCY:
            unmarshal_nfs41_getattr(cur, &buf);
            break;
        case NFS41_SYSOP_EA_GET:
            unmarshal_nfs41_eaget(cur, &buf);
            break;
        case NFS41_SYSOP_SYMLINK_GET:
        case NFS41_SYSOP_SYMLINK_SET:
            unmarshal_nfs41_symlink(cur, &buf);
            break;
        case NFS41_SYSOP_VOLUME_QUERY:
            unmarshal_nfs41_volume(cur, &buf);
            break;
        case NFS41_SYSOP_ACL_QUERY:
            status = unmarshal_nfs41_getacl(cur, &buf);
            break;
        case NFS41_SYSOP_FILE_SET:
            unmarshal_nfs41_setattr(cur, &cur->ChangeTime, &buf);
            break;
        case NFS41_SYSOP_EA_SET:
            unmarshal_nfs41_setattr(cur, &cur->ChangeTime, &buf);
            break;
        case NFS41_SYSOP_ACL_SET:
            unmarshal_nfs41_setattr(cur, &cur->ChangeTime, &buf);
            break;
        case NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES:
            unmarshal_nfs41_queryallocatedranges(cur, &buf);
            break;
        case NFS41_SYSOP_FSCTL_SET_ZERO_DATA:
            unmarshal_nfs41_setzerodata(cur, &buf);
            break;
        case NFS41_SYSOP_FSCTL_DUPLICATE_DATA:
            unmarshal_nfs41_duplicatedata(cur, &buf);
            break;
        }
    }
    ExReleaseFastMutex(&cur->lock);
    if (cur->async_op) {
        switch (cur->opcode) {
            case NFS41_SYSOP_WRITE:
            case NFS41_SYSOP_READ:
                if (cur->status == STATUS_SUCCESS) {
                    cur->u.ReadWrite.rxcontext->StoredStatus =
                        STATUS_SUCCESS;
                    cur->u.ReadWrite.rxcontext->InformationToReturn =
                        cur->buf_len;
                } else {
                    cur->u.ReadWrite.rxcontext->StoredStatus =
                        map_readwrite_errors(cur->status);
                    cur->u.ReadWrite.rxcontext->InformationToReturn = 0;
                }
                nfs41_RemoveEntry(downcallLock, cur);
                RxLowIoCompletion(cur->u.ReadWrite.rxcontext);
                nfs41_UpcallDestroy(cur);
                break;
            default:
                print_error("##### nfs41_downcall: "
                    "unknown async opcode=%d ####\n",
                    (int)cur->opcode);
                break;
        }
    } else {
        (void)KeSetEvent(&cur->cond, IO_NFS41FS_INCREMENT, FALSE);
    }

out_free:
#ifdef USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM
    ;
#else
    nfs41_downcall_free_updowncall_entry(tmp);
out:
#endif /* USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM */

    return status;
}
