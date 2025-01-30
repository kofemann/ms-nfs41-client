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

static
NTSTATUS check_nfs41_queryallocatedranges_args(
    PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
    const USHORT HeaderLen = sizeof(FILE_ALLOCATED_RANGE_BUFFER);

    /*
     * Must have a filename longer than vnetroot name,
     * or it's trying to operate on the volume itself
     */
    if (is_root_directory(RxContext)) {
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    if (!FsCtl->pOutputBuffer) {
        status = STATUS_INVALID_USER_BUFFER;
        goto out;
    }

    if (FsCtl->OutputBufferLength < HeaderLen) {
        RxContext->InformationToReturn = HeaderLen;
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }
out:
    return status;
}

static
NTSTATUS nfs41_QueryAllocatedRanges(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    __notnull XXCTL_LOWIO_COMPONENT *FsCtl =
        &RxContext->LowIoContext.ParamsFor.FsCtl;
    __notnull PFILE_ALLOCATED_RANGE_BUFFER in_range_buffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)FsCtl->pInputBuffer;
    __notnull PFILE_ALLOCATED_RANGE_BUFFER out_range_buffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)FsCtl->pOutputBuffer;
    __notnull PNFS41_FCB nfs41_fcb =
        NFS41GetFcbExtension(RxContext->pFcb);

    DbgEn();

    RxContext->IoStatusBlock.Information = 0;

    status = check_nfs41_queryallocatedranges_args(RxContext);
    if (status)
        goto out;

    if (FsCtl->InputBufferLength <
        sizeof(FILE_ALLOCATED_RANGE_BUFFER)) {
        DbgP("nfs41_QueryAllocatedRanges: "
            "in_range_buffer to small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

/*
 * FIXME: For now we implement |FSCTL_QUERY_ALLOCATED_RANGES| using
 * a dummy implementation which just returns { 0, filesize }
 * so we can do testing with Cygwin >= 3.6.x
 * |lseek(..., SEEK_HOLE/SEEK_DATA, ...)| and
 * Windows $ fsutil sparse queryrange mysparsefile.txt #.
 *
 * We really need an upcall which issues NFSv4.2 SEEK to enumerate the
 * data/hole sections and fill an array of
 * |FILE_ALLOCATED_RANGE_BUFFER|s with the positions of tha SEEK_DATA
 * results.
 */
#define NFS41SYS_FSCTL_QUERY_ALLOCATED_RANGES_PLACEHOLDER_DUMMY_IMPL 1

#ifdef NFS41SYS_FSCTL_QUERY_ALLOCATED_RANGES_PLACEHOLDER_DUMMY_IMPL
    DbgP("nfs41_QueryAllocatedRanges: "
        "in_range_buffer=(FileOffset=%lld,Length=%lld)\n",
        (long long)in_range_buffer->FileOffset.QuadPart,
        (long long)in_range_buffer->Length.QuadPart);

    if (FsCtl->OutputBufferLength <
        (1*sizeof(FILE_ALLOCATED_RANGE_BUFFER))) {
        DbgP("nfs41_QueryAllocatedRanges: "
            "FsCtl->OutputBufferLength too small\n");
        status = STATUS_BUFFER_TOO_SMALL;
        goto out;
    }

    out_range_buffer->FileOffset.QuadPart = 0;
    out_range_buffer->Length.QuadPart =
        nfs41_fcb->StandardInfo.EndOfFile.QuadPart;

    RxContext->IoStatusBlock.Information =
        (ULONG_PTR)1*sizeof(FILE_ALLOCATED_RANGE_BUFFER);

    status = STATUS_SUCCESS;
#endif /* NFS41SYS_FSCTL_QUERY_ALLOCATED_RANGES_PLACEHOLDER_DUMMY_IMPL */

out:
    DbgEx();
    return status;
}

NTSTATUS nfs41_FsCtl(
    IN OUT PRX_CONTEXT RxContext)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
#ifdef DEBUG_FSCTL
    DbgEn();
    print_debug_header(RxContext);
#endif
    const ULONG fscontrolcode =
        RxContext->LowIoContext.ParamsFor.FsCtl.FsControlCode;

    switch (fscontrolcode) {
    case FSCTL_SET_REPARSE_POINT:
        status = nfs41_SetReparsePoint(RxContext);
        break;
    case FSCTL_GET_REPARSE_POINT:
        status = nfs41_GetReparsePoint(RxContext);
        break;
    case FSCTL_QUERY_ALLOCATED_RANGES:
        status = nfs41_QueryAllocatedRanges(RxContext);
        break;
    default:
        break;
    }

#ifdef DEBUG_FSCTL
    const char *fsctl_str = fsctl2string(fscontrolcode);

    if (fsctl_str) {
        DbgP("nfs41_FsCtl: FsControlCode='%s', status=0x%lx\n",
            fsctl_str, (long)status);
    }
    else {
        DbgP("nfs41_FsCtl: FsControlCode=0x%lx, status=0x%lx\n",
            (unsigned long)fscontrolcode, (long)status);
    }
#endif /* DEBUG_FSCTL */

#ifdef DEBUG_FSCTL
    DbgEx();
#endif
    return status;
}
