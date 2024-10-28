/* NFSv4.1 client for Windows
 * Copyright (C) Dan Shelton <dan.f.shelton@gmail.com>
 *
 * Dan Shelton <dan.f.shelton@gmail.com>
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


#include <rx.h>
#include <windef.h>
#include <winerror.h>
#include <Ntstrsafe.h>
#include <stdbool.h>

#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#define COPYSUP_MAX_HOLE_SIZE (2*4096LL)


BOOLEAN FsRtlCopyRead2(
    IN PFILE_OBJECT FObj,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    OUT PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG_PTR TopLevelContext
)
{
    BOOLEAN retval = TRUE;
    ULONG pagecount;
    LARGE_INTEGER readpos_end;
    PDEVICE_OBJECT RelatedDeviceObject;
    PFSRTL_COMMON_FCB_HEADER fo_fcb;

    pagecount = ADDRESS_AND_SIZE_TO_SPAN_PAGES((ULongToPtr(FileOffset->LowPart)), Length);

    if (Length == 0) {
        IoStatus->Status = STATUS_SUCCESS;
        IoStatus->Information = 0;

        retval = TRUE;
        goto done;
    }

    readpos_end.QuadPart = FileOffset->QuadPart + (LONGLONG)Length;
    fo_fcb = (PFSRTL_COMMON_FCB_HEADER)FObj->FsContext;

    FsRtlEnterFileSystem();

    if (Wait) {
        (void)ExAcquireResourceSharedLite(fo_fcb->Resource, TRUE);
    }
    else {
        if (!ExAcquireResourceSharedLite(fo_fcb->Resource, FALSE)) {
            retval = FALSE;
            goto done_exit_filesystem;
        }
    }

    if ((FObj->PrivateCacheMap == NULL) ||
        (fo_fcb->IsFastIoPossible == FastIoIsNotPossible)) {
        retval = FALSE;
        goto done_release_resource;
    }

    if (fo_fcb->IsFastIoPossible == FastIoIsQuestionable) {
        PFAST_IO_DISPATCH FastIoDispatch;

        RelatedDeviceObject = IoGetRelatedDeviceObject(FObj);
        FastIoDispatch =
            RelatedDeviceObject->DriverObject->FastIoDispatch;

        /* This should not happen... */
        if (!((FastIoDispatch != NULL) &&
            (FastIoDispatch->FastIoCheckIfPossible != NULL))) {
            retval = FALSE;
            goto done_release_resource;
        }

        if (!FastIoDispatch->FastIoCheckIfPossible(FObj,
            FileOffset,
            Length,
            Wait,
            LockKey,
            TRUE,
            IoStatus,
            RelatedDeviceObject)) {
            retval = FALSE;
            goto done_release_resource;
        }
    }

    if (readpos_end.QuadPart > fo_fcb->FileSize.QuadPart) {
        if (FileOffset->QuadPart >= fo_fcb->FileSize.QuadPart) {
            IoStatus->Status = STATUS_END_OF_FILE;
            IoStatus->Information = 0;

            retval = TRUE;
            goto done_release_resource;
        }

        Length =
            (ULONG)(fo_fcb->FileSize.QuadPart - FileOffset->QuadPart);
    }

    IoSetTopLevelIrp((PIRP)TopLevelContext);

    retval = FALSE;
    __try {
        if (!(Wait && (readpos_end.HighPart == 0) && (fo_fcb->FileSize.HighPart == 0))) {
            retval = CcCopyRead(FObj,
                FileOffset,
                Length,
                Wait,
                Buffer,
                IoStatus);

            FObj->Flags |= FO_FILE_FAST_IO_READ;

            ASSERT((!retval) ||
                (IoStatus->Status == STATUS_END_OF_FILE) ||
                (((ULONGLONG)FileOffset->QuadPart + IoStatus->Information) <=
                    (ULONGLONG)fo_fcb->FileSize.QuadPart));
        }
        else {
            CcFastCopyRead(FObj,
                FileOffset->LowPart,
                Length,
                pagecount,
                Buffer,
                IoStatus);

            FObj->Flags |= FO_FILE_FAST_IO_READ;

            ASSERT((IoStatus->Status == STATUS_END_OF_FILE) ||
                ((FileOffset->LowPart + IoStatus->Information) <=
                    fo_fcb->FileSize.LowPart));
        }

        if (retval) {
            FObj->CurrentByteOffset.QuadPart =
                FileOffset->QuadPart + IoStatus->Information;
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
    }

    IoSetTopLevelIrp(NULL);

done_release_resource:
    ExReleaseResourceLite(fo_fcb->Resource);
done_exit_filesystem:
    FsRtlExitFileSystem();
done:
    return retval;
}


BOOLEAN
FsRtlCopyWrite2(
    IN PFILE_OBJECT FObj,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN BOOLEAN Wait,
    IN ULONG LockKey,
    IN PVOID Buffer,
    OUT PIO_STATUS_BLOCK IoStatus,
    IN PDEVICE_OBJECT DeviceObject,
    IN ULONG_PTR TopLevelContext
)
{
    BOOLEAN retval; /* fixme: |volatile| ? */
    PFSRTL_COMMON_FCB_HEADER fo_fcb;
    bool fcb_resource_acquired_shared = false;
    bool filesize_changed = false;
    bool append_file;

    append_file = (bool)
        ((FileOffset->LowPart == FILE_WRITE_TO_END_OF_FILE) &&
        (FileOffset->HighPart == -1));

    fo_fcb = (PFSRTL_COMMON_FCB_HEADER)FObj->FsContext;

    if (!(CcCanIWrite(FObj, Length, Wait, FALSE) &&
        !FlagOn(FObj->Flags, FO_WRITE_THROUGH) &&
        CcCopyWriteWontFlush(FObj, FileOffset, Length))) {
        retval = FALSE;
        goto done;
    }

    IoStatus->Status = STATUS_SUCCESS;
    IoStatus->Information = Length;

    if (Length == 0) {
        retval = TRUE;
        goto done;
    }

    FsRtlEnterFileSystem();

#ifdef COPYSUP_FORCE4GBWRITE
    if (true) {
#else
    if ((!Wait) || (fo_fcb->AllocationSize.HighPart != 0)) {
#endif /* COPYSUP_FORCE4GBWRITE */
        LARGE_INTEGER writepos_start = { .QuadPart = 0 };
        LARGE_INTEGER writepos_end;
        LARGE_INTEGER filesize_orig = { .QuadPart = 0 };
        LARGE_INTEGER validdatalen_orig = { .QuadPart = 0 };

        writepos_end.QuadPart = FileOffset->QuadPart + (LONGLONG)Length;

        if (append_file || (writepos_end.QuadPart > fo_fcb->ValidDataLength.QuadPart)) {

            if (!ExAcquireResourceExclusiveLite(fo_fcb->Resource, Wait)) {
                retval = FALSE;
                goto done_exit_filesystem;
            }
        }
        else {
            if (!ExAcquireResourceSharedLite(fo_fcb->Resource, Wait)) {
                retval = FALSE;
                goto done_exit_filesystem;
            }

            fcb_resource_acquired_shared = true;
        }

        if (append_file) {
            writepos_start = fo_fcb->FileSize;
            writepos_end.QuadPart = fo_fcb->FileSize.QuadPart + (LONGLONG)Length;
        }
        else {
            writepos_start = *FileOffset;
            writepos_end.QuadPart = FileOffset->QuadPart + (LONGLONG)Length;
        }

        if ((FObj->PrivateCacheMap == NULL) ||
            (fo_fcb->IsFastIoPossible == FastIoIsNotPossible)) {
            retval = FALSE;
            goto done_release_resource;
        }

#ifdef COPYSUP_MAX_HOLE_SIZE
        if ((writepos_start.QuadPart >=
                (fo_fcb->ValidDataLength.QuadPart + COPYSUP_MAX_HOLE_SIZE))) {
            retval = FALSE;
            goto done_release_resource;
        }
#endif /* COPYSUP_MAX_HOLE_SIZE */

        if (writepos_end.QuadPart > fo_fcb->AllocationSize.QuadPart) {
            retval = FALSE;
            goto done_release_resource;
        }

        if (fcb_resource_acquired_shared &&
            (writepos_end.QuadPart > fo_fcb->ValidDataLength.QuadPart)) {
            ExReleaseResourceLite(fo_fcb->Resource);

            if (!ExAcquireResourceExclusiveLite(fo_fcb->Resource, Wait)) {
                retval = FALSE;
                goto done_exit_filesystem;
            }

            if (append_file) {
                writepos_start = fo_fcb->FileSize;
                writepos_end.QuadPart = fo_fcb->FileSize.QuadPart + (LONGLONG)Length;
            }

            if ((FObj->PrivateCacheMap == NULL) ||
                (fo_fcb->IsFastIoPossible == FastIoIsNotPossible) ||
                (writepos_end.QuadPart > fo_fcb->AllocationSize.QuadPart)) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (fo_fcb->IsFastIoPossible == FastIoIsQuestionable) {
            PDEVICE_OBJECT RelatedDeviceObject = IoGetRelatedDeviceObject(FObj);
            PFAST_IO_DISPATCH FastIoDispatch =
                RelatedDeviceObject->DriverObject->FastIoDispatch;
            IO_STATUS_BLOCK ios;

            /* This should not happen... */
            if (!((FastIoDispatch != NULL) &&
                (FastIoDispatch->FastIoCheckIfPossible != NULL))) {
                retval = FALSE;
                goto done_release_resource;
            }

            if (!FastIoDispatch->FastIoCheckIfPossible(FObj,
                ((FileOffset->QuadPart != (LONGLONG)-1)?
                    FileOffset:&fo_fcb->FileSize),
                Length,
                Wait,
                LockKey,
                FALSE,
                &ios,
                RelatedDeviceObject)) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (writepos_end.QuadPart > fo_fcb->FileSize.QuadPart) {
            filesize_changed = true;
            filesize_orig = fo_fcb->FileSize;
            validdatalen_orig = fo_fcb->ValidDataLength;

            if ((fo_fcb->FileSize.HighPart != writepos_end.HighPart) &&
                 (fo_fcb->PagingIoResource != NULL)) {
                (void)ExAcquireResourceExclusiveLite(fo_fcb->PagingIoResource, TRUE);
                fo_fcb->FileSize = writepos_end;
                ExReleaseResourceLite(fo_fcb->PagingIoResource);
            }
            else {
                fo_fcb->FileSize = writepos_end;
            }
        }

        IoSetTopLevelIrp((PIRP)TopLevelContext);

        retval = FALSE;
        __try {
            if (writepos_start.QuadPart > fo_fcb->ValidDataLength.QuadPart) {
                retval = CcZeroData(FObj,
                    &fo_fcb->ValidDataLength,
                    &writepos_start,
                    Wait);
            }

            if (retval) {
                retval = CcCopyWrite(FObj,
                    &writepos_start,
                    Length,
                    Wait,
                    Buffer);
            }
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
        }

        IoSetTopLevelIrp(NULL);

        if (retval) {
            if (writepos_end.QuadPart > fo_fcb->ValidDataLength.QuadPart) {
                if ((fo_fcb->ValidDataLength.HighPart != writepos_end.HighPart) &&
                     (fo_fcb->PagingIoResource != NULL)) {
                    (void)ExAcquireResourceExclusiveLite(fo_fcb->PagingIoResource, TRUE);
                    fo_fcb->ValidDataLength = writepos_end;
                    ExReleaseResourceLite(fo_fcb->PagingIoResource);
                }
                else {
                    fo_fcb->ValidDataLength = writepos_end;
                }
            }

            FObj->Flags |= FO_FILE_MODIFIED;

            if (filesize_changed) {
                (*CcGetFileSizePointer(FObj)).QuadPart =
                    writepos_end.QuadPart;
                FObj->Flags |= FO_FILE_SIZE_CHANGED;
            }

            FObj->CurrentByteOffset.QuadPart =
                writepos_start.QuadPart + Length;
        }
        else {
            if (filesize_changed) {
                if (fo_fcb->PagingIoResource != NULL) {
                    (void)ExAcquireResourceExclusiveLite(
                        fo_fcb->PagingIoResource, TRUE);
                }
                fo_fcb->FileSize = filesize_orig;
                fo_fcb->ValidDataLength = validdatalen_orig;
                if (fo_fcb->PagingIoResource != NULL) {
                    ExReleaseResourceLite(fo_fcb->PagingIoResource);
                }
            }
        }
    }
    else {
        ULONG writepos_start = 0L;
        ULONG writepos_end = 0L;
        ULONG filesize_orig = 0L;
        ULONG validdatalen_orig = 0L;
        bool write_beyond4gb;

        writepos_end = FileOffset->LowPart + Length;

        if (append_file || (writepos_end > fo_fcb->ValidDataLength.LowPart)) {
            (void)ExAcquireResourceExclusiveLite(fo_fcb->Resource, TRUE);
        }
        else {
            (void)ExAcquireResourceSharedLite(fo_fcb->Resource, TRUE);
            fcb_resource_acquired_shared = true;
        }

        if (append_file) {
            writepos_start = fo_fcb->FileSize.LowPart;
            writepos_end = fo_fcb->FileSize.LowPart + Length;
            write_beyond4gb =
                writepos_end < fo_fcb->FileSize.LowPart;
        }
        else {
            writepos_start = FileOffset->LowPart;
            writepos_end = FileOffset->LowPart + Length;
            write_beyond4gb =
                (writepos_end < FileOffset->LowPart) ||
                (FileOffset->HighPart != 0);
        }

        if ((FObj->PrivateCacheMap == NULL) ||
            (fo_fcb->IsFastIoPossible == FastIoIsNotPossible) ||
            (writepos_end > fo_fcb->AllocationSize.LowPart)) {
            retval = FALSE;
            goto done_release_resource;
        }

#ifdef COPYSUP_MAX_HOLE_SIZE
        if (writepos_start >=
            (fo_fcb->ValidDataLength.LowPart + COPYSUP_MAX_HOLE_SIZE)) {
            retval = FALSE;
            goto done_release_resource;
        }
#endif /* COPYSUP_MAX_HOLE_SIZE */

        if ((fo_fcb->AllocationSize.HighPart != 0) || write_beyond4gb) {
            retval = FALSE;
            goto done_release_resource;
        }

        if (fcb_resource_acquired_shared && (writepos_end > fo_fcb->ValidDataLength.LowPart)) {
            ExReleaseResourceLite(fo_fcb->Resource);
            (void)ExAcquireResourceExclusiveLite(fo_fcb->Resource, TRUE);

            if (append_file) {
                writepos_start = fo_fcb->FileSize.LowPart;
                writepos_end = fo_fcb->FileSize.LowPart + Length;
                write_beyond4gb = writepos_end < fo_fcb->FileSize.LowPart;
            }

            if ((FObj->PrivateCacheMap == NULL) ||
                (fo_fcb->IsFastIoPossible == FastIoIsNotPossible) ||
                (writepos_end > fo_fcb->AllocationSize.LowPart) ||
                (fo_fcb->AllocationSize.HighPart != 0) || write_beyond4gb) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (fo_fcb->IsFastIoPossible == FastIoIsQuestionable) {
            PDEVICE_OBJECT RelatedDeviceObject = IoGetRelatedDeviceObject(FObj);
            PFAST_IO_DISPATCH FastIoDispatch =
                RelatedDeviceObject->DriverObject->FastIoDispatch;
            IO_STATUS_BLOCK ios;

            /* This should not happen... */
            if (!((FastIoDispatch != NULL) &&
                (FastIoDispatch->FastIoCheckIfPossible != NULL))) {
                retval = FALSE;
                goto done_release_resource;
            }

            if (!FastIoDispatch->FastIoCheckIfPossible(FObj,
                    ((FileOffset->QuadPart != (LONGLONG)-1)?
                        FileOffset:&fo_fcb->FileSize),
                    Length,
                    TRUE,
                    LockKey,
                    FALSE,
                    &ios,
                    RelatedDeviceObject)) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (writepos_end > fo_fcb->FileSize.LowPart) {
            filesize_changed = true;
            filesize_orig = fo_fcb->FileSize.LowPart;
            validdatalen_orig = fo_fcb->ValidDataLength.LowPart;
            fo_fcb->FileSize.LowPart = writepos_end;
        }

        IoSetTopLevelIrp((PIRP)TopLevelContext);

        retval = FALSE;
        __try {
            if (writepos_start > fo_fcb->ValidDataLength.LowPart) {
                LARGE_INTEGER ZeroEnd = {
                    .LowPart = writepos_start,
                    .HighPart = 0L
                };

                CcZeroData(FObj,
                    &fo_fcb->ValidDataLength,
                    &ZeroEnd,
                    TRUE);
            }

            CcFastCopyWrite(FObj,
                writepos_start,
                Length,
                Buffer);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
        }

        IoSetTopLevelIrp(NULL);

        if (retval) {
            if (writepos_end > fo_fcb->ValidDataLength.LowPart) {
                fo_fcb->ValidDataLength.LowPart = writepos_end;
            }

            FObj->Flags |= FO_FILE_MODIFIED;

            if (filesize_changed) {
                CcGetFileSizePointer(FObj)->LowPart = writepos_end;
                FObj->Flags |= FO_FILE_SIZE_CHANGED;
            }

            FObj->CurrentByteOffset.LowPart =
                writepos_start + Length;
            FObj->CurrentByteOffset.HighPart = 0;
        }
        else {
            if (filesize_changed) {
                if (fo_fcb->PagingIoResource != NULL) {
                    (void)ExAcquireResourceExclusiveLite(
                        fo_fcb->PagingIoResource, TRUE);
                }
                fo_fcb->FileSize.LowPart = filesize_orig;
                fo_fcb->ValidDataLength.LowPart = validdatalen_orig;
                if (fo_fcb->PagingIoResource != NULL) {
                    ExReleaseResourceLite(fo_fcb->PagingIoResource);
                }
            }
        }
    }

done_release_resource:
    ExReleaseResourceLite(fo_fcb->Resource);
done_exit_filesystem:
    FsRtlExitFileSystem();
done:
    return retval;
}


#if defined(_ARM_) || defined(_ARM64_)

void __security_push_cookie()
{
}

void __security_pop_cookie()
{
}

#endif /* defined(_ARM_) || defined(_ARM64_) */
