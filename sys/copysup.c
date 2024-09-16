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

#include <rx.h>
#include <windef.h>
#include <winerror.h>
#include <Ntstrsafe.h>
#include <stdbool.h>

#include "nfs41_debug.h"
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
    IN PVOID TopLevelContext)
{
    BOOLEAN retval = TRUE;
    ULONG pagecount;
    LARGE_INTEGER readpos_end;
    PFSRTL_COMMON_FCB_HEADER fo_fcb;

    pagecount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(FileOffset, Length);

    if (Length == 0) {
        IoStatus->Information = 0;
        IoStatus->Status = STATUS_SUCCESS;
        retval = TRUE;
        goto done;
    }

    readpos_end.QuadPart = FileOffset->QuadPart + Length;
    if (readpos_end.QuadPart <= 0) {
        retval = FALSE;
        goto done;
    }

    fo_fcb = FObj->FsContext;

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
        PDEVICE_OBJECT RelatedDeviceObject;
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

        if (!FastIoDispatch->FastIoCheckIfPossible(
            FObj, FileOffset, Length,
            Wait, LockKey, TRUE, IoStatus, RelatedDeviceObject)) {
            retval = FALSE;
            goto done_release_resource;
        }
    }

    if (readpos_end.QuadPart > fo_fcb->FileSize.QuadPart) {
        if (FileOffset->QuadPart >= fo_fcb->FileSize.QuadPart) {
            IoStatus->Information = 0;
            IoStatus->Status = STATUS_END_OF_FILE;
            goto done_release_resource;
        }

        Length =
            (ULONG)(fo_fcb->FileSize.QuadPart - FileOffset->QuadPart);
    }

    IoSetTopLevelIrp(TopLevelContext);

    retval = FALSE;

    __try {
        if ((!Wait) ||
            (readpos_end.HighPart != 0) ||
            (fo_fcb->FileSize.HighPart != 0)) {
            retval = CcCopyRead(FObj, FileOffset, Length, Wait,
                Buffer, IoStatus);
            SetFlag(FObj->Flags, FO_FILE_FAST_IO_READ);

            ASSERT(
                ((ULONGLONG)FileOffset->QuadPart +
                    IoStatus->Information) <=
                (ULONGLONG)fo_fcb->FileSize.QuadPart);
        }
        else {
            CcFastCopyRead(FObj, FileOffset->LowPart, Length,
                pagecount, Buffer, IoStatus);
            retval = TRUE;
            SetFlag(FObj->Flags, FO_FILE_FAST_IO_READ);

            ASSERT((FileOffset->LowPart + IoStatus->Information) <=
                fo_fcb->FileSize.LowPart);
        }

        ASSERT(IoStatus->Status == STATUS_END_OF_FILE);

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
    IN PVOID TopLevelContext)
{
    BOOLEAN retval; /* fixme: |volatile| ? */
    IO_STATUS_BLOCK ios;
    PFSRTL_ADVANCED_FCB_HEADER fo_fcb = FObj->FsContext;
    bool append_file;
    bool fcb_resource_acquired_shared;
    bool filesize_changed = false;
    LARGE_INTEGER filesize_orig = { .QuadPart = 0LL };
    LARGE_INTEGER validdatalength_orig = { .QuadPart = 0LL };
    LARGE_INTEGER writepos_start;
    LARGE_INTEGER writepos_end;

    append_file =
        ((FileOffset->LowPart == FILE_WRITE_TO_END_OF_FILE) &&
        (FileOffset->HighPart == -1));

    if (!CcCanIWrite(FObj, Length, Wait, FALSE)) {
        retval = FALSE;
        goto done;
    }

    if (BooleanFlagOn(FObj->Flags, FO_WRITE_THROUGH)) {
        retval = FALSE;
        goto done;
    }

    if (!CcCopyWriteWontFlush(FObj, FileOffset, Length)) {
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
    if (!Wait || (fo_fcb->AllocationSize.HighPart != 0)) {
#endif /* COPYSUP_FORCE4GBWRITE */
        if (append_file ||
            ((FileOffset->QuadPart + Length) >
                fo_fcb->ValidDataLength.QuadPart)) {
            if (!ExAcquireResourceExclusiveLite(fo_fcb->Resource,
                Wait)) {
                retval = FALSE;
                goto done_exit_filesystem;
            }

            fcb_resource_acquired_shared = false;
        }
        else {
            if (!ExAcquireResourceSharedLite(fo_fcb->Resource, Wait)) {
                retval = FALSE;
                goto done_exit_filesystem;
            }

            fcb_resource_acquired_shared = true;
        }

        if (append_file) {
            writepos_start.QuadPart = fo_fcb->FileSize.QuadPart;
            writepos_end.QuadPart = writepos_start.QuadPart + Length;
        }
        else {
            writepos_start.QuadPart = FileOffset->QuadPart;
            writepos_end.QuadPart = writepos_start.QuadPart + Length;
        }

        if ((FObj->PrivateCacheMap == NULL) ||
            (fo_fcb->IsFastIoPossible == FastIoIsNotPossible)) {
            retval = FALSE;
            goto done_release_resource;
        }

#ifdef COPYSUP_MAX_HOLE_SIZE
        if ((fo_fcb->ValidDataLength.QuadPart +
            COPYSUP_MAX_HOLE_SIZE) <=
                writepos_start.QuadPart) {
            retval = FALSE;
            goto done_release_resource;
        }
#endif /* COPYSUP_MAX_HOLE_SIZE */

        if ((Length > (MAXLONGLONG - writepos_start.QuadPart)) ||
            (fo_fcb->AllocationSize.QuadPart < writepos_end.QuadPart)) {
            retval = FALSE;
            goto done_release_resource;
        }

        if (fcb_resource_acquired_shared &&
            (writepos_end.QuadPart > fo_fcb->ValidDataLength.QuadPart)) {
            ExReleaseResourceLite(fo_fcb->Resource);
            if (!ExAcquireResourceExclusiveLite(fo_fcb->Resource,
                Wait)) {
                retval = FALSE;
                goto done_exit_filesystem;
            }
            fcb_resource_acquired_shared = false;

            if (append_file) {
                writepos_start.QuadPart = fo_fcb->FileSize.QuadPart;
                writepos_end.QuadPart = writepos_start.QuadPart + Length;
            }

            if ((FObj->PrivateCacheMap == NULL) ||
                (fo_fcb->IsFastIoPossible == FastIoIsNotPossible)) {
                retval = FALSE;
                goto done_release_resource;
            }

            if (fo_fcb->AllocationSize.QuadPart < writepos_end.QuadPart) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (fo_fcb->IsFastIoPossible == FastIoIsQuestionable) {
            PDEVICE_OBJECT RelatedDeviceObject;
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
                    &writepos_start, Length, Wait, LockKey,
                    FALSE, &ios,
                RelatedDeviceObject)) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (writepos_end.QuadPart > fo_fcb->FileSize.QuadPart) {
            filesize_changed = TRUE;
            filesize_orig.QuadPart = fo_fcb->FileSize.QuadPart;
            validdatalength_orig.QuadPart =
                fo_fcb->ValidDataLength.QuadPart;

            if ((writepos_end.HighPart != fo_fcb->FileSize.HighPart) &&
                (fo_fcb->PagingIoResource != NULL)) {
                (void)ExAcquireResourceExclusiveLite(
                    fo_fcb->PagingIoResource, TRUE);
                fo_fcb->FileSize.QuadPart = writepos_end.QuadPart;
                ExReleaseResourceLite(fo_fcb->PagingIoResource);
            }
            else {
                fo_fcb->FileSize.QuadPart = writepos_end.QuadPart;
            }
        }

        IoSetTopLevelIrp(TopLevelContext);

        retval = FALSE;

        __try {
            retval = CcCopyWrite(FObj, &writepos_start,
                Length, Wait, Buffer);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
        }

        IoSetTopLevelIrp(NULL);

        if (retval) {
            if (writepos_end.QuadPart >
                fo_fcb->ValidDataLength.QuadPart) {
                if ((writepos_end.HighPart !=
                    fo_fcb->ValidDataLength.HighPart) &&
                    (fo_fcb->PagingIoResource != NULL)) {
                    (void)ExAcquireResourceExclusiveLite(
                        fo_fcb->PagingIoResource, TRUE);
                    fo_fcb->ValidDataLength.QuadPart =
                        writepos_end.QuadPart;
                    ExReleaseResourceLite(fo_fcb->PagingIoResource);
                }
                else {
                    fo_fcb->ValidDataLength.QuadPart =
                        writepos_end.QuadPart;
                }
            }

            SetFlag(FObj->Flags, FO_FILE_MODIFIED);

            if (filesize_changed) {
                (*CcGetFileSizePointer(FObj)).QuadPart =
                    writepos_end.QuadPart;
                SetFlag(FObj->Flags, FO_FILE_SIZE_CHANGED);
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

                fo_fcb->FileSize.QuadPart = filesize_orig.QuadPart;
                fo_fcb->ValidDataLength.QuadPart =
                    validdatalength_orig.QuadPart;

                if (fo_fcb->PagingIoResource != NULL) {
                    ExReleaseResourceLite(fo_fcb->PagingIoResource);
                }
            }
        }
    }
    else {
        bool write_beyond4gb;

        writepos_start.HighPart = 0;
        writepos_end.HighPart = 0;

        if (append_file ||
            ((FileOffset->QuadPart + Length) >
                fo_fcb->ValidDataLength.QuadPart)) {
            (void)ExAcquireResourceExclusiveLite(fo_fcb->Resource,
                TRUE);
            fcb_resource_acquired_shared = false;
        }
        else {
            (void)ExAcquireResourceSharedLite(fo_fcb->Resource, TRUE);
            fcb_resource_acquired_shared = true;
        }

        if (append_file) {
            writepos_start.LowPart = fo_fcb->FileSize.LowPart;
            writepos_end.LowPart = writepos_start.LowPart + Length;
            write_beyond4gb =
                (writepos_end.LowPart < fo_fcb->FileSize.LowPart);
        }
        else {
            writepos_start.LowPart = FileOffset->LowPart;
            writepos_end.LowPart = writepos_start.LowPart + Length;
            write_beyond4gb =
                (writepos_end.LowPart < FileOffset->LowPart) ||
                (FileOffset->HighPart != 0);
        }

        if ((FObj->PrivateCacheMap == NULL) ||
            (fo_fcb->IsFastIoPossible == FastIoIsNotPossible)) {
            retval = FALSE;
            goto done_release_resource;
        }

#ifdef COPYSUP_MAX_HOLE_SIZE
        if (writepos_start.LowPart >=
                (fo_fcb->ValidDataLength.LowPart +
                    COPYSUP_MAX_HOLE_SIZE)) {
            retval = FALSE;
            goto done_release_resource;
        }
#endif /* COPYSUP_MAX_HOLE_SIZE */

        if ((fo_fcb->AllocationSize.LowPart < writepos_end.LowPart) ||
            write_beyond4gb) {
            retval = FALSE;
            goto done_release_resource;
        }

        if (fcb_resource_acquired_shared &&
            (writepos_end.LowPart > fo_fcb->ValidDataLength.LowPart)) {
            ExReleaseResourceLite(fo_fcb->Resource);
            (void)ExAcquireResourceExclusiveLite(fo_fcb->Resource,
                TRUE);

            if (append_file) {
                writepos_start.LowPart = fo_fcb->FileSize.LowPart;
                writepos_end.LowPart = writepos_start.LowPart + Length;
                write_beyond4gb =
                    (writepos_end.LowPart < fo_fcb->FileSize.LowPart);
            }

            if ((FObj->PrivateCacheMap == NULL) ||
                (fo_fcb->IsFastIoPossible == FastIoIsNotPossible)) {
                retval = FALSE;
                goto done_release_resource;
            }

            if (write_beyond4gb ||
                (fo_fcb->AllocationSize.LowPart < writepos_end.LowPart) ||
                (fo_fcb->AllocationSize.HighPart != 0)) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (fo_fcb->IsFastIoPossible == FastIoIsQuestionable) {
            PFAST_IO_DISPATCH FastIoDispatch;
            PDEVICE_OBJECT RelatedDeviceObject;

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
                &writepos_start, Length, Wait, LockKey,
                FALSE, &ios, RelatedDeviceObject)) {
                retval = FALSE;
                goto done_release_resource;
            }
        }

        if (writepos_end.LowPart > fo_fcb->FileSize.LowPart) {
            filesize_changed = true;
            filesize_orig.LowPart = fo_fcb->FileSize.LowPart;
            validdatalength_orig.LowPart =
                fo_fcb->ValidDataLength.LowPart;
            fo_fcb->FileSize.LowPart = writepos_end.LowPart;
        }

        IoSetTopLevelIrp(TopLevelContext);

        retval = FALSE;

        __try {
            CcFastCopyWrite(FObj, writepos_start.LowPart,
                Length, Buffer);
            retval = TRUE;
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
        }

        IoSetTopLevelIrp(NULL);

        if (retval) {
            if (writepos_end.LowPart > fo_fcb->ValidDataLength.LowPart) {
                fo_fcb->ValidDataLength.LowPart = writepos_end.LowPart;
            }

            SetFlag(FObj->Flags, FO_FILE_MODIFIED);

            if (filesize_changed) {
                (*CcGetFileSizePointer(FObj)).LowPart =
                    writepos_end.LowPart;
                SetFlag(FObj->Flags, FO_FILE_SIZE_CHANGED);
            }

            FObj->CurrentByteOffset.LowPart =
                writepos_start.LowPart + Length;
            FObj->CurrentByteOffset.HighPart = 0;
        }
        else {
            if (filesize_changed) {
                if (fo_fcb->PagingIoResource != NULL) {
                    (void)ExAcquireResourceExclusiveLite(
                        fo_fcb->PagingIoResource, TRUE);
                }

                fo_fcb->FileSize.LowPart = filesize_orig.LowPart;
                fo_fcb->ValidDataLength.LowPart = validdatalength_orig.LowPart;

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
