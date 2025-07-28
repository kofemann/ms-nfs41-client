/*
 * MIT License
 *
 * Copyright (c) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * winfsinfo1.c - print Windows filesystem info in ksh93 compound
 * variable format (suiteable for ksh93 $ read -C varnname #)
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#define UNICODE 1
#define _UNICODE 1

#include <io.h>
#include <fcntl.h>
#include <stdio.h>
#include <windows.h>
#include <npapi.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "nfs_ea.h"
#include "from_kernel.h"

static
bool filetime2localsystemtime(const FILETIME *ft, SYSTEMTIME *st)
{
    FILETIME localft;

    if (!FileTimeToLocalFileTime(ft, &localft))
        return false;
    if (!FileTimeToSystemTime(&localft, st))
        return false;
    return true;
}

static
int getuniversalname(const char *progname, const char *filename, DWORD dwInfoLevel)
{
    wchar_t wfilename[4096];
    char buffer[4096];
    DWORD buffersize = 4096;
    DWORD np_res;

    (void)swprintf(wfilename, 4096, L"%s", filename);

    np_res = WNetGetUniversalName(wfilename,
        dwInfoLevel,
        buffer,
        &buffersize);
    if (np_res != WN_SUCCESS) {
        (void)fprintf(stderr,
            "%s: WNetGetUniversalName() failed with error=0x%lx\n",
            progname,
            np_res);
        return EXIT_FAILURE;
    }

    if (dwInfoLevel == UNIVERSAL_NAME_INFO_LEVEL) {
        UNIVERSAL_NAME_INFOW *uni = (UNIVERSAL_NAME_INFOW *)buffer;

        (void)printf("(\n");
        (void)printf("\tfilename='%ls'\n", wfilename);
        (void)printf("\tlpUniversalName='%ls'\n", uni->lpUniversalName);
        (void)printf(")\n");
    }
    else if (dwInfoLevel == REMOTE_NAME_INFO_LEVEL) {
        REMOTE_NAME_INFOW *rni = (REMOTE_NAME_INFOW *)buffer;

        (void)printf("(\n");
        (void)printf("\tfilename='%ls'\n", wfilename);
        (void)printf("\tlpUniversalName='%ls'\n", rni->lpUniversalName);
        (void)printf("\tlpConnectionName='%ls'\n", rni->lpConnectionName);
        (void)printf("\tlpRemainingPath='%ls'\n", rni->lpRemainingPath);
        (void)printf(")\n");
    }
    else {
        (void)fprintf(stderr,
            "%s: unsupported dwInfoLevel=%ld\n",
            progname,
            (long)dwInfoLevel);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static
int getvolumeinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    wchar_t volumeNameBuffer[MAX_PATH+1];
    wchar_t fileSystemNameBuffer[MAX_PATH+1];
    DWORD volumeSerialNumber = 0ULL;
    DWORD maximumComponentLength = 0ULL;

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    DWORD volumeFlags = 0;
    ok = GetVolumeInformationByHandleW(fileHandle,
        volumeNameBuffer,
        sizeof(volumeNameBuffer),
        &volumeSerialNumber,
        &maximumComponentLength,
        &volumeFlags,
        fileSystemNameBuffer,
        sizeof(fileSystemNameBuffer));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetVolumeInformationByHandleW() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);
    (void)printf("\tvolumename='%ls'\n", volumeNameBuffer);
    (void)printf("\tvolumeserialnumber=0x%lx\n", (long)volumeSerialNumber);
    (void)printf("\tmaximumcomponentlength='%lu'\n", (long)maximumComponentLength);
    (void)printf("\tfilesystemname='%ls'\n", fileSystemNameBuffer);

    (void)printf("\ttypeset -A volumeflags=(\n");

#define TESTVOLFLAG(s) \
    if (volumeFlags & (s)) { \
        (void)printf("\t\t['%s']=0x%lx\n", (#s), (unsigned long)(s)); \
        volumeFlags &= ~(s); \
    }

    TESTVOLFLAG(FILE_SUPPORTS_USN_JOURNAL);
    TESTVOLFLAG(FILE_SUPPORTS_OPEN_BY_FILE_ID);
    TESTVOLFLAG(FILE_SUPPORTS_EXTENDED_ATTRIBUTES);
    TESTVOLFLAG(FILE_SUPPORTS_HARD_LINKS);
    TESTVOLFLAG(FILE_SUPPORTS_TRANSACTIONS);
    TESTVOLFLAG(FILE_SEQUENTIAL_WRITE_ONCE);
    TESTVOLFLAG(FILE_READ_ONLY_VOLUME);
    TESTVOLFLAG(FILE_NAMED_STREAMS);
    TESTVOLFLAG(FILE_SUPPORTS_ENCRYPTION);
    TESTVOLFLAG(FILE_SUPPORTS_OBJECT_IDS);
    TESTVOLFLAG(FILE_VOLUME_IS_COMPRESSED);
    TESTVOLFLAG(FILE_SUPPORTS_REMOTE_STORAGE);
    TESTVOLFLAG(FILE_RETURNS_CLEANUP_RESULT_INFO);
    TESTVOLFLAG(FILE_SUPPORTS_POSIX_UNLINK_RENAME);
    TESTVOLFLAG(FILE_SUPPORTS_REPARSE_POINTS);
    TESTVOLFLAG(FILE_SUPPORTS_SPARSE_FILES);
    TESTVOLFLAG(FILE_VOLUME_QUOTAS);
    TESTVOLFLAG(FILE_FILE_COMPRESSION);
    TESTVOLFLAG(FILE_PERSISTENT_ACLS);
    TESTVOLFLAG(FILE_UNICODE_ON_DISK);
    TESTVOLFLAG(FILE_CASE_PRESERVED_NAMES);
    TESTVOLFLAG(FILE_CASE_SENSITIVE_SEARCH);
    TESTVOLFLAG(FILE_SUPPORTS_INTEGRITY_STREAMS);
#ifdef FILE_SUPPORTS_BLOCK_REFCOUNTING
    TESTVOLFLAG(FILE_SUPPORTS_BLOCK_REFCOUNTING);
#endif
#ifdef FILE_SUPPORTS_SPARSE_VDL
    TESTVOLFLAG(FILE_SUPPORTS_SPARSE_VDL);
#endif
#ifdef FILE_DAX_VOLUME
    TESTVOLFLAG(FILE_DAX_VOLUME);
#endif
#ifdef FILE_SUPPORTS_GHOSTING
    TESTVOLFLAG(FILE_SUPPORTS_GHOSTING);
#endif


    /*
     * print any leftover flags not covered by |TESTVOLFLAG(FILE_*)|
     * above
     */
    if (volumeFlags) {
        (void)printf("\t\t['remainingflags']=0x%lx\n",
            (unsigned long)volumeFlags);
    }

    (void)printf("\t)\n");

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

static
int getfinalpath(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    wchar_t buffer[4096];

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    typedef struct _gfpn_ops{
        const char *name;
        DWORD flags;
    } gfpn_ops;

    gfpn_ops opts[] ={
        { .name = "normalized_volume_name_dos",     .flags = FILE_NAME_NORMALIZED|VOLUME_NAME_DOS },
        { .name = "normalized_volume_name_guid",    .flags = FILE_NAME_NORMALIZED|VOLUME_NAME_GUID },
        { .name = "normalized_volume_name_none",    .flags = FILE_NAME_NORMALIZED|VOLUME_NAME_NONE },
        { .name = "normalized_volume_name_nt",      .flags = FILE_NAME_NORMALIZED|VOLUME_NAME_NT },
        { .name = "opened_volume_name_dos",         .flags = FILE_NAME_OPENED|VOLUME_NAME_DOS },
        { .name = "opened_volume_name_guid",        .flags = FILE_NAME_OPENED|VOLUME_NAME_GUID },
        { .name = "opened_volume_name_none",        .flags = FILE_NAME_OPENED|VOLUME_NAME_NONE },
        { .name = "opened_volume_name_nt",          .flags = FILE_NAME_OPENED|VOLUME_NAME_NT },
        { .name = NULL,                             .flags = 0 }
    };

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\ttypeset -A paths=(\n");

    for (gfpn_ops *o = opts ; o->name != NULL ; o++) {
        ok = GetFinalPathNameByHandleW(fileHandle, buffer, 4096, o->flags);
        if (ok) {
            (void)printf("\t\t['%s']='%ls'\n", o->name, buffer);
        }
        else {
            (void)fprintf(stderr, "%s: GetFinalPathNameByHandleW(%s) "
                "error. GetLastError()==%d.\n",
                progname,
                o->name,
                (int)GetLastError());
        }
    }

    (void)printf("\t)\n");
    (void)printf(")\n");
    res = EXIT_SUCCESS;

    (void)CloseHandle(fileHandle);
    return res;
}

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#ifdef _WIN64
#define NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE 1
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_NO_EAS_ON_FILE ((NTSTATUS)0xC0000052)

#ifdef NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE
NTSYSAPI
NTSTATUS
ZwQueryVolumeInformationFile(
    HANDLE               FileHandle,
    PIO_STATUS_BLOCK     IoStatusBlock,
    PVOID                FsInformation,
    ULONG                Length,
    FS_INFORMATION_CLASS FsInformationClass
);

static
int getfilefssectorsizeinformation(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    FILE_FS_SECTOR_SIZE_INFORMATION ffssi = { 0 };
    NTSTATUS status;
    IO_STATUS_BLOCK io;

    status = ZwQueryVolumeInformationFile(fileHandle, &io, &ffssi, sizeof ffssi,
        FileFsSectorSizeInformation);

    switch (status) {
        case STATUS_SUCCESS:
            break;
        default:
            (void)fprintf(stderr, "ZwQueryVolumeInformationFile() failed with 0x%lx\n", (long)status);
            res = EXIT_FAILURE;
            goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tLogicalBytesPerSector=%lu\n",
        (unsigned long)ffssi.LogicalBytesPerSector);
    (void)printf("\tPhysicalBytesPerSectorForAtomicity=%lu\n",
        (unsigned long)ffssi.PhysicalBytesPerSectorForAtomicity);
    (void)printf("\tPhysicalBytesPerSectorForPerformance=%lu\n",
        (unsigned long)ffssi.PhysicalBytesPerSectorForPerformance);
    (void)printf("\t"
        "FileSystemEffectivePhysicalBytesPerSectorForAtomicity=%lu\n",
        (unsigned long)ffssi.FileSystemEffectivePhysicalBytesPerSectorForAtomicity);


    DWORD fssiflags = ffssi.Flags;

    (void)printf("\ttypeset -A Flags=(\n");

#define TESTFSSI(s) \
    if (fssiflags & (s)) { \
        (void)printf("\t\t['%s']=0x%lx\n", (#s), (unsigned long)(s)); \
        fssiflags &= ~(s); \
    }
    TESTFSSI(SSINFO_FLAGS_ALIGNED_DEVICE);
    TESTFSSI(SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE);
    TESTFSSI(SSINFO_FLAGS_NO_SEEK_PENALTY);
    TESTFSSI(SSINFO_FLAGS_TRIM_ENABLED);
    TESTFSSI(SSINFO_FLAGS_BYTE_ADDRESSABLE);

    /*
     * print any leftover flags not covered by |TESTFBIA(FILE_*)|
     * above
     */
    if (fssiflags) {
        (void)printf("\t\t['remainingflags']=0x%lx\n", (unsigned long)fssiflags);
    }

    (void)printf("\t)\n");

    (void)printf("\tByteOffsetForSectorAlignment=%lu\n",
        (unsigned long)ffssi.ByteOffsetForSectorAlignment);
    (void)printf("\tByteOffsetForPartitionAlignment=%lu\n",
        (unsigned long)ffssi.ByteOffsetForPartitionAlignment);

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}
#endif /* NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE */


static
int get_file_basic_info(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_BASIC_INFO finfo;
    (void)memset(&finfo, 0, sizeof(finfo));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle, FileBasicInfo, &finfo,
        sizeof(finfo));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tCreationTime=%lld\n", (long long)finfo.CreationTime.QuadPart);
    (void)printf("\tLastAccessTime=%lld\n", (long long)finfo.LastAccessTime.QuadPart);
    (void)printf("\tLastWriteTime=%lld\n", (long long)finfo.LastWriteTime.QuadPart);
    (void)printf("\tChangeTime=%lld\n", (long long)finfo.ChangeTime.QuadPart);
    DWORD fattr = finfo.FileAttributes;

    (void)printf("\ttypeset -A FileAttributes=(\n");

#define TESTFBIA(s) \
    if (fattr & (s)) { \
        (void)printf("\t\t['%s']=0x%lx\n", (#s), (unsigned long)(s)); \
        fattr &= ~(s); \
    }
    TESTFBIA(FILE_ATTRIBUTE_READONLY);
    TESTFBIA(FILE_ATTRIBUTE_HIDDEN);
    TESTFBIA(FILE_ATTRIBUTE_SYSTEM);
    TESTFBIA(FILE_ATTRIBUTE_DIRECTORY);
    TESTFBIA(FILE_ATTRIBUTE_ARCHIVE);
    TESTFBIA(FILE_ATTRIBUTE_DEVICE);
    TESTFBIA(FILE_ATTRIBUTE_NORMAL);
    TESTFBIA(FILE_ATTRIBUTE_TEMPORARY);
    TESTFBIA(FILE_ATTRIBUTE_SPARSE_FILE);
    TESTFBIA(FILE_ATTRIBUTE_REPARSE_POINT);
    TESTFBIA(FILE_ATTRIBUTE_COMPRESSED);
    TESTFBIA(FILE_ATTRIBUTE_OFFLINE);
    TESTFBIA(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    TESTFBIA(FILE_ATTRIBUTE_ENCRYPTED);
    TESTFBIA(FILE_ATTRIBUTE_INTEGRITY_STREAM);
    TESTFBIA(FILE_ATTRIBUTE_VIRTUAL);
    TESTFBIA(FILE_ATTRIBUTE_NO_SCRUB_DATA);
    TESTFBIA(FILE_ATTRIBUTE_EA);
    TESTFBIA(FILE_ATTRIBUTE_PINNED);
    TESTFBIA(FILE_ATTRIBUTE_UNPINNED);
    TESTFBIA(FILE_ATTRIBUTE_RECALL_ON_OPEN);
    TESTFBIA(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);

    /*
     * print any leftover flags not covered by |TESTFBIA(FILE_*)|
     * above
     */
    if (fattr) {
        (void)printf("\t\t['remainingflags']=0x%lx\n",
            (unsigned long)fattr);
    }

    (void)printf("\t)\n");

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

/*
 * Win10 uses |FileNetworkOpenInformation| to get the information
 * for |GetFileExInfoStandard|
 */
static
int get_fileexinfostandard(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    WIN32_FILE_ATTRIBUTE_DATA finfo;
    (void)memset(&finfo, 0, sizeof(finfo));

    ok = GetFileAttributesExA(filename, GetFileExInfoStandard, &finfo);

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileAttributesExA(filename='%s') "
            "error. GetLastError()==%d.\n",
            progname,
            filename,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    SYSTEMTIME st;

    (void)filetime2localsystemtime(&finfo.ftCreationTime, &st);
    (void)printf("\tftCreationTime='%04d-%02d-%02d %02d:%02d:%02d.%d'\n",
        st.wYear, st.wMonth, st.wDay, st.wHour,
        st.wMinute, st.wSecond, st.wMilliseconds);

    (void)filetime2localsystemtime(&finfo.ftLastAccessTime, &st);
    (void)printf("\tftLastAccessTime='%04d-%02d-%02d %02d:%02d:%02d.%d'\n",
        st.wYear, st.wMonth, st.wDay, st.wHour,
        st.wMinute, st.wSecond, st.wMilliseconds);

    (void)filetime2localsystemtime(&finfo.ftLastWriteTime, &st);
    (void)printf("\tftLastWriteTime='%04d-%02d-%02d %02d:%02d:%02d.%d'\n",
        st.wYear, st.wMonth, st.wDay, st.wHour,
        st.wMinute, st.wSecond, st.wMilliseconds);

    (void)printf("\tnFileSize=%lld\n",
        ((long long)finfo.nFileSizeHigh << 32) | finfo.nFileSizeLow);

    DWORD fattr = finfo.dwFileAttributes;

    (void)printf("\ttypeset -A dwFileAttributes=(\n");

#define TESTFEIS(s) \
    if (fattr & (s)) { \
        (void)printf("\t\t['%s']=0x%lx\n", (#s), (unsigned long)(s)); \
        fattr &= ~(s); \
    }
    TESTFEIS(FILE_ATTRIBUTE_READONLY);
    TESTFEIS(FILE_ATTRIBUTE_HIDDEN);
    TESTFEIS(FILE_ATTRIBUTE_SYSTEM);
    TESTFEIS(FILE_ATTRIBUTE_DIRECTORY);
    TESTFEIS(FILE_ATTRIBUTE_ARCHIVE);
    TESTFEIS(FILE_ATTRIBUTE_DEVICE);
    TESTFEIS(FILE_ATTRIBUTE_NORMAL);
    TESTFEIS(FILE_ATTRIBUTE_TEMPORARY);
    TESTFEIS(FILE_ATTRIBUTE_SPARSE_FILE);
    TESTFEIS(FILE_ATTRIBUTE_REPARSE_POINT);
    TESTFEIS(FILE_ATTRIBUTE_COMPRESSED);
    TESTFEIS(FILE_ATTRIBUTE_OFFLINE);
    TESTFEIS(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    TESTFEIS(FILE_ATTRIBUTE_ENCRYPTED);
    TESTFEIS(FILE_ATTRIBUTE_INTEGRITY_STREAM);
    TESTFEIS(FILE_ATTRIBUTE_VIRTUAL);
    TESTFEIS(FILE_ATTRIBUTE_NO_SCRUB_DATA);
    TESTFEIS(FILE_ATTRIBUTE_EA);
    TESTFEIS(FILE_ATTRIBUTE_PINNED);
    TESTFEIS(FILE_ATTRIBUTE_UNPINNED);
    TESTFEIS(FILE_ATTRIBUTE_RECALL_ON_OPEN);
    TESTFEIS(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS);

    /*
     * print any leftover flags not covered by |TESTFNOI(FILE_*)|
     * above
     */
    if (fattr) {
        (void)printf("\t\t['remainingflags']=0x%lx\n",
            (unsigned long)fattr);
    }

    (void)printf("\t)\n");

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    return res;
}


static
int get_file_standard_info(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_STANDARD_INFO finfo;
    (void)memset(&finfo, 0, sizeof(finfo));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle, FileStandardInfo, &finfo,
        sizeof(finfo));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tAllocationSize=%lld\n", (long long)finfo.AllocationSize.QuadPart);
    (void)printf("\tEndOfFile=%lld\n",      (long long)finfo.EndOfFile.QuadPart);
    (void)printf("\tNumberOfLinks=%ld\n",   (long)finfo.NumberOfLinks);
    (void)printf("\tDeletePending=%s\n",    finfo.DeletePending?"true":"false");
    (void)printf("\tDirectory=%s\n",        finfo.Directory?"true":"false");
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

/*
 * |FILE_NAME_INFORMATION| variation with 4096 bytes, matching
 * Linux |PATH_MAX| value of 4096
 */
typedef struct _FILE_NAME_INFORMATION4096 {
  ULONG FileNameLength;
  WCHAR FileName[4096];
} FILE_NAME_INFORMATION4096, *PFILE_NAME_INFORMATION4096;


/*
 * |FileNameInfo| will get the absolute path of a file with symbolic
 * links resolved
 */
static
int get_filenameinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_NAME_INFORMATION4096 finfo;
    (void)memset(&finfo, 0, sizeof(finfo));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle,
        FileNameInfo,
        &finfo, sizeof(finfo));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tFileNameLength=%ld\n",
        (long)finfo.FileNameLength);
    (void)printf("\tFileName='%S'\n",   finfo.FileName);
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}


static
int get_filenormalizednameinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_NAME_INFORMATION4096 finfo;
    (void)memset(&finfo, 0, sizeof(finfo));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    /*
     * MinGW header bug: Wrong |FileNormalizedNameInfo| value
     * Per
     * https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ne-minwinbase-file_info_by_handle_class
     * |FileNormalizedNameInfo| should be |24|, but with older MinGW
     * headers we get the value |48|.
     * This has been reported as
     * https://github.com/mingw-w64/mingw-w64/issues/48 ("Integer
     * value of |FileNormalizedNameInfo| shifts with Windows
     * version")
     */
    ok = GetFileInformationByHandleEx(fileHandle,
        24/*FileNormalizedNameInfo*/,
        &finfo, sizeof(finfo));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tFileNameLength=%ld\n",
        (long)finfo.FileNameLength);
    (void)printf("\tFileName='%S'\n",   finfo.FileName);
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}


static
int get_filecasesensitiveinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_CASE_SENSITIVE_INFO finfo;
    (void)memset(&finfo, 0, sizeof(finfo));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle,
        23/*FileCaseSensitiveInfo*/,
        &finfo, sizeof(finfo));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\ttypeset -A Flags=(\n");

    ULONG fcsi_flags = finfo.Flags;
#define TESTFCSI(s) \
    if (fcsi_flags & (s)) { \
        (void)printf("\t\t['%s']=0x%lx\n", (#s), (unsigned long)(s)); \
        fcsi_flags &= ~(s); \
    }
    TESTFCSI(FILE_CS_FLAG_CASE_SENSITIVE_DIR);

    /*
     * print any leftover flags not covered by |TESTFCSI(FILE_*)|
     * above
     */
    if (fcsi_flags) {
        (void)printf("\t\t['remainingflags']=0x%lx\n",
            (unsigned long)fcsi_flags);
    }

    (void)printf("\t)\n");

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

static
int get_getfiletime(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILETIME creationTime;
    FILETIME lastAccessTime;
    FILETIME lastWriteTime;

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileTime(fileHandle, &creationTime, &lastAccessTime, &lastWriteTime);

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileTime() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    SYSTEMTIME st;

    (void)filetime2localsystemtime(&creationTime, &st);
    (void)printf("\tcreationTime='%04d-%02d-%02d %02d:%02d:%02d.%d'\n",
        st.wYear, st.wMonth, st.wDay, st.wHour,
        st.wMinute, st.wSecond, st.wMilliseconds);

    (void)filetime2localsystemtime(&lastAccessTime, &st);
    (void)printf("\tlastAccessTime='%04d-%02d-%02d %02d:%02d:%02d.%d'\n",
        st.wYear, st.wMonth, st.wDay, st.wHour,
        st.wMinute, st.wSecond, st.wMilliseconds);

    (void)filetime2localsystemtime(&lastWriteTime, &st);
    (void)printf("\tlastWriteTime='%04d-%02d-%02d %02d:%02d:%02d.%d'\n",
        st.wYear, st.wMonth, st.wDay, st.wHour,
        st.wMinute, st.wSecond, st.wMilliseconds);

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryEaFile(
  IN HANDLE FileHandle,
  OUT PIO_STATUS_BLOCK IoStatusBlock,
  OUT PVOID Buffer,
  IN ULONG Length,
  IN BOOLEAN ReturnSingleEntry,
  IN PVOID EaList OPTIONAL,
  IN ULONG EaListLength,
  IN PULONG EaIndex OPTIONAL,
  IN BOOLEAN RestartScan);

static
int get_nfs3attr(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    struct {
        FILE_FULL_EA_INFORMATION ffeai;
        char buf[sizeof(EA_NFSV3ATTRIBUTES) + sizeof(nfs3_attrs)];
    } ffeai_buf;
    struct {
        FILE_GET_EA_INFORMATION fgeai;
        char buf[sizeof(EA_NFSV3ATTRIBUTES)];
    } fgeai_buf;

    NTSTATUS status;
    IO_STATUS_BLOCK io;

    fgeai_buf.fgeai.NextEntryOffset = 0;
    fgeai_buf.fgeai.EaNameLength = 15;
    (void)strcpy(fgeai_buf.fgeai.EaName, EA_NFSV3ATTRIBUTES);

    status = ZwQueryEaFile(fileHandle, &io,
        &ffeai_buf.ffeai, sizeof(ffeai_buf), TRUE,
        &fgeai_buf.fgeai, sizeof(fgeai_buf), NULL, TRUE);

    switch (status) {
        case STATUS_SUCCESS:
            break;
        case STATUS_NO_EAS_ON_FILE:
            (void)fprintf(stderr, "No EAs on file, status=0x%lx.\n", (long)status);
            res = EXIT_FAILURE;
            goto done;
        default:
            (void)fprintf(stderr, "ZwQueryEaFile() failed with 0x%lx\n", (long)status);
            res = EXIT_FAILURE;
            goto done;
    }

    if (ffeai_buf.ffeai.EaValueLength < sizeof(nfs3_attrs)) {
            (void)fprintf(stderr,
                "EA '%s' size too small (%ld bytes), "
                "expected at least %ld bytes for nfs3_attrs\n",
                EA_NFSV3ATTRIBUTES,
                (long)ffeai_buf.ffeai.EaValueLength,
                (long)sizeof(nfs3_attrs));
            res = EXIT_FAILURE;
            goto done;
    }

    nfs3_attrs *n3a = (nfs3_attrs *)(ffeai_buf.ffeai.EaName
        + ffeai_buf.ffeai.EaNameLength + 1);

    (void)printf("(\n");

    (void)printf("\tfilename='%s'\n"
        "\ttype=%d\n"
        "\tmode=0%o\n"
        "\tnlink=%d\n"
        "\tuid=%d\n\tgid=%d\n"
        "\tsize=%lld\n\tused=%lld\n"
        "\trdev=( specdata1=0x%x specdata2=0x%x )\n"
        "\tfsid=0x%llx\n\tfileid=0x%llx\n"
        "\tatime=( tv_sec=%ld tv_nsec=%lu )\n"
        "\tmtime=( tv_sec=%ld tv_nsec=%lu )\n"
        "\tctime=( tv_sec=%ld tv_nsec=%lu )\n"
        ")\n",
        filename,
        (int)n3a->type,
        (int)n3a->mode,
        (int)n3a->nlink,
        (int)n3a->uid,
        (int)n3a->gid,
        (long long)n3a->size,
        (long long)n3a->used,
        (int)n3a->rdev.specdata1,
        (int)n3a->rdev.specdata2,
        (unsigned long long)n3a->fsid,
        (unsigned long long)n3a->fileid,
        (long)n3a->atime.tv_sec, (unsigned long)n3a->atime.tv_nsec,
        (long)n3a->mtime.tv_sec, (unsigned long)n3a->mtime.tv_nsec,
        (long)n3a->ctime.tv_sec, (unsigned long)n3a->ctime.tv_nsec);
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

static
int get_file_remote_protocol_info(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_REMOTE_PROTOCOL_INFO frpi;
    int i;
    (void)memset(&frpi, 0, sizeof(frpi));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle,
        FileRemoteProtocolInfo, &frpi, sizeof(frpi));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tStructureVersion=%u\n",
        (unsigned int)frpi.StructureVersion);
    (void)printf("\tStructureSize=%u\n",
        (unsigned int)frpi.StructureSize);
    (void)printf("\tProtocol=%ld\n",
        (long)frpi.Protocol);
    (void)printf("\tProtocolMajorVersion=%u\n",
        (unsigned int)frpi.ProtocolMajorVersion);
    (void)printf("\tProtocolMinorVersion=%u\n",
        (unsigned int)frpi.ProtocolMinorVersion);
    (void)printf("\tProtocolRevision=%u\n",
        (unsigned int)frpi.ProtocolRevision);
    (void)printf("\tReserved=0x%x\n",
        (unsigned int)frpi.Reserved);

    (void)printf("\ttypeset -A Flags=(\n");

#define TESTREMOTEPROTOCOLFLAG(s) \
    if (frpi.Flags & (s)) { \
        (void)printf("\t\t['%s']=0x%lx\n", (#s), (unsigned long)(s)); \
        frpi.Flags &= ~(s); \
    }

    TESTREMOTEPROTOCOLFLAG(REMOTE_PROTOCOL_FLAG_LOOPBACK);
    TESTREMOTEPROTOCOLFLAG(REMOTE_PROTOCOL_FLAG_OFFLINE);
    TESTREMOTEPROTOCOLFLAG(REMOTE_PROTOCOL_FLAG_PERSISTENT_HANDLE);
    TESTREMOTEPROTOCOLFLAG(REMOTE_PROTOCOL_FLAG_PRIVACY);
    TESTREMOTEPROTOCOLFLAG(REMOTE_PROTOCOL_FLAG_INTEGRITY);
    TESTREMOTEPROTOCOLFLAG(REMOTE_PROTOCOL_FLAG_MUTUAL_AUTH);

    /*
     * print any leftover flags not covered by
     * |TESTREMOTEPROTOCOLFLAG()| above
     */
    if (frpi.Flags) {
        (void)printf("\t\t['remainingflags']=0x%lx\n",
            (unsigned long)frpi.Flags);
    }

    (void)printf("\t)\n");

    /* GenericReserved */
    (void)printf("\tcompound GenericReserved=(\n");
    (void)printf("\t\ttypeset -a Reserved=(\n");
    for (i=0 ; i < 8 ; i++) {
        (void)printf("\t\t\t[%d]=0x%lx\n",
            i,
            (long)frpi.GenericReserved.Reserved[i]);
    }
    (void)printf("\t\t)\n");
    (void)printf("\t)\n");

#if (_WIN32_WINNT < _WIN32_WINNT_WIN8)
    /* ProtocolSpecificReserved */
    (void)printf("\tcompound ProtocolSpecificReserved=(\n");
    (void)printf("\t\ttypeset -a Reserved=(\n");
    for (i=0 ; i < 16 ; i++) {
        (void)printf("\t\t\t[%d]=0x%lx\n",
            i,
            (long)frpi.ProtocolSpecificReserved.Reserved[i]);
    }
    (void)printf("\t\t)\n");
    (void)printf("\t)\n");
#else
    /* ProtocolSpecific */
    (void)printf("\tcompound ProtocolSpecific=(\n");
    (void)printf("\t\ttypeset -a Reserved=(\n");
    for (i=0 ; i < 16 ; i++) {
        (void)printf("\t\t\t[%d]=0x%lx\n",
            i,
            (long)frpi.ProtocolSpecific.Reserved[i]);
    }
    (void)printf("\t\t)\n");
    (void)printf("\t)\n");
#endif /* (_WIN32_WINNT < _WIN32_WINNT_WIN8) */
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

static
int get_fileidinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;
    FILE_ID_INFO idinfo;
    (void)memset(&idinfo, 0, sizeof(idinfo));

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle,
        FileIdInfo,
        &idinfo, sizeof(idinfo));

    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);

    (void)printf("\tVolumeSerialNumber=0x%llx\n",
        idinfo.VolumeSerialNumber);
    (void)printf("\ttypeset -a FileId=(\n");
    int i;
    for (i=0 ; i < 16 ; i++) {
        (void)printf("\t\t[%d]=0x%02.2x\n",
            i,
            (int)idinfo.FileId.Identifier[i]);
    }
    (void)printf("\t)\n");

    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    (void)CloseHandle(fileHandle);
    return res;
}

static
int fsctlqueryallocatedranges(const char *progname, const char *filename)
{
    HANDLE hFile;

    FILE_STANDARD_INFO finfo;
    bool ok;

    DWORD bytesReturned = 0;
    size_t max_ranges_per_query = 2;
    PFILE_ALLOCATED_RANGE_BUFFER ranges = NULL;
    FILE_ALLOCATED_RANGE_BUFFER inputBuffer;
    /*
     * |lastReturnedRange| - We start counting at |1| for
     * compatibility with "fsutil sparse queryrange"
     */
    size_t lastReturnedRange = 1;
    int retval = 0;
    size_t i;
    size_t cycle;
    DWORD numRangesReturned;
    DWORD lasterr;

    (void)memset(&finfo, 0, sizeof(finfo));

    ranges = malloc((sizeof(FILE_ALLOCATED_RANGE_BUFFER) * max_ranges_per_query));
    if (ranges == NULL) {
        (void)fprintf(stderr, "%s: Error out of memory\n", progname);
        return 1;
    }

    hFile = CreateFileA(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s', lasterr=%d\n",
            progname,
            filename,
            (int)GetLastError());
        return 1;
    }

    ok = GetFileInformationByHandleEx(hFile, FileStandardInfo, &finfo,
        sizeof(finfo));
    if (!ok) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. GetLastError()==%d.\n",
            progname,
            (int)GetLastError());
        retval = 1;
        goto out;
    }

    inputBuffer.FileOffset.QuadPart = 0ULL;
    /*
     * Set |inputBuffer.Length.QuadPart| to a value to query all
     * data ranges in a file
     *
     * Notes:
     * - |FILE_STANDARD_INFO.AllocationSize| can be zero on some
     * filesystems, smaller than |FILE_STANDARD_INFO.EndOfFile|
     * for sparse files and larger than
     * |FILE_STANDARD_INFO.EndOfFile| for normal files, or value
     * set by an user
     * - Also add 1GB (0x40000000) to test the API
     */
    inputBuffer.Length.QuadPart =
        max(finfo.AllocationSize.QuadPart,
            finfo.EndOfFile.QuadPart) +
        0x40000000;

    for (cycle = 0 ; ; cycle ++) {
retry_fsctl:
        if (!DeviceIoControl(hFile,
            FSCTL_QUERY_ALLOCATED_RANGES,
            &inputBuffer,  1*sizeof(FILE_ALLOCATED_RANGE_BUFFER),
            ranges, (sizeof(FILE_ALLOCATED_RANGE_BUFFER) * max_ranges_per_query),
            &bytesReturned,
            NULL)) {
            lasterr = GetLastError();
            if (lasterr == ERROR_MORE_DATA) {
                /*
                 * Windows BUG: NTFS on Win10 returns the number of
                 * bytes we passed in, not the number of bytes which
                 * we should allocate
                 */
                max_ranges_per_query += 16;
                ranges = realloc(ranges,
                    (sizeof(FILE_ALLOCATED_RANGE_BUFFER) * max_ranges_per_query));
                if (ranges == NULL) {
                    (void)fprintf(stderr, "%s: Error out of memory\n",
                        progname);
                    retval = 1;
                    goto out;
                }

                /* |memset(..., 0, ...)| only here for debuging */
                (void)memset(ranges, 0, sizeof(FILE_ALLOCATED_RANGE_BUFFER) * max_ranges_per_query);
                goto retry_fsctl;
            }

            (void)fprintf(stderr,
                "%s: DeviceIoControl() failed, lasterr=%d\n",
                progname,
                (int)lasterr);

            retval = 1;
            goto out;
        }

        numRangesReturned = bytesReturned / sizeof(FILE_ALLOCATED_RANGE_BUFFER);

        if (numRangesReturned > 0) {
            /*
             * If we do more than one query make sure the data range
             * offset we used to start the next query is the same
             * as the first returned data range (both should be
             * identical in offset)
             */
            if (cycle > 0) {
                if ((ranges[0].FileOffset.QuadPart != inputBuffer.FileOffset.QuadPart)) {
                    (void)fprintf(stderr,
                        "%s: Internal error: Restart query did not return "
                        "the same data range offset\n",
                        progname);
                    retval = 1;
                    goto out;
                }
            }

            for (i = 0; i < numRangesReturned; i++) {
                if ((i < max_ranges_per_query) &&
                    ((cycle > 0)?(i > 0):true)) {
                    (void)printf("Data range[%ld]: Offset: 0x%llx, Length: 0x%llx\n",
                        (unsigned long)lastReturnedRange++,
                        (unsigned long long)ranges[i].FileOffset.QuadPart,
                        (unsigned long long)ranges[i].Length.QuadPart);
                }
            }

            inputBuffer.FileOffset.QuadPart = ranges[i-1].FileOffset.QuadPart;
        }

        /* Done ? */
        if (numRangesReturned < max_ranges_per_query)
            break;
    }

out:
    (void)CloseHandle(hFile);
    return retval;
}

typedef struct _FILE_NETWORK_PHYSICAL_NAME_INFORMATION {
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NETWORK_PHYSICAL_NAME_INFORMATION, *PFILE_NETWORK_PHYSICAL_NAME_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryInformationFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID FileInformation,
    _In_ ULONG Length,
    _In_ FILE_INFORMATION_CLASS FileInformationClass
);

static
int get_filenetworkphysicalnameinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    NTSTATUS status;
    IO_STATUS_BLOCK iostatus;
    PFILE_NETWORK_PHYSICAL_NAME_INFORMATION fnpni = NULL;

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

#define FNPNI_MAXCHARS (16384)
    fnpni = calloc(1,
        sizeof(FILE_NETWORK_PHYSICAL_NAME_INFORMATION)+sizeof(wchar_t)*FNPNI_MAXCHARS);
    if (fnpni == NULL) {
         (void)fprintf(stderr,
            "%s: Out of memory.\n",
            progname);
        return EXIT_FAILURE;
    }

    status = ZwQueryInformationFile(fileHandle,
        &iostatus,
        fnpni,
        (sizeof(FILE_NETWORK_PHYSICAL_NAME_INFORMATION)+sizeof(wchar_t)*FNPNI_MAXCHARS),
        FileNetworkPhysicalNameInformation);

    if (status != STATUS_SUCCESS) {
        (void)fprintf(stderr, "%s: GetFileInformationByHandleEx() "
            "error. status==0x%lx.\n",
            progname,
            (long)status);
        res = EXIT_FAILURE;
        goto done;
    }

    (void)printf("(\n");
    (void)printf("\tfilename='%s'\n", filename);
    (void)printf("\tfnpni_FileName='%S'\n",
        fnpni->FileName);
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    free(fnpni);
    (void)CloseHandle(fileHandle);
    return res;
}

static
void usage(void)
{
    (void)fprintf(stderr, "winfsinfo <"
        "getuniversalname_universalnameinfo|"
        "getuniversalname_remotenameinfo|"
        "getvolumeinfo|"
        "getfinalpath|"
#ifdef NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE
        "getfilefssectorsizeinformation|"
#endif /* NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE */
        "filebasicinfo|"
        "fileexinfostandard|"
        "filestandardinfo|"
        "filenameinfo|"
        "filenormalizednameinfo|"
        "filecasesensitiveinfo|"
        "getfiletime|"
        "nfs3attr|"
        "fileremoteprotocolinfo|"
        "fileidinfo|"
        "filenetworkphysicalnameinfo|"
        "fsctlqueryallocatedranges"
        "> path\n");
}

int main(int ac, char *av[])
{
    const char *subcmd;

    /*
     * Force |O_BINARY| mode for stdio so we do not set <CR> to be
     * UNIX/POSIX-compatible, otherwise we would need dos2unix each
     * time to make our output compatble to POSIX sh shell scripts
     */
    (void)_setmode(fileno(stdin), O_BINARY);
    (void)_setmode(fileno(stdout), O_BINARY);
    (void)_setmode(fileno(stderr), O_BINARY);

    if (ac < 3) {
        usage();
        return 2;
    }

    subcmd = av[1];

    if (!strcmp(subcmd, "getuniversalname_universalnameinfo")) {
        return getuniversalname(av[0], av[2], UNIVERSAL_NAME_INFO_LEVEL);
    }
    else if (!strcmp(subcmd, "getuniversalname_remotenameinfo")) {
        return getuniversalname(av[0], av[2], REMOTE_NAME_INFO_LEVEL);
    }
    else if (!strcmp(subcmd, "getvolumeinfo")) {
        return getvolumeinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "getfinalpath")) {
        return getfinalpath(av[0], av[2]);
    }
#ifdef NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE
    else if (!strcmp(subcmd, "getfilefssectorsizeinformation")) {
        return getfilefssectorsizeinformation(av[0], av[2]);
    }
#endif /* NTDLL_HAS_ZWQUERYVOLUMEINFORMATIONFILE */
    else if (!strcmp(subcmd, "filebasicinfo")) {
        return get_file_basic_info(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "fileexinfostandard")) {
        return get_fileexinfostandard(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filestandardinfo")) {
        return get_file_standard_info(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filenameinfo")) {
        return get_filenameinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filenormalizednameinfo")) {
        return get_filenormalizednameinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "getfiletime")) {
        return get_getfiletime(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filecasesensitiveinfo")) {
        return get_filecasesensitiveinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "nfs3attr")) {
        return get_nfs3attr(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "fileremoteprotocolinfo")) {
        return get_file_remote_protocol_info(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "fileidinfo")) {
        return get_fileidinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filenetworkphysicalnameinfo")) {
        return get_filenetworkphysicalnameinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "fsctlqueryallocatedranges")) {
        return fsctlqueryallocatedranges(av[0], av[2]);
    }
    else {
        (void)fprintf(stderr, "%s: Unknown subcmd '%s'\n", av[0], subcmd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
