/*
 * MIT License
 *
 * Copyright (c) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
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

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

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
bool getvolumeinfo(const char *progname, const char *filename)
{
    int res = EXIT_FAILURE;
    bool ok;

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
    ok = GetVolumeInformationByHandleW(fileHandle, NULL, 0,
        NULL, NULL, &volumeFlags, NULL, 0);

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
    (void)printf("\ttypeset -a volumeflags=(\n");

#define TESTVOLFLAG(s) \
    if (volumeFlags & (s)) { \
        (void)puts("\t\t"#s); \
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

    (void)printf("\t)\n");

    /*
     * print any leftover flags not covered by |TESTVOLFLAG(FILE_*)|
     * above
     */
    if (volumeFlags) {
        (void)printf("\tattr=0x%lx\n", (long)volumeFlags);
    }
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    CloseHandle(fileHandle);
    return res;
}


static
bool get_file_basic_info(const char *progname, const char *filename)
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

    (void)printf("\ttypeset -a FileAttributes=(\n");

#define TESTFBIA(s) \
    if (fattr & (s)) { \
        (void)puts("\t\t"#s); \
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

    (void)printf("\t)\n");

    /*
     * print any leftover flags not covered by |TESTFBIA(FILE_*)|
     * above
     */
    if (fattr) {
        (void)printf("\tfattr=0x%lx\n", (long)fattr);
    }
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    CloseHandle(fileHandle);
    return res;
}

/*
 * Win10 uses |FileNetworkOpenInformation| to get the information
 * for |GetFileExInfoStandard|
 */
static
bool get_fileexinfostandard(const char *progname, const char *filename)
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

    (void)printf("\ttypeset -a dwFileAttributes=(\n");

#define TESTFEIS(s) \
    if (fattr & (s)) { \
        (void)puts("\t\t"#s); \
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

    (void)printf("\t)\n");

    /*
     * print any leftover flags not covered by |TESTFNOI(FILE_*)|
     * above
     */
    if (fattr) {
        (void)printf("\tfattr=0x%lx\n", (long)fattr);
    }
    (void)printf(")\n");
    res = EXIT_SUCCESS;

done:
    return res;
}


static
bool get_file_standard_info(const char *progname, const char *filename)
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
    CloseHandle(fileHandle);
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


static
bool get_filenormalizednameinfo(const char *progname, const char *filename)
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
    CloseHandle(fileHandle);
    return res;
}


static
bool get_getfiletime(const char *progname, const char *filename)
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

static
void usage(void)
{
    (void)fprintf(stderr, "winfsinfo <"
        "getvolumeinfo|"
        "filebasicinfo|"
        "fileexinfostandard|"
        "filestandardinfo|"
        "filenormalizednameinfo|"
        "getfiletime"
        "> path\n");
}

int main(int ac, char *av[])
{
    const char *subcmd;

    if (ac < 3) {
        usage();
        return 2;
    }

    subcmd = av[1];

    if (!strcmp(subcmd, "getvolumeinfo")) {
        return getvolumeinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filebasicinfo")) {
        return get_file_basic_info(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "fileexinfostandard")) {
        return get_fileexinfostandard(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filestandardinfo")) {
        return get_file_standard_info(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "filenormalizednameinfo")) {
        return get_filenormalizednameinfo(av[0], av[2]);
    }
    else if (!strcmp(subcmd, "getfiletime")) {
        return get_getfiletime(av[0], av[2]);
    }
    else {
        (void)fprintf(stderr, "%s: Unknown subcmd '%s'\n", av[0], subcmd);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
