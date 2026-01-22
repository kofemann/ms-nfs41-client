/*
 * MIT License
 *
 * Copyright (c) 2004-2026 Roland Mainz <roland.mainz@nrubsig.org>
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
 * winstreamsutil.c - Win32 named streams utility
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Compile with
 * $ clang -target x86_64-pc-windows-gnu -std=gnu17 -Wall -Wextra \
 * -municode -g winstreamsutil.c \
 * -lntdll -o winstreamsutil.exe
 */

#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>

#define	EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

#define NT_MAX_LONG_PATH 4096/*32767*/

static
int lsstream_list_streams(const wchar_t *restrict progname,
    const wchar_t *restrict path,
    bool skip_default_stream,
    bool print_details)
{
    WIN32_FIND_STREAM_DATA sd;
    (void)memset(&sd, 0, sizeof(sd));

    HANDLE h = FindFirstStreamW(path, FindStreamInfoStandard, &sd, 0);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_HANDLE_EOF)
            return EXIT_SUCCESS;
        (void)fwprintf(stderr,
            L"%ls: FindFirstStreamW(path='%ls'), lasterr=%d\n",
            progname, path, (int)e);
        return 3;
    }

    for (;;) {
        if (skip_default_stream) {
            if (wcscmp(sd.cStreamName, L"::$DATA") == 0)
                goto nextstr;
        }

        if (print_details) {
            (void)wprintf(L"filename='%ls%ls' size=%lld\n",
                path,
                sd.cStreamName,
                (long long)sd.StreamSize.QuadPart);
        }
        else {
            (void)wprintf(L"%ls%ls\n", path, sd.cStreamName);
        }

nextstr:
        if (!FindNextStreamW(h, &sd)) {
            DWORD e = GetLastError();
            if (e == ERROR_HANDLE_EOF)
                break;
            (void)fwprintf(stderr,
                L"%ls: FindNextStreamW() returned lasterr=%d\n",
                progname, (int)e);
            (void)FindClose(h);
            return 4;
        }
    }

    (void)FindClose(h);
    return EXIT_SUCCESS;
}

static
int lsstream_walk(const wchar_t *restrict progname,
    const wchar_t *restrict path,
    bool find_recursive,
    bool print_details)
{
    wchar_t pattern[NT_MAX_LONG_PATH];
    (void)swprintf(pattern, NT_MAX_LONG_PATH, L"%ls\\*", path);

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) {
        (void)fwprintf(stderr,
            L"%ls: FindFirstFileW(path=%ls) returned lasterr=%d\n",
            progname, path, (int)GetLastError());
        return EXIT_FAILURE;
    }

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t full[NT_MAX_LONG_PATH];
        (void)swprintf(full, NT_MAX_LONG_PATH, L"%ls\\%ls", path, fd.cFileName);

        lsstream_list_streams(progname, full, true, print_details);

        if (find_recursive && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            lsstream_walk(progname, full, find_recursive, print_details);
        }
    } while (FindNextFileW(h, &fd));

    DWORD e = GetLastError();
    if (e != ERROR_NO_MORE_FILES) {
        (void)fwprintf(stderr,
            L"%ls: FindNextFileW() returned lasterr=%d\n",
            progname, (int)e);
    }

    (void)FindClose(h);
    return EXIT_SUCCESS;
}

static
int cmd_find(int ac, wchar_t *av[])
{
    const wchar_t *progname = av[0];
    bool find_recursive = false;
    bool print_details = false;
    bool print_usage = false;
    int i;
    wchar_t *find_path = NULL;

    for (i=2 ; i < ac ; i++) {
        if (av[i][0] == L'/') {
            if (wcscmp(av[i], L"/?") == 0)
                print_usage = true;
            else if (wcscmp(av[i], L"/s") == 0)
                find_recursive = true;
            else if (wcscmp(av[i], L"/-s") == 0)
                find_recursive = false;
            else if (wcscmp(av[i], L"/l") == 0)
                print_details = true;
            else if (wcscmp(av[i], L"/-l") == 0)
                print_details = false;
            else {
                (void)fwprintf(stderr,
                    L"%ls: Unknown option '%ls'\n", progname, av[i]);
                return EXIT_FAILURE;
            }
        }
        else {
            find_path = av[i];
        }
    }

    if (print_usage) {
        (void)fwprintf(stderr,
            L"Usage: winstreamutil find [/s} [path]\n"
            L"\t/s\tRecurse into subdirs.\n"
            L"\t/l\tPrint details.\n"
            L"\tpath\tPath to search.");
        return EXIT_USAGE;
    }

    if (find_path == NULL) {
        (void)fwprintf(stderr,
            L"%ls: No path given.\n", progname);
            return EXIT_FAILURE;
    }

    lsstream_walk(progname, find_path, find_recursive, print_details);
    return EXIT_SUCCESS;
}

typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _IO_STATUS_BLOCK {
    union { NTSTATUS Status; PVOID Pointer; } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileRenameInformation = 10
} FILE_INFORMATION_CLASS;

typedef struct _FILE_RENAME_INFORMATION {
    BOOLEAN ReplaceIfExists;
    HANDLE  RootDirectory;
    ULONG   FileNameLength;
    WCHAR   FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

NTSTATUS NTAPI NtSetInformationFile(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);
ULONG NTAPI RtlNtStatusToDosError(NTSTATUS);

static
HANDLE OpenForRenameW(const wchar_t *restrict path)
{
    DWORD share  = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    DWORD flags  = FILE_FLAG_BACKUP_SEMANTICS;
    return CreateFileW(path, DELETE | SYNCHRONIZE, share, NULL, OPEN_EXISTING, flags, NULL);
}

static
int cmd_renamestream(int ac, wchar_t *av[])
{
    int res;
    bool print_usage = false;
    int i;
    const wchar_t *progname = av[0];
    wchar_t *base_path = NULL;
    wchar_t *src_streamname = NULL;
    wchar_t *dst_streamname = NULL;

    for (i=2 ; i < ac ; i++) {
        if (av[i][0] == L'/') {
            if (wcscmp(av[i], L"/?") == 0)
                print_usage = true;
            else {
                (void)fwprintf(stderr, L"%ls: Unknown option '%ls'\n",
                    progname, av[i]);
                return EXIT_FAILURE;
            }
        }
        else {
            if (base_path == NULL)
                base_path = av[i];
            else if (src_streamname == NULL)
                src_streamname = av[i];
            else if (dst_streamname == NULL)
                dst_streamname = av[i];
            else {
                (void)fwprintf(stderr,
                    L"%ls: Too many filenames\n", progname);
                return EXIT_FAILURE;
            }
        }
    }

    if ((base_path == NULL) && (src_streamname == NULL) && (dst_streamname == NULL))
        print_usage = true;

    if (print_usage) {
        (void)fwprintf(stderr,
            L"Usage: winstreamutil renamestream path srcstreamname dststreamname\n"
            L"\tpath\tPath of base file/dir (e.g. C:\\foo.txt)\n"
            L"\tsrcstreamname\tsrc stream name (e.g. \":mystr1:$DATA\")\n"
            L"\tdststreamname\tdst stream name (e.g. \":mystr2:$DATA\")\n");
        return EXIT_USAGE;
    }

    if ((base_path == NULL) || (src_streamname == NULL) || (dst_streamname == NULL)) {
        (void)fwprintf(stderr,
            L"%ls: Missing paths/stream.\n", progname);
            return EXIT_FAILURE;
    }

    if ((src_streamname[0] != L':') || (dst_streamname[0] != L':')) {
        (void)fwprintf(stderr,
            L"%ls: Stream names must start with ':'\n", progname);
            return EXIT_FAILURE;
    }

    PFILE_RENAME_INFORMATION fri = calloc(1,
        sizeof(FILE_RENAME_INFORMATION)+256*sizeof(wchar_t));
    if (fri == NULL) {
        (void)fwprintf(stderr,
            L"%ls: Out of memory for fri.\n", progname);
            return EXIT_FAILURE;
    }

    wchar_t src_stream_path[NT_MAX_LONG_PATH];
    (void)swprintf(src_stream_path, NT_MAX_LONG_PATH,
        L"%ls%ls", base_path, src_streamname);

    HANDLE bh = OpenForRenameW(src_stream_path);
    if (bh == INVALID_HANDLE_VALUE) {
        (void)fwprintf(stderr,
            L"%ls: Cannot open src stream '%ls', lasterr=%d\n",
            progname,
            src_stream_path, (int)GetLastError());
        free(fri);
        return EXIT_FAILURE;
    }

    fri->ReplaceIfExists = FALSE;
    fri->RootDirectory   = NULL;
    fri->FileNameLength  = wcslen(dst_streamname)*sizeof(wchar_t);
    (void)wcscpy(fri->FileName, dst_streamname);

    IO_STATUS_BLOCK iosb = { 0 };
    NTSTATUS status = NtSetInformationFile(bh, &iosb,
        fri,
        (sizeof(FILE_RENAME_INFORMATION)+fri->FileNameLength),
        FileRenameInformation);

    bool ok = (bool)NT_SUCCESS(status);
    if (ok) {
        (void)fwprintf(stdout, L"Renamed stream '%ls%ls' to '%ls%ls'.\n",
            base_path, src_streamname,
            base_path, dst_streamname);
        res = EXIT_SUCCESS;
    }
    else {
        (void)fwprintf(stderr,
            L"%ls: Renaming stream '%ls%ls' to '%ls%ls' failed with lasterr=%d\n",
            progname,
            base_path, src_streamname,
            base_path, dst_streamname,
            (int)RtlNtStatusToDosError(status));
        res = EXIT_FAILURE;
    }

    (void)CloseHandle(bh);
    free(fri);

    return res;
}

static
int cmd_deletestream(int ac, wchar_t *av[])
{
    int res;
    bool print_usage = false;
    int i;
    const wchar_t *progname = av[0];
    wchar_t *base_path = NULL;
    wchar_t *streamname = NULL;

    for (i=2 ; i < ac ; i++) {
        if (av[i][0] == L'/') {
            if (wcscmp(av[i], L"/?") == 0)
                print_usage = true;
            else {
                (void)fwprintf(stderr,
                    L"%ls: Unknown option '%ls'\n",
                    progname, av[i]);
                return EXIT_FAILURE;
            }
        }
        else {
            if (base_path == NULL)
                base_path = av[i];
            else if (streamname == NULL)
                streamname = av[i];
            else {
                (void)fwprintf(stderr,
                    L"%ls: Too many filenames\n",
                    progname);
                return EXIT_FAILURE;
            }
        }
    }

    if ((base_path == NULL) && (streamname == NULL))
        print_usage = true;

    if (print_usage) {
        (void)fwprintf(stderr,
            L"Usage: winstreamutil deletestream path streamname\n"
            L"\tpath\tPath of base file/dir (e.g. C:\\foo.txt)\n"
            L"\tstreamname\tdst stream name (e.g. \":mystr2:$DATA\")\n");
        return EXIT_USAGE;
    }

    if ((base_path == NULL) || (streamname == NULL)) {
        (void)fwprintf(stderr,
            L"%ls: Missing paths/stream.\n", progname);
            return EXIT_FAILURE;
    }

    if (streamname[0] != L':') {
        (void)fwprintf(stderr,
            L"%ls: Stream names must start with ':'\n", progname);
            return EXIT_FAILURE;
    }

    wchar_t stream_path[NT_MAX_LONG_PATH];
    (void)swprintf(stream_path, NT_MAX_LONG_PATH,
        L"%ls%ls", base_path, streamname);

    bool ok = (bool)DeleteFileW(stream_path);
    if (ok) {
        (void)fwprintf(stdout, L"Deleted stream '%ls%ls'.\n",
            base_path, streamname);
        res = EXIT_SUCCESS;
    }
    else {
        (void)fwprintf(stderr,
            L"%ls: Delete failed with lasterr=%d\n",
            progname, (int)GetLastError());
        res = EXIT_FAILURE;
    }

    return res;
}

static
int cmd_info(int ac, wchar_t *av[])
{
    int res = EXIT_FAILURE;
    bool ok;
    PFILE_STREAM_INFO fsi = NULL;

    bool print_usage = false;
    int i;
    const wchar_t *progname = av[0];
    const wchar_t *filename = NULL;

    for (i=2 ; i < ac ; i++) {
        if (av[i][0] == L'/') {
            if (wcscmp(av[i], L"/?") == 0)
                print_usage = true;
            else {
                (void)fwprintf(stderr,
                    L"%ls: Unknown option '%ls'\n",
                    progname, av[i]);
                return EXIT_FAILURE;
            }
        }
        else {
            if (filename == NULL)
                filename = av[i];
            else {
                (void)fwprintf(stderr,
                    L"%ls: Too many filenames\n", progname);
                return EXIT_FAILURE;
            }
        }
    }

    if (filename == NULL)
        print_usage = true;

    if (print_usage) {
        (void)fwprintf(stderr,
            L"Usage: winstreamutil info path\n"
            L"\tpath\tPath of base file/dir (e.g. C:\\foo.txt)\n");
        return EXIT_USAGE;
    }

    HANDLE fileHandle = CreateFileW(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fwprintf(stderr,
            L"%ls: Error opening file '%ls', lasterr=%d.\n",
            progname,
            filename,
            (int)GetLastError());
        return EXIT_FAILURE;
    }

#define MAX_STREAM_INFOS (16)
#define FSI_MAXCHARS (256)
    size_t fsi_size = (sizeof(FILE_STREAM_INFO)+sizeof(wchar_t)*FSI_MAXCHARS)*MAX_STREAM_INFOS;
    fsi = calloc(1, fsi_size);
    if (fsi == NULL) {
         (void)fwprintf(stderr,
            L"%ls: Out of memory.\n",
            progname);
        return EXIT_FAILURE;
    }

    ok = GetFileInformationByHandleEx(fileHandle,
        FileStreamInfo,
        fsi, fsi_size);

    if (!ok) {
        (void)fwprintf(stderr,
            L"%ls: GetFileInformationByHandleEx() error, lasterr=%d.\n",
            progname,
            (int)GetLastError());
        res = EXIT_FAILURE;
        goto done;
    }

    int streamindex;
    const FILE_STREAM_INFO *stream;

    /*
     * Output data as ksh93 compound variable (CPV), ksh93 can read+print
     * this format with $ typeset -C var ; read -C var ; print -v var #
     */
    (void)wprintf(L"(\n");
    (void)wprintf(L"\tfilename='%ls'\n", filename);
    (void)wprintf(L"\ttypeset -a streams=(\n");

    for (stream = fsi, streamindex = 0 ; ; streamindex++) {
        (void)wprintf(L"\t\t[%d]=(\n", streamindex);
        (void)wprintf(L"\t\t\tStreamName='%.*ls'\n",
            (int)(stream->StreamNameLength/sizeof(WCHAR)),
            stream->StreamName);
        (void)wprintf(L"\t\t\tStreamSize=%lld\n",
            (long long)stream->StreamSize.QuadPart);
        (void)wprintf(L"\t\t\tStreamAllocationSize=%lld\n",
            (long long)stream->StreamAllocationSize.QuadPart);
        (void)wprintf(L"\t\t)\n");

        if (stream->NextEntryOffset == 0)
            break;

        stream = (const FILE_STREAM_INFO *)(((char *)stream) + stream->NextEntryOffset);
    }
    (void)wprintf(L"\t)\n");
    (void)wprintf(L")\n");

    res = EXIT_SUCCESS;

done:
    free(fsi);
    (void)CloseHandle(fileHandle);
    return res;
}

static
void usage(const wchar_t *restrict progname)
{
    (void)fwprintf(stderr,
        L"%ls: Win32 named streams utility\n"
        L"(written by Roland Mainz <roland.mainz@nrubsig.org> "
        L"for the ms-nfs41-client project)\n\n"
        L"Available commands:\n"
        L"info\tprint info about a stream as ksh93 compound variable\n"
        L"find\tfind all non-default named streams in path\n"
        L"renamestream\trename stream\n"
        L"deletestream\tdelete stream\n",
        progname);
}

int wmain(int ac, wchar_t *av[])
{
    if (ac < 2) {
        (void)usage(av[0]);
        return EXIT_USAGE;
    }

    /*
     * FIXME: ToDO: Add more sub commands:
     * createnew, cat
     */

    if (wcscmp(av[1], L"info") == 0) {
        return cmd_info(ac, av);
    }
    else if (wcscmp(av[1], L"find") == 0) {
        return cmd_find(ac, av);
    }
    else if (wcscmp(av[1], L"renamestream") == 0) {
        return cmd_renamestream(ac, av);
    }
    else if (wcscmp(av[1], L"deletestream") == 0) {
        return cmd_deletestream(ac, av);
    }
    else {
        (void)fwprintf(stderr,
            L"%ls: Unknown subcmd '%ls':\n",
            av[0], av[1]);
    }

    return EXIT_SUCCESS;
}
