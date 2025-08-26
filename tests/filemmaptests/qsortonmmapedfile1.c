
/*
 * MIT License
 *
 * Copyright (c) 2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
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
 * qsortonmmapedfile1.c - test |qsort()| on memory mapped file
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Example usage:
 *
 * builtin cat
 * builtin rm
 * if [[ -f numfile1_orig ]] ; then
 *     for ((i=1*1024*1024 ; i > 0 ; i--)) ; do
 *         printf "%15.15d\n" i
 *     # cat is used for buffering
 *     done | cat >"numfile1_orig"
 * fi
 * set -o xtrace
 *
 * rm -f numfile1
 * cp numfile1_orig numfile1
 * time sort numfile1 -o numfile1_sort_out
 * ls -l numfile1
 * head numfile1
 * time ./qsortonmmapedfile1.exe numfile1
 * head numfile1
 * ls -l numfile1
 * diff -u numfile1 numfile1_sort_out
 */

#define _CRT_SECURE_NO_WARNINGS 1

#include <windows.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

#define RECORD_DATA_SIZE 15
#define RECORD_SIZE (RECORD_DATA_SIZE+1)

static
int compare_records_strcmp(const void *a, const void *b)
{
    return strncmp(a, b, RECORD_DATA_SIZE);
}

int main(int argc, char *argv[])
{
    int res;

    (void)setlocale(LC_ALL, "C");

    if (argc != 2) {
        (void)fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        (void)fprintf(stderr,
            "Note: File must contain 10 ASCII characters per line.\n");
        return EXIT_USAGE;
    }

    const char *filename = argv[1];
    HANDLE hFile = NULL;
    HANDLE hMapping = NULL;
    char *fileView = NULL;

    hFile = CreateFileA(filename,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "Error: Could not open file '%s' for writing (lasterr=%ld)\n",
            filename, (long)GetLastError());
        res = EXIT_FAILURE;
        goto cleanup;
    }

    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMapping == NULL) {
        (void)fprintf(stderr,
            "Error: CreateFileMapping failed (lasterr=%ld)\n",
            (long)GetLastError());
        res = EXIT_FAILURE;
        goto cleanup;
    }

    fileView = (char *)MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
    if (fileView == NULL) {
        (void)fprintf(stderr,
            "Error: MapViewOfFile failed (lasterr=%ld)\n",
            (long)GetLastError());
        res = EXIT_FAILURE;
        goto cleanup;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        (void)fprintf(stderr,
            "Error: Could not get file size (lasterr=%lu)\n",
            (long)GetLastError());
        res = EXIT_FAILURE;
        goto cleanup;
    }

    if (fileSize.QuadPart == 0) {
        printf("File is empty.\n");
        res = EXIT_FAILURE;
        goto cleanup;
    }

    if (fileSize.QuadPart % RECORD_SIZE != 0) {
        (void)fprintf(stderr,
            "Error: File size (%lld) "
            "is not a multiple of the expected record size (%d).\n",
            (long long)fileSize.QuadPart, RECORD_SIZE);
        (void)fprintf(stderr,
            "Please ensure the file uses LF (\\n) line endings "
            "and has 10 chars per line.\n");
        res = EXIT_FAILURE;
        goto cleanup;
    }

    size_t record_count = fileSize.QuadPart / RECORD_SIZE;
    (void)printf("File mapped successfully. Found %zu records to sort.\n",
        record_count);

    (void)printf("Sorting records in-place (lexicographically)...\n");
    qsort(fileView, record_count, RECORD_SIZE, compare_records_strcmp);

    if (!FlushViewOfFile(fileView, 0)) {
        (void)fprintf(stderr,
            "Warning: Could not flush changes to disk (lassterr=%ld)\n",
            (long)GetLastError());
    }

    (void)printf("\nFile has been sorted and saved successfully.\n");
    res = EXIT_SUCCESS;

cleanup:
    if (fileView != NULL) {
        (void)UnmapViewOfFile(fileView);
    }
    if (hMapping != NULL) {
        (void)CloseHandle(hMapping);
    }
    if (hFile != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hFile);
    }

    return res;
}
