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
 * winoffloadcopyfile.c - copy a file with Win32
 * |FSCTL_OFFLOAD_READ|+|FSCTL_OFFLOAD_WRITE|
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

#ifndef FSCTL_OFFLOAD_READ
#define FSCTL_OFFLOAD_READ  \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 153, METHOD_BUFFERED, FILE_READ_ACCESS)
#endif /* !FSCTL_OFFLOAD_READ */
#ifndef FSCTL_OFFLOAD_WRITE
#define FSCTL_OFFLOAD_WRITE \
    CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 154, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif /* !FSCTL_OFFLOAD_WRITE */

/* MinGW headers are currently missing these defines and types */
#ifndef OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND_CURRENT_RANGE
typedef struct _FSCTL_OFFLOAD_READ_INPUT {
    DWORD Size;
    DWORD Flags;
    DWORD TokenTimeToLive;
    DWORD Reserved;
    DWORDLONG FileOffset;
    DWORDLONG CopyLength;
} FSCTL_OFFLOAD_READ_INPUT, *PFSCTL_OFFLOAD_READ_INPUT;

typedef struct _FSCTL_OFFLOAD_READ_OUTPUT {
    DWORD Size;
    DWORD Flags;
    DWORDLONG TransferLength;
    BYTE  Token[512];
} FSCTL_OFFLOAD_READ_OUTPUT, *PFSCTL_OFFLOAD_READ_OUTPUT;

#define OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND_CURRENT_RANGE (1)

typedef struct _FSCTL_OFFLOAD_WRITE_INPUT {
    DWORD Size;
    DWORD Flags;
    DWORDLONG FileOffset;
    DWORDLONG CopyLength;
    DWORDLONG TransferOffset;
    BYTE  Token[512];
} FSCTL_OFFLOAD_WRITE_INPUT, *PFSCTL_OFFLOAD_WRITE_INPUT;

typedef struct _FSCTL_OFFLOAD_WRITE_OUTPUT {
    DWORD Size;
    DWORD Flags;
    DWORDLONG LengthWritten;
} FSCTL_OFFLOAD_WRITE_OUTPUT, *PFSCTL_OFFLOAD_WRITE_OUTPUT;
#endif /* OFFLOAD_READ_FLAG_ALL_ZERO_BEYOND_CURRENT_RANGE */

#ifndef STORAGE_OFFLOAD_MAX_TOKEN_LENGTH
#define STORAGE_OFFLOAD_MAX_TOKEN_LENGTH        (512)
#define STORAGE_OFFLOAD_TOKEN_ID_LENGTH         (0x1F8)
#define STORAGE_OFFLOAD_TOKEN_TYPE_ZERO_DATA    (0xFFFF0001)

typedef struct _STORAGE_OFFLOAD_TOKEN {

    BYTE  TokenType[4];
    BYTE  Reserved[2];
    BYTE  TokenIdLength[2];
    union {
        struct {
            BYTE    Reserved2[STORAGE_OFFLOAD_TOKEN_ID_LENGTH];
        } StorageOffloadZeroDataToken;
        BYTE        Token[STORAGE_OFFLOAD_TOKEN_ID_LENGTH];
    } DUMMYUNIONNAME;
} STORAGE_OFFLOAD_TOKEN, *PSTORAGE_OFFLOAD_TOKEN;
#endif /* STORAGE_OFFLOAD_MAX_TOKEN_LENGTH */

static
void print_usage(const char *av0)
{
    (void)fprintf(stderr,
        "Usage: %s [--copychunksize <numbytes>] <infile> <outfile>\n",
        av0);
}

static
BOOL offloadcopy(
    HANDLE hSrc,
    HANDLE hDest,
    LONGLONG src_offset,
    LONGLONG dst_offset,
    LONGLONG copy_length,
    LONGLONG *pBytesCopied)
{
    BOOL bSuccess;
    DWORD ioctlBytesReturned = 0;

    BYTE tokenBuffer[STORAGE_OFFLOAD_MAX_TOKEN_LENGTH] = { 0 };
    PSTORAGE_OFFLOAD_TOKEN pToken = (PSTORAGE_OFFLOAD_TOKEN)tokenBuffer;

    FSCTL_OFFLOAD_READ_INPUT readInput = { 0 };
    readInput.Size = sizeof(FSCTL_OFFLOAD_READ_INPUT);
    readInput.FileOffset = src_offset;
    readInput.CopyLength = copy_length;

    FSCTL_OFFLOAD_READ_OUTPUT readOutput = { 0 };
    readOutput.Size = sizeof(FSCTL_OFFLOAD_READ_OUTPUT);

    bSuccess = DeviceIoControl(
        hSrc,
        FSCTL_OFFLOAD_READ,
        &readInput,
        sizeof(readInput),
        &readOutput,
        sizeof(readOutput),
        &ioctlBytesReturned,
        NULL);

    if (!bSuccess) {
        (void)fprintf(stderr,
            "FSCTL_OFFLOAD_READ failed, lasterr=%d\n",
            (int)GetLastError());
        return FALSE;
    }

    (void)memcpy(pToken, readOutput.Token, sizeof(tokenBuffer));

    FSCTL_OFFLOAD_WRITE_INPUT writeInput = { 0 };
    writeInput.Size = sizeof(FSCTL_OFFLOAD_WRITE_INPUT);
    writeInput.FileOffset = dst_offset;
    writeInput.CopyLength = copy_length;
    writeInput.TransferOffset = 0LL;
    (void)memcpy(writeInput.Token, pToken, sizeof(tokenBuffer));

    FSCTL_OFFLOAD_WRITE_OUTPUT writeOutput = { 0 };
    writeOutput.Size = sizeof(FSCTL_OFFLOAD_WRITE_OUTPUT);

    (void)printf("Performing copy with FSCTL_OFFLOAD_WRITE...\n");
    bSuccess = DeviceIoControl(
        hDest,
        FSCTL_OFFLOAD_WRITE,
        &writeInput,
        sizeof(writeInput),
        &writeOutput,
        sizeof(writeOutput),
        &ioctlBytesReturned,
        NULL);

    if (!bSuccess) {
        (void)fprintf(stderr,
            "FSCTL_OFFLOAD_WRITE failed, lasterr=%d\n",
            (int)GetLastError());
        return FALSE;
    }

    *pBytesCopied = writeOutput.LengthWritten;

    (void)printf("Offload write successful. Bytes written: %lld\n",
        (long long)*pBytesCopied);
    (void)printf("Offloaded copy completed successfully!\n");

    return TRUE;
}

int main(int ac, char *av[])
{
    int retval = EXIT_FAILURE;
    LONGLONG maxCopyChunkSize =
        1024LL*1024LL*1024LL*1024LL*1024LL; /* 1PB */
    const char *srcFilename;
    const char *destFilename;

    if (ac == 3) {
        srcFilename = av[1];
        destFilename = av[2];
    }
    else if (ac == 5) {
        if (strcmp(av[1], "--copychunksize") != 0) {
            print_usage(av[0]);
            return (EXIT_USAGE);
        }

        maxCopyChunkSize = atoll(av[2]);
        srcFilename = av[3];
        destFilename = av[4];
    }
    else {
        print_usage(av[0]);
        return (EXIT_USAGE);
    }

    HANDLE hSrc = INVALID_HANDLE_VALUE;
    HANDLE hDest = INVALID_HANDLE_VALUE;

    if (ac == 3) {
        (void)printf("# Attempting offloded copy from '%s' to '%s' using "
            "FSCTL_OFFLOAD_READ+FSCTL_OFFLOAD_WRITE...\n",
            srcFilename,
            destFilename);
    }
    else if (ac == 5) {
        (void)printf("# Attempting offloded copy from '%s' to '%s' in "
            "%lld byte chunks using "
            "FSCTL_OFFLOAD_READ+FSCTL_OFFLOAD_WRITE...\n",
            srcFilename,
            destFilename,
            maxCopyChunkSize);
    }

    hSrc = CreateFileA(srcFilename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "Cannot open src file, lasterr=%d\n",
            (int)GetLastError());
        goto cleanup;
    }

    hDest = CreateFileA(destFilename,
        GENERIC_ALL,
        FILE_SHARE_DELETE|FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hDest == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "Cannot open dst file, lasterr=%d\n",
            (int)GetLastError());
        goto cleanup;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hSrc, &fileSize)) {
        (void)fprintf(stderr,
            "Cannot src file size, lasterr=%d\n",
            (int)GetLastError());
        goto cleanup;
    }

    /*
     * Extend destination file
     */
    if (!SetFilePointerEx(hDest, fileSize, NULL, FILE_BEGIN)) {
        (void)fprintf(stderr,
            "Cannot set dest file pointer, lasterr=%d\n",
            (int)GetLastError());
        goto cleanup;
    }

    if (!SetEndOfFile(hDest)) {
        (void)fprintf(stderr,
            "Cannot set dest file size, lasterr=%d\n",
            (int)GetLastError());
        goto cleanup;
    }

    LONGLONG bytesCopied = 0LL;
    LONGLONG byteCount = fileSize.QuadPart;
    LONGLONG copyOffset = 0LL;
    BOOL bResult;

    while (byteCount > 0) {
        (void)printf("# offloadcopy: copyOffset=%lld)\n",
            copyOffset);

        bResult = offloadcopy(hSrc,
            hDest,
            copyOffset,
            copyOffset,
            __min(byteCount, maxCopyChunkSize),
            &bytesCopied);

        if (!bResult) {
            goto cleanup;
        }

        byteCount -= bytesCopied;
        copyOffset += bytesCopied;
    }

    (void)printf("# Successfully used offload read+write to copy '%s' to '%s'!\n",
        srcFilename,
        destFilename);
    retval = EXIT_SUCCESS;

cleanup:
    if ((retval != EXIT_SUCCESS) && (hDest != INVALID_HANDLE_VALUE)) {
        (void)printf("# Failure, deleting destination file...\n");

        FILE_DISPOSITION_INFO di = { .DeleteFile = TRUE };
        bResult = SetFileInformationByHandle(hDest,
            FileDispositionInfo, &di, sizeof(di));
        if (!bResult) {
            (void)fprintf(stderr,
                "Cannot mark destination file for deletion, lasterr=%d\n",
                (int)GetLastError());
        }
    }

    if (hSrc != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hSrc);
    }
    if (hDest != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hDest);
    }

    return retval;
}
