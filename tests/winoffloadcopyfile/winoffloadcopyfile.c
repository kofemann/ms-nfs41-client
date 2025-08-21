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
 * winoffloadcopyfile.c - clone a file
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define EXIT_USAGE (2)

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

int main(int argc, char* argv[])
{
    int retval = EXIT_FAILURE;

    if (argc != 3) {
        (void)fprintf(stderr,
            "Usage: %s <source_file> <destination_file>\n",
            argv[0]);
        return EXIT_USAGE;
    }

    const char *srcFilename = argv[1];
    const char *destFilename = argv[2];
    HANDLE hSrc = INVALID_HANDLE_VALUE;
    HANDLE hDest = INVALID_HANDLE_VALUE;
    BOOL bSuccess = FALSE;
    DWORD ioctlBytesReturned = 0;

    BYTE tokenBuffer[STORAGE_OFFLOAD_MAX_TOKEN_LENGTH] = { 0 };
    PSTORAGE_OFFLOAD_TOKEN pToken = (PSTORAGE_OFFLOAD_TOKEN)tokenBuffer;

    (void)printf("Attempting offloaded copy from '%s' to '%s'\n",
        srcFilename,
        destFilename);

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

    FSCTL_OFFLOAD_READ_INPUT readInput = { 0 };
    readInput.Size = sizeof(FSCTL_OFFLOAD_READ_INPUT);
    readInput.FileOffset = 0;
    readInput.CopyLength = fileSize.QuadPart;

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
        goto cleanup;
    }

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

    (void)memcpy(pToken, readOutput.Token, sizeof(tokenBuffer));

    FSCTL_OFFLOAD_WRITE_INPUT writeInput = { 0 };
    writeInput.Size = sizeof(FSCTL_OFFLOAD_WRITE_INPUT);
    writeInput.FileOffset = 0;
    writeInput.CopyLength = fileSize.QuadPart;
    writeInput.TransferOffset = 0;
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
        goto cleanup;
    }

    (void)printf("Offload write successful. Bytes written: %lld\n",
        (long long)writeOutput.LengthWritten);
    (void)printf("Offloaded copy completed successfully!\n");
    retval = EXIT_SUCCESS;

cleanup:
    if (hSrc != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hSrc);
    }
    if (hDest != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hDest);
    }

    return retval;
}
