
/*
 * MIT License
 *
 * Copyright (c) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
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
 * winclonefile.c - clone a file
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define EXIT_USAGE (2)

#if 1
/*
 * MinGW include do not define |DUPLICATE_EXTENTS_DATA| yet,
 * see https://github.com/mingw-w64/mingw-w64/issues/90
 * ("[mingw-w64/mingw-w64] No |DUPLICATE_EXTENTS_DATA|/
 * |DUPLICATE_EXTENTS_DATA_EX| in MinGW includes")
 */
typedef struct _DUPLICATE_EXTENTS_DATA {
    HANDLE FileHandle;
    LARGE_INTEGER SourceFileOffset;
    LARGE_INTEGER TargetFileOffset;
    LARGE_INTEGER ByteCount;
} DUPLICATE_EXTENTS_DATA, *PDUPLICATE_EXTENTS_DATA;
#endif


void
PrintWin32Error(const char *functionName, DWORD lasterrCode)
{
    char *lpMsgBuf;

    (void)FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        lasterrCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0, NULL);

    (void)fprintf(stderr,
        "%s failed with error %lu: %s\n",
        functionName,
        (unsigned long)lasterrCode,
        lpMsgBuf);

    LocalFree(lpMsgBuf);
}

int
main(int ac, char *av[])
{
    const char* srcFileName;
    const char* dstFileName;
    HANDLE hSrc = INVALID_HANDLE_VALUE;
    HANDLE hDst = INVALID_HANDLE_VALUE;
    BOOL bResult = FALSE;
    LARGE_INTEGER fileSize = { .QuadPart = 0LL };
    DUPLICATE_EXTENTS_DATA ded = {
        .FileHandle = INVALID_HANDLE_VALUE,
        .SourceFileOffset.QuadPart = 0LL,
        .TargetFileOffset.QuadPart = 0LL,
        .ByteCount.QuadPart = 0LL
    };
    DWORD bytesReturnedDummy = 0; /* dummy var */

    if (ac != 3) {
        (void)fprintf(stderr, "Usage: %s <infile> <outfile>\n", av[0]);
        return (EXIT_USAGE);
    }

    srcFileName = av[1];
    dstFileName = av[2];

    (void)printf("# Attempting to clone existing file '%s' to '%s' "
        "using FSCTL_DUPLICATE_EXTENTS_TO_FILE...\n",
        srcFileName,
        dstFileName);

    hSrc = CreateFileA(
        srcFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hSrc == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileA (source read)",
            GetLastError());
        goto cleanup;
    }
    (void)printf("# Successfully opened existing source file '%s'.\n",
        srcFileName);

    bResult = GetFileSizeEx(hSrc, &fileSize);
    if (!bResult) {
        PrintWin32Error("GetFileSizeEx",
            GetLastError());
        goto cleanup;
    }

    if (fileSize.QuadPart == 0LL) {
        (void)fprintf(stderr,
            "# [NOTE] Source file '%s' is empty, "
            "cloning will result in an empty file.\n",
            srcFileName);
    }

    (void)printf("Source file size: %lld bytes.\n",
        fileSize.QuadPart);

    /* Get cluster size */
    FILE_STORAGE_INFO fsi = { 0 };
    bResult = GetFileInformationByHandleEx(hSrc,
        FileStorageInfo, &fsi, sizeof(fsi));
    if (!bResult) {
        PrintWin32Error("FileStorageInfo",
            GetLastError());
        goto cleanup;
    }

    unsigned long long srcClusterSize =
        fsi.PhysicalBytesPerSectorForAtomicity;
    (void)printf("src file cluster size=%llu\n", srcClusterSize);

    hDst = CreateFileA(
        dstFileName,
        GENERIC_ALL,
        FILE_SHARE_DELETE|FILE_SHARE_WRITE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDst == INVALID_HANDLE_VALUE) {
        PrintWin32Error("CreateFileA (destination)",
            GetLastError());
        goto cleanup;
    }

    if (fileSize.QuadPart > 0LL) {
        if (!SetFilePointerEx(hDst, fileSize, NULL, FILE_BEGIN)) {
             PrintWin32Error("SetFilePointerEx (pre-allocate)",
                GetLastError());
             goto cleanup;
        }

        /* Sets the file size to the current position of the file pointer */
        bResult = SetEndOfFile(hDst);
        if (!bResult) {
            PrintWin32Error("SetEndOfFile (pre-allocate)",
                GetLastError());
            goto cleanup;
        }

        /* Reset file pointer to pos 0 */
        LARGE_INTEGER currentPos = { .QuadPart = 0LL };
        SetFilePointerEx(hDst, currentPos, NULL, FILE_BEGIN);
    }

    ded.FileHandle = hSrc;
    ded.SourceFileOffset.QuadPart = 0LL;
    ded.TargetFileOffset.QuadPart = 0LL;
    ded.ByteCount = fileSize;

    /*
     * |FSCTL_DUPLICATE_EXTENTS_TO_FILE| spec requires that the src size
     * is rounded to the filesytem's cluster size
     *
     * FIXME: What about the size of the destination file ?
     */
    ded.ByteCount.QuadPart =
        (ded.ByteCount.QuadPart+srcClusterSize) & ~(srcClusterSize-1);

    (void)printf("# DeviceIoControl(FSCTL_DUPLICATE_EXTENTS_TO_FILE)\n");

    bResult = DeviceIoControl(
        hDst,
        FSCTL_DUPLICATE_EXTENTS_TO_FILE,
        &ded,
        sizeof(ded),
        NULL,
        0,
        &bytesReturnedDummy,
        NULL);

    if (!bResult) {
        PrintWin32Error("DeviceIoControl(FSCTL_DUPLICATE_EXTENTS_TO_FILE)",
            GetLastError());
        goto cleanup;
    }

    (void)printf("# Successfully cloned '%s' to '%s'!\n",
        srcFileName, dstFileName);


cleanup:
    if ((!bResult) && (hDst != INVALID_HANDLE_VALUE)) {
        (void)printf("# Failure, deleting destination file...\n");

        FILE_DISPOSITION_INFO di = { .DeleteFile = TRUE };
        bResult = SetFileInformationByHandle(hDst,
            FileDispositionInfo, &di, sizeof(di));
        if (!bResult) {
            PrintWin32Error("Delete destination file",
                GetLastError());
        }
    }

    (void)printf("# Cleaning up...\n");
    if (hSrc != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hSrc);
    }
    if (hDst != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hDst);
    }

    return bResult ? EXIT_SUCCESS : EXIT_FAILURE;
}
