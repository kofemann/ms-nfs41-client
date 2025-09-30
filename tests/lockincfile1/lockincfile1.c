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
 * lockincfile1.c - lock file, read last line with "<tag> <value>", and write a new line "<mytag> <value+1>", unlock file
 *
 * Usage:
 * $ clang -Wall -Wextra -O -g lockincfile1.c -o lockincfile1.exe
 * $ rm -f contestedfile1.txt ; touch contestedfile1.txt
 *
 * Test run
 * # on machine 1:
 * $ time bash -c 'set -o errexit ; (for ((i=0 ; i < 400 ; i++)) ; do ./lockincfile1 contestedfile1.txt "aaa"; done) ; echo $?'
 * # on machine 2:
 * $ time bash -c 'set -o errexit ; (for ((i=0 ; i < 400 ; i++)) ; do ./lockincfile1 contestedfile1.txt "bbb"; done) ; echo $?'
 * When both machines are finished the last line should match eregex ".+800"
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

int main(int argc, char *av[])
{
    if (argc != 3) {
        (void)fprintf(stderr, "Usage:\n%s <filename> <tag>\n", av[0]);
        return EXIT_USAGE;
    }

    int retval = EXIT_FAILURE;
    const char *fileName = av[1];
    const char *tag = av[2];
    long last_val = 0;
    HANDLE h;
    LARGE_INTEGER liFileSize;
    char buffer[256];
    char writeBuffer[256];
    DWORD bytesRead, bytesWritten;

    h = CreateFileA(fileName,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        /*FILE_ATTRIBUTE_NORMAL*/FILE_FLAG_NO_BUFFERING,
        NULL);
    if (h == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr, "%s: Cannot open file '%s', lasterr=%ld\n",
            av[0],
            av[1],
            (long)GetLastError());
        (void)CloseHandle(h);
        return EXIT_FAILURE;
    }

    OVERLAPPED ov = {
        .hEvent = 0,
        .Offset = 0,
        .OffsetHigh = 0
    };
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &ov)) {
        (void)fprintf(stderr,
            "%s: Locking failed, lasterr=%ld\n",
            av[0], (long)GetLastError());
        (void)CloseHandle(h);
        return EXIT_FAILURE;
    }

    (void)GetFileSizeEx(h, &liFileSize);

    if (liFileSize.QuadPart > 0LL) {
        LARGE_INTEGER liSeekPos;
        if (liFileSize.QuadPart > (long long)(sizeof(buffer)-1))
            liSeekPos.QuadPart = (liFileSize.QuadPart - (sizeof(buffer)-1));
        else
            liSeekPos.QuadPart = 0LL;

        (void)SetFilePointerEx(h, liSeekPos, NULL, FILE_BEGIN);

        if (!ReadFile(h, buffer, sizeof(buffer)-1, &bytesRead, NULL) || (bytesRead == 0)) {
            (void)fprintf(stderr,
                "%s: ReadFile() failed, lasterr=%ld\n",
                av[0], (long)GetLastError());
            goto cleanup;
        }
        buffer[bytesRead] = '\0';

        char *line_start = buffer;
        char *p = buffer + bytesRead - 1;

        while ((p >= buffer) &&
            isspace((unsigned char)*p)) {
            p--;
        }

        if (p >= buffer) {
            line_start = p;
            while (line_start > buffer && *(line_start - 1) != '\n') {
                line_start--;
            }

            char *separator = NULL;
            char *temp_p = p;
            while (temp_p >= line_start) {
                if (*temp_p == ' ' || *temp_p == '\t') {
                    separator = temp_p;
                    break;
                }
                temp_p--;
            }

            if (separator && isdigit((unsigned char)*(separator + 1))) {
                last_val = strtol(separator + 1, NULL, 10);
            }
        }
    }

    LARGE_INTEGER liEndPos = { .QuadPart = 0LL };
    (void)SetFilePointerEx(h, liEndPos, NULL, FILE_END);

    if (liFileSize.QuadPart > 0LL) {
        char lastChar;
        LARGE_INTEGER liLastCharPos;
        liLastCharPos.QuadPart = -1LL;
        (void)SetFilePointerEx(h, liLastCharPos, NULL, FILE_END);
        if (ReadFile(h, &lastChar, 1, &bytesRead, NULL) && (bytesRead == 1)) {
            if (lastChar != '\n') {
                 (void)WriteFile(h, "\n", 1, &bytesWritten, NULL);
            }
        }
    }

    int len = snprintf(writeBuffer, sizeof(writeBuffer),
        "%s\t%ld\n", tag, (last_val + 1));
    (void)WriteFile(h, writeBuffer, len, &bytesWritten, NULL);

    (void)FlushFileBuffers(h);
    retval = EXIT_SUCCESS;

cleanup:
    (void)UnlockFileEx(h, 0, MAXDWORD, MAXDWORD, &ov);
    (void)CloseHandle(h);

    return retval;
}
