/*
 * MIT License
 *
 * Copyright (c) 2023 Roland Mainz <roland.mainz@nrubsig.org>
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
 * winfsinfo1.c - print Windows filesystem info
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

#define UNICODE 1
#define _UNICODE 1

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <stdbool.h>

static
bool print_volume_info(const char *progname, const char *filename)
{
    bool ok = false;

    HANDLE fileHandle = CreateFileA(filename,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        (void)fprintf(stderr,
            "%s: Error opening file '%s'. Last error was %d.\n",
            progname,
            filename,
            GetLastError());
        return false;
    }

    (void)printf("filename='%s'\n", filename);

    DWORD volumeFlags = 0;
    ok = GetVolumeInformationByHandleW(fileHandle, NULL, 0,
        NULL, NULL, &volumeFlags, NULL, 0);

    if (!ok) {
        (void)fprintf(stderr, "%s: GetVolumeInformationByHandleW() "
            "error. GetLastError()==%d.\n",
            progname,
            GetLastError());
        ok = false;
        goto done;
    }

#define TESTFSATTR(s) \
    if (volumeFlags & (s)) { \
        (void)puts("volumeflag="#s); \
        volumeFlags &= ~(s); \
    }

    TESTFSATTR(FILE_SUPPORTS_USN_JOURNAL);
    TESTFSATTR(FILE_SUPPORTS_OPEN_BY_FILE_ID);
    TESTFSATTR(FILE_SUPPORTS_EXTENDED_ATTRIBUTES);
    TESTFSATTR(FILE_SUPPORTS_HARD_LINKS);
    TESTFSATTR(FILE_SUPPORTS_TRANSACTIONS);
    TESTFSATTR(FILE_SEQUENTIAL_WRITE_ONCE);
    TESTFSATTR(FILE_READ_ONLY_VOLUME);
    TESTFSATTR(FILE_NAMED_STREAMS);
    TESTFSATTR(FILE_SUPPORTS_ENCRYPTION);
    TESTFSATTR(FILE_SUPPORTS_OBJECT_IDS);
    TESTFSATTR(FILE_VOLUME_IS_COMPRESSED);
    TESTFSATTR(FILE_SUPPORTS_REMOTE_STORAGE);
    TESTFSATTR(FILE_RETURNS_CLEANUP_RESULT_INFO);
    TESTFSATTR(FILE_SUPPORTS_POSIX_UNLINK_RENAME);
    TESTFSATTR(FILE_SUPPORTS_REPARSE_POINTS);
    TESTFSATTR(FILE_SUPPORTS_SPARSE_FILES);
    TESTFSATTR(FILE_VOLUME_QUOTAS);
    TESTFSATTR(FILE_FILE_COMPRESSION);
    TESTFSATTR(FILE_PERSISTENT_ACLS);
    TESTFSATTR(FILE_UNICODE_ON_DISK);
    TESTFSATTR(FILE_CASE_PRESERVED_NAMES);
    TESTFSATTR(FILE_CASE_SENSITIVE_SEARCH);
    TESTFSATTR(FILE_SUPPORTS_INTEGRITY_STREAMS);
#ifdef FILE_SUPPORTS_BLOCK_REFCOUNTING
    TESTFSATTR(FILE_SUPPORTS_BLOCK_REFCOUNTING);
#endif
#ifdef FILE_SUPPORTS_SPARSE_VDL
    TESTFSATTR(FILE_SUPPORTS_SPARSE_VDL);
#endif
#ifdef FILE_DAX_VOLUME
    TESTFSATTR(FILE_DAX_VOLUME);
#endif
#ifdef FILE_SUPPORTS_GHOSTING
    TESTFSATTR(FILE_SUPPORTS_GHOSTING);
#endif

    /*
     * print any leftover flags not covered by |TESTFSATTR(FILE_*)|
     * above
     */
    if (volumeFlags) {
        (void)printf("attr=0x%lx\n", (long)volumeFlags);
    }
    ok = true;

done:
    CloseHandle(fileHandle);
    return ok;
}

int main(int ac, char *av[])
{
    print_volume_info(av[0], av[1]);
    return EXIT_SUCCESS;
}
