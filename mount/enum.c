/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
 * Roland Mainz <roland.mainz@nrubsig.org>
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

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

#ifndef _CRT_STDIO_ISO_WIDE_SPECIFIERS
#error Code requires ISO wide-char behaviour
#endif /* !_CRT_STDIO_ISO_WIDE_SPECIFIERS */

#include <Windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <malloc.h>

#include "nfs41_build_features.h"
#include "nfs41_driver.h" /* |NFS41_PROVIDER_NAME_U| */

/* prototypes */
char *wcs2utf8str(const wchar_t *wstr);
void PrintErrorMessage(IN DWORD dwError);

/* fixme: this function needs a cleanup */
static __inline
void PrintMountLine(
    IN LPCWSTR local,
    IN LPCWSTR remote,
    IN BOOL printURLShellSafe)
{
    size_t remote_len = wcslen(remote);
    wchar_t *cygwin_unc_buffer =
        alloca((remote_len+32)*sizeof(wchar_t));
    char *cygwin_nfsurl_buffer =
        alloca(((remote_len+32)*3)+8 +
        9 /* "?public=1" */
        );
    wchar_t *b;
    LPCWSTR s;
    wchar_t sc;
    bool is_pubfh = false;
    bool found_unc_nfs_tag = false;

    for(b = cygwin_unc_buffer, s = remote ;
        (sc = *s++) != L'\0' ; ) {
        switch(sc) {
            case L'\\':
                *b++ = L'/';
                break;
            default:
                *b++ = sc;
                break;
        }
    }
    *b = L'\0';


    /*
     * print nfs://-URL
     */
/*
 * From RFC 1738 ("Uniform Resource Locators (URL)"):
 * unsafe characters in URLS:
 * "{", "}", "|", "\", "^", "~", "[", "]", and "`"
 * characters which must always be encoded:
 * "#", "%"
 * characters which must be encoded because they have a special meaning:
 * ";", "/", "?", ":", "@", "=" and "&"
 * Only alphanumerics, "$-_.+!*'()," and reserved characters
 * ("/" for nfs://-URLS) are allowed.
 * Note that '+' must always be encoded because urldecoding
 * turns it into a <space>.
 */
/*
 * SHELL_SAFE_URLS - urlencode characters which are special words
 * in POSIX shells, e.g. '!', '(', ')', '*', "'", "$".
 * Fixme: This should be a command-line option
 */

#define ISVALIDSHELLSAFEURLCHAR(c) \
	( \
            ((c) >= '0' && (c) <= '9') || \
	    ((c) >= 'a' && (c) <= 'z') || \
	    ((c) >= 'A' && (c) <= 'Z') || \
            ((c) == '-') || ((c) == '_') || ((c) == '.') || \
            ((c) == '/') \
        )
#define ISVALIDURLCHAR(c) \
	( \
            ((c) >= '0' && (c) <= '9') || \
	    ((c) >= 'a' && (c) <= 'z') || \
	    ((c) >= 'A' && (c) <= 'Z') || \
            ((c) == '$') || ((c) == '-') || ((c) == '_') || ((c) == '.') || \
            ((c) == '!') || ((c) == '*') || ((c) == '\'') || \
            ((c) == '(') || ((c) == ')') || ((c) == ',') || ((c) == '/') \
        )

    unsigned int slash_counter = 0;
    char *utf8unc = wcs2utf8str(cygwin_unc_buffer);
    if (utf8unc == NULL)
        goto out;
    char *utf8unc_p = utf8unc;
    char *us = cygwin_nfsurl_buffer;

#pragma warning( push )
    /*
     * Disable "'strcpy': This function or variable may be unsafe",
     * in this context it is safe to use
     */
#pragma warning (disable : 4996)
    (void)strcpy(us, "nfs://");
#pragma warning( pop )
    us+=6;

    /* skip leading "//" */
    utf8unc_p += 2;

    for ( ; *utf8unc_p != '\0' ; ) {
        unsigned char uc = *utf8unc_p++;

        if (uc == '/')
            slash_counter++;

        /*
         * Intercept "tags" in UNC hostnames, e.g.
         * "\hostname@TAG1@TAG2@port\path"
         */
        if (uc == '@') {
            /* |slash_counter == 0| means we are processing the UNC hostname */
            if (slash_counter == 0) {
                if (found_unc_nfs_tag) {
                    /*
                     * Replace '@' for UNC port number with ':' for
                     * URL port number
                     */
                    *us++ = ':';
                    continue;
                }
                else {
                    if (strncmp(utf8unc_p, "NFS", 3) == 0) {
                        /* Skip "NFS" */
                        utf8unc_p += 3;
                        found_unc_nfs_tag = true;
                    }
                    else if (strncmp(utf8unc_p, "PUBNFS", 6) == 0) {
                        /* Skip "PUBNFS" */
                        utf8unc_p += 6;
                        is_pubfh = true;
                        found_unc_nfs_tag = true;
                    }
                    else {
                        (void)fwprintf(stderr,
                            L"PrintMountLine: ## Internal error, "
                            "unknown UNC tag, utf8unc_p='%s'\n",
                            utf8unc_p);
                        goto out;
                    }
                    continue;
                }
            }
        }

        if (printURLShellSafe?
            (ISVALIDSHELLSAFEURLCHAR(uc)):
            (ISVALIDURLCHAR(uc))) {
            *us++ = uc;
        }
        else {
#pragma warning( push )
    /*
     * Disable "'sprintf': This function or variable may be unsafe",
     * in this context it is safe to use
     */
#pragma warning (disable : 4996)
            (void)sprintf(us, "%%%2.2x", (int)uc);
#pragma warning( pop )
            us+=3;
        }
    }
    *us = '\0';

    if (is_pubfh) {
#pragma warning( push )
    /*
     * Disable "'strcat': This function or variable may be unsafe",
     * in this context it is safe to use
     */
#pragma warning (disable : 4996)
        (void)strcat(cygwin_nfsurl_buffer, "?public=1");
#pragma warning( pop )
    }

    (void)wprintf(L"%-8ls\t%-50ls\t%-50ls\t%-50s\n",
        local, remote, cygwin_unc_buffer, cygwin_nfsurl_buffer);

out:
    free(utf8unc);
}

/* ENUM_RESOURCE_BUFFER_SIZE
 * from msdn re: WNetEnumResource
 *   "An application cannot set the lpBuffer parameter to NULL and
 * retrieve the required buffer size from the lpBufferSize parameter.
 * Instead, the application should allocate a buffer of a reasonable
 * size�16 kilobytes is typical�and use the value of lpBufferSize for
 * error detection." */
#define ENUM_RESOURCE_BUFFER_SIZE (16*1024)

DWORD EnumMounts(
    IN LPNETRESOURCEW pContainer,
    IN BOOL printURLShellSafe)
{
    DWORD result = NO_ERROR;
    LPNETRESOURCEW pResources;
    DWORD i, dwCount, dwTotal = 0;
    DWORD dwBufferSize = ENUM_RESOURCE_BUFFER_SIZE;
    HANDLE hEnum;

    pResources = (LPNETRESOURCEW)GlobalAlloc(0, ENUM_RESOURCE_BUFFER_SIZE);
    if (pResources == NULL) {
        result = WN_OUT_OF_MEMORY;
        goto out;
    }

    result = WNetOpenEnumW(RESOURCE_CONNECTED,
        RESOURCETYPE_DISK, 0, pContainer, &hEnum);
    if (result)
        goto out_free;

    (void)wprintf(L"Listing '%ls' mounts:\n\n",
        NFS41_PROVIDER_NAME_U);
    (void)wprintf(L"%-8ls\t%-50ls\t%-50ls\t%-50ls\n",
        L"Volume", L"Remote path", L"Cygwin UNC path", L"URL");

    do
    {
        dwCount = (DWORD)-1;
        result = WNetEnumResource(hEnum,
            &dwCount, pResources, &dwBufferSize);

        if (result == NO_ERROR)
        {
            for (i = 0; i < dwCount; i++)
            {
                if (pResources[i].lpProvider == NULL)
                    continue;

                if (!wcscmp(pResources[i].lpProvider,
                    NFS41_PROVIDER_NAME_U))
                {
                    PrintMountLine(pResources[i].lpLocalName,
                        pResources[i].lpRemoteName,
                        printURLShellSafe);
                    dwTotal++;
                }
            }
        }
        else if (result != WN_NO_MORE_ENTRIES)
            break;
    }
    while (result != WN_NO_MORE_ENTRIES);

    result = WNetCloseEnum(hEnum);

    (void)wprintf(L"\nFound %d share%ls.\n", dwTotal,
        (dwTotal == 1) ? L"" : L"s");

out_free:
    GlobalFree((HGLOBAL)pResources);
out:
    return result;
}