/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
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

#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <malloc.h>

#include "nfs41_driver.h" /* NFS41_PROVIDER_NAME_A */


void PrintErrorMessage(
    IN DWORD dwError);

static __inline
void PrintMountLine(
    LPCTSTR local,
    LPCTSTR remote)
{
    TCHAR *cygwin_unc_buffer = alloca((_tcslen(remote)+32)*sizeof(TCHAR));
    TCHAR *b = cygwin_unc_buffer;
    LPCTSTR s = remote;
    TCHAR sc;
#ifndef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
    unsigned int backslash_counter = 0;
#endif

    while((sc = *s++) != TEXT('\0')) {
        switch(sc) {
            case TEXT('\\'):
                *b++ = TEXT('/');
#ifndef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
                if (backslash_counter++ == 2) {
                    (void)wcscpy_s(b, 6, TEXT("nfs4/"));
                    b+=5;
                }
#endif
                break;
            default:
                *b++ = sc;
                break;
        }
    }
    *b = TEXT('\0');
// FIXME: We should print the URL
    _tprintf(TEXT("%-8s\t%-40s\t%s\n"), local, remote, cygwin_unc_buffer);
}

/* ENUM_RESOURCE_BUFFER_SIZE
 * from msdn re: WNetEnumResource
 *   "An application cannot set the lpBuffer parameter to NULL and
 * retrieve the required buffer size from the lpBufferSize parameter.
 * Instead, the application should allocate a buffer of a reasonable
 * size—16 kilobytes is typical—and use the value of lpBufferSize for
 * error detection." */
#define ENUM_RESOURCE_BUFFER_SIZE (16*1024)

DWORD EnumMounts(
    IN LPNETRESOURCE pContainer)
{
    DWORD result = NO_ERROR;
    LPNETRESOURCE pResources;
    DWORD i, dwCount, dwTotal = 0;
    DWORD dwBufferSize = ENUM_RESOURCE_BUFFER_SIZE;
    HANDLE hEnum;

    pResources = (LPNETRESOURCE)GlobalAlloc(0, ENUM_RESOURCE_BUFFER_SIZE);
    if (pResources == NULL) {
        result = WN_OUT_OF_MEMORY;
        goto out;
    }

    result = WNetOpenEnum(RESOURCE_CONNECTED,
        RESOURCETYPE_DISK, 0, pContainer, &hEnum);
    if (result)
        goto out_free;

    _tprintf(TEXT("Listing '%s' mounts:\n\n"), TEXT(NFS41_PROVIDER_NAME_A));
    _tprintf(TEXT("%-8s\t%-40s\t%s\n"), TEXT("Volume"), TEXT("Remote path"), TEXT("Cygwin UNC path"));

    do
    {
        dwCount = (DWORD)-1;
        result = WNetEnumResource(hEnum,
            &dwCount, pResources, &dwBufferSize);

        if (result == NO_ERROR)
        {
            for (i = 0; i < dwCount; i++)
            {
                if (_tcscmp(pResources[i].lpProvider,
                    TEXT(NFS41_PROVIDER_NAME_A)) == 0)
                {
                    PrintMountLine(pResources[i].lpLocalName,
                        pResources[i].lpRemoteName);
                    dwTotal++;
                }
            }
        }
        else if (result != WN_NO_MORE_ENTRIES)
            break;
    }
    while (result != WN_NO_MORE_ENTRIES);

    result = WNetCloseEnum(hEnum);

    _tprintf(TEXT("\nFound %d share%s.\n"), dwTotal,
        dwTotal == 1 ? TEXT("") : TEXT("s"));

out_free:
    GlobalFree((HGLOBAL)pResources);
out:
    return result;
}