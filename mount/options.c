/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
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

#ifndef _CRT_STDIO_ISO_WIDE_SPECIFIERS
#error Code requires ISO wide-char behaviour
#endif /* !_CRT_STDIO_ISO_WIDE_SPECIFIERS */

#include <crtdbg.h>
#include <Windows.h>
#include <strsafe.h>
#include <stdio.h>

#include "options.h"


DWORD InitializeMountOptions(
    IN OUT PMOUNT_OPTION_LIST Options,
    IN ULONG BufferSize)
{
    Options->Current = NULL;
    Options->Remaining = BufferSize;
    Options->Buffer = LocalAlloc(LMEM_ZEROINIT, BufferSize);
    if (Options->Buffer == NULL)
        return ERROR_OUTOFMEMORY;

    Options->Buffer->Secret = MOUNT_OPTION_BUFFER_SECRET;
    return NO_ERROR;
}

void FreeMountOptions(
    IN OUT PMOUNT_OPTION_LIST Options)
{
    Options->Current = NULL;
    Options->Remaining = 0;
    if (Options->Buffer)
    {
        LocalFree(Options->Buffer);
        Options->Buffer = NULL;
    }
}

BOOL FindOptionByName(
    IN LPCWSTR Name,
    IN PMOUNT_OPTION_LIST Options,
    OUT PFILE_FULL_EA_INFORMATION* ppOption)
{
    PFILE_FULL_EA_INFORMATION Current =
        (PFILE_FULL_EA_INFORMATION)Options->Buffer->Buffer;
    ULONG NameLength = (ULONG)wcslen(Name) * sizeof(wchar_t);

    for (;;)
    {
        if ((Current->EaNameLength == NameLength) &&
            (!wcscmp((LPWSTR)Current->EaName, Name))) {
            *ppOption = Current;
            return TRUE;
        }
        if (Current->NextEntryOffset == 0)
            break;
        Current = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Current + Current->NextEntryOffset);
    }
    return FALSE;
}

static FORCEINLINE ULONG EaBufferSize(
    IN UCHAR NameSize,
    IN USHORT ValueSize)
{
    ULONG Size = sizeof(ULONG) + 2 * sizeof(UCHAR) + sizeof(USHORT)
        + NameSize + ValueSize + sizeof(wchar_t);
    /* extended attributes require ULONG alignment;
     * see documentation for IoCheckEaBufferValidity() */
    return ( (Size + (sizeof(ULONG)-1)) / sizeof(ULONG) ) * sizeof(ULONG);
}

static FORCEINLINE ULONG EaBufferNextOffset(
    IN PFILE_FULL_EA_INFORMATION EaBuffer)
{
    return EaBufferSize(
        EaBuffer->EaNameLength,
        EaBuffer->EaValueLength);
}

BOOL InsertOption(
    IN LPCWSTR Name,
    IN LPCWSTR Value,
    IN OUT PMOUNT_OPTION_LIST Options)
{
    PFILE_FULL_EA_INFORMATION Current;
    UCHAR NameLen = (UCHAR)wcslen(Name) * sizeof(wchar_t);
    USHORT ValueLen = (USHORT)wcslen(Value) * sizeof(wchar_t);
    ULONG SpaceRequired = EaBufferSize(NameLen, ValueLen);

    /*
     * Filter "port" option, as it's value has already been encoded
     *  in the hostname as hostport
     */
    if (!wcscmp(Name, L"port")) {
        return TRUE;
    }

    /*
     * FIXME: Some duplicates are wanted, e.g. "rw" overriding "ro" etc
     * So better just let the kernel do the work
     */
#if 0
    /* don't allow duplicate options */
    if (FindOptionByName(Name, Options, &Current)) {
        (void)fwprintf(stderr, L"Found a duplicate option "
            L"'%s%s%s' while parsing '%s%s%s'.\n",
            (PWCH)Current->EaName,
            Current->EaValueLength ? L"=" : L"",
            (PWCH)(Current->EaName + Current->EaNameLength + sizeof(wchar_t)),
            Name, ValueLen ? L"=" : Value, Value);
        return FALSE;
    }
#endif

    /* fail if we're out of space */
    if (SpaceRequired > Options->Remaining) {
        (void)fwprintf(stderr, L"Out of space for options!\n");
        return FALSE;
    }

    if (Options->Current == NULL)
        Current = Options->Current = (PFILE_FULL_EA_INFORMATION)
            Options->Buffer->Buffer;
    else
        Current = Options->Current = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Options->Current + Options->Current->NextEntryOffset);

    Current->EaNameLength = NameLen;
    if (NameLen) /* copy attribute name */
        StringCbCopyW((LPWSTR)Current->EaName,
            NameLen + sizeof(wchar_t), Name);

    Current->EaValueLength = ValueLen;
    if (ValueLen) /* copy attribute value */
        StringCbCopyW((LPWSTR)(Current->EaName + NameLen + sizeof(wchar_t)),
            ValueLen + sizeof(wchar_t), Value);

    Current->Flags = 0;
    Current->NextEntryOffset = EaBufferNextOffset(Options->Current);

    Options->Buffer->Length = (ULONG)(
        (Current->EaName + NameLen + ValueLen + 2 * sizeof(wchar_t))
            - Options->Buffer->Buffer );
    Options->Remaining -= SpaceRequired;
    return TRUE;
}

void RecursivePrintEaInformation(
    IN PFILE_FULL_EA_INFORMATION EA)
{
    (void)wprintf(
        L"----------------------\n"
        L"Alignment:           %5lu\n"
        L"NextEntryOffset:     %5lu\n"
        L"Flags:               %5u\n"
        L"EaNameLength:        %5u\n"
        L"EaValueLength:       %5u\n"
        L"EaName:   %16ls\n"
        L"EaValue:  %16ls\n\n",
        (unsigned long)((ULONG_PTR)EA % sizeof(ULONG)),
        EA->NextEntryOffset,
        EA->Flags,
        EA->EaNameLength,
        EA->EaValueLength,
        (LPWSTR)EA->EaName,
        (LPWSTR)(EA->EaName + EA->EaNameLength + sizeof(wchar_t)));

    if (EA->NextEntryOffset)
        RecursivePrintEaInformation((PFILE_FULL_EA_INFORMATION)
            ((PBYTE)EA + EA->NextEntryOffset));
}

static const wchar_t COMMA_T = L',';
static const wchar_t EQUAL_T = L'=';

BOOL ParseMountOptions(
    IN LPWSTR Arg,
    IN OUT PMOUNT_OPTION_LIST Options)
{
    PWCH pos, comma, equals;

    pos = Arg;
    for (;;)
    {
        comma = wcschr(pos, COMMA_T);
        if (comma)
        {
            if (comma == pos)
                goto out_empty_option;
            *comma = 0;
        }
        else if (wcslen(pos) == 0)
            goto out_empty_option;

        /* accept 'option=value' or 'option' */
        equals = wcschr(pos, EQUAL_T);
        if (equals)
        {
            if (equals == pos)
                goto out_empty_option;
            *equals = 0;
            if (!InsertOption(pos, equals + 1, Options))
                return FALSE;
        }
        else if (!InsertOption(pos, L"", Options))
            return FALSE;

        if (comma == NULL)
            break;

        pos = comma + 1;
    }

/*  RecursivePrintEaInformation(
        (PFILE_FULL_EA_INFORMATION)Options->Buffer->Buffer); */
    return TRUE;

out_empty_option:
    (void)fwprintf(stderr, L"Found an empty option while "
        L"reading mount options at '%ls'.\n",
        pos);
    return FALSE;
}
