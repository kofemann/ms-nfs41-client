/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
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

#include <ntifs.h>
#include <strsafe.h>
#include <stdio.h>

#if 1
typedef unsigned long DWORD, *PDWORD, *LPDWORD;
#endif

#include "nfs_ea.h"

#define MAX_LIST_LEN 4096
#define MAX_EA_VALUE 256

#define MAX_GETEA (sizeof(FILE_GET_EA_INFORMATION) + MAX_EA_VALUE)
#define MAX_FULLEA (sizeof(FILE_FULL_EA_INFORMATION) + 2 * MAX_EA_VALUE)

static NTSTATUS ea_list(
    HANDLE FileHandle)
{
    IO_STATUS_BLOCK IoStatusBlock;
    CHAR Buffer[MAX_LIST_LEN];
    PFILE_FULL_EA_INFORMATION EaBuffer;
    NTSTATUS status;
    BOOLEAN RestartScan = TRUE;

    (void)memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));

on_overflow:
    EaBuffer = (PFILE_FULL_EA_INFORMATION)Buffer;

    status = ZwQueryEaFile(FileHandle, &IoStatusBlock,
        EaBuffer, MAX_LIST_LEN, FALSE, NULL, 0, NULL, RestartScan);
    switch (status) {
    case STATUS_SUCCESS:
    case STATUS_BUFFER_OVERFLOW:
        break;
    case STATUS_NO_EAS_ON_FILE:
        printf("No EAs on file, status=0x%lx.\n", (long)status);
        goto out;
    default:
        fprintf(stderr, "ZwQueryEaFile() failed with 0x%lx\n", (long)status);
        goto out;
    }

    while (EaBuffer) {
        (void)printf("'%.*s' = '%.*s'\n",
            EaBuffer->EaNameLength,
            EaBuffer->EaName,
            EaBuffer->EaValueLength,
            EaBuffer->EaName + EaBuffer->EaNameLength + 1);

        if (EaBuffer->NextEntryOffset == 0)
            break;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)
            ((PCHAR)EaBuffer + EaBuffer->NextEntryOffset);
    }

    if (status == STATUS_BUFFER_OVERFLOW) {
        printf("overflow, querying more, status=0x%lx\n", (long)status);
        RestartScan = FALSE;
        goto on_overflow;
    }
out:
    return status;
}

static NTSTATUS ea_get(
    HANDLE FileHandle,
    IN LPCWSTR EaNames[],
    IN DWORD Count)
{
    IO_STATUS_BLOCK IoStatusBlock;
    CHAR GetBuffer[MAX_LIST_LEN] = { 0 };
    CHAR FullBuffer[MAX_LIST_LEN] = { 0 };
    PFILE_GET_EA_INFORMATION EaList = (PFILE_GET_EA_INFORMATION)GetBuffer, EaQuery;
    PFILE_FULL_EA_INFORMATION EaBuffer = (PFILE_FULL_EA_INFORMATION)FullBuffer;
    ULONG ActualByteCount, EaListLength;
    DWORD i;
    NTSTATUS status;

    (void)memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));

    EaQuery = EaList;
    EaListLength = 0;

    for (i = 0; i < Count; i++) {
        LPCWSTR EaName = EaNames[i];
        ULONG EaNameLength = (ULONG)((wcslen(EaName)+1) * sizeof(WCHAR));

        /* convert EaName */
        status = RtlUnicodeToUTF8N(EaQuery->EaName, MAX_EA_VALUE,
            &ActualByteCount, EaName, EaNameLength);
        if (status) {
            fwprintf(stderr, L"RtlUnicodeToUTF8N('%ls') failed with 0x%lx\n", EaName, (long)status);
            goto out;
        }
        EaQuery->EaNameLength = (UCHAR)ActualByteCount - 1;
        EaQuery->NextEntryOffset = FIELD_OFFSET(FILE_GET_EA_INFORMATION, EaName) + EaQuery->EaNameLength + 1;

        if (i == Count - 1) {
            EaListLength += EaQuery->NextEntryOffset;
            EaQuery->NextEntryOffset = 0;
        } else {
            EaQuery->NextEntryOffset = 4 + ((EaQuery->NextEntryOffset - 1) & ~3);
            EaListLength += EaQuery->NextEntryOffset;
        }
        EaQuery = (PFILE_GET_EA_INFORMATION)((PCHAR)EaQuery + EaQuery->NextEntryOffset);
    }

    status = ZwQueryEaFile(FileHandle, &IoStatusBlock,
        EaBuffer, MAX_FULLEA, FALSE, EaList, EaListLength, NULL, TRUE);
    switch (status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_NO_EAS_ON_FILE:
        printf("No EAs on file, status=0x%lx.\n", (long)status);
        goto out;
    default:
        fprintf(stderr, "ZwQueryEaFile('%s') failed with 0x%lx\n", EaList->EaName, (long)status);
        goto out;
    }

    while (EaBuffer) {
        (void)printf("'%.*s' = '%.*s'\n",
            EaBuffer->EaNameLength,
            EaBuffer->EaName,
            EaBuffer->EaValueLength,
            EaBuffer->EaName + EaBuffer->EaNameLength + 1);


        if (EaBuffer->NextEntryOffset == 0)
            break;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)
            ((PCHAR)EaBuffer + EaBuffer->NextEntryOffset);
    }
out:
    return status;
}

static NTSTATUS ea_get_nfs3attr(
    HANDLE FileHandle)
{
    IO_STATUS_BLOCK IoStatusBlock;
    CHAR GetBuffer[MAX_LIST_LEN] = { 0 };
    CHAR FullBuffer[MAX_LIST_LEN] = { 0 };
    PFILE_GET_EA_INFORMATION EaList = (PFILE_GET_EA_INFORMATION)GetBuffer, EaQuery;
    PFILE_FULL_EA_INFORMATION EaBuffer = (PFILE_FULL_EA_INFORMATION)FullBuffer;
    ULONG EaListLength;
    NTSTATUS status;

    (void)memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));

    EaQuery = EaList;
    EaListLength = 0;

    (void)strcpy(EaQuery->EaName, "NfsV3Attributes");
    EaQuery->EaNameLength = 15;
    EaQuery->NextEntryOffset = FIELD_OFFSET(FILE_GET_EA_INFORMATION, EaName) + EaQuery->EaNameLength + 1;

    EaListLength += EaQuery->NextEntryOffset;
    EaQuery->NextEntryOffset = 0;
    EaQuery = (PFILE_GET_EA_INFORMATION)((PCHAR)EaQuery + EaQuery->NextEntryOffset);

    status = ZwQueryEaFile(FileHandle, &IoStatusBlock,
        EaBuffer, MAX_FULLEA, FALSE, EaList, EaListLength, NULL, TRUE);
    switch (status) {
    case STATUS_SUCCESS:
        break;
    case STATUS_NO_EAS_ON_FILE:
        (void)fprintf(stderr, "No EAs on file, status=0x%lx.\n", (long)status);
        goto out;
    default:
        (void)fprintf(stderr, "ZwQueryEaFile('%s') failed with 0x%lx\n", EaList->EaName, (long)status);
        goto out;
    }

    (void)printf("%.*s:\n", EaBuffer->EaNameLength, EaBuffer->EaName);
    nfs3_attrs *n3a = (void *)(EaBuffer->EaName + EaBuffer->EaNameLength + 1);
    (void)printf("(\n"
        "\ttype=%d\n"
        "\tmode=0%o\n"
        "\tnlink=%d\n"
        "\tuid=%d\n\tgid=%d\n"
        "\tsize=%lld\n\tused=%lld\n"
        "\trdev=( specdata1=0x%x specdata2=0x%x )\n"
        "\tfsid=%lld\n\tfileid=%lld\n"
        "\tatime=(tv_sec=%ld,tv_nsec=%lu)\n"
        "\tmtime=(tv_sec=%ld,tv_nsec=%lu)\n"
        "\tctime=(tv_sec=%ld,tv_nsec=%lu)\n"
        ")\n",
        (int)n3a->type,
        (int)n3a->mode,
        (int)n3a->nlink,
        (int)n3a->uid,
        (int)n3a->gid,
        (long long)n3a->size,
        (long long)n3a->used,
        (int)n3a->rdev.specdata1,
        (int)n3a->rdev.specdata2,
        (long long)n3a->fsid,
        (long long)n3a->fileid,
        (long)n3a->atime.tv_sec, (unsigned long)n3a->atime.tv_nsec,
        (long)n3a->mtime.tv_sec, (unsigned long)n3a->mtime.tv_nsec,
        (long)n3a->ctime.tv_sec, (unsigned long)n3a->ctime.tv_nsec);

out:
    return status;
}

static NTSTATUS full_ea_init(
    IN LPCWSTR EaName,
    IN LPCWSTR EaValue,
    OUT PFILE_FULL_EA_INFORMATION EaBuffer,
    OUT PULONG EaLength)
{
    ULONG ActualByteCount, EaNameLength;
    NTSTATUS status;

    EaBuffer->NextEntryOffset = 0;
    EaBuffer->Flags = 0;

    EaNameLength = (ULONG)((wcslen(EaName)+1) * sizeof(WCHAR));

    /* convert EaName */
    status = RtlUnicodeToUTF8N(EaBuffer->EaName, MAX_FULLEA -
        FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName),
        &ActualByteCount, EaName, EaNameLength);
    if (status) {
        fwprintf(stderr, L"RtlUnicodeToUTF8N('%ls') failed with 0x%lx\n", EaName, (long)status);
        goto out;
    }
    EaBuffer->EaNameLength = (UCHAR)ActualByteCount - 1;

    if (EaValue == NULL) {
        EaBuffer->EaValueLength = 0;
    } else {
        ULONG EaValueLength = (ULONG)((wcslen(EaValue)+1) * sizeof(WCHAR));

        /* convert EaValue */
        status = RtlUnicodeToUTF8N(EaBuffer->EaName + EaBuffer->EaNameLength + 1,
            MAX_FULLEA - FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) - EaBuffer->EaNameLength - 1,
            &ActualByteCount, EaValue, EaValueLength);
        if (status) {
            fwprintf(stderr, L"RtlUnicodeToUTF8N('%ls') failed with 0x%lx\n", EaName, (long)status);
            goto out;
        }
        EaBuffer->EaValueLength = (UCHAR)ActualByteCount - 1;
    }

    *EaLength = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) +
        EaBuffer->EaNameLength + 1 + EaBuffer->EaValueLength;
out:
    return status;
}

static NTSTATUS ea_set(
    HANDLE FileHandle,
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaLength)
{
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    (void)memset(&IoStatusBlock, 0, sizeof(IoStatusBlock));

    status = ZwSetEaFile(FileHandle, &IoStatusBlock, EaBuffer, EaLength);
    switch (status) {
    case STATUS_SUCCESS:
        (void)printf("'%.*s' = '%.*s'\n",
            EaBuffer->EaNameLength,
            EaBuffer->EaName,
            EaBuffer->EaValueLength,
            EaBuffer->EaName + EaBuffer->EaNameLength + 1);
        break;
    default:
        fprintf(stderr, "ZwSetEaFile() failed with 0x%lx\n", (long)status);
        break;
    }
    return status;
}

int wmain(int argc, const wchar_t *argv[])
{
    UNICODE_STRING FileName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    ACCESS_MASK DesiredAccess = GENERIC_READ;
    ULONG FileAttributes = 0;
    ULONG ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    ULONG CreateDisposition = FILE_OPEN_IF;
    //ULONG CreateOptions = FILE_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT;
    ULONG CreateOptions = 0;
    HANDLE FileHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS status;

    CHAR Buffer[MAX_FULLEA] = { 0 };
    PFILE_FULL_EA_INFORMATION EaBuffer = NULL;
    ULONG EaLength = 0;

    if (argc < 3) {
        fwprintf(stderr, L"Usage: nfs_ea <ntobjectpath> <create|set|get|getnfs3attr|list> ...\n");
        fwprintf(stderr, L"Example:\n");
        fwprintf(stderr, L"\tnfs_ea '\\??\\L:\\builds\\bash_build1' getnfs3attr\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }
    if (wcscmp(argv[2], L"create") == 0) {
        if (argc < 5) {
            fwprintf(stderr, L"Usage: nfs_ea <ntobjectpath> create <name> <value>\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        CreateDisposition = FILE_OVERWRITE_IF;
        EaBuffer = (PFILE_FULL_EA_INFORMATION)Buffer;
        status = full_ea_init(argv[3], argv[4], EaBuffer, &EaLength);
        if (status)
            goto out;
        wprintf(L"Creating file '%ls'.\n", argv[1]);
    } else if (wcscmp(argv[2], L"set") == 0) {
        if (argc < 4) {
            fwprintf(stderr, L"Usage: nfs_ea <ntobjectpath> set <name> [value]\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
        DesiredAccess |= GENERIC_WRITE;
    } else if (wcscmp(argv[2], L"get") == 0) {
        if (argc < 4) {
            fwprintf(stderr, L"Usage: nfs_ea <ntobjectpath> get <name> [name...]\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
    } else if (wcscmp(argv[2], L"getnfs3attr") == 0) {
        if (argc < 3) {
            fwprintf(stderr, L"Usage: nfs_ea <ntobjectpath> getnfs3attr\n");
            status = STATUS_INVALID_PARAMETER;
            goto out;
        }
    } else if (wcscmp(argv[2], L"list") != 0) {
        fwprintf(stderr, L"Usage: nfs_ea <ntobjectpath> <create|set|get|list> ...\n");
        status = STATUS_INVALID_PARAMETER;
        goto out;
    }

    RtlInitUnicodeString(&FileName, argv[1]);
    InitializeObjectAttributes(&ObjectAttributes, &FileName, 0, NULL, NULL);

    status = NtCreateFile(&FileHandle, DesiredAccess, &ObjectAttributes,
        &IoStatusBlock, NULL, FileAttributes, ShareAccess,
        CreateDisposition, CreateOptions, EaBuffer, EaLength);
    if (status) {
        fwprintf(stderr, L"NtCreateFile('%ls') failed with 0x%lx\n", FileName.Buffer, (long)status);
        goto out;
    }

    if (wcscmp(argv[2], L"set") == 0) {
        EaBuffer = (PFILE_FULL_EA_INFORMATION)Buffer;
        status = full_ea_init(argv[3], argc > 4 ? argv[4] : NULL,
            EaBuffer, &EaLength);
        if (status)
            goto out_close;

        wprintf(L"Setting extended attribute '%ls' on file '%ls':\n",
            argv[3], FileName.Buffer);
        status = ea_set(FileHandle, EaBuffer, EaLength);
    } else if (wcscmp(argv[2], L"get") == 0) {
        wprintf(L"Querying extended attribute on file '%ls':\n",
            FileName.Buffer);
        status = ea_get(FileHandle, argv + 3, argc - 3);
    } else if (wcscmp(argv[2], L"getnfs3attr") == 0) {
        wprintf(L"Querying extended attribute 'NfsV3Attributes' on file '%ls':\n",
            FileName.Buffer);
        status = ea_get_nfs3attr(FileHandle);
    } else if (wcscmp(argv[2], L"list") == 0) {
        wprintf(L"Listing extended attributes for '%ls':\n", FileName.Buffer);
        status = ea_list(FileHandle);
    } else if (wcscmp(argv[2], L"create") == 0) {
        wprintf(L"File '%ls' was created with \n", FileName.Buffer);
        status = ea_get(FileHandle, argv + 3, 1);
    }

out_close:
    NtClose(FileHandle);
out:
    return status;
}
