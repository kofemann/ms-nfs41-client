/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
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

#include <Windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>

#include "daemon_debug.h"
#include "util.h"
#include "nfs41_ops.h"


ULONG nfs_file_info_to_attributes(
    IN const nfs41_file_info *info)
{
    ULONG attrs = 0;

    if (info->type == NF4DIR)
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    else if (info->type == NF4LNK) {
        attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
        if (info->symlink_dir)
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else if (info->type != NF4REG) {
        DPRINTF(1,
            ("nfs_file_info_to_attributes: "
            "unhandled file type %d, defaulting to NF4REG\n",
            info->type));
    }

    EASSERT((info->attrmask.count > 0) &&
        (info->attrmask.arr[1] & FATTR4_WORD1_MODE));
    if (info->mode == 0444) /* XXX: 0444 for READONLY */
        attrs |= FILE_ATTRIBUTE_READONLY;

    if (info->hidden)
        attrs |= FILE_ATTRIBUTE_HIDDEN;
    if (info->system)
        attrs |= FILE_ATTRIBUTE_SYSTEM;
    if (info->archive)
        attrs |= FILE_ATTRIBUTE_ARCHIVE;

    /*
     * |FILE_ATTRIBUTE_NORMAL| attribute is only set if no other
     * attributes are present.
     * all other override this value.
     */
    return attrs ? attrs : FILE_ATTRIBUTE_NORMAL;
}

void nfs_to_basic_info(
    IN const char *name,
    IN const nfs41_file_info *info,
    OUT PFILE_BASIC_INFO basic_out)
{
    EASSERT(info->attrmask.count > 0);

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&info->time_create, &basic_out->CreationTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_create not set\n", name));
        basic_out->CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&info->time_access, &basic_out->LastAccessTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_access not set\n", name));
        basic_out->LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &basic_out->LastWriteTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_modify not set\n", name));
        basic_out->LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &basic_out->ChangeTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_modify2 not set\n", name));
        basic_out->ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    basic_out->FileAttributes = nfs_file_info_to_attributes(info);
}

void nfs_to_standard_info(
    IN const nfs41_file_info *info,
    OUT PFILE_STANDARD_INFO std_out)
{
    const ULONG FileAttributes = nfs_file_info_to_attributes(info);

    EASSERT(info->attrmask.arr[0] & FATTR4_WORD0_SIZE);
    EASSERT((info->attrmask.count > 0) &&
        (info->attrmask.arr[1] & FATTR4_WORD1_NUMLINKS));

    std_out->AllocationSize.QuadPart =
        std_out->EndOfFile.QuadPart = (LONGLONG)info->size;
    std_out->NumberOfLinks = info->numlinks;
    std_out->DeletePending = FALSE;
    std_out->Directory = FileAttributes & FILE_ATTRIBUTE_DIRECTORY ?
        TRUE : FALSE;
}

void nfs_to_network_openinfo(
    IN const char *name,
    IN const nfs41_file_info *info,
    OUT PFILE_NETWORK_OPEN_INFORMATION net_out)
{
    EASSERT(info->attrmask.count > 0);

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&info->time_create, &net_out->CreationTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_create not set\n", name));
        net_out->CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&info->time_access, &net_out->LastAccessTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_access not set\n", name));
        net_out->LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &net_out->LastWriteTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_modify not set\n", name));
        net_out->LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &net_out->ChangeTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_modify2 not set\n", name));
        net_out->ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    net_out->AllocationSize.QuadPart =
        net_out->EndOfFile.QuadPart = (LONGLONG)info->size;
    net_out->FileAttributes = nfs_file_info_to_attributes(info);
}

/* copy |nfs41_file_info| */
void nfs41_file_info_cpy(
    OUT nfs41_file_info *dest,
    IN const nfs41_file_info *src)
{
    (void)memcpy(dest, src, sizeof(nfs41_file_info));
    if (src->owner != NULL)
        dest->owner = dest->owner_buf;
    if (src->owner_group != NULL)
        dest->owner_group = dest->owner_group_buf;
}
