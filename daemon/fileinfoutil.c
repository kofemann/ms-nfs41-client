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

#include "nfs41_build_features.h"
#include "daemon_debug.h"
#include "nfs41_daemon.h"
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

#ifdef NFS41_DRIVER_WSL_SUPPORT
void nfs_to_stat_info(
    IN const char *name,
    IN const nfs41_file_info *info,
    OUT PFILE_STAT_INFORMATION stat_out)
{
    EASSERT(info->attrmask.count > 0);

    stat_out->FileId.QuadPart = info->fileid;

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&info->time_create, &stat_out->CreationTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_info(name='%s'): "
            "time_create not set\n", name));
        stat_out->CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&info->time_access, &stat_out->LastAccessTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_info(name='%s'): "
            "time_access not set\n", name));
        stat_out->LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &stat_out->LastWriteTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_info(name='%s'): "
            "time_modify not set\n", name));
        stat_out->LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &stat_out->ChangeTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_info(name='%s'): "
            "time_modify2 not set\n", name));
        stat_out->ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    stat_out->AllocationSize.QuadPart =
        stat_out->EndOfFile.QuadPart = (LONGLONG)info->size;

    stat_out->FileAttributes = nfs_file_info_to_attributes(info);

    stat_out->ReparseTag = (info->type == NF4LNK)?
        IO_REPARSE_TAG_SYMLINK : 0;

    stat_out->NumberOfLinks = info->numlinks;
    stat_out->EffectiveAccess =
        GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ; /* FIXME */
}

void nfs_to_stat_lx_info(
    IN void *daemon_context,
    IN const char *name,
    IN const nfs41_file_info *info,
    OUT PFILE_STAT_LX_INFORMATION stat_lx_out)
{
    nfs41_daemon_globals *nfs41_dg =
        (nfs41_daemon_globals *)daemon_context;

    EASSERT(info->attrmask.count > 0);

    stat_lx_out->FileId.QuadPart = info->fileid;

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&info->time_create,
            &stat_lx_out->CreationTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_lx_info(name='%s'): "
            "time_create not set\n", name));
        stat_lx_out->CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&info->time_access,
            &stat_lx_out->LastAccessTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_lx_info(name='%s'): "
            "time_access not set\n", name));
        stat_lx_out->LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify,
            &stat_lx_out->LastWriteTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_lx_info(name='%s'): "
            "time_modify not set\n", name));
        stat_lx_out->LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &stat_lx_out->ChangeTime);
    }
    else {
        DPRINTF(1, ("nfs_to_stat_lx_info(name='%s'): "
            "time_modify2 not set\n", name));
        stat_lx_out->ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    stat_lx_out->AllocationSize.QuadPart =
        stat_lx_out->EndOfFile.QuadPart = (LONGLONG)info->size;

    stat_lx_out->FileAttributes = nfs_file_info_to_attributes(info);

    stat_lx_out->ReparseTag = (info->type == NF4LNK)?
        IO_REPARSE_TAG_SYMLINK : 0;

    stat_lx_out->NumberOfLinks = info->numlinks;
    stat_lx_out->EffectiveAccess =
        GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ; /* FIXME */

    stat_lx_out->LxFlags = 0UL;

    if (!info->case_insensitive) {
        stat_lx_out->LxFlags |= LX_FILE_CASE_SENSITIVE_DIR;
    }

    stat_lx_out->LxFlags |= LX_FILE_METADATA_HAS_MODE;

    stat_lx_out->LxMode = 0UL;
    switch(info->type) {
        case NF4REG:
            stat_lx_out->LxMode |= LX_MODE_S_IFREG;
            break;
        case NF4DIR:
            stat_lx_out->LxMode |= LX_MODE_S_IFDIR;
            break;
        case NF4BLK:
            /* Map block dev to WSL char dev */
            stat_lx_out->LxMode |= LX_MODE_S_IFCHR;
            break;
        case NF4CHR:
            stat_lx_out->LxMode |= LX_MODE_S_IFCHR;
            break;
        case NF4LNK:
            /*
             * gisburn: Is this really correct to do nothing here,
             * or is |stat_lx_out->ReparseTag| enough ?
             */
            if (info->symlink_dir)
                stat_lx_out->LxMode |= LX_MODE_S_IFDIR;
            break;
        case NF4SOCK:
            /* Map socket dev to WSL char dev */
            stat_lx_out->LxMode |= LX_MODE_S_IFCHR;
            break;
        case NF4FIFO:
            stat_lx_out->LxMode |= LX_MODE_S_IFIFO;
            break;
        default:
            DPRINTF(0,
                ("nfs_to_stat_lx_info: "
                "unhandled file type %d, defaulting to NF4REG\n",
                info->type));
            stat_lx_out->LxMode |= LX_MODE_S_IFREG;
            break;
    }

    EASSERT((info->attrmask.count > 0) &&
        (info->attrmask.arr[1] & FATTR4_WORD1_MODE));
    if (info->mode & MODE4_RUSR)
        stat_lx_out->LxMode |= LX_MODE_S_IREAD;
    if (info->mode & MODE4_WUSR)
        stat_lx_out->LxMode |= LX_MODE_S_IWRITE;
    if (info->mode & MODE4_XUSR)
        stat_lx_out->LxMode |= LX_MODE_S_IEXEC;

    char owner[NFS4_FATTR4_OWNER_LIMIT+1];
    char owner_group[NFS4_FATTR4_OWNER_LIMIT+1];
    uid_t map_uid = ~0UL;
    gid_t map_gid = ~0UL;
    char *at_ch; /* pointer to '@' */

    EASSERT((info->attrmask.arr[1] & FATTR4_WORD1_OWNER) != 0);
    EASSERT((info->attrmask.arr[1] & FATTR4_WORD1_OWNER_GROUP) != 0);

    /* Make copies as we will modify  them */
    (void)strcpy(owner, info->owner);
    (void)strcpy(owner_group, info->owner_group);

    /*
     * Map owner to local uid
     *
     * |owner| can be numeric string ("1616"), plain username
     * ("gisburn") or username@domain ("gisburn@sun.com")
     */
    /* stomp over '@' */
    at_ch = strchr(owner, '@');
    if (at_ch)
        *at_ch = '\0';

    if (!nfs41_idmap_name_to_uid(
        nfs41_dg->idmapper,
        owner,
        &map_uid)) {
        stat_lx_out->LxFlags |= LX_FILE_METADATA_HAS_UID;
        stat_lx_out->LxUid = map_uid;
    }
    else {
        /*
         * No mapping --> Use |NFS NFS_USER_NOBODY_UID| and set
         * |LX_FILE_METADATA_HAS_UID|, because we have an user
         * name, but just no name2uid mapping
         */
        stat_lx_out->LxFlags |= LX_FILE_METADATA_HAS_UID;
        stat_lx_out->LxUid = NFS_USER_NOBODY_UID;
    }

    /*
     * Map owner_group to local gid
     *
     * |owner_group| can be numeric string ("1616"), plain username
     * ("gisgrp") or username@domain ("gisgrp@sun.com")
     */
    /* stomp over '@' */
    at_ch = strchr(owner_group, '@');
    if (at_ch)
        *at_ch = '\0';

    if (!nfs41_idmap_group_to_gid(
        nfs41_dg->idmapper,
        owner_group,
        &map_gid)) {
        stat_lx_out->LxFlags |= LX_FILE_METADATA_HAS_GID;
        stat_lx_out->LxGid = map_gid;
    }
    else {
        /*
         * No mapping --> Use |NFS NFS_GROUP_NOGROUP_GID| and set
         * |LX_FILE_METADATA_HAS_GID|, because we have a group
         * name, but just no name2gid mapping
         */
        stat_lx_out->LxFlags |= LX_FILE_METADATA_HAS_GID;
        stat_lx_out->LxUid = NFS_GROUP_NOGROUP_GID;
    }

    /* FIXME: |LX_FILE_METADATA_HAS_DEVICE_ID| not implemented yet */
    stat_lx_out->LxDeviceIdMajor = 0UL;
    stat_lx_out->LxDeviceIdMinor = 0UL;
}
#endif /* NFS41_DRIVER_WSL_SUPPORT */

/* copy |nfs41_file_info| */
void nfs41_file_info_cpy(
    OUT nfs41_file_info *dest,
    IN const nfs41_file_info *src)
{
    /*
     * FIXME: Using |memcpy()| here over the whole struct
     * |nfs41_file_info| will trigger DrMemory uninitialized
     * variable hits if |*src| was not completely initialized
     */
    (void)memcpy(dest, src, sizeof(nfs41_file_info));
    if (src->owner != NULL)
        dest->owner = dest->owner_buf;
    if (src->owner_group != NULL)
        dest->owner_group = dest->owner_group_buf;
}
