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

#include <Windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>

#include "nfs41_build_features.h"
#include "daemon_debug.h"
#include "nfs41_daemon.h"
#include "util.h"
#include "nfs41_ops.h"
#include "nfs41_driver.h" /* for |FILE_INFO_TIME_NOT_SET| */


ULONG nfs_file_info_to_attributes(
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info)
{
    ULONG attrs = 0;

    if (info->type == NF4DIR)
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    else if (info->type == NF4LNK) {
        attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
        if (info->symlink_dir)
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else if (info->type == NF4REG) {
        if (superblock->sparse_file_support) {
            /* FIXME: What about pNFS ? */
            attrs |= FILE_ATTRIBUTE_SPARSE_FILE;
        }
    }
    else {
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
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
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

    basic_out->FileAttributes =
        nfs_file_info_to_attributes(superblock, info);
}

void nfs_to_standard_info(
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_STANDARD_INFO restrict std_out)
{
    const ULONG FileAttributes =
        nfs_file_info_to_attributes(superblock, info);

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
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_NETWORK_OPEN_INFORMATION restrict net_out)
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
    net_out->FileAttributes =
        nfs_file_info_to_attributes(superblock, info);
}

void nfs_to_remote_protocol_info(
    IN nfs41_open_state *state,
    OUT PFILE_REMOTE_PROTOCOL_INFORMATION restrict rpi_out)
{
    (void)memset(rpi_out, 0, sizeof(FILE_REMOTE_PROTOCOL_INFORMATION));

    rpi_out->StructureVersion = 1;
    rpi_out->StructureSize = sizeof(FILE_REMOTE_PROTOCOL_INFORMATION);
    rpi_out->Protocol = WNNC_NET_RDR2SAMPLE; /* FIXME! */

    /* ToDo: Add pNFS info */
    rpi_out->ProtocolMajorVersion = 4;
    rpi_out->ProtocolMinorVersion =
        (USHORT)state->session->client->root->nfsminorvers;
    rpi_out->ProtocolRevision = 0;

    /*
     * FIXME: |FILE_REMOTE_PROTOCOL_INFORMATION.Flags| should contain
     * |REMOTE_PROTOCOL_FLAG_PRIVACY| (krb5p) and
     * |REMOTE_PROTOCOL_FLAG_INTEGRITY| (krb5i) in case of Krb5 auth
     */
    rpi_out->Flags = 0;
}

#ifdef NFS41_DRIVER_WSL_SUPPORT
void nfs_to_stat_info(
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_STAT_INFORMATION restrict stat_out)
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

    stat_out->FileAttributes =
        nfs_file_info_to_attributes(superblock, info);

    stat_out->ReparseTag = (info->type == NF4LNK)?
        IO_REPARSE_TAG_SYMLINK : 0;

    stat_out->NumberOfLinks = info->numlinks;
    stat_out->EffectiveAccess =
        GENERIC_EXECUTE|GENERIC_WRITE|GENERIC_READ; /* FIXME */
}

void nfs_to_stat_lx_info(
    IN void *daemon_context,
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_STAT_LX_INFORMATION restrict stat_lx_out)
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

    stat_lx_out->FileAttributes =
        nfs_file_info_to_attributes(superblock, info);

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
    OUT nfs41_file_info *restrict dest,
    IN const nfs41_file_info *restrict src,
    IN int flags)
{
    const bitmap4 *attrmask = &src->attrmask;
    bitmap4_cpy(&dest->attrmask, &src->attrmask);

    if (attrmask->count > 0) {
        if (attrmask->arr[0] & FATTR4_WORD0_SUPPORTED_ATTRS) {
            dest->supported_attrs = src->supported_attrs;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_TYPE) {
            dest->type = src->type;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_CHANGE) {
            dest->change = src->change;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_SIZE) {
            dest->size = src->size;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_LINK_SUPPORT) {
            dest->link_support = src->link_support;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_SYMLINK_SUPPORT) {
            dest->symlink_support = src->symlink_support;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_FSID) {
            dest->fsid = src->fsid;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_LEASE_TIME) {
            dest->lease_time = src->lease_time;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_RDATTR_ERROR) {
            dest->rdattr_error = src->rdattr_error;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_ACL) {
            /* fixme: we should copy the contents! */
            dest->acl = src->acl;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_ACLSUPPORT) {
            dest->aclsupport = src->aclsupport;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_ARCHIVE) {
            dest->archive = src->archive;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_CANSETTIME) {
            dest->cansettime = src->cansettime;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_CASE_INSENSITIVE) {
            dest->case_insensitive = src->case_insensitive;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_CASE_PRESERVING) {
            dest->case_preserving = src->case_preserving;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_FILEID) {
            dest->fileid = src->fileid;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_FS_LOCATIONS) {
            /* fixme: we should copy the contents, not the pointer! */
            dest->fs_locations = src->fs_locations;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_HIDDEN) {
            dest->hidden = src->hidden;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_MAXREAD) {
            dest->maxread = src->maxread;
        }
        if (attrmask->arr[0] & FATTR4_WORD0_MAXWRITE) {
            dest->maxwrite = src->maxwrite;
        }
    }
    if (attrmask->count > 1) {
        if (attrmask->arr[1] & FATTR4_WORD1_MODE) {
            dest->mode = src->mode;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_NUMLINKS) {
            dest->numlinks = src->numlinks;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_OWNER) {
            EASSERT(src->owner != NULL);
            EASSERT(src->owner[0] != '\0');
            dest->owner = dest->owner_buf;
            (void)strcpy(dest->owner, src->owner);
        }
        if (attrmask->arr[1] & FATTR4_WORD1_OWNER_GROUP) {
            EASSERT(src->owner_group != NULL);
            EASSERT(src->owner_group[0] != '\0');
            dest->owner_group = dest->owner_group_buf;
            (void)strcpy(dest->owner_group_buf, src->owner_group_buf);
        }
        if (attrmask->arr[1] & FATTR4_WORD1_SPACE_AVAIL) {
            dest->space_avail = src->space_avail;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_SPACE_FREE) {
            dest->space_free = src->space_free;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_SPACE_TOTAL) {
            dest->space_total = src->space_total;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_SYSTEM) {
            dest->system = src->system;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_TIME_ACCESS) {
            dest->time_access = src->time_access;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_TIME_CREATE) {
            dest->time_create = src->time_create;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_TIME_DELTA) {
            dest->time_delta = src->time_delta;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_TIME_MODIFY) {
            dest->time_modify = src->time_modify;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_DACL) {
            /* fixme: we should copy the contents! */
            dest->acl = src->acl;
        }
        if (attrmask->arr[1] & FATTR4_WORD1_FS_LAYOUT_TYPE) {
            dest->fs_layout_types = src->fs_layout_types;
        }
    }
    if (attrmask->count > 2) {
        if (attrmask->arr[2] & FATTR4_WORD2_MODE_SET_MASKED) {
            dest->mode_mask = src->mode_mask;
        }
        if (attrmask->arr[2] & FATTR4_WORD2_MDSTHRESHOLD) {
            dest->mdsthreshold = src->mdsthreshold;
        }
        if (attrmask->arr[2] & FATTR4_WORD2_SUPPATTR_EXCLCREAT) {
            dest->suppattr_exclcreat = src->suppattr_exclcreat;
        }
    }

    if (flags & NFS41FILEINFOCPY_COPY_SYMLINK_DIR) {
        dest->symlink_dir = src->symlink_dir;
    }
}
