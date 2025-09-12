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
#include <stdio.h>

#include "nfs41_build_features.h"
#include "daemon_debug.h"
#include "nfs41.h"
#include "nfs41_ops.h"
#include "name_cache.h"
#include "from_kernel.h"
#include "nfs41_driver.h"
#include "util.h"


#define SBLVL 3 /* dprintf level for superblock logging */


static __inline int compare_fsid(
    IN const nfs41_fsid *lhs,
    IN const nfs41_fsid *rhs)
{
    if (lhs->major > rhs->major) return 1;
    if (lhs->major < rhs->major) return -1;
    if (lhs->minor > rhs->minor) return 1;
    if (lhs->minor < rhs->minor) return -1;
    return 0;
}


/* nfs41_superblock */
static int superblock_create(
    IN const nfs41_fsid *fsid,
    OUT nfs41_superblock **superblock_out)
{
    int status = NO_ERROR;
    nfs41_superblock *superblock;

    DPRINTF(SBLVL, ("creating superblock for fsid(%llu,%llu)\n",
        fsid->major, fsid->minor));

    superblock = calloc(1, sizeof(nfs41_superblock));
    if (superblock == NULL) {
        status = GetLastError();
        eprintf("failed to allocate superblock "
            "for fsid(%llu,%llu)\n", fsid->major, fsid->minor);
        goto out;
    }

    memcpy(&superblock->fsid, fsid, sizeof(nfs41_fsid));
    InitializeSRWLock(&superblock->lock);

    *superblock_out = superblock;
out:
    return status;
}

static int get_superblock_attrs(
    IN nfs41_session *session,
    IN nfs41_superblock *superblock,
    IN nfs41_path_fh *file)
{
    bool_t supports_named_attrs;
    int status;
    bitmap4 attr_request;
    nfs41_file_info info = { 0 };

    attr_request.arr[0] = FATTR4_WORD0_SUPPORTED_ATTRS |
        FATTR4_WORD0_LINK_SUPPORT | FATTR4_WORD0_SYMLINK_SUPPORT |
        FATTR4_WORD0_ACLSUPPORT | FATTR4_WORD0_CANSETTIME |
        FATTR4_WORD0_CASE_INSENSITIVE | FATTR4_WORD0_CASE_PRESERVING |
        FATTR4_WORD0_MAXREAD | FATTR4_WORD0_MAXWRITE;
    attr_request.arr[1] = FATTR4_WORD1_FS_LAYOUT_TYPE |
        FATTR4_WORD1_TIME_DELTA;
    attr_request.arr[2] = FATTR4_WORD2_SUPPATTR_EXCLCREAT;
    attr_request.count = 3;

    info.supported_attrs = &superblock->supported_attrs;
    info.suppattr_exclcreat = &superblock->suppattr_exclcreat;
    info.time_delta = &superblock->time_delta;

    status = nfs41_superblock_getattr(session, file,
        &attr_request, &info, &supports_named_attrs);
    if (status) {
        eprintf("nfs41_superblock_getattr() failed with '%s'/%d when "
            "fetching attributes for fsid(%llu,%llu)\n",
            nfs_error_string(status), status,
            superblock->fsid.major, superblock->fsid.minor);
        goto out;
    }

    if (info.maxread)
        superblock->maxread = info.maxread;
    else
        superblock->maxread = session->fore_chan_attrs.ca_maxresponsesize;

    if (info.maxwrite)
        superblock->maxwrite = info.maxwrite;
    else
        superblock->maxwrite = session->fore_chan_attrs.ca_maxrequestsize;

    superblock->layout_types = info.fs_layout_types;
    superblock->aclsupport = info.aclsupport;
    superblock->link_support = info.link_support;
    superblock->symlink_support = info.symlink_support;
    superblock->ea_support = supports_named_attrs;
//#define TEST_LINUX_FORCE_FAT32 1
#ifdef TEST_LINUX_FORCE_FAT32
    /*
     * Testing-ONLY: Force FAT32 behaviour, because Linux nfsd returns
     * |info.case_insensitive==0| even on FAT32
     * Windows Server 2019 nfsd and OpenText nfsd do this correctly
     */
    DPRINTF(0, ("get_superblock_attrs: TEST_LINUX_FORCE_FAT32 enabled!\n"));
    superblock->case_preserving = 0/*info.case_preserving*/;
    superblock->case_insensitive = 1/*info.case_insensitive*/;
#else
    superblock->case_preserving = info.case_preserving;
    superblock->case_insensitive = info.case_insensitive;
#endif /* TEST_FS_FORCE_FAT32 */
    superblock->sparse_file_support = 1; /* always ON for now */
    if (session->client->root->nfsminorvers >= 2) {
        superblock->block_clone_support = 1;
    }
    else {
        superblock->block_clone_support = 0;
    }

    nfs41_name_cache_set_casesensitivesearch(
        session->client->server->name_cache,
        superblock->case_insensitive?false:true);

    if (bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CANSETTIME))
        superblock->cansettime = info.cansettime;
    else /* cansettime is not supported, try setting them anyway */
        superblock->cansettime = 1;

    /* if time_delta is not supported, default to 1s */
    if (!bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_TIME_DELTA))
        superblock->time_delta.seconds = 1;

    /* initialize the default getattr mask */
    superblock->default_getattr.count = 2;
    superblock->default_getattr.arr[0] = FATTR4_WORD0_TYPE
        | FATTR4_WORD0_CHANGE | FATTR4_WORD0_SIZE
        | FATTR4_WORD0_FSID | FATTR4_WORD0_FILEID
        | FATTR4_WORD0_HIDDEN | FATTR4_WORD0_ARCHIVE;
    superblock->default_getattr.arr[1] = FATTR4_WORD1_MODE
        | FATTR4_WORD1_NUMLINKS | FATTR4_WORD1_SPACE_USED
        | FATTR4_WORD1_SYSTEM
        | FATTR4_WORD1_TIME_ACCESS | FATTR4_WORD1_TIME_CREATE
        | FATTR4_WORD1_TIME_MODIFY;
    superblock->default_getattr.arr[2] = 0;

    nfs41_superblock_supported_attrs(superblock, &superblock->default_getattr);

    DPRINTF(SBLVL, ("attributes for fsid(%llu,%llu): "
        "maxread=%llu, maxwrite=%llu, layout_types: 0x%X, "
        "cansettime=%u, time_delta={%llu,%u}, aclsupport=%u, "
        "link_support=%u, symlink_support=%u, case_preserving=%u, "
        "case_insensitive=%u, sparse_file_support=%u, "
        "block_clone_support=%u\n",
        superblock->fsid.major, superblock->fsid.minor,
        superblock->maxread, superblock->maxwrite,
        superblock->layout_types, superblock->cansettime,
        superblock->time_delta.seconds, superblock->time_delta.nseconds,
        superblock->aclsupport, superblock->link_support,
        superblock->symlink_support, superblock->case_preserving,
        superblock->case_insensitive,
        superblock->sparse_file_support,
        superblock->block_clone_support));
out:
    return status;
}

void nfs41_superblock_fs_attributes(
    IN const nfs41_superblock *restrict superblock,
    OUT NFS41_FILE_FS_ATTRIBUTE_INFORMATION *restrict FsAttrs)
{
    /*
     * |FileSystemAttributes| - general filesystem attributes
     *
     * Notes:
     * - |FILE_SUPPORTS_REMOTE_STORAGE| can only be set if we are on
     * HSM storage (tape worm etc.), see
     * https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/d4bc551b-7aaf-4b4f-ba0e-3a75e7c528f0#Appendix_A_167
     */

    FsAttrs->FileSystemAttributes = 0;
    FsAttrs->FileSystemAttributes |= FILE_SUPPORTS_SPARSE_FILES;
    /* NFSv4 protocol uses Unicode by default */
    FsAttrs->FileSystemAttributes |= FILE_UNICODE_ON_DISK;

    /* We support |FileCaseSensitiveInformation| to query each dir */
    FsAttrs->FileSystemAttributes |= FILE_SUPPORTS_CASE_SENSITIVE_DIRS;

    if (superblock->link_support)
        FsAttrs->FileSystemAttributes |= FILE_SUPPORTS_HARD_LINKS;
    if (superblock->symlink_support)
        FsAttrs->FileSystemAttributes |= FILE_SUPPORTS_REPARSE_POINTS;
    if (superblock->ea_support)
        FsAttrs->FileSystemAttributes |= FILE_SUPPORTS_EXTENDED_ATTRIBUTES;
    if (superblock->case_preserving)
        FsAttrs->FileSystemAttributes |= FILE_CASE_PRESERVED_NAMES;
    if (!superblock->case_insensitive)
        FsAttrs->FileSystemAttributes |= FILE_CASE_SENSITIVE_SEARCH;
    if (superblock->aclsupport)
        FsAttrs->FileSystemAttributes |= FILE_PERSISTENT_ACLS;
    if (superblock->block_clone_support)
        FsAttrs->FileSystemAttributes |= FILE_SUPPORTS_BLOCK_REFCOUNTING;

    /* gisburn: Fixme: We should someone query this (NFSv4.2 ?) */
    FsAttrs->MaximumComponentNameLength = NFS41_MAX_COMPONENT_LEN;

    /* let the driver fill in FileSystemName */
#if ((NFS41_DRIVER_DEBUG_FS_NAME) == 1)
    (void)wcscpy(FsAttrs->FileSystemName, L"NFS");
    FsAttrs->FileSystemNameLength = 3*sizeof(wchar_t);
#elif  ((NFS41_DRIVER_DEBUG_FS_NAME) == 2)
    (void)wcscpy(FsAttrs->FileSystemName, L"DEBUG-NFS41");
    FsAttrs->FileSystemNameLength = 11*sizeof(wchar_t);
#else
#error NFS41_DRIVER_DEBUG_FS_NAME not defined
#endif

    DPRINTF(SBLVL, ("FileFsAttributeInformation: "
        "link_support=%u, "
        "symlink_support=%u, "
        "ea_support=%u, "
        "case_preserving=%u, "
        "case_insensitive=%u, "
        "aclsupport=%u, "
        "MaximumComponentNameLength=%u, "
        "FileSystemAttributes=0x%lx\n",
        superblock->link_support,
        superblock->symlink_support,
        superblock->ea_support,
        superblock->case_preserving,
        superblock->case_insensitive,
        superblock->aclsupport,
        (unsigned int)FsAttrs->MaximumComponentNameLength,
        (unsigned long)FsAttrs->FileSystemAttributes));
}


/* nfs41_superblock_list */
#define superblock_entry(pos) list_container(pos, nfs41_superblock, entry)

static int superblock_compare(
    const struct list_entry *entry,
    const void *value)
{
    const nfs41_superblock *superblock = superblock_entry(entry);
    return compare_fsid(&superblock->fsid, (const nfs41_fsid*)value);
}

static nfs41_superblock* find_superblock(
    IN nfs41_superblock_list *superblocks,
    IN const nfs41_fsid *fsid)
{
    struct list_entry *entry;
    entry = list_search(&superblocks->head, fsid, superblock_compare);
    return entry ? superblock_entry(entry) : NULL;
}

void nfs41_superblock_list_init(
    IN nfs41_superblock_list *superblocks)
{
    list_init(&superblocks->head);
    InitializeSRWLock(&superblocks->lock);
}

void nfs41_superblock_list_free(
    IN nfs41_superblock_list *superblocks)
{
    struct list_entry *entry, *tmp;

    DPRINTF(SBLVL, ("nfs41_superblock_list_free()\n"));

    list_for_each_tmp(entry, tmp, &superblocks->head)
        free(superblock_entry(entry));
}


int nfs41_superblock_for_fh(
    IN nfs41_session *session,
    IN const nfs41_fsid *fsid,
    IN const nfs41_fh *parent OPTIONAL,
    OUT nfs41_path_fh *file)
{
    int status = NFS4_OK;
    nfs41_server *server = client_server(session->client);
    nfs41_superblock_list *superblocks = &server->superblocks;
    nfs41_superblock *superblock;

    DPRINTF(SBLVL, ("--> nfs41_superblock_for_fh(fsid(%llu,%llu)))\n",
        fsid->major, fsid->minor));

    /* compare with the parent's fsid, and use that if it matches */
    if (parent && parent->superblock &&
            compare_fsid(fsid, &parent->superblock->fsid) == 0) {
        file->fh.superblock = parent->superblock;
        DPRINTF(SBLVL, ("using superblock from parent\n"));
        goto out;
    }

    /* using a shared lock, search for an existing superblock */
    AcquireSRWLockShared(&superblocks->lock);
    superblock = find_superblock(superblocks, fsid);
    ReleaseSRWLockShared(&superblocks->lock);

    if (superblock) {
        DPRINTF(SBLVL, ("found existing superblock in server list "
            "[shared lock]\n"));
    } else {
        AcquireSRWLockExclusive(&superblocks->lock);
        /* must search again under an exclusive lock, in case another thread
         * created it after our first search */
        superblock = find_superblock(superblocks, fsid);
        if (superblock) {
            DPRINTF(SBLVL, ("found newly created superblock in server list "
                "[exclusive lock]\n"));
        } else {
            /* create the superblock */
            status = superblock_create(fsid, &superblock);
            if (status == NO_ERROR) /* add it to the list */
                list_add_tail(&superblocks->head, &superblock->entry);
        }
        ReleaseSRWLockExclusive(&superblocks->lock);
    }

    if (status == NO_ERROR && superblock->supported_attrs.count == 0) {
        /* exclusive lock on the superblock while fetching attributes */
        AcquireSRWLockExclusive(&superblock->lock);
        if (superblock->supported_attrs.count == 0)
            status = get_superblock_attrs(session, superblock, file);
        ReleaseSRWLockExclusive(&superblock->lock);
    }

    file->fh.superblock = superblock;
out:
    DPRINTF(SBLVL, ("<-- nfs41_superblock_for_fh() returning 0x%p, status %d\n",
        file->fh.superblock, status));
    return status;
}

void nfs41_superblock_space_changed(
    IN nfs41_superblock *superblock)
{
    /* invalidate cached volume size attributes */
    AcquireSRWLockExclusive(&superblock->lock);
    superblock->cache_expiration = 0;
    ReleaseSRWLockExclusive(&superblock->lock);
}
