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
#include <strsafe.h>

#include "from_kernel.h"
#include "nfs41_ops.h"
#include "delegation.h"
#include "name_cache.h"
#include "upcall.h"
#include "util.h"
#include "daemon_debug.h"

/*
 * |UPCALL_BUF_SIZE| must fit at least twice (for rename) the
 * maximum path length plus header
 */
#if UPCALL_BUF_SIZE < ((NFS41_MAX_PATH_LEN*2)+2048)
#error UPCALL_BUF_SIZE too small for rename ((NFS41_MAX_PATH_LEN*2)+2048)
#endif

/* NFS41_SYSOP_FILE_SET */
static int parse_setattr(
    const unsigned char *restrict buffer,
    uint32_t length,
    nfs41_upcall *upcall)
{
    int status;
    setattr_upcall_args *args = &upcall->args.setattr;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->set_class, sizeof(args->set_class));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    status = get_safe_read_bufferpos(&buffer, &length,
        args->buf_len, (const void **)&args->buf);
    if (status) goto out;

    args->root = upcall->root_ref;
    args->state = upcall->state_ref;

    DPRINTF(1, ("parsing NFS41_SYSOP_FILE_SET: filename='%s' info_class=%d "
        "buf_len=%d\n", args->path, args->set_class, args->buf_len));
out:
    return status;
}

static int handle_nfs41_setattr_basicinfo(void *daemon_context, setattr_upcall_args *args)
{
    PFILE_BASIC_INFORMATION basic_info = (PFILE_BASIC_INFORMATION)args->buf;
    nfs41_open_state *state = args->state;
    nfs41_superblock *superblock = state->file.fh.superblock;
    stateid_arg stateid;
    nfs41_file_info info, old_info;
    int status = NO_ERROR;
    int getattr_status;

    (void)memset(&info, 0, sizeof(info));
    (void)memset(&old_info, 0, sizeof(old_info));

    if (basic_info == NULL) {
        eprintf("handle_nfs41_setattr_basicinfo: basic_info==NULL\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    getattr_status = nfs41_cached_getattr(state->session,
        &state->file, NULL, &old_info);
    if (getattr_status) {
        DPRINTF(0, ("handle_nfs41_setattr_basicinfo(args->path='%s'): "
            "nfs41_cached_getattr() failed with error %d.\n",
            args->path, getattr_status));
        status = getattr_status;
        goto out;
    }

    if (basic_info->FileAttributes) {
        info.hidden = basic_info->FileAttributes & FILE_ATTRIBUTE_HIDDEN ? 1 : 0;
        info.system = basic_info->FileAttributes & FILE_ATTRIBUTE_SYSTEM ? 1 : 0;
        info.archive = basic_info->FileAttributes & FILE_ATTRIBUTE_ARCHIVE ? 1 : 0;

        if (info.hidden != old_info.hidden) {
            info.attrmask.arr[0] |= FATTR4_WORD0_HIDDEN;
            info.attrmask.count = __max(info.attrmask.count, 1);
        }
        if (info.archive != old_info.archive) {
            info.attrmask.arr[0] |= FATTR4_WORD0_ARCHIVE;
            info.attrmask.count = __max(info.attrmask.count, 1);
        }
        if (info.system != old_info.system) {
            info.attrmask.arr[1] |= FATTR4_WORD1_SYSTEM;
            info.attrmask.count = __max(info.attrmask.count, 2);
        }

        EASSERT_MSG(((basic_info->FileAttributes & FILE_ATTRIBUTE_EA) == 0),
            ("handle_nfs41_setattr_basicinfo(args->path='%s)': "
            "Unsupported flag FILE_ATTRIBUTE_EA ignored.\n",
            args->path));
        EASSERT_MSG(((basic_info->FileAttributes & FILE_ATTRIBUTE_COMPRESSED) == 0),
            ("handle_nfs41_setattr_basicinfo(args->path='%s)': "
            "Unsupported flag FILE_ATTRIBUTE_COMPRESSED ignored.\n",
            args->path));
    }

    /* mode */
    if (basic_info->FileAttributes & FILE_ATTRIBUTE_READONLY) {
        info.mode = 0444;
        info.attrmask.arr[1] |= FATTR4_WORD1_MODE;
        info.attrmask.count = __max(info.attrmask.count, 2);
    }
    else {
        if (old_info.mode == 0444) {
            info.mode = 0644;
            info.attrmask.arr[1] |= FATTR4_WORD1_MODE;
            info.attrmask.count = __max(info.attrmask.count, 2);
        }
    }

    if (superblock->cansettime) {
        /* set the time_delta so xdr_settime4() can decide
         * whether or not to use SET_TO_SERVER_TIME4 */
        info.time_delta = &superblock->time_delta;

        /* time_create */
        if (basic_info->CreationTime.QuadPart > 0) {
            file_time_to_nfs_time(&basic_info->CreationTime,
                &info.time_create);
            info.attrmask.arr[1] |= FATTR4_WORD1_TIME_CREATE;
            info.attrmask.count = __max(info.attrmask.count, 2);
        }
        /* time_access_set */
        if (basic_info->LastAccessTime.QuadPart > 0) {
            file_time_to_nfs_time(&basic_info->LastAccessTime,
                &info.time_access);
            info.attrmask.arr[1] |= FATTR4_WORD1_TIME_ACCESS_SET;
            info.attrmask.count = __max(info.attrmask.count, 2);
        }
        /* time_modify_set */
        if (basic_info->LastWriteTime.QuadPart > 0) {
            file_time_to_nfs_time(&basic_info->LastWriteTime,
                &info.time_modify);
            info.attrmask.arr[1] |= FATTR4_WORD1_TIME_MODIFY_SET;
            info.attrmask.count = __max(info.attrmask.count, 2);
        }
    }

    /* mask out unsupported attributes */
    nfs41_superblock_supported_attrs(superblock, &info.attrmask);

    if (info.attrmask.count == 0)
        goto out;

    /* break read delegations before SETATTR */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_READ, FALSE);

    nfs41_open_stateid_arg(state, &stateid);

    status = nfs41_setattr(state->session, &state->file, &stateid, &info);
    if (status) {
        DPRINTF(1, ("handle_nfs41_setattr_basicinfo(args->path='%s'): "
            "nfs41_setattr() failed with error '%s'.\n",
            args->path,
            nfs_error_string(status)));
        status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
        goto out;
    }
    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;
out:
    return status;
}

static int handle_nfs41_remove(void *daemon_context, setattr_upcall_args *args)
{
    nfs41_open_state *state = args->state;
    int status;

    /* break any delegations and truncate before REMOVE */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_WRITE, TRUE);

    status = nfs41_remove(state->session, &state->parent,
        &state->file.name, state->file.fh.fileid);
    if (status) {
        DPRINTF(1, ("nfs41_remove() failed with error '%s'.\n",
            nfs_error_string(status)));
    }

    return nfs_to_windows_error(status, ERROR_ACCESS_DENIED);
}

static void open_state_rename(
    OUT nfs41_open_state *state,
    IN const nfs41_abs_path *path)
{
    AcquireSRWLockExclusive(&state->path.lock);

    abs_path_copy(&state->path, path);
    last_component(state->path.path, state->path.path + state->path.len,
        &state->file.name);
    last_component(state->path.path, state->file.name.name,
        &state->parent.name);

    ReleaseSRWLockExclusive(&state->path.lock);
}

static int nfs41_abs_path_compare(
    IN const struct list_entry *entry,
    IN const void *value)
{
    nfs41_open_state *client = list_container(entry, nfs41_open_state, client_entry);
    const nfs41_abs_path *name = (const nfs41_abs_path *)value;
    if (client->path.len == name->len && 
            !strncmp(client->path.path, name->path, client->path.len))
        return NO_ERROR;
    return ERROR_FILE_NOT_FOUND;
}

static int is_dst_name_opened(nfs41_abs_path *dst_path, nfs41_session *dst_session)
{
    int status;
    nfs41_client *client = dst_session->client;

    EnterCriticalSection(&client->state.lock);
    if (list_search(&client->state.opens, dst_path, nfs41_abs_path_compare))
        status = TRUE;
    else
        status = FALSE;
    LeaveCriticalSection(&client->state.lock);

    return status;
}

#define CYGWIN_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE 1
#define MSYS2_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE 1

#if defined(CYGWIN_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE) || \
    defined(MSYS2_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE)
#define STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE_SUPPORT 1
#endif

#ifdef STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE_SUPPORT
typedef struct _silly_rename_seq
{
    const char *name;
    size_t size;
    const wchar_t *in_sequence;
    const wchar_t *out_sequence;
} silly_rename_seq;

const silly_rename_seq silly_rename_seqlist[] = {
#ifdef CYGWIN_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE
    /* old Cygwin sequence, using valid Unicode characters */
    {
        .name="Cygwin1",
        .size=4,
        .in_sequence=L".\xdc63\xdc79\xdc67",
        .out_sequence=L".cyg"
    },
    /*
     * New Cygwin sequence, using valid Unicode characters -
     * see Cygwin commit "Cygwin: try_to_bin: transpose
     * deleted file name to valid Unicode chars"
     */
    {
        .name="Cygwin2",
        .size=4,
        .in_sequence=L".\xf763\xf779\xf767",
        .out_sequence=L".cyg"
    },
#endif /* CYGWIN_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE */
#ifdef MSYS2_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE
    {
        .name="msys2",
        .size=5,
        .in_sequence=L".\xdc6d\xdc73\xdc79\xdc73",
        .out_sequence=L".msys"
    },
#endif /* MSYS2_STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE */
    {
        .name = NULL
    }
};
#endif /* STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE_SUPPORT */

static int handle_nfs41_rename(void *daemon_context, setattr_upcall_args *args)
{
    nfs41_open_state *state = args->state;
    nfs41_session *dst_session;
    PFILE_RENAME_INFORMATION rename = (PFILE_RENAME_INFORMATION)args->buf;
    nfs41_abs_path dst_path = { 0 };
    nfs41_path_fh dst_dir, dst;
    nfs41_component dst_name, *src_name;
    uint32_t depth = 0;
    int status;

    src_name = &state->file.name;

    if (rename->FileNameLength == 0) {
        /* start from state->path instead of args->path, in case we got
         * the file from a referred server */
        AcquireSRWLockShared(&state->path.lock);
        abs_path_copy(&dst_path, &state->path);
        ReleaseSRWLockShared(&state->path.lock);

        path_fh_init(&dst_dir, &dst_path);
        fh_copy(&dst_dir.fh, &state->parent.fh);

        create_silly_rename(&dst_path, &state->file.fh, &dst_name);
        DPRINTF(1, ("silly rename: '%s' -> '%s'\n",
            src_name->name, dst_name.name));

        /* break any delegations and truncate before silly rename */
        nfs41_delegation_return(state->session, &state->file,
            OPEN_DELEGATE_WRITE, TRUE);

        status = nfs41_rename(state->session,
            &state->parent, src_name,
            &dst_dir, &dst_name);
        if (status) {
            DPRINTF(1, ("nfs41_rename() failed with error '%s'.\n",
                nfs_error_string(status)));
            status = nfs_to_windows_error(status, ERROR_ACCESS_DENIED);
        } else {
            /* rename state->path on success */
            open_state_rename(state, &dst_path);
        }
        goto out;
    }

    EASSERT((rename->FileNameLength%sizeof(WCHAR)) == 0);

#ifdef STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE_SUPPORT
    /*
     * Stomp old+new Cygwin+MSYS2 "silly rename" invalid Unicode
     * sequence
     *
     * Cygwin+MSYS2 has it's own variation of "silly rename" (i.e. if
     * someone deletes a file while someone else still has
     * a valid fd to that file it first renames that file with a
     * special prefix, see
     * newlib-cygwin/winsup/cygwin/syscalls.cc, function
     * |try_to_bin()|).
     *
     * Unfortunately on filesystems supporting Unicode
     * (i.e. |FILE_UNICODE_ON_DISK|) older Cygwin (before Cygwin
     * commit "Cygwin: try_to_bin: transpose deleted file name to
     * valid Unicode chars") adds the prefix
     * L".\xdc63\xdc79\xdc67", which is NOT a valid UTF-16 sequence,
     * and will be rejected by a filesystem validating the
     * UTF-16 sequence (e.g. SAMBA, ReFS, OpenZFS, ...; for SAMBA
     * Cygwin uses the ".cyg" prefix used for
     * non-|FILE_UNICODE_ON_DISK| filesystems).
     *
     * In our case the NFSv4.1 protocol requires valid UTF-8
     * sequences, and the NFS server will reject filenames if either
     * the server or the exported filesystem will validate the UTF-8
     * sequence.
     *
     * Since Cygwin only does a |rename()| and never a lookup by
     * that filename we just stomp the prefix with the ".cyg" prefix
     * used for non-|FILE_UNICODE_ON_DISK| filesystems.
     * We ignore the side-effects here, e.g. that Win32 will still
     * "remember" the original filename in the file name cache.
     *
     * For MSYS2+newer Cygwin we do the same.
     */
    for (const silly_rename_seq *srs = &silly_rename_seqlist[0];
        srs->name != NULL ; srs++) {
        if ((rename->FileNameLength > (srs->size*sizeof(wchar_t))) &&
            (!memcmp(rename->FileName,
                srs->in_sequence, (srs->size*sizeof(wchar_t))))) {
            DPRINTF(1, ("handle_nfs41_rename(args->path='%s'): "
                "'%s' sillyrename prefix "
                "detected, squishing prefix to '%ls'\n",
                args->path, srs->name, srs->out_sequence));
                (void)memcpy(rename->FileName, srs->out_sequence,
                srs->size*sizeof(wchar_t));
        }
    }
#endif /* STOMP_SILLY_RENAME_INVALID_UTF16_SEQUENCE_SUPPORT */

    dst_path.len = (unsigned short)WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS|WC_NO_BEST_FIT_CHARS,
        rename->FileName, rename->FileNameLength/sizeof(WCHAR),
        dst_path.path, NFS41_MAX_PATH_LEN, NULL, NULL);
    if (dst_path.len == 0) {
        eprintf("handle_nfs41_rename(args->path='%s'): "
            "WideCharToMultiByte() failed to convert destination "
            "filename '%.*S', lasterr=%d.\n",
            args->path,
            (int)(rename->FileNameLength/sizeof(WCHAR)),
            rename->FileName,
            (int)GetLastError());
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }
    path_fh_init(&dst_dir, &dst_path);

    /* the destination path is absolute, so start from the root session */
    status = nfs41_lookup(args->root, nfs41_root_session(args->root),
        BIT2BOOL(state->file.fh.superblock->case_insensitive),
        &dst_path, &dst_dir, &dst, NULL, &dst_session);

    while (status == ERROR_REPARSE) {
        if (++depth > NFS41_MAX_SYMLINK_DEPTH) {
            status = ERROR_TOO_MANY_LINKS;
            goto out;
        }

        /* replace the path with the symlink target's */
        status = nfs41_symlink_target(dst_session, &dst_dir, &dst_path);
        if (status) {
            eprintf("nfs41_symlink_target() for '%s' failed with %d\n",
                dst_dir.path->path, status);
            goto out;
        }

        /* redo the lookup until it doesn't return REPARSE */
        status = nfs41_lookup(args->root, dst_session,
            BIT2BOOL(state->file.fh.superblock->case_insensitive),
            &dst_path, &dst_dir, NULL, NULL, &dst_session);
    }

    /* get the components after lookup in case a referral changed its path */
    last_component(dst_path.path, dst_path.path + dst_path.len, &dst_name);
    last_component(dst_path.path, dst_name.name, &dst_dir.name);

    if (status == NO_ERROR) {
        if (!rename->ReplaceIfExists) {
            status = ERROR_FILE_EXISTS;
            goto out;
        }
        /* break any delegations and truncate the destination file */
        nfs41_delegation_return(dst_session, &dst,
            OPEN_DELEGATE_WRITE, TRUE);
    } else if (status != ERROR_FILE_NOT_FOUND) {
        DPRINTF(1, ("nfs41_lookup('%s') failed to find destination "
            "directory with %d\n", dst_path.path, status));
        goto out;
    }

    /* http://tools.ietf.org/html/rfc5661#section-18.26.3
     * "Source and target directories MUST reside on the same
     * file system on the server." */
    if (state->parent.fh.superblock != dst_dir.fh.superblock) {
        status = ERROR_NOT_SAME_DEVICE;
        goto out;
    }

    status = is_dst_name_opened(&dst_path, dst_session);
    if (status) {
        /* AGLO: 03/21/2011: we can't handle rename of a file with a filename
         * that is currently opened by this client
         */
        eprintf("handle_nfs41_rename: destination '%s' is opened, "
            "ReplaceIfExists=%d\n",
            dst_path.path,
            (int)rename->ReplaceIfExists);
/*
 * gisburn: HACK: We have disabled this check to get MariaDB working,
 * but we have to figure out what is the correct solution compared
 * to NTFS and SMBFS
 */
#ifdef DISABLED_FOR_NOW
        status = ERROR_FILE_EXISTS;
        goto out;
#endif
    }

    /* break any delegations on the source file */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_WRITE, FALSE);

    status = nfs41_rename(state->session,
        &state->parent, src_name,
        &dst_dir, &dst_name);
    if (status) {
        DPRINTF(1, ("nfs41_rename() failed with error '%s'.\n",
            nfs_error_string(status)));
        status = nfs_to_windows_error(status, ERROR_ACCESS_DENIED);
    } else {
        /* rename state->path on success */
        open_state_rename(state, &dst_path);
    }
out:
    return status;
}

static int handle_nfs41_set_size(void *daemon_context, setattr_upcall_args *args)
{
    nfs41_file_info info;
    stateid_arg stateid;
    /* note: this is called with either FILE_END_OF_FILE_INFO or
     * FILE_ALLOCATION_INFO, both of which contain a single LARGE_INTEGER */
    PLARGE_INTEGER size = (PLARGE_INTEGER)args->buf;
    nfs41_open_state *state = args->state;
    int status;

    (void)memset(&info, 0, sizeof(info));

    EASSERT_MSG(args->buf_len == sizeof(size->QuadPart),
        ("args->buf_len=%ld\n", (long)args->buf_len));

    DPRINTF(2,
        ("handle_nfs41_set_size: set_class='%s', new_file=%lld\n",
            FILE_INFORMATION_CLASS2string(args->set_class),
            (long long)size->QuadPart));

    /*
     * We cannot set the allocation size, the NFS server handles this
     * automagically
     */
    if (args->set_class == FileAllocationInformation) {
        status = nfs41_cached_getchangeattr(state, &info);
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
        args->ctime = info.change;
        goto out;
    }

    /* break read delegations before SETATTR */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_READ, FALSE);

    nfs41_open_stateid_arg(state, &stateid);

    info.size = size->QuadPart;
    info.attrmask.count = 1;
    info.attrmask.arr[0] = FATTR4_WORD0_SIZE;

    status = nfs41_setattr(state->session, &state->file, &stateid, &info);
    if (status) {
        DPRINTF(1, ("nfs41_setattr() failed with error '%s'.\n",
            nfs_error_string(status)));
        goto out;
    }

    /* update the last offset for LAYOUTCOMMIT */
    AcquireSRWLockExclusive(&state->lock);
    state->pnfs_last_offset = info.size ? info.size - 1 : 0;
    ReleaseSRWLockExclusive(&state->lock);
    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;
out:
    return status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
}

static int handle_nfs41_link(void *daemon_context, setattr_upcall_args *args)
{
    nfs41_open_state *state = args->state;
    PFILE_LINK_INFORMATION link = (PFILE_LINK_INFORMATION)args->buf;
    nfs41_session *dst_session;
    nfs41_abs_path dst_path = { 0 };
    nfs41_path_fh dst_dir, dst;
    nfs41_component dst_name;
    uint32_t depth = 0;
    nfs41_file_info info;
    int status;

    (void)memset(&info, 0, sizeof(info));

    EASSERT((link->FileNameLength%sizeof(WCHAR)) == 0);

    dst_path.len = (unsigned short)WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS|WC_NO_BEST_FIT_CHARS,
        link->FileName, link->FileNameLength/sizeof(WCHAR),
        dst_path.path, NFS41_MAX_PATH_LEN, NULL, NULL);
    if (dst_path.len == 0) {
        eprintf("handle_nfs41_link(args->path='%s'): "
            "WideCharToMultiByte() failed to convert destination "
            "filename '%.*S', lasterr=%d.\n",
            args->path,
            (int)(link->FileNameLength/sizeof(WCHAR)),
            link->FileName, (int)GetLastError());
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }
    path_fh_init(&dst_dir, &dst_path);

    /* the destination path is absolute, so start from the root session */
    status = nfs41_lookup(args->root, nfs41_root_session(args->root),
        BIT2BOOL(state->file.fh.superblock->case_insensitive),
        &dst_path, &dst_dir, &dst, NULL, &dst_session);

    while (status == ERROR_REPARSE) {
        if (++depth > NFS41_MAX_SYMLINK_DEPTH) {
            status = ERROR_TOO_MANY_LINKS;
            goto out;
        }

        /* replace the path with the symlink target's */
        status = nfs41_symlink_target(dst_session, &dst_dir, &dst_path);
        if (status) {
            eprintf("nfs41_symlink_target() for '%s' failed with %d\n",
                dst_dir.path->path, status);
            goto out;
        }

        /* redo the lookup until it doesn't return REPARSE */
        status = nfs41_lookup(args->root, dst_session,
            BIT2BOOL(state->file.fh.superblock->case_insensitive),
            &dst_path, &dst_dir, &dst, NULL, &dst_session);
    }

    /* get the components after lookup in case a referral changed its path */
    last_component(dst_path.path, dst_path.path + dst_path.len, &dst_name);
    last_component(dst_path.path, dst_name.name, &dst_dir.name);

    if (status == NO_ERROR) {
        if (!link->ReplaceIfExists) {
            status = ERROR_FILE_EXISTS;
            goto out;
        }
    } else if (status != ERROR_FILE_NOT_FOUND) {
        DPRINTF(1, ("nfs41_lookup('%s') failed to find destination "
            "directory with %d\n", dst_path.path, status));
        goto out;
    }

    /* http://tools.ietf.org/html/rfc5661#section-18.9.3
     * "The existing file and the target directory must reside within
     * the same file system on the server." */
    if (state->file.fh.superblock != dst_dir.fh.superblock) {
        status = ERROR_NOT_SAME_DEVICE;
        goto out;
    }

    if (status == NO_ERROR) {
        /* break any delegations and truncate the destination file */
        nfs41_delegation_return(dst_session, &dst,
            OPEN_DELEGATE_WRITE, TRUE);

        /* LINK will return NFS4ERR_EXIST if the target file exists,
         * so we have to remove it ourselves */
        status = nfs41_remove(state->session,
            &dst_dir, &dst_name, dst.fh.fileid);
        if (status) {
            DPRINTF(1, ("nfs41_remove() failed with error '%s'.\n",
                nfs_error_string(status)));
            status = ERROR_FILE_EXISTS;
            goto out;
        }
    }

    /* break read delegations on the source file */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_READ, FALSE);

    status = nfs41_link(state->session, &state->file, &dst_dir, &dst_name,
            &info);
    if (status) {
        DPRINTF(1, ("nfs41_link() failed with error '%s'.\n",
            nfs_error_string(status)));
        status = nfs_to_windows_error(status, ERROR_INVALID_PARAMETER);
        goto out;
    }
    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;
out:
    return status;
}

static int handle_setattr(void *daemon_context, nfs41_upcall *upcall)
{
    setattr_upcall_args *args = &upcall->args.setattr;
    int status;

    switch (args->set_class) {
    case FileBasicInformation:
        status = handle_nfs41_setattr_basicinfo(daemon_context, args);
        break;
    case FileDispositionInformation:
        status = handle_nfs41_remove(daemon_context, args);
        break;
    case FileRenameInformation:
        status = handle_nfs41_rename(daemon_context, args);
        break;
    case FileAllocationInformation:
    case FileEndOfFileInformation:
        status = handle_nfs41_set_size(daemon_context, args);
        break;
    case FileLinkInformation:
        status = handle_nfs41_link(daemon_context, args);
        break;
    default:
        eprintf("handle_setattr: unknown set_file information class %d\n",
            args->set_class);
        status = ERROR_NOT_SUPPORTED;
        break;
    }

    return status;
}

static int marshall_setattr(
    unsigned char *restrict buffer,
    uint32_t *restrict length,
    nfs41_upcall *restrict upcall)
{
    const setattr_upcall_args *args = &upcall->args.setattr;
    return safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
}


const nfs41_upcall_op nfs41_op_setattr = {
    .parse = parse_setattr,
    .handle = handle_setattr,
    .marshall = marshall_setattr,
    .arg_size = sizeof(setattr_upcall_args)
};
