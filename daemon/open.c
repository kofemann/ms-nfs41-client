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
#include <ctype.h>
#include <strsafe.h>

#include "nfs41_build_features.h"
#include "nfs41_ops.h"
#include "nfs41_daemon.h"
#include "delegation.h"
#include "from_kernel.h"
#include "daemon_debug.h"
#include "upcall.h"
#include "fileinfoutil.h"
#include "util.h"
#include "idmap.h"
#include "accesstoken.h"

static int create_open_state(
    IN const char *path,
    IN uint32_t open_owner_id,
    OUT nfs41_open_state **state_out)
{
    int status;
    nfs41_open_state *state;
    size_t path_len;


    state = calloc(1, sizeof(nfs41_open_state));
    if (state == NULL) {
        status = GetLastError();
        goto out;
    }

    InitializeSRWLock(&state->path.lock);

    path_len = strlen(path);
    if (path_len >= NFS41_MAX_PATH_LEN) {
        status = ERROR_FILENAME_EXCED_RANGE;
        goto out_free;
    }

    (void)strcpy(state->path.path, path);
    state->path.len = (unsigned short)path_len;

    path_fh_init(&state->file, &state->path);
    path_fh_init(&state->parent, &state->path);
    last_component(state->path.path, state->file.name.name, &state->parent.name);

    /*
     * We use |_ultoa()| as optimised version of this code:
     * |StringCchPrintfA((LPSTR)state->owner.owner, NFS4_OPAQUE_LIMIT, "%u",
     * open_owner_id);|
     */
    (void)_ultoa(open_owner_id, (LPSTR)state->owner.owner, 10);
    state->owner.owner_len = (uint32_t)strlen((const char*)state->owner.owner);

    InitializeSRWLock(&state->lock);
    state->ref_count = 1; /* will be released in |cleanup_close()| */
    list_init(&state->locks.list);
    list_init(&state->client_entry);
    InitializeCriticalSection(&state->locks.lock);

    state->ea.list = INVALID_HANDLE_VALUE;
    InitializeCriticalSection(&state->ea.lock);

    *state_out = state;
    status = NO_ERROR;
out:
    return status;

out_free:
    free(state);
    goto out;
}

static void open_state_free(
    IN nfs41_open_state *state)
{
    struct list_entry *entry, *tmp;

    EASSERT(waitcriticalsection(&state->ea.lock) == TRUE);
    EASSERT(waitcriticalsection(&state->locks.lock) == TRUE);

    EASSERT(waitSRWlock(&state->lock) == TRUE);
    EASSERT(waitSRWlock(&state->path.lock) == TRUE);

    /* free associated lock state */
    list_for_each_tmp(entry, tmp, &state->locks.list)
        free(list_container(entry, nfs41_lock_state, open_entry));
    if (state->delegation.state)
        nfs41_delegation_deref(state->delegation.state);
    if (state->ea.list != INVALID_HANDLE_VALUE)
        free(state->ea.list);

    DeleteCriticalSection(&state->ea.lock);
    DeleteCriticalSection(&state->locks.lock);

    EASSERT(state->ref_count == 0);

    free(state);
}

/* open state reference counting */
void nfs41_open_state_ref(
    IN nfs41_open_state *state)
{
    EASSERT(state->ref_count > 0);

    const LONG count = InterlockedIncrement(&state->ref_count);

    DPRINTF(2, ("nfs41_open_state_ref('%s') count %d\n", state->path.path, count));
}

void nfs41_open_state_deref(
    IN nfs41_open_state *state)
{
    EASSERT(state->ref_count > 0);

    const LONG count = InterlockedDecrement(&state->ref_count);

    DPRINTF(2, ("nfs41_open_state_deref('%s') count %d\n", state->path.path, count));
    if (count == 0)
        open_state_free(state);
}

/* 8.2.5. Stateid Use for I/O Operations
 * o  If the client holds a delegation for the file in question, the
 *    delegation stateid SHOULD be used.
 * o  Otherwise, if the entity corresponding to the lock-owner (e.g., a
 *    process) sending the I/O has a byte-range lock stateid for the
 *    associated open file, then the byte-range lock stateid for that
 *    lock-owner and open file SHOULD be used.
 * o  If there is no byte-range lock stateid, then the OPEN stateid for
 *    the open file in question SHOULD be used.
 * o  Finally, if none of the above apply, then a special stateid SHOULD
 *    be used. */
void nfs41_open_stateid_arg(
    IN nfs41_open_state *state,
    OUT stateid_arg *arg)
{
    arg->open = state;
    arg->delegation = NULL;

    AcquireSRWLockShared(&state->lock);

    if (state->delegation.state) {
        nfs41_delegation_state *deleg = state->delegation.state;
        AcquireSRWLockShared(&deleg->lock);
        if (deleg->status == DELEGATION_GRANTED) {
            arg->type = STATEID_DELEG_FILE;
            stateid4_cpy(&arg->stateid, &deleg->state.stateid);
        }
        ReleaseSRWLockShared(&deleg->lock);

        if (arg->type == STATEID_DELEG_FILE)
            goto out;

        DPRINTF(2, ("delegation recalled, waiting for open stateid...\n"));

        /* wait for nfs41_delegation_to_open() to recover open stateid */
        while (!state->do_close)
            SleepConditionVariableSRW(&state->delegation.cond, &state->lock,
                INFINITE, CONDITION_VARIABLE_LOCKMODE_SHARED);
    }

    if (state->locks.stateid.seqid) {
        stateid4_cpy(&arg->stateid, &state->locks.stateid);
        arg->type = STATEID_LOCK;
    } else if (state->do_close) {
        stateid4_cpy(&arg->stateid, &state->stateid);
        arg->type = STATEID_OPEN;
    } else {
        stateid4_clear(&arg->stateid);
        arg->type = STATEID_SPECIAL;
    }
out:
    ReleaseSRWLockShared(&state->lock);
}

/* client list of associated open state */
static void client_state_add(
    IN nfs41_open_state *state)
{
    nfs41_client *client = state->session->client;

    EnterCriticalSection(&client->state.lock);
    list_add_tail(&client->state.opens, &state->client_entry);
    LeaveCriticalSection(&client->state.lock);
}

static void client_state_remove(
    IN nfs41_open_state *state)
{
    nfs41_client *client = state->session->client;

    EnterCriticalSection(&client->state.lock);
    list_remove(&state->client_entry);
    LeaveCriticalSection(&client->state.lock);
}

static int do_open(
    IN OUT nfs41_open_state *state,
    IN uint32_t create,
    IN uint32_t createhow,
    IN nfs41_file_info *createattrs,
    IN bool_t try_recovery,
    OUT nfs41_file_info *info)
{
    open_claim4 claim;
    stateid4 open_stateid;
    open_delegation4 delegation = { 0 };
    nfs41_delegation_state *deleg_state = NULL;
    int status;

    claim.claim = CLAIM_NULL;
    claim.u.null.filename = &state->file.name;

    status = nfs41_open(state->session, &state->parent, &state->file,
        &state->owner, &claim, state->share_access, state->share_deny,
        create, createhow, createattrs, TRUE, &open_stateid,
        &delegation, info);
    if (status)
        goto out;

    /* allocate delegation state and register it with the client */
    nfs41_delegation_granted(state->session, &state->parent,
        &state->file, &delegation, TRUE, &deleg_state);
    if (deleg_state) {
        deleg_state->srv_open = state->srv_open;
        DPRINTF(1, ("do_open: "
            "received delegation: saving srv_open = 0x%p\n",
            state->srv_open));
    }

    AcquireSRWLockExclusive(&state->lock);
    /* update the stateid */
    stateid4_cpy(&state->stateid, &open_stateid);
    state->do_close = 1;
    state->delegation.state = deleg_state;
    ReleaseSRWLockExclusive(&state->lock);
out:
    return status;
}

static int open_or_delegate(
    IN OUT nfs41_open_state *state,
    IN uint32_t create,
    IN uint32_t createhow,
    IN nfs41_file_info *createattrs,
    IN bool_t try_recovery,
    OUT nfs41_file_info *info)
{
    int status;

    /* check for existing delegation */
    status = nfs41_delegate_open(state, create, createattrs, info);

    /* get an open stateid if we have no delegation stateid */
    if (status)
        status = do_open(state, create, createhow,
            createattrs, try_recovery, info);

    state->pnfs_last_offset = info->size ? info->size - 1 : 0;

    /* register the client's open state on success */
    if (status == NFS4_OK)
        client_state_add(state);
    return status;
}


static int parse_abs_path(unsigned char **buffer, uint32_t *length, nfs41_abs_path *path)
{
    int status = safe_read(buffer, length, &path->len, sizeof(USHORT));
    if (status) goto out;
    if (path->len == 0)
        goto out;
    if (path->len >= NFS41_MAX_PATH_LEN) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    status = safe_read(buffer, length, path->path, path->len);
    if (status) goto out;
    path->len--; /* subtract 1 for null */
out:
    return status;
}

/* NFS41_SYSOP_OPEN */
static int parse_open(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    open_upcall_args *args = &upcall->args.open;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->access_mask, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->access_mode, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->file_attrs, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->create_opts, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->disposition, sizeof(ULONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->open_owner_id, sizeof(LONG));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->mode, sizeof(DWORD));
    if (status) goto out;
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    status = safe_read(&buffer, &length, &args->owner_local_uid, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->owner_group_local_gid, sizeof(DWORD));
    if (status) goto out;
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
    status = safe_read(&buffer, &length, &args->srv_open, sizeof(HANDLE));
    if (status) goto out;
    status = parse_abs_path(&buffer, &length, &args->symlink);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->ea, sizeof(HANDLE));
    if (status) goto out;

#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    DPRINTF(1, ("parsing NFS41_SYSOP_OPEN: filename='%s' access mask=%d "
        "access mode=%d\n\tfile attrs=0x%x create attrs=0x%x "
        "(kernel) disposition=%d\n\topen_owner_id=%d mode=0%o "
        "owner_local_uid=%u owner_group_local_gid=%u "
        "srv_open=0x%p symlink=%s ea=0x%p\n", args->path, args->access_mask,
        args->access_mode, args->file_attrs, args->create_opts,
        args->disposition, args->open_owner_id, args->mode,
        (unsigned int)args->owner_local_uid, (unsigned int)args->owner_group_local_gid,
        args->srv_open,
        args->symlink.path, args->ea));
#else
    DPRINTF(1, ("parsing NFS41_SYSOP_OPEN: filename='%s' access mask=%d "
        "access mode=%d\n\tfile attrs=0x%x create attrs=0x%x "
        "(kernel) disposition=%d\n\topen_owner_id=%d mode=0%o "
        "srv_open=0x%p symlink=%s ea=0x%p\n", args->path, args->access_mask,
        args->access_mode, args->file_attrs, args->create_opts,
        args->disposition, args->open_owner_id, args->mode,
        args->srv_open,
        args->symlink.path, args->ea));
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */

    if (DPRINTF_LEVEL_ENABLED(2)) {
        print_disposition(2, args->disposition);
        print_access_mask(2, args->access_mask);
        print_share_mode(2, args->access_mode);
        print_create_attributes(2, args->create_opts);
    }
out:
    return status;
}

static BOOLEAN open_for_attributes(uint32_t type, ULONG access_mask, 
                                   ULONG disposition, int status)
{
    if (type == NF4DIR) {
        if (disposition == FILE_OPEN || disposition == FILE_OVERWRITE ||
                (!status && (disposition == FILE_OPEN_IF ||
                    disposition == FILE_OVERWRITE_IF ||
                    disposition == FILE_SUPERSEDE))) {
            DPRINTF(1, ("Opening a directory\n"));
            return TRUE;
        } else {
            DPRINTF(1, ("Creating a directory\n"));
            return FALSE;
        }
    }

    if ((access_mask & FILE_READ_DATA) ||
            (access_mask & FILE_WRITE_DATA) ||
            (access_mask & FILE_APPEND_DATA) ||
            (access_mask & FILE_EXECUTE) ||
            disposition == FILE_CREATE ||
            disposition == FILE_OVERWRITE_IF ||
            disposition == FILE_SUPERSEDE ||
            disposition == FILE_OPEN_IF ||
            disposition == FILE_OVERWRITE)
        return FALSE;
    else {
        DPRINTF(1, ("Open call that wants to manage attributes\n"));
        return TRUE;
    }
}

static int map_disposition_2_nfsopen(ULONG disposition, int in_status, bool_t persistent,
                                     uint32_t *create, uint32_t *createhowmode,
                                     uint32_t *last_error)
{
    int status = NO_ERROR;
    if (disposition == FILE_SUPERSEDE) {
        if (in_status == NFS4ERR_NOENT)           
            *last_error = ERROR_FILE_NOT_FOUND;
        //remove and recreate the file
        *create = OPEN4_CREATE;
        if (persistent) *createhowmode = GUARDED4;
        else *createhowmode = EXCLUSIVE4_1;
    } else if (disposition == FILE_CREATE) {
        // if lookup succeeded which means the file exist, return an error
        if (!in_status)
            status = ERROR_FILE_EXISTS;
        else {
            *create = OPEN4_CREATE;
            if (persistent) *createhowmode = GUARDED4;
            else *createhowmode = EXCLUSIVE4_1;
        }
    } else if (disposition == FILE_OPEN) {
        if (in_status == NFS4ERR_NOENT)
            status = ERROR_FILE_NOT_FOUND;
        else
            *create = OPEN4_NOCREATE;
    } else if (disposition == FILE_OPEN_IF) {
        if (in_status == NFS4ERR_NOENT) {
            DPRINTF(1, ("creating new file\n"));
            *create = OPEN4_CREATE;
            *last_error = ERROR_FILE_NOT_FOUND;
        } else {
            DPRINTF(1, ("opening existing file\n"));
            *create = OPEN4_NOCREATE;
        }
    } else if (disposition == FILE_OVERWRITE) {
        if (in_status == NFS4ERR_NOENT)
            status = ERROR_FILE_NOT_FOUND;
        //truncate file
        *create = OPEN4_CREATE;
    } else if (disposition == FILE_OVERWRITE_IF) {
        if (in_status == NFS4ERR_NOENT)
            *last_error = ERROR_FILE_NOT_FOUND;
        //truncate file
        *create = OPEN4_CREATE;
    }
    return status;
}

static void map_access_2_allowdeny(ULONG access_mask, ULONG access_mode,
                                   ULONG disposition, uint32_t *allow, uint32_t *deny)
{
    if ((access_mask & 
            (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES)) &&
            (access_mask & (FILE_READ_DATA | FILE_EXECUTE)))
        *allow = OPEN4_SHARE_ACCESS_BOTH;
    else if (access_mask & (FILE_READ_DATA | FILE_EXECUTE))
        *allow = OPEN4_SHARE_ACCESS_READ;
    else if (access_mask & 
                (FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES))
        *allow = OPEN4_SHARE_ACCESS_WRITE;
    /* if we are creating a file and no data access is specified, then 
     * do an open and request no delegations. example open with share access 0
     * and share deny 0 (ie deny_both).
     */
    if ((disposition == FILE_CREATE || disposition == FILE_OPEN_IF || 
            disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE ||
            disposition == FILE_OVERWRITE) &&
            !(access_mask & (FILE_WRITE_DATA | FILE_APPEND_DATA | 
            FILE_WRITE_ATTRIBUTES | FILE_READ_DATA | FILE_EXECUTE)))
        *allow = OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG;

#define FIX_ALLOW_DENY_WIN2NFS_CONVERSION
#ifdef FIX_ALLOW_DENY_WIN2NFS_CONVERSION
    if ((access_mode & FILE_SHARE_READ) &&
            (access_mode & FILE_SHARE_WRITE))
        *deny = OPEN4_SHARE_DENY_NONE;
    else if (access_mode & FILE_SHARE_READ)
        *deny = OPEN4_SHARE_DENY_WRITE;
    else if (access_mode & FILE_SHARE_WRITE)
        *deny = OPEN4_SHARE_DENY_READ;
    else
        *deny = OPEN4_SHARE_DENY_BOTH;
#else
    // AGLO: 11/13/2009.
    // readonly file that is being opened for reading with a
    // share read mode given above logic translates into deny
    // write and linux server does not allow it.
    *deny = OPEN4_SHARE_DENY_NONE;
#endif
}

static int check_execute_access(nfs41_open_state *state)
{
    uint32_t supported, access;
    int status = nfs41_access(state->session, &state->file,
        ACCESS4_EXECUTE | ACCESS4_READ, &supported, &access);
    if (status) {
        eprintf("nfs41_access() failed with '%s' for '%s'\n",
            nfs_error_string(status), state->path.path);
        status = ERROR_ACCESS_DENIED;
    } else if ((supported & ACCESS4_EXECUTE) == 0) {
        /* server can't verify execute access;
         * for now, assume that read access is good enough */
        if ((supported & ACCESS4_READ) == 0 || (access & ACCESS4_READ) == 0) {
            eprintf("server can't verify execute access, and user does "
                "not have read access to file %s\n", state->path.path);
            status = ERROR_ACCESS_DENIED;
        }
    } else if ((access & ACCESS4_EXECUTE) == 0) {
        DPRINTF(1, ("user does not have execute access to file '%s'\n",
            state->path.path));
        status = ERROR_ACCESS_DENIED;
    } else
        DPRINTF(2, ("user has execute access to file\n"));
    return status;
}

static int create_with_ea(
    IN uint32_t disposition,
    IN uint32_t lookup_status)
{
    /* only set EAs on file creation */
    return disposition == FILE_SUPERSEDE || disposition == FILE_CREATE
        || disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF
        || (disposition == FILE_OPEN_IF && lookup_status == NFS4ERR_NOENT);
}

static
void symlink2ntpath(
    IN OUT nfs41_abs_path *restrict symlink,
    OUT nfs41_sysop_open_symlinktarget_type *out_target_type)
{
    DPRINTF(1, ("--> symlink2ntpath(symlink='%.*s', len=%d)\n",
        (int)symlink->len,
        symlink->path,
        (int)symlink->len));

    /*
     * Path with \cygdrive\<devletter> prefix
     * (e.g. "\cygdrive\l\path" or "\cygdrive\l" ) ?
     */
    if ((symlink->len > 10) &&
        (!memcmp(symlink->path, "\\cygdrive\\", 10)) &&
        ((symlink->path[11] == '\\') || (symlink->len == 11))) {
        char deviceletter;
        char ntpath_buf[NFS41_MAX_PATH_LEN];

        deviceletter = symlink->path[10];

        EASSERT(((deviceletter >= 'a') && (deviceletter <= 'z')) ||
            ((deviceletter >= 'A') && (deviceletter <= 'Z')));

        /* Return an "drive absolute" NT path */
        (void)snprintf(ntpath_buf, sizeof(ntpath_buf),
            "\\??\\%c:\\%.*s",
            toupper(deviceletter),
            (int)(symlink->len-12),
            &symlink->path[12]);
        (void)strcpy(symlink->path, ntpath_buf);
        symlink->len = (unsigned short)strlen(ntpath_buf);

        DPRINTF(1, ("drive abolute symlink='%.*s', len=%d\n",
            (int)symlink->len,
            symlink->path,
            (int)symlink->len));
        *out_target_type = NFS41_SYMLINKTARGET_NTPATH;
    }
    /* UNC path (e.g. "\\server\path") ? */
    else if ((symlink->len > 3) &&
        (!memcmp(symlink->path, "\\\\", 2)) &&
        (memchr(&symlink->path[3], '\\', symlink->len-3) != NULL)) {
        char ntpath_buf[NFS41_MAX_PATH_LEN];

        /* return an (absolute) UNC NT PATH*/
        (void)snprintf(ntpath_buf, sizeof(ntpath_buf),
            "\\??\\UNC\\%.*s",
            (int)(symlink->len-2),
            &symlink->path[2]);
        (void)strcpy(symlink->path, ntpath_buf);
        symlink->len = (unsigned short)strlen(ntpath_buf);

        DPRINTF(1, ("UNC symlink='%.*s', len=%d\n",
            (int)symlink->len,
            symlink->path,
            (int)symlink->len));
        *out_target_type = NFS41_SYMLINKTARGET_NTPATH;
    }
    else {
        /*
         * All other paths just return a "drive abolute" path,
         * e.g. \foo\bar
         */

        /* These asserts should never be triggered... */
        EASSERT(symlink->len > 0);
        EASSERT((symlink->len > 0) && (symlink->path[0] == '\\'));
        *out_target_type = NFS41_SYMLINKTARGET_FILESYSTEM_ABSOLUTE;
    }

    DPRINTF(1,
        ("<-- symlink2ntpath(symlink='%.*s', len=%d, "
            "*out_target_type=%d)\n",
        (int)symlink->len,
        symlink->path,
        (int)symlink->len,
        (int)*out_target_type));
}

#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
static
void open_get_localuidgid(IN nfs41_daemon_globals *restrict nfs41dg,
    IN nfs41_open_state *restrict state,
    IN OUT nfs41_file_info *restrict info,
    OUT DWORD *restrict owner_local_uid,
    OUT DWORD *restrict owner_group_local_gid)
{
    int status = 0;
    char owner[NFS4_FATTR4_OWNER_LIMIT+1];
    char owner_group[NFS4_FATTR4_OWNER_LIMIT+1];
    uid_t map_uid = ~0UL;
    gid_t map_gid = ~0UL;
    char *at_ch; /* pointer to '@' */

#if 1
    EASSERT(info->attrmask.count >= 2);

    /* this should only happen for newly created files/dirs */
    if ((info->attrmask.count < 2) ||
        ((info->attrmask.arr[1] & FATTR4_WORD1_OWNER) == 0) ||
        ((info->attrmask.arr[1] & FATTR4_WORD1_OWNER_GROUP) == 0)) {
        bitmap4 og_attr_request;
        nfs41_file_info og_info = { 0 };

        og_attr_request.count = 2;
        og_attr_request.arr[0] = 0;
        og_attr_request.arr[1] =
            FATTR4_WORD1_OWNER | FATTR4_WORD1_OWNER_GROUP;
        og_info.owner = og_info.owner_buf;
        og_info.owner_group = og_info.owner_group_buf;
        status = nfs41_getattr(state->session, &state->file,
            &og_attr_request, &og_info);
        if (status) {
            eprintf("open_get_localuidgid: nfs41_getattr('%s') "
                "failed with %d\n",
                state->path.path,
                status);
            *owner_local_uid = NFS_USER_NOBODY_UID;
            *owner_group_local_gid = NFS_GROUP_NOGROUP_GID;
            goto out;
        }

        info->owner = info->owner_buf;
        (void)strcpy(info->owner, og_info.owner);
        info->attrmask.arr[1] |= FATTR4_WORD1_OWNER;
        info->owner_group = info->owner_group_buf;
        (void)strcpy(info->owner_group, og_info.owner_group);
        info->attrmask.arr[1] |= FATTR4_WORD1_OWNER_GROUP;
    }
#endif

    EASSERT((info->attrmask.arr[1] & FATTR4_WORD1_OWNER) != 0);
    EASSERT((info->attrmask.arr[1] & FATTR4_WORD1_OWNER_GROUP) != 0);
    EASSERT(info->owner != NULL);
    EASSERT(info->owner_group != NULL);
    EASSERT(info->owner == info->owner_buf);
    EASSERT(info->owner_group == info->owner_group_buf);
    EASSERT(strlen(info->owner) > 0);
    EASSERT(strlen(info->owner_group) > 0);

    /* Make copies as we will modify  them */
    (void)strcpy(owner, info->owner);
    (void)strcpy(owner_group, info->owner_group);

    /*
     * Map owner to local uid
     *
     * |owner| can be numeric string ("1616"), plain username
     *  ("gisburn") or username@domain ("gisburn@sun.com")
     */
    /* stomp over '@' */
    at_ch = strchr(owner, '@');
    if (at_ch)
        *at_ch = '\0';

    if (nfs41_idmap_name_to_uid(
        nfs41dg->idmapper,
        owner,
        &map_uid) == 0) {
         *owner_local_uid = map_uid;
    }
    else {
        *owner_local_uid = NFS_USER_NOBODY_UID;
        eprintf("open_get_localuidgid('%s'): "
            "no username mapping for '%s', fake uid=%u\n",
            state->path.path,
            owner,
            (unsigned int)*owner_local_uid);
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

    if (nfs41_idmap_group_to_gid(
        nfs41dg->idmapper,
        owner_group,
        &map_gid) == 0) {
        *owner_group_local_gid = map_gid;
    }
    else {
        *owner_group_local_gid = NFS_GROUP_NOGROUP_GID;
        eprintf("open_get_localuidgid('%s'): "
            "no group mapping for '%s', fake gid=%u\n",
            state->path.path,
            owner_group,
            (unsigned int)*owner_group_local_gid);
    }

out:
    DPRINTF(1,
        ("open_get_localuidgid('%s'): "
        "stat: owner=%u/'%s', owner_group=%u/'%s'\n",
        state->path.path,
        (unsigned int)*owner_local_uid, owner,
        (unsigned int)*owner_group_local_gid,
        owner_group));
}
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */

static int handle_open(void *daemon_context, nfs41_upcall *upcall)
{
    int status = 0;
    nfs41_daemon_globals *nfs41dg = daemon_context;
    open_upcall_args *args = &upcall->args.open;
    nfs41_open_state *state;
    nfs41_file_info info = { 0 };

    EASSERT_MSG(!(args->create_opts & FILE_COMPLETE_IF_OPLOCKED),
        ("handle_open: file='%s': "
        "FILE_COMPLETE_IF_OPLOCKED not supported\n", args->path));
    EASSERT_MSG(!(args->create_opts & FILE_OPEN_BY_FILE_ID),
        ("handle_open: file='%s': "
        "FILE_OPEN_BY_FILE_ID not supported\n", args->path));
    /*
     * Kernel rejects |FILE_OPEN_REQUIRING_OPLOCK|, we just use
     * this here as safeguard
     */
    EASSERT_MSG(!(args->create_opts & FILE_OPEN_REQUIRING_OPLOCK),
        ("handle_open: file='%s': "
        "FILE_OPEN_REQUIRING_OPLOCK not supported\n", args->path));
    EASSERT_MSG(!(args->create_opts & FILE_DISALLOW_EXCLUSIVE),
        ("handle_open: file='%s': "
        "FILE_DISALLOW_EXCLUSIVE not supported\n", args->path));
    EASSERT_MSG(!(args->create_opts & FILE_RESERVE_OPFILTER),
        ("handle_open: file='%s': "
        "FILE_RESERVE_OPFILTER not supported\n", args->path));

    status = create_open_state(args->path, args->open_owner_id, &state);
    if (status) {
        eprintf("handle_open(args->path='%s'): "
            "create_open_state(%d) failed with %d\n",
            args->path,
            args->open_owner_id, status);
        goto out;
    }
    state->srv_open = args->srv_open;

    // first check if windows told us it's a directory
    if (args->create_opts & FILE_DIRECTORY_FILE)
        state->type = NF4DIR;
    else
        state->type = NF4REG;

    // always do a lookup
    status = nfs41_lookup(upcall->root_ref, nfs41_root_session(upcall->root_ref),
        &state->path, &state->parent, &state->file, &info, &state->session);

    if (status == ERROR_REPARSE) {
        uint32_t depth = 0;
        /* one of the parent components was a symlink */
        do {
            if (++depth > NFS41_MAX_SYMLINK_DEPTH) {
                status = ERROR_TOO_MANY_LINKS;
                goto out_free_state;
            }

            /* replace the path with the symlink target's */
            status = nfs41_symlink_target(state->session,
                &state->parent, &state->path);
            if (status) {
                /* can't do the reparse if we can't get the target */
                eprintf("handle_open(args->path='%s'): "
                    "nfs41_symlink_target() "
                    "failed with %d\n",
                    args->path,
                    status);
                goto out_free_state;
            }

            /* redo the lookup until it doesn't return REPARSE */
            status = nfs41_lookup(upcall->root_ref, state->session,
                &state->path, &state->parent, NULL, NULL, &state->session);
        } while (status == ERROR_REPARSE);

        if (status == NO_ERROR || status == ERROR_FILE_NOT_FOUND) {
            abs_path_copy(&args->symlink, &state->path);
            status = NO_ERROR;
            upcall->last_error = ERROR_REPARSE;
            args->symlink_embedded = TRUE;
            args->symlinktarget_type =
                NFS41_SYMLINKTARGET_FILESYSTEM_ABSOLUTE;
        }
        goto out_free_state;
    }

    // now if file/dir exists, use type returned by lookup
    if (status == NO_ERROR) {
        if (info.type == NF4DIR) {
            DPRINTF(2, ("handle_nfs41_open: DIRECTORY\n"));
            if (args->create_opts & FILE_NON_DIRECTORY_FILE) {
                DPRINTF(1, ("trying to open directory '%s' as a file\n",
                    state->path.path));
                /*
                 * Notes:
                 * - NTFS+SMB returns |STATUS_FILE_IS_A_DIRECTORY|
                 * - See |map_open_errors()| for the mapping to
                 * |STATUS_*|
                 */
                status = ERROR_DIRECTORY_NOT_SUPPORTED;
                goto out_free_state;
            }
        } else if (info.type == NF4REG) {
            DPRINTF(2, ("handle nfs41_open: FILE\n"));
            if (args->create_opts & FILE_DIRECTORY_FILE) {
                DPRINTF(1, ("trying to open file '%s' as a directory\n",
                    state->path.path));
                /*
                 * Notes:
                 * - SMB returns |STATUS_OBJECT_TYPE_MISMATCH|
                 * while NTFS returns |STATUS_NOT_A_DIRECTORY|
                 * - See |map_open_errors()| for the mapping to
                 * |STATUS_*|
                 */
                status = ERROR_DIRECTORY;
                goto out_free_state;
            }
        } else if (info.type == NF4LNK) {
            DPRINTF(2, ("handle nfs41_open: SYMLINK\n"));
            if (args->create_opts & FILE_OPEN_REPARSE_POINT) {
                /* continue and open the symlink itself, but we need to
                 * know if the target is a regular file or directory */
                nfs41_file_info target_info = { 0 };
                int target_status = nfs41_symlink_follow(upcall->root_ref,
                    state->session, &state->file, &target_info);
                if (target_status == NO_ERROR) {
                    info.symlink_dir = target_info.type == NF4DIR;
                }
                else {
#ifdef NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS
                    target_info.type = TRUE;
#else
                    target_info.type = FALSE;
#endif /* NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS */
                }
            } else {
                /* replace the path with the symlink target */
                status = nfs41_symlink_target(state->session,
                    &state->file, &args->symlink);
                if (status) {
                    eprintf("handle_open(args->path='%s'): "
                        "nfs41_symlink_target() failed with %d\n",
                        args->path,
                        status);
                } else {
                    symlink2ntpath(&args->symlink, &args->symlinktarget_type);
                    /* tell the driver to call RxPrepareToReparseSymbolicLink() */
                    upcall->last_error = ERROR_REPARSE;
                    args->symlink_embedded = FALSE;
                }
                goto out_free_state;
            }
        } else
            DPRINTF(2, ("handle_open(): unsupported type=%d\n", info.type));
        state->type = info.type;
    } else if (status != ERROR_FILE_NOT_FOUND)
        goto out_free_state;

    /* XXX: this is a hard-coded check for the open arguments we see from
     * the CreateSymbolicLink() system call.  we respond to this by deferring
     * the CREATE until we get the upcall to set the symlink.  this approach
     * is troublesome for two reasons:
     * -an application might use these exact arguments to create a normal
     *   file, and we would return success without actually creating it
     * -an application could create a symlink by sending the FSCTL to set
     *   the reparse point manually, and their open might be different.  in
     *   this case we'd create the file on open, and need to remove it
     *   before creating the symlink */
    if (args->disposition == FILE_CREATE &&
            args->access_mask == (FILE_WRITE_ATTRIBUTES | SYNCHRONIZE | DELETE) &&
            args->access_mode == 0 &&
            args->create_opts & FILE_OPEN_REPARSE_POINT) {
        /* fail if the file already exists */
        if (status == NO_ERROR) {
            status = ERROR_FILE_EXISTS;
            goto out_free_state;
        }

        /* defer the call to CREATE until we get the symlink set upcall */
        DPRINTF(1, ("trying to create a symlink, deferring create\n"));

        /* because of WRITE_ATTR access, be prepared for a setattr upcall;
         * will crash if the superblock is null, so use the parent's */
        state->file.fh.superblock = state->parent.fh.superblock;

        status = NO_ERROR;
    } else if (args->symlink.len) {
        /* handle cygwin symlinks */
        nfs41_file_info createattrs;
        createattrs.attrmask.count = 2;
        createattrs.attrmask.arr[0] = 0;
        createattrs.attrmask.arr[1] = FATTR4_WORD1_MODE;
        createattrs.mode = 0777;

        DPRINTF(1, ("creating cygwin symlink '%s' -> '%s'\n",
            state->file.name.name, args->symlink.path));

        status = nfs41_create(state->session, NF4LNK, &createattrs,
            args->symlink.path, &state->parent, &state->file, &info);
        if (status) {
            eprintf("handle_open(args->path='%s'): "
                "nfs41_create() for symlink='%s' failed with '%s'\n",
                args->path,
                args->symlink.path,
                nfs_error_string(status));
            status = map_symlink_errors(status);
            goto out_free_state;
        }
        nfs_to_basic_info(state->file.name.name,
            state->file.fh.superblock,
            &info,
            &args->basic_info);
        nfs_to_standard_info(state->file.fh.superblock,
            &info,
            &args->std_info);
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_FILEID));
        args->fileid = info.fileid;
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_FSID));
        args->fsid_major = info.fsid.major;
        args->fsid_minor = info.fsid.minor;
        EASSERT(bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_MODE));
        args->mode = info.mode;
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
        args->changeattr = info.change;
    } else if (open_for_attributes(state->type, args->access_mask,
                args->disposition, status)) {
        if (status) {
            DPRINTF(1, ("nfs41_lookup failed with %d\n", status));
            goto out_free_state;
        }

        nfs_to_basic_info(state->file.name.name,
            state->file.fh.superblock,
            &info,
            &args->basic_info);
        nfs_to_standard_info(state->file.fh.superblock,
            &info,
            &args->std_info);
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_FILEID));
        args->fileid = info.fileid;
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_FSID));
        args->fsid_major = info.fsid.major;
        args->fsid_minor = info.fsid.minor;
        EASSERT(bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_MODE));
        args->mode = info.mode;
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
        args->changeattr = info.change;
        /*
         + |args->owner_local_uid| and |args->owner_group_local_gid|
         * is set below
         */
    } else {
        nfs41_file_info createattrs;
        uint32_t create = 0, createhowmode = 0, lookup_status = status;

        if (!lookup_status && (args->disposition == FILE_OVERWRITE ||
                args->disposition == FILE_OVERWRITE_IF ||
                args->disposition == FILE_SUPERSEDE)) {
            if ((info.hidden && !(args->file_attrs & FILE_ATTRIBUTE_HIDDEN)) ||
                    (info.system && !(args->file_attrs & FILE_ATTRIBUTE_SYSTEM))) {
                status = ERROR_ACCESS_DENIED;
                goto out_free_state;
            }
            if (args->disposition != FILE_SUPERSEDE)
                args->mode = info.mode;
        }
        createattrs.attrmask.count = 2;
        createattrs.attrmask.arr[0] = FATTR4_WORD0_HIDDEN | FATTR4_WORD0_ARCHIVE;
        createattrs.attrmask.arr[1] = FATTR4_WORD1_MODE | FATTR4_WORD1_SYSTEM;
        createattrs.mode = args->mode;
        createattrs.hidden = args->file_attrs & FILE_ATTRIBUTE_HIDDEN ? 1 : 0;
        createattrs.system = args->file_attrs & FILE_ATTRIBUTE_SYSTEM ? 1 : 0;
        createattrs.archive = args->file_attrs & FILE_ATTRIBUTE_ARCHIVE ? 1 : 0;

        map_access_2_allowdeny(args->access_mask, args->access_mode,
            args->disposition, &state->share_access, &state->share_deny);
        status = map_disposition_2_nfsopen(args->disposition, status, 
                    state->session->flags & CREATE_SESSION4_FLAG_PERSIST, 
                    &create, &createhowmode, &upcall->last_error);
        if (status)
            goto out_free_state;

        if (args->access_mask & FILE_EXECUTE && state->file.fh.len) {
            status = check_execute_access(state);
            if (status)
                goto out_free_state;
        }

supersede_retry:
        // XXX file exists and we have to remove it first
        if (args->disposition == FILE_SUPERSEDE && lookup_status == NO_ERROR) {
            nfs41_component *name = &state->file.name;
            if (!(args->create_opts & FILE_DIRECTORY_FILE))
                nfs41_delegation_return(state->session, &state->file,
                    OPEN_DELEGATE_WRITE, TRUE);

            DPRINTF(1, ("open for FILE_SUPERSEDE removing '%s' first\n", name->name));
            status = nfs41_remove(state->session, &state->parent,
                name, state->file.fh.fileid);
            if (status)
                goto out_free_state;
        }

        if (create == OPEN4_CREATE && (args->create_opts & FILE_DIRECTORY_FILE)) {
            status = nfs41_create(state->session, NF4DIR, &createattrs, NULL, 
                &state->parent, &state->file, &info);
            args->created = status == NFS4_OK ? TRUE : FALSE;
        } else {
            createattrs.attrmask.arr[0] |= FATTR4_WORD0_SIZE;
            createattrs.size = 0;
            DPRINTF(1, ("creating with mode 0%o\n", args->mode));
            status = open_or_delegate(state, create, createhowmode, &createattrs,
                TRUE, &info);
            if (status == NFS4_OK && state->delegation.state)
                    args->deleg_type = state->delegation.state->state.type;
        }
        if (status) {
            DPRINTF(1, ("'%s' failed with '%s'\n", (create == OPEN4_CREATE &&
                (args->create_opts & FILE_DIRECTORY_FILE))?"nfs41_create":"nfs41_open",
                nfs_error_string(status)));
            if (args->disposition == FILE_SUPERSEDE && status == NFS4ERR_EXIST)
                goto supersede_retry;
            status = nfs_to_windows_error(status, ERROR_FILE_NOT_FOUND);
            goto out_free_state;
        } else {
#ifdef NFS41_DRIVER_SETGID_NEWGRP_SUPPORT
            /*
             * Hack: Support |setgid()|/newgrp(1)/sg(1)/winsg(1) by
             * fetching groupname from auth token for new files and
             * do a "manual" chgrp on the new file
             *
             * Note that |RPCSEC_AUTH_NONE| does not have any
             * user/group information, therefore newgrp will be a
             * NOP here.
             */
            if ((create == OPEN4_CREATE) &&
                (state->session->client->rpc->sec_flavor !=
                    RPCSEC_AUTH_NONE)) {
                char *s;
                int chgrp_status;
                stateid_arg stateid;
                nfs41_file_info createchgrpattrs;

                createchgrpattrs.attrmask.count = 2;
                createchgrpattrs.attrmask.arr[0] = 0;
                createchgrpattrs.attrmask.arr[1] = FATTR4_WORD1_OWNER_GROUP;
                createchgrpattrs.owner_group = createchgrpattrs.owner_group_buf;
                /* fixme: we should store the |owner_group| name in |upcall| */
                if (!get_token_primarygroup_name(upcall->currentthread_token,
                    createchgrpattrs.owner_group)) {
                    eprintf("handle_open(args->path='%s'): "
                        "OPEN4_CREATE: "
                        "get_token_primarygroup_name() failed.\n",
                        args->path);
                    goto create_chgrp_out;
                }
                s = createchgrpattrs.owner_group+strlen(createchgrpattrs.owner_group);
                s = stpcpy(s, "@");
                (void)stpcpy(s, nfs41dg->localdomain_name);
                DPRINTF(1, ("handle_open(state->file.name.name='%s'): "
                    "OPEN4_CREATE: owner_group='%s'\n",
                    state->file.name.name,
                    createchgrpattrs.owner_group));

                nfs41_open_stateid_arg(state, &stateid);
                chgrp_status = nfs41_setattr(state->session,
                    &state->file, &stateid, &createchgrpattrs);
                if (chgrp_status) {
                    eprintf("handle_open(args->path='%s'): "
                        "OPEN4_CREATE: "
                        "nfs41_setattr(owner_group='%s') "
                        "failed with error '%s'.\n",
                        args->path,
                        createchgrpattrs.owner_group,
                        nfs_error_string(chgrp_status));
                }
create_chgrp_out:
                ;
            }
#endif /* NFS41_DRIVER_SETGID_NEWGRP_SUPPORT */

            nfs_to_basic_info(state->file.name.name,
                state->file.fh.superblock,
                &info,
                &args->basic_info);
            nfs_to_standard_info(state->file.fh.superblock,
                &info,
                &args->std_info);
            EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_FILEID));
            args->fileid = info.fileid;
            EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_FSID));
            args->fsid_major = info.fsid.major;
            args->fsid_minor = info.fsid.minor;
            EASSERT(bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_MODE));
            args->mode = info.mode;
            EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
            args->changeattr = info.change;
        }

        /* set extended attributes on file creation */
        if (DPRINTF_LEVEL_ENABLED(1)) {
            if (args->ea)
                debug_print_ea(args->ea);
            else
                DPRINTF(1, ("handle_open: No EA\n"));
        }

        if (args->ea && create_with_ea(args->disposition, lookup_status)) {
            status = nfs41_ea_set(state, args->ea);
            status = nfs_to_windows_error(status, ERROR_FILE_NOT_FOUND);
        }
    }

#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    if (status == 0) {
        open_get_localuidgid(nfs41dg,
            state,
            &info,
            &args->owner_local_uid,
            &args->owner_group_local_gid);
    }
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */

#ifdef DEBUG_OPEN_SPARSE_FILES
    if ((status == 0) &&
        (info.type == NF4REG) &&
        (state->session->client->root->supports_nfs42_seek)) {
        //debug_list_sparsefile_holes(state);
        debug_list_sparsefile_datasections(state);
    }
#endif /* DEBUG_OPEN_SPARSE_FILES */

    upcall->state_ref = state;
    nfs41_open_state_ref(upcall->state_ref);
out:
    return status;
out_free_state:
    nfs41_open_state_deref(state);
    goto out;
}

static int marshall_open(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    open_upcall_args *args = &upcall->args.open;

    status = safe_write(&buffer, length, &args->basic_info, sizeof(args->basic_info));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->std_info, sizeof(args->std_info));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->fileid, sizeof(args->fileid));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->fsid_major, sizeof(args->fsid_major));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->fsid_minor, sizeof(args->fsid_minor));
    if (status) goto out;
    status = safe_write(&buffer, length, &upcall->state_ref, sizeof(HANDLE));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->mode, sizeof(args->mode));
    if (status) goto out;
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    status = safe_write(&buffer, length, &args->owner_local_uid, sizeof(args->owner_local_uid));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->owner_group_local_gid, sizeof(args->owner_group_local_gid));
    if (status) goto out;
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
    status = safe_write(&buffer, length, &args->changeattr, sizeof(args->changeattr));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->deleg_type, sizeof(args->deleg_type));
    if (status) goto out;
    if (upcall->last_error == ERROR_REPARSE) {
        unsigned short len = (args->symlink.len + 1) * sizeof(WCHAR);
        status = safe_write(&buffer, length, &args->symlink_embedded, sizeof(BOOLEAN));
        if (status) goto out;
        BYTE tmp_symlinktarget_type = args->symlinktarget_type;
        status = safe_write(&buffer, length, &tmp_symlinktarget_type, sizeof(BYTE));
        if (status) goto out;
        status = safe_write(&buffer, length, &len, sizeof(len));
        if (status) goto out;
        /* convert args->symlink to wchar */
        if (*length <= len || !MultiByteToWideChar(CP_UTF8,
            MB_ERR_INVALID_CHARS,
            args->symlink.path, args->symlink.len,
            (LPWSTR)buffer, len / sizeof(WCHAR))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
    }
    DPRINTF(2, ("NFS41_SYSOP_OPEN: downcall "
        "open_state=0x%p "
        "fileid=0x%llx fsid=(0x%llx.0x%llx) "
        "mode=0%o changeattr=0x%llu\n",
        upcall->state_ref,
        (unsigned long long)args->fileid,
        (unsigned long long)args->fsid_major,
        (unsigned long long)args->fsid_minor,
        args->mode, args->changeattr));
out:
    return status;
}

static void cancel_open(IN nfs41_upcall *upcall)
{
    int status = NFS4_OK;
    open_upcall_args *args = &upcall->args.open;
    nfs41_open_state *state = upcall->state_ref;

    DPRINTF(1, ("--> cancel_open('%s')\n", args->path));

    if (upcall->state_ref == NULL ||
            upcall->state_ref == INVALID_HANDLE_VALUE)
        goto out; /* if handle_open() failed, the state was already freed */

    if (state->do_close) {
        stateid_arg stateid;
        stateid.open = state;
        stateid.delegation = NULL;
        stateid.type = STATEID_OPEN;
        stateid4_cpy(&stateid.stateid, &state->stateid);

        status = nfs41_close(state->session, &state->file, &stateid);
        if (status) {
            DPRINTF(1, ("cancel_open: nfs41_close() failed with '%s'\n",
                nfs_error_string(status)));
        }
    } else if (args->created) {
        const nfs41_component *name = &state->file.name;
        /* break any delegations and truncate before REMOVE */
        nfs41_delegation_return(state->session, &state->file,
            OPEN_DELEGATE_WRITE, TRUE);
        status = nfs41_remove(state->session, &state->parent,
            name, state->file.fh.fileid);
        if (status)
            DPRINTF(1, ("cancel_open: nfs41_remove() failed with '%s'\n",
                nfs_error_string(status)));
    }

    /* remove from the client's list of state for recovery */
    client_state_remove(state);
    nfs41_open_state_deref(state);
out:
    status = nfs_to_windows_error(status, ERROR_INTERNAL_ERROR);
    DPRINTF(1, ("<-- cancel_open() returning %d\n", status));
}


/* NFS41_SYSOP_CLOSE */
static int parse_close(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    close_upcall_args *args = &upcall->args.close;

    status = safe_read(&buffer, &length, &args->remove, sizeof(BOOLEAN));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->srv_open, sizeof(HANDLE));
    if (status) goto out;
    if (args->remove) {
        status = get_name(&buffer, &length, &args->path);
        if (status) goto out;
        status = safe_read(&buffer, &length, &args->renamed, sizeof(BOOLEAN));
        if (status) goto out;
    }

    DPRINTF(1,
        ("parsing NFS41_SYSOP_CLOSE: "
        "remove=%d srv_open=0x%p renamed=%d "
        "filename='%s'\n",
        args->remove, args->srv_open, args->renamed,
        args->remove ? args->path : ""));
out:
    return status;
}

static int do_nfs41_close(nfs41_open_state *state)
{
    int status;
    stateid_arg stateid;
    stateid.open = state;
    stateid.delegation = NULL;
    stateid.type = STATEID_OPEN;
    stateid4_cpy(&stateid.stateid, &state->stateid);

    status = nfs41_close(state->session, &state->file, &stateid);
    if (status) {
        DPRINTF(1, ("nfs41_close() failed with error '%s'.\n",
            nfs_error_string(status)));
        status = nfs_to_windows_error(status, ERROR_INTERNAL_ERROR);
    }

    return status;
}

static int handle_close(void *deamon_context, nfs41_upcall *upcall)
{
    int status = NFS4_OK, rm_status = NFS4_OK;
    close_upcall_args *args = &upcall->args.close;
    nfs41_open_state *state = upcall->state_ref;

    /* return associated file layouts if necessary */
    if (state->type == NF4REG)
        pnfs_layout_state_close(state->session, state, args->remove);

    if (state->srv_open == args->srv_open)
        nfs41_delegation_remove_srvopen(state->session, &state->file);

    if (args->remove) {
        nfs41_component *name = &state->file.name;

        if (args->renamed) {
            DPRINTF(1, ("removing a renamed file '%s'\n", name->name));
            create_silly_rename(&state->path, &state->file.fh, name);
            status = do_nfs41_close(state);
            if (status)
                goto out;
            else
                state->do_close = 0;
        }

        /* break any delegations and truncate before REMOVE */
        nfs41_delegation_return(state->session, &state->file,
            OPEN_DELEGATE_WRITE, TRUE);

        DPRINTF(1, ("calling nfs41_remove for '%s'\n", name->name));
retry_delete:
        rm_status = nfs41_remove(state->session, &state->parent,
            name, state->file.fh.fileid);
        if (rm_status) {
			if (rm_status == NFS4ERR_FILE_OPEN) {
				status = do_nfs41_close(state);
				if (!status) {
					state->do_close = 0;
					goto retry_delete;
				}  else goto out;
			}
            DPRINTF(1, ("nfs41_remove() failed with error '%s'.\n",
                nfs_error_string(rm_status)));
            rm_status = nfs_to_windows_error(rm_status, ERROR_INTERNAL_ERROR);
        }
    }

    if (state->do_close) {
        status = do_nfs41_close(state);
    }
out:
    /* remove from the client's list of state for recovery */
    client_state_remove(state);

    if (status || !rm_status)
        return status;
    else
        return rm_status;
}

static void cleanup_close(nfs41_upcall *upcall)
{
    /* release the initial reference from create_open_state() */
    nfs41_open_state_deref(upcall->state_ref);
}


const nfs41_upcall_op nfs41_op_open = {
    .parse = parse_open,
    .handle = handle_open,
    .marshall = marshall_open,
    .cancel = cancel_open,
    .arg_size = sizeof(open_upcall_args)
};
const nfs41_upcall_op nfs41_op_close = {
    .parse = parse_close,
    .handle = handle_close,
    .cleanup = cleanup_close,
    .arg_size = sizeof(close_upcall_args)
};
