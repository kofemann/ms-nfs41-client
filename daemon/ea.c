/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2024-2026 Roland Mainz <roland.mainz@nrubsig.org>
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
#include "upcall.h"
#include "daemon_debug.h"
#include "nfs_ea.h"

/*
 * Compile safeguard to see whether |NFS4_EASIZE+header| will still fit into
 * |UPCALL_BUF_SIZE|
 */
#if (NFS4_EASIZE+1024) > UPCALL_BUF_SIZE
#error NFS4_EASIZE does not fit into UPCALL_BUF_SIZE
#endif

/*
 * |WIN_NFS4_EA_NAME_PREFIX| - Prefix for Windows EAs in NFSv4
 * named attribute namespace
 *
 * We need such a prefix to avoid colliding with other users
 * in the NFSv4 named attribute namespace - for example SUN Microsystrems
 * (Solaris, Illumos, ...) uses "SUNWattr_" as prefix, and setting
 * such attributes can cause data corruption (or in case of
 * "SUNWattr_ro" will fail, because the attribute file is
 * read-only).
 */
#define WIN_NFS4_EA_NAME_PREFIX "win32.ea."
#define WIN_NFS4_EA_NAME_PREFIX_LEN (9)


#define EALVL 2 /* dprintf level for extended attribute logging */


static int set_ea_value(
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN state_owner4 *owner,
    IN PFILE_FULL_EA_INFORMATION ea)
{
    nfs41_path_fh file = { 0 };
    nfs41_file_info createattrs;
    open_claim4 claim;
    stateid_arg stateid;
    open_delegation4 delegation = { 0 };
    nfs41_write_verf verf;
    uint32_t bytes_written;
    int status;
    char prefixed_name[256];

    DPRINTF(EALVL,
        ("set_ea_value: "
            "ea->(EaName='%.*s' EaNameLength=%d)\n",
            (int)ea->EaNameLength,
            ea->EaName,
            (int)ea->EaNameLength));

    (void)snprintf(prefixed_name, sizeof(prefixed_name), "%s%.*s",
        WIN_NFS4_EA_NAME_PREFIX,
        (int)ea->EaNameLength,
        ea->EaName);

    /* don't allow values larger than NFS4_EASIZE */
    if (ea->EaValueLength > NFS4_EASIZE) {
        eprintf("set_ea_value: "
            "trying to write extended attribute value of size %d, "
            "max allowed %d\n", ea->EaValueLength, NFS4_EASIZE);
        status = NFS4ERR_FBIG;
        goto out;
    }
    /* remove the file on empty value */
    if (ea->EaValueLength == 0) {
        nfs41_component name;
        name.name = prefixed_name;
        name.len = (USHORT)strlen(prefixed_name);
        nfs41_remove(session, parent, &name, 0);
        status = NFS4_OK;
        goto out;
    }

    claim.claim = CLAIM_NULL;
    claim.u.null.filename = &file.name;
    file.name.name = prefixed_name;
    file.name.len = (USHORT)strlen(prefixed_name);

    createattrs.attrmask.count = 2;
    createattrs.attrmask.arr[0] = FATTR4_WORD0_SIZE;
    createattrs.attrmask.arr[1] = FATTR4_WORD1_MODE;
    createattrs.size = 0;
    createattrs.mode = 0664;

    status = nfs41_open(session, parent, &file, owner, &claim,
        OPEN4_SHARE_ACCESS_WRITE | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
        OPEN4_SHARE_DENY_BOTH, OPEN4_CREATE, UNCHECKED4,
        &createattrs, TRUE, &stateid.stateid, &delegation, NULL);
    if (status) {
        eprintf("set_ea_value: "
            "nfs41_open(ea_name='%s') failed with '%s'\n",
            prefixed_name,
            nfs_error_string(status));
        goto out;
    }

    status = nfs41_write(session, &file, &stateid,
        EA_VALUE(ea),
        ea->EaValueLength, 0, FILE_SYNC4, &bytes_written,
        &verf, NULL);
    if (status) {
        eprintf("set_ea_value: "
            "nfs41_write(ea_name='%s') failed with '%s'\n",
            prefixed_name,
            nfs_error_string(status));
        goto out_close;
    }

out_close:
    nfs41_close(session, &file, &stateid);
out:
    return status;
}

/* Is this a NFS extended attribute (commonly used by Cygwin) ? */
static bool is_nfs_ea(
    PFILE_FULL_EA_INFORMATION ea)
{
    return (((ea->EaNameLength == EA_NFSV3ATTRIBUTES_LEN) &&
            (!memcmp(EA_NFSV3ATTRIBUTES, ea->EaName, ea->EaNameLength)))
        || ((ea->EaNameLength == EA_NFSACTONLINK_LEN) &&
            (!memcmp(EA_NFSACTONLINK, ea->EaName, ea->EaNameLength)))
        || ((ea->EaNameLength == EA_NFSSYMLINKTARGETNAME_LEN) &&
            (!memcmp(EA_NFSSYMLINKTARGETNAME, ea->EaName, ea->EaNameLength))));
}


int nfs41_ea_set(
    IN nfs41_open_state *state,
    IN PFILE_FULL_EA_INFORMATION ea)
{
    nfs41_path_fh attrdir = { 0 };
    int status;

    status = nfs41_rpc_openattr(state->session, &state->file, TRUE, &attrdir.fh);
    if (status) {
        eprintf("nfs41_ea_set: "
            "nfs41_rpc_openattr() failed with error '%s'\n",
            nfs_error_string(status));
        goto out;
    }

    while (status == NFS4_OK) {
        if (!is_nfs_ea(ea))
            status = set_ea_value(state->session, &attrdir, &state->owner, ea);

        if (ea->NextEntryOffset == 0)
            break;
        ea = (PFILE_FULL_EA_INFORMATION)EA_NEXT_ENTRY(ea);
    }
out:
    return status;
}


/* NFS41_SYSOP_EA_SET */
static int parse_setexattr(
    const unsigned char *restrict buffer,
    uint32_t length,
    nfs41_upcall *upcall)
{
    int status;
    setexattr_upcall_args *args = &upcall->args.setexattr;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->mode, sizeof(args->mode));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    status = get_safe_read_bufferpos(&buffer, &length,
        args->buf_len, (const void **)&args->buf);
    if (status) goto out;

    EASSERT(length == 0);

    DPRINTF(1, ("parsing NFS41_SYSOP_EA_SET: mode=0%o\n", args->mode));
out:
    return status;
}

static int handle_setexattr(void *daemon_context, nfs41_upcall *upcall)
{
    int status;
    setexattr_upcall_args *args = &upcall->args.setexattr;
    nfs41_open_state *state = upcall->state_ref;
    PFILE_FULL_EA_INFORMATION ea =
        (PFILE_FULL_EA_INFORMATION)args->buf;

    if (ea == NULL) {
        eprintf("handle_setexattr: ea==NULL\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    /* break read delegations before SETATTR */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_READ, FALSE);

    if ((ea->EaNameLength == EA_NFSV3ATTRIBUTES_LEN) &&
        (!memcmp(EA_NFSV3ATTRIBUTES, ea->EaName, ea->EaNameLength))) {
        nfs41_file_info info;
        stateid_arg stateid;

        nfs41_open_stateid_arg(state, &stateid);

        info.mode = args->mode;
        info.attrmask.arr[0] = 0;
        info.attrmask.arr[1] = FATTR4_WORD1_MODE;
        info.attrmask.count = 2;

        status = nfs41_setattr(state->session, &state->file, &stateid, &info);
        if (status) {
            DPRINTF(1, ("nfs41_setattr() failed with error '%s'.\n",
                nfs_error_string(status)));
            goto out;
        }

        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
        args->ctime = info.change;
        goto out;
    }

    status = nfs41_ea_set(state, ea);
out:
    return nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
}

static int marshall_setexattr(
    unsigned char *restrict buffer,
    uint32_t *restrict length,
    nfs41_upcall *restrict upcall)
{
    const setexattr_upcall_args *args = &upcall->args.setexattr;
    return safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
}


/* NFS41_SYSOP_EA_GET */
static int parse_getexattr(
    const unsigned char *restrict buffer,
    uint32_t length,
    nfs41_upcall *upcall)
{
    int status;
    getexattr_upcall_args *args = &upcall->args.getexattr;

    status = get_name(&buffer, &length, &args->path);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->eaindex, sizeof(args->eaindex));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->restart, sizeof(args->restart));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->single, sizeof(args->single));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->ealist_len, sizeof(args->ealist_len));
    if (status) goto out;
    status = get_safe_read_bufferpos(&buffer, &length,
        args->ealist_len, (const void **)&args->ealist);
    if (status) goto out;

    EASSERT(length == 0);

    DPRINTF(1, ("parsing NFS41_SYSOP_EA_GET: buf_len=%d Index %d Restart %d "
        "Single %d\n", args->buf_len,args->eaindex, args->restart, args->single));
out:
    return status;
}

#define ALIGNED_EASIZE(len) \
    (align4(sizeof(FILE_GET_EA_INFORMATION) + (len)))

static uint32_t calculate_ea_list_length(
    IN const unsigned char *position,
    IN uint32_t remaining)
{
    const nfs41_readdir_entry *entry;
    uint32_t length = 0;

    while (remaining) {
        entry = (const nfs41_readdir_entry*)position;

        if ((entry->name_len > WIN_NFS4_EA_NAME_PREFIX_LEN) &&
            (memcmp(entry->name,
                WIN_NFS4_EA_NAME_PREFIX, WIN_NFS4_EA_NAME_PREFIX_LEN) == 0)) {
            length +=
                ALIGNED_EASIZE(entry->name_len-WIN_NFS4_EA_NAME_PREFIX_LEN);
        }

        if (!entry->next_entry_offset)
            break;

        position += entry->next_entry_offset;
        remaining -= entry->next_entry_offset;
    }
    return length;
}

static void populate_ea_list(
    IN const unsigned char *position,
    OUT PFILE_GET_EA_INFORMATION ea_list)
{
    const nfs41_readdir_entry *entry;
    PFILE_GET_EA_INFORMATION ea = ea_list;
    PFILE_GET_EA_INFORMATION last_win_ea = NULL;
    bool is_win_ea;

    for (;;) {
        entry = (const nfs41_readdir_entry*)position;

        if ((entry->name_len > WIN_NFS4_EA_NAME_PREFIX_LEN) &&
            (memcmp(entry->name,
                WIN_NFS4_EA_NAME_PREFIX, WIN_NFS4_EA_NAME_PREFIX_LEN) == 0)) {
            is_win_ea = true;
        }
        else {
            is_win_ea = false;
        }

        if (is_win_ea) {
            ea->EaNameLength =
                (UCHAR)(entry->name_len - WIN_NFS4_EA_NAME_PREFIX_LEN);
            (void)memcpy(ea->EaName,
                entry->name+WIN_NFS4_EA_NAME_PREFIX_LEN,
                ea->EaNameLength);

            DPRINTF(EALVL,
                ("populate_ea_list: adding ea "
                    "entry->(name='%.*s' name_len=%d) "
                    "ea->(EaName='%.*s' EaNameLength=%d)\n",
                    (int)entry->name_len,
                    entry->name,
                    (int)entry->name_len,
                    (int)ea->EaNameLength,
                    ea->EaName,
                    (int)ea->EaNameLength));
            last_win_ea = ea;
        }

        if (!entry->next_entry_offset) {
            (last_win_ea?last_win_ea:ea)->NextEntryOffset = 0;
            break;
        }

        if (is_win_ea) {
            ea->NextEntryOffset = ALIGNED_EASIZE(ea->EaNameLength);
            ea = (PFILE_GET_EA_INFORMATION)EA_NEXT_ENTRY(ea);
        }

        position += entry->next_entry_offset;
    }
}

static int get_ea_list(
    IN OUT nfs41_open_state *state,
    IN nfs41_path_fh *eadir,
    OUT PFILE_GET_EA_INFORMATION *ealist_out,
    OUT uint32_t *eaindex_out)
{
    unsigned char *entry_list;
    PFILE_GET_EA_INFORMATION ea_list;
    uint32_t entry_len, ea_size;
    int status = NO_ERROR;
    bitmap4 attr_request = {
        .count = 0 /* don't request attributes */
    };

    EnterCriticalSection(&state->ea.lock);

    if (state->ea.list != INVALID_HANDLE_VALUE) {
        /* use cached ea names */
        *ealist_out = state->ea.list;
        *eaindex_out = state->ea.index;
        goto out;
    }

    /* read the entire directory into a nfs41_readdir_entry buffer */
    status = read_entire_dir(state->session, eadir, &attr_request,
        &entry_list, &entry_len);
    if (status)
        goto out;

    ea_size = calculate_ea_list_length(entry_list, entry_len);
    if (ea_size == 0) {
        *ealist_out = state->ea.list = NULL;
        goto out_free;
    }
    ea_list = calloc(1, ea_size);
    if (ea_list == NULL) {
        status = GetLastError();
        goto out_free;
    }

    populate_ea_list(entry_list, ea_list);

    *ealist_out = state->ea.list = ea_list;
    *eaindex_out = state->ea.index;
out_free:
    free_entire_dir(entry_list); /* allocated by read_entire_dir() */
out:
    LeaveCriticalSection(&state->ea.lock);
    return status;
}

static int get_ea_value(
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN state_owner4 *owner,
    OUT PFILE_FULL_EA_INFORMATION ea,
    IN uint32_t length,
    OUT uint32_t *needed)
{
    nfs41_path_fh file = { 0 };
    open_claim4 claim;
    stateid_arg stateid;
    open_delegation4 delegation = { 0 };
    nfs41_file_info info;
    unsigned char *buffer;
    uint32_t diff, bytes_read;
    bool_t eof;
    int status;
    char prefixed_name[256];

    if (parent->fh.len == 0) /* no named attribute directory */
        goto out_empty;

    DPRINTF(EALVL,
        ("get_ea_value: "
            "ea->(EaName='%.*s' EaNameLength=%d)\n",
            (int)ea->EaNameLength,
            ea->EaName,
            (int)ea->EaNameLength));

    (void)snprintf(prefixed_name, sizeof(prefixed_name), "%s%.*s",
        WIN_NFS4_EA_NAME_PREFIX,
        (int)ea->EaNameLength,
        ea->EaName);

    claim.claim = CLAIM_NULL;
    claim.u.null.filename = &file.name;
    file.name.name = prefixed_name;
    file.name.len = (USHORT)strlen(prefixed_name);

    status = nfs41_open(session, parent, &file, owner, &claim,
        OPEN4_SHARE_ACCESS_READ | OPEN4_SHARE_ACCESS_WANT_NO_DELEG,
        OPEN4_SHARE_DENY_WRITE, OPEN4_NOCREATE, UNCHECKED4, NULL, TRUE,
        &stateid.stateid, &delegation, &info);
    if (status) {
        eprintf("get_ea_value: "
            "nfs41_open(ea_name='%s') failed with '%s'\n",
            prefixed_name,
            nfs_error_string(status));
        if (status == NFS4ERR_NOENT)
            goto out_empty;
        goto out;
    }

    if (info.size > NFS4_EASIZE) {
        status = NFS4ERR_FBIG;
        eprintf("get_ea_value: "
            "EA value for '%s' longer than maximum %u "
            "(%llu bytes), returning '%s'\n",
            prefixed_name, NFS4_EASIZE,
            info.size, nfs_error_string(status));
        goto out_close;
    }

    buffer = (unsigned char*)ea->EaName + ea->EaNameLength + 1;
    diff = (uint32_t)(buffer - (unsigned char*)ea);

    /* make sure we have room for the value */
    if (length < diff + info.size) {
        *needed = (uint32_t)(sizeof(FILE_FULL_EA_INFORMATION) +
            ea->EaNameLength + info.size);
        status = NFS4ERR_TOOSMALL;
        goto out_close;
    }

    /* read directly into the ea buffer */
    status = nfs41_read(session, &file, &stateid,
        0, length - diff, buffer, &bytes_read, &eof);
    if (status) {
        eprintf("get_ea_value: nfs41_read() failed with '%s'\n",
            nfs_error_string(status));
        goto out_close;
    }
    if (!eof) {
        *needed = (uint32_t)(sizeof(FILE_FULL_EA_INFORMATION) +
            ea->EaNameLength + NFS4_EASIZE);
        status = NFS4ERR_TOOSMALL;
        goto out_close;
    }

    ea->EaValueLength = (USHORT)bytes_read;

out_close:
    nfs41_close(session, &file, &stateid);
out:
    return status;

out_empty: /* return an empty value */
    ea->EaValueLength = 0;
    status = NFS4_OK;
    goto out;
}

static int empty_ea_error(
    IN uint32_t index,
    IN BOOLEAN restart)
{
    /* choose an error value depending on the arguments */
    if (index)
        return ERROR_INVALID_EA_HANDLE;

    if (!restart)
        return ERROR_NO_MORE_FILES;  /* -> STATUS_NO_MORE_EAS */

    return ERROR_FILE_NOT_FOUND; /* -> STATUS_NO_EAS_ON_FILE */
}

static int overflow_error(
    IN OUT getexattr_upcall_args *args,
    IN PFILE_FULL_EA_INFORMATION prev,
    IN uint32_t needed)
{
    if (prev) {
        /* unlink the overflowing entry, but copy the entries that fit */
        prev->NextEntryOffset = 0;
        args->overflow = ERROR_BUFFER_OVERFLOW;
    } else {
        /* no entries fit; return only the length needed */
        args->buf_len = needed;
        args->overflow = ERROR_INSUFFICIENT_BUFFER;
    }

    /* in either case, the upcall must return NO_ERROR so we
     * can copy this information down to the driver */
    return NO_ERROR;
}

static int handle_getexattr(void *daemon_context, nfs41_upcall *upcall)
{
    getexattr_upcall_args *args = &upcall->args.getexattr;
    PFILE_GET_EA_INFORMATION query = (PFILE_GET_EA_INFORMATION)args->ealist;
    PFILE_FULL_EA_INFORMATION ea, prev = NULL;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_path_fh parent = { 0 };
    uint32_t remaining, needed, index = 0;
    int status;

    status = nfs41_rpc_openattr(state->session, &state->file, FALSE, &parent.fh);
    if (status == NFS4ERR_NOENT) { /* no named attribute directory */
        DPRINTF(EALVL, ("no named attribute directory for '%s'\n", args->path));
        if (query == NULL) {
            status = empty_ea_error(args->eaindex, args->restart);
            goto out;
        }
    } else if (status) {
        eprintf("handle_getexattr: "
            "nfs41_rpc_openattr() failed with '%s'\n",
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_EAS_NOT_SUPPORTED);
        goto out;
    }

    if (query == NULL) {
        /* if no names are queried, use READDIR to list them all */
        uint32_t i;
        status = get_ea_list(state, &parent, &query, &index);
        if (status)
            goto out;

        if (query == NULL) { /* the file has no EAs */
            DPRINTF(EALVL, ("empty named attribute directory for '%s'\n",
                args->path));
            status = empty_ea_error(args->eaindex, args->restart);
            goto out;
        }

        if (args->eaindex)
            index = args->eaindex - 1; /* convert to zero-based index */
        else if (args->restart)
            index = 0;

        /* advance the list to the specified index */
        for (i = 0; i < index; i++) {
            if (query->NextEntryOffset == 0) {
                if (args->eaindex)
                    status = ERROR_INVALID_EA_HANDLE;
                else
                    status = ERROR_NO_MORE_FILES; /* STATUS_NO_MORE_EAS */
                goto out;
            }
            query = (PFILE_GET_EA_INFORMATION)EA_NEXT_ENTRY(query);
        }
    }

    /* returned ea information can't exceed the downcall buffer size */
    if (args->buf_len > UPCALL_BUF_SIZE - 2 * sizeof(uint32_t))
        args->buf_len = UPCALL_BUF_SIZE - 2 * sizeof(uint32_t);

    args->buf = malloc(args->buf_len);
    if (args->buf == NULL) {
        status = GetLastError();
        goto out;
    }

    ea = (PFILE_FULL_EA_INFORMATION)args->buf;
    remaining = args->buf_len;

    for (;;) {
        /* make sure we have room for at least the name */
        needed = sizeof(FILE_FULL_EA_INFORMATION) + query->EaNameLength;
        if (needed > remaining) {
            status = overflow_error(args, prev, needed + NFS4_EASIZE);
            goto out;
        }

        ea->EaNameLength = query->EaNameLength;
        (void)memcpy(ea->EaName, query->EaName, ea->EaNameLength);
        ea->Flags = 0;

        /* read the value from file */
        status = get_ea_value(state->session, &parent,
            &state->owner, ea, remaining, &needed);
        if (status == NFS4ERR_TOOSMALL) {
            status = overflow_error(args, prev, needed);
            goto out;
        }
        if (status) {
            status = nfs_to_windows_error(status, ERROR_EA_FILE_CORRUPT);
            goto out_free;
        }

        needed = align4(FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) +
            ea->EaNameLength + 1 + ea->EaValueLength);

        if (remaining < needed) {
            /* align4 may push NextEntryOffset past our buffer, but we
             * were still able to fit the ea value.  set remaining = 0
             * so we'll fail on the next ea (if any) */
            remaining = 0;
        } else
            remaining -= needed;

        index++;
        if (query->NextEntryOffset == 0 || args->single)
            break;

        prev = ea;
        ea->NextEntryOffset = needed;
        ea = (PFILE_FULL_EA_INFORMATION)EA_NEXT_ENTRY(ea);
        query = (PFILE_GET_EA_INFORMATION)EA_NEXT_ENTRY(query);
    }

    ea->NextEntryOffset = 0;
    args->buf_len -= remaining;
out:
    if (args->ealist == NULL) { /* update the ea index */
        EnterCriticalSection(&state->ea.lock);
        state->ea.index = index;
        if (status == NO_ERROR && !args->overflow && !args->single) {
            /* listing was completed, free the cache */
            free(state->ea.list);
            state->ea.list = INVALID_HANDLE_VALUE;
        }
        LeaveCriticalSection(&state->ea.lock);
    }
    return status;

out_free:
    free(args->buf);
    goto out;
}

static int marshall_getexattr(
    unsigned char *restrict buffer,
    uint32_t *restrict length,
    nfs41_upcall *restrict upcall)
{
    int status;
    const getexattr_upcall_args *args = &upcall->args.getexattr;

    status = safe_write(&buffer, length, &args->overflow, sizeof(args->overflow));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    if (args->overflow == ERROR_INSUFFICIENT_BUFFER)
        goto out;
    status = safe_write(&buffer, length, args->buf, args->buf_len);
    if (status) goto out;
out:
    free(args->buf);
    return status;
}


const nfs41_upcall_op nfs41_op_setexattr = {
    .parse = parse_setexattr,
    .handle = handle_setexattr,
    .marshall = marshall_setexattr,
    .arg_size = sizeof(setexattr_upcall_args)
};

const nfs41_upcall_op nfs41_op_getexattr = {
    .parse = parse_getexattr,
    .handle = handle_getexattr,
    .marshall = marshall_getexattr,
    .arg_size = sizeof(getexattr_upcall_args)
};
