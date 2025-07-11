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

#include <Windows.h>
#include <stdio.h>

#include "nfs41_ops.h"
#include "name_cache.h"
#include "upcall.h"
#include "daemon_debug.h"
#include "util.h"


/* number of times to retry on write/commit verifier mismatch */
#define MAX_WRITE_RETRIES 6


const stateid4 special_read_stateid = {0xffffffff, 
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static int parse_rw(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    readwrite_upcall_args *args = &upcall->args.rw;

    status = safe_read(&buffer, &length, &args->len, sizeof(args->len));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->offset, sizeof(args->offset));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buffer, sizeof(args->buffer));
    if (status) goto out;

    DPRINTF(1, ("parsing '%s' len=%lu offset=%llu buf=0x%p\n",
            opcode2string(upcall->opcode), args->len, args->offset, args->buffer));
out:
    return status;
}

/* NFS41_SYSOP_READ */
static int read_from_mds(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    nfs41_session *session = upcall->state_ref->session;
    nfs41_path_fh *file = &upcall->state_ref->file;
    readwrite_upcall_args *args = &upcall->args.rw;
    int status = 0;
    bool_t eof;
    unsigned char *p = args->buffer;
    ULONG to_rcv = args->len, reloffset = 0, len = 0;
    const uint32_t maxreadsize = max_read_size(session, &file->fh);

    if (to_rcv > maxreadsize) {
        DPRINTF(1, ("handle_nfs41_read: reading %d in chunks of %d\n",
            to_rcv, maxreadsize));
    }

    while(to_rcv > 0) {
        uint32_t bytes_read = 0, chunk = min(to_rcv, maxreadsize);

        if (session->client->root->supports_nfs42_read_plus) {
            status = nfs42_read_plus(session, file, stateid,
                args->offset + reloffset, chunk,
                p, &bytes_read, &eof);
            if (status == NFS4ERR_IO) {
                DPRINTF(0,
                    ("read_from_mds: "
                    "nfs42_read_plus() failed, error '%s', "
                    "disabling OP_READ_PLUS\n",
                    nfs_error_string(status)));
                session->client->root->supports_nfs42_read_plus = false;
            }
        }
        else {
            status = nfs41_read(session, file, stateid,
                args->offset + reloffset, chunk,
                p, &bytes_read, &eof);
        }

        if (status == NFS4ERR_OPENMODE && !len) {
            stateid->type = STATEID_SPECIAL;
            stateid4_cpy(&stateid->stateid, &special_read_stateid);
            continue;
        } else if (status && !len) {
            status = nfs_to_windows_error(status, ERROR_NET_WRITE_FAULT);
            goto out;
        }

        p += bytes_read;
        to_rcv -= bytes_read;
        len += bytes_read;
        args->offset += bytes_read;
        if (status) {
            status = NO_ERROR;
            break;
        }
        if (eof) {
            if (!len)
                status = ERROR_HANDLE_EOF;
            break;
        }
    }
out:
    args->out_len = len;
    return status;
}

static int read_from_pnfs(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    pnfs_layout_state *layout;
    enum pnfs_status pnfsstat;
    int status = NO_ERROR;

    if (pnfs_layout_state_open(upcall->state_ref, &layout)) {
        status = ERROR_NOT_SUPPORTED;
        goto out;
    }

    pnfsstat = pnfs_read(upcall->root_ref, upcall->state_ref, stateid, layout, 
        args->offset, args->len, args->buffer, &args->out_len);
    switch (pnfsstat) {
    case PNFS_SUCCESS:
        break;
    case PNFS_READ_EOF:
        status = ERROR_HANDLE_EOF;
        break;
    default:
        status = ERROR_READ_FAULT;
        break;
    }
out:
    return status;
}

static int handle_read(void *daemon_context, nfs41_upcall *upcall)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    stateid_arg stateid;
    ULONG pnfs_bytes_read = 0;
    int status = NO_ERROR;

    nfs41_open_stateid_arg(upcall->state_ref, &stateid);

#ifdef PNFS_ENABLE_READ
    status = read_from_pnfs(upcall, &stateid);

    if (status == NO_ERROR || status == ERROR_HANDLE_EOF)
        goto out;

    if (args->out_len) {
        pnfs_bytes_read = args->out_len;
        args->out_len = 0;

        args->offset += pnfs_bytes_read;
        args->buffer += pnfs_bytes_read;
        args->len -= pnfs_bytes_read;
    }
#endif

    status = read_from_mds(upcall, &stateid);

    args->out_len += pnfs_bytes_read;
out:
    return status;
}


/* NFS41_SYSOP_WRITE */
static int write_to_mds(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    nfs41_open_state *state = upcall->state_ref;
    nfs41_session *session = state->session;
    nfs41_path_fh *file = &state->file;
    readwrite_upcall_args *args = &upcall->args.rw;
    nfs41_write_verf verf;
    enum stable_how4 stable, committed;
    unsigned char *p;
    const uint32_t maxwritesize = max_write_size(session, &file->fh);
    uint32_t to_send, reloffset, len;
    int status = 0;
    /* on write verifier mismatch, retry N times before failing */
    uint32_t retries = MAX_WRITE_RETRIES;
    nfs41_file_info info;

    (void)memset(&info, 0, sizeof(info));


#ifdef TEST_OP_ALLOCAE_OP_DEALLOCATE
    /*
     * Test code for OP_ALLOCATE and OP_DEALLOCATE, do not use except for
     * testing!
     */
    size_t data_i;

    /* Test whether the data block consists is a block of zero bytes */
    for (data_i = 0 ; data_i < args->len ; data_i++) {
        if (((char *)args->buffer)[data_i] != '\0')
            break;
    }

    if (data_i == args->len) {
        DPRINTF(0, ("write_to_mds(state->path.path='%s'): "
            "Using DEALLOCATE+ALLOCATE for zero block\n",
            state->path.path));

        status = nfs42_deallocate(session, file, stateid,
            args->offset, args->len,
            &info);
        if (status) {
            DPRINTF(0, ("write_to_mds(state->path.path='%s'): "
                "DEALLOCATE failed with '%s'\n",
                state->path.path,
                nfs_error_string(status)));
        }
        else {
            status = nfs42_allocate(session, file, stateid,
                args->offset, args->len,
                &info);
            if (status) {
                DPRINTF(0, ("write_to_mds(state->path.path='%s'): "
                    "ALLOCATE failed with '%s'\n",
                    state->path.path,
                    nfs_error_string(status)));
            }
        }

        if (!status) {
            /* Update ctime on success */
            args->ctime = info.change;
        }

        len = args->len;
        goto out;
    }
#endif /* TEST_OP_ALLOCAE_OP_DEALLOCATE */

retry_write:
    p = args->buffer;
    to_send = args->len;
    reloffset = 0;
    len = 0;
    stable = to_send <= maxwritesize ? FILE_SYNC4 : UNSTABLE4;
    committed = FILE_SYNC4;

    if (to_send > maxwritesize) {
        DPRINTF(1, ("handle_nfs41_write: writing %lu in chunks of %lu\n",
            (unsigned long)to_send, (unsigned long)maxwritesize));
    }

    while(to_send > 0) {
        uint32_t bytes_written = 0, chunk = min(to_send, maxwritesize);

        status = nfs41_write(session, file, stateid, p, chunk,
            args->offset + reloffset, stable, &bytes_written, &verf, &info);
        if (status && !len)
            goto out;
        p += bytes_written;
        to_send -= bytes_written;
        len += bytes_written;
        reloffset += bytes_written;
        if (status) {
            status = 0;
            break;
        }
        if (!verify_write(&verf, &committed)) {
            if (retries--) goto retry_write;
            goto out_verify_failed;
        }
    }
    if (committed != FILE_SYNC4) {
        DPRINTF(1, ("sending COMMIT for offset=%llu and len=%d\n",
            (unsigned long long)args->offset,
            (unsigned long)len));
        status = nfs41_commit(session, file, args->offset, len, 1, &verf, &info);
        if (status)
            goto out;

        if (!verify_commit(&verf)) {
            if (retries--) goto retry_write;
            goto out_verify_failed;
        }
    } else if (stable == UNSTABLE4) {
		nfs41_file_info info;
        bitmap4 attr_request; 
        nfs41_superblock_getattr_mask(file->fh.superblock, &attr_request);
		status = nfs41_getattr(session, file, &attr_request, &info);
		if (status)
			goto out;
	}

    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;

out:
    args->out_len = len;
    return nfs_to_windows_error(status, ERROR_NET_WRITE_FAULT);

out_verify_failed:
    len = 0;
    status = NFS4ERR_IO;
    goto out;
}

static int write_to_pnfs(
    IN nfs41_upcall *upcall,
    IN stateid_arg *stateid)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    pnfs_layout_state *layout;
    int status = NO_ERROR;
    nfs41_file_info info;

    (void)memset(&info, 0, sizeof(info));

    if (pnfs_layout_state_open(upcall->state_ref, &layout)) {
        status = ERROR_NOT_SUPPORTED;
        goto out;
    }

    if (pnfs_write(upcall->root_ref, upcall->state_ref, stateid, layout, 
            args->offset, args->len, args->buffer, &args->out_len, &info)) {
        status = ERROR_WRITE_FAULT;
        goto out;
    }
    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;
out:
    return status;
}

static int handle_write(void *daemon_context, nfs41_upcall *upcall)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    stateid_arg stateid;
    uint32_t pnfs_bytes_written = 0;
    int status;

    nfs41_open_stateid_arg(upcall->state_ref, &stateid);

#ifdef PNFS_ENABLE_WRITE
    status = write_to_pnfs(upcall, &stateid);
    if (args->out_len) {
        pnfs_bytes_written = args->out_len;
        args->out_len = 0;

        args->offset += pnfs_bytes_written;
        args->buffer += pnfs_bytes_written;
        args->len -= pnfs_bytes_written;

        if (args->len == 0)
            goto out;
    }
#endif

    status = write_to_mds(upcall, &stateid);
out:
    args->out_len += pnfs_bytes_written;
    return status;
}

static int marshall_rw(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    readwrite_upcall_args *args = &upcall->args.rw;
    int status;
    status = safe_write(&buffer, length, &args->out_len, sizeof(args->out_len));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
out:
    return status;
}


const nfs41_upcall_op nfs41_op_read = {
    .parse = parse_rw,
    .handle = handle_read,
    .marshall = marshall_rw,
    .arg_size = sizeof(readwrite_upcall_args)
};
const nfs41_upcall_op nfs41_op_write = {
    .parse = parse_rw,
    .handle = handle_write,
    .marshall = marshall_rw,
    .arg_size = sizeof(readwrite_upcall_args)
};
