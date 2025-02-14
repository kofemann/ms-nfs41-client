/* NFSv4.1 client for Windows
 * Copyright (C) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
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

#define QARLVL 2 /* dprintf level for "query allocated ranges" logging */

static int parse_queryallocatedranges(unsigned char *buffer,
    uint32_t length, nfs41_upcall *upcall)
{
    int status;
    queryallocatedranges_upcall_args *args = &upcall->args.queryallocatedranges;

    status = safe_read(&buffer, &length, &args->inrange, sizeof(args->inrange));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->outbuffersize, sizeof(args->outbuffersize));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->outbuffer, sizeof(args->outbuffer));
    if (status) goto out;

    DPRINTF(QARLVL, ("parse_queryallocatedranges: "
        "parsing '%s' inrange=(FileOffset=%lld Length=%lld) "
        "outbuffersize=%lu outbuffer=0x%p\n",
        opcode2string(upcall->opcode),
        args->inrange.FileOffset.QuadPart,
        args->inrange.Length.QuadPart,
        (unsigned long)args->outbuffersize,
        (void *)args->outbuffer));
out:
    return status;
}

static
int query_sparsefile_datasections(nfs41_open_state *state,
    uint64_t start_offset,
    FILE_ALLOCATED_RANGE_BUFFER *outbuffer,
    size_t out_maxrecords,
    size_t *restrict res_num_records)
{
    int status = NO_ERROR;
    uint64_t next_offset;
    uint64_t data_size;
    int data_seek_status;
    bool_t data_seek_sr_eof;
    uint64_t data_seek_sr_offset;
    int hole_seek_status;
    bool_t hole_seek_sr_eof;
    uint64_t hole_seek_sr_offset;
    size_t i;

    stateid_arg stateid;

    DPRINTF(QARLVL,
        ("--> query_sparsefile_datasections(state->path.path='%s')\n",
        state->path.path));

    /* NFS SEEK requires NFSv4.2 */
    if (state->session->client->root->nfsminorvers < 2) {
        status = ERROR_NOT_SUPPORTED;
        goto out;
    }

    nfs41_open_stateid_arg(state, &stateid);

    next_offset = start_offset;
    *res_num_records = 0;

    for (i=0 ; i < out_maxrecords ; i++) {
        data_seek_status = nfs42_seek(state->session,
            &state->file,
            &stateid,
            next_offset,
            NFS4_CONTENT_DATA,
            &data_seek_sr_eof,
            &data_seek_sr_offset);

        /*
         * 1. Note that Linux returns |NFS4ERR_NXIO| if it cannot find
         * a data block, but
         * https://datatracker.ietf.org/doc/html/rfc7862#section-15.11.3
         * says "... If the server cannot find a corresponding sa_what,
         * then the status will still be NFS4_OK, but sr_eof would be
         * TRUE. ..."
         * 2. NFSv4.2 spec bug:
         * https://datatracker.ietf.org/doc/html/rfc7862#section-11.2
         * section "SEEK" does not list |NFS4ERR_NXIO| as valid error
         * for SEEK, but
         * https://datatracker.ietf.org/doc/html/rfc7862#section-15.11.3
         * states "If the sa_offset is beyond the end of the file, then
         * SEEK MUST return NFS4ERR_NXIO."
         *
         * Question is... which offset should a conforming NFSv4.2
         * SEEK_DATA return if there is no data block (i.e. sparse
         * file which only consists of one hole) ?
         */
#define LINUX_NFSD_SEEK_NXIO_BUG_WORKAROUND 1

#ifdef LINUX_NFSD_SEEK_NXIO_BUG_WORKAROUND
        if (data_seek_status == NFS4ERR_NXIO) {
            DPRINTF(QARLVL, ("SEEK_DATA failed with NFS4ERR_NXIO\n"));
            goto out;
        }
#endif
        if (data_seek_status) {
            status = nfs_to_windows_error(data_seek_status,
                ERROR_INVALID_PARAMETER);
            DPRINTF(QARLVL, ("SEEK_DATA failed "
                "OP_SEEK(sa_offset=%llu,sa_what=SEEK_DATA) "
                "failed with %d(='%s')\n",
                next_offset,
                data_seek_status,
                nfs_error_string(data_seek_status)));
            goto out;
        }

        next_offset = data_seek_sr_offset;

        hole_seek_status = nfs42_seek(state->session,
            &state->file,
            &stateid,
            next_offset,
            NFS4_CONTENT_HOLE,
            &hole_seek_sr_eof,
            &hole_seek_sr_offset);
        if (hole_seek_status) {
            status = nfs_to_windows_error(hole_seek_status,
                ERROR_INVALID_PARAMETER);
            DPRINTF(QARLVL, ("SEEK_HOLE failed "
                "OP_SEEK(sa_offset=%llu,sa_what=SEEK_HOLE) "
                "failed with %d(='%s')\n",
                next_offset,
                hole_seek_status,
                nfs_error_string(hole_seek_status)));
            goto out;
        }

        next_offset = hole_seek_sr_offset;

        data_size = hole_seek_sr_offset - data_seek_sr_offset;

        DPRINTF(QARLVL, ("data_section: from "
            "%llu to %llu, size=%llu (data_eof=%d, hole_eof=%d)\n",
            data_seek_sr_offset,
            hole_seek_sr_offset,
            data_size,
            (int)data_seek_sr_eof,
            (int)hole_seek_sr_eof));

        outbuffer[i].FileOffset.QuadPart = data_seek_sr_offset;
        outbuffer[i].Length.QuadPart = data_size;
        (*res_num_records)++;

        if (data_seek_sr_eof || hole_seek_sr_eof) {
            break;
        }
    }

out:
    DPRINTF(QARLVL, ("<-- query_sparsefile_datasections(), status=0x%x\n",
        status));
    return status;
}


static
int handle_queryallocatedranges(void *daemon_context,
    nfs41_upcall *upcall)
{
    queryallocatedranges_upcall_args *args =
        &upcall->args.queryallocatedranges;
    nfs41_open_state *state = upcall->state_ref;
    PFILE_ALLOCATED_RANGE_BUFFER outbuffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)args->outbuffer;
    int status = ERROR_INVALID_PARAMETER;
    size_t num_records;

    DPRINTF(QARLVL,
        ("--> handle_queryallocatedranges("
            "state->path.path='%s', "
            "args->inrange.FileOffset=%llu, "
            "args->inrange.Length=%llu)\n",
            state->path.path,
            args->inrange.FileOffset.QuadPart,
            args->inrange.Length.QuadPart));

    num_records =
        ((size_t)args->outbuffersize /
            sizeof(FILE_ALLOCATED_RANGE_BUFFER));

    DPRINTF(QARLVL,
        ("handle_queryallocatedranges:"
            "got space for %ld records\n",
            (int)num_records));

    args->returned_size = 0;

    size_t res_num_records = 0;

    status = query_sparsefile_datasections(state,
        args->inrange.FileOffset.QuadPart,
        outbuffer,
        num_records,
        &res_num_records);

    if (!status) {
        args->returned_size =
            (ULONG)res_num_records*sizeof(FILE_ALLOCATED_RANGE_BUFFER);
    }

    DPRINTF(QARLVL,
        ("<-- handle_queryallocatedranges(), status=0x%lx\n",
        status));
    return status;
}

static int marshall_queryallocatedranges(unsigned char *buffer,
    uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    queryallocatedranges_upcall_args *args = &upcall->args.queryallocatedranges;

    status = safe_write(&buffer, length, &args->returned_size, sizeof(args->returned_size));

    return status;
}

const nfs41_upcall_op nfs41_op_queryallocatedranges = {
    .parse = parse_queryallocatedranges,
    .handle = handle_queryallocatedranges,
    .marshall = marshall_queryallocatedranges,
    .arg_size = sizeof(queryallocatedranges_upcall_args)
};
