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
#define SZDLVL 2 /* dprintf level for "set zero data" logging */

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
    uint64_t end_offset,
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
    bool error_more_data = false;

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

    for (i=0 ; ; i++) {
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

        if (i < out_maxrecords) {
            outbuffer[i].FileOffset.QuadPart = data_seek_sr_offset;
            outbuffer[i].Length.QuadPart = data_size;
        }
        else {
            /*
             * Return |ERROR_MORE_DATA| if we reach end of the
             * caller-supplied record array and still have more
             * data sections (i.e. no EOF from
             + |NFS4_CONTENT_HOLE|/|NFS4_CONTENT_DATA| yet).
             *
             * FIXME: We should also implement |out_maxrecords==0|,
             * and then return the size for an array to store
             * all records.
             * This can still be too small if between the first
             * FSCTL call (to get the needed size of the array)
             * and second FSCTL call to enumerate the
             * |FILE_ALLOCATED_RANGE_BUFFER| someone adds more
             * data sections.
             */
            error_more_data = true;
            break;
        }

        (*res_num_records)++;

        if (data_seek_sr_offset > end_offset) {
            DPRINTF(QARLVL,
                ("end offset reached, "
                "i=%d, data_seek_sr_offset(=%lld) > end_offset(=%lld)\n",
                (int)i,
                (long long)data_seek_sr_offset,
                (long long)end_offset));
            break;
        }

        if (data_seek_sr_eof || hole_seek_sr_eof) {
            DPRINTF(QARLVL,
                ("EOF reached (data_seek_sr_eof=%d, hole_seek_sr_eof=%d)\n",
                (int)data_seek_sr_eof,
                (int)hole_seek_sr_eof));
            break;
        }
    }

out:
    if (error_more_data) {
        DPRINTF(QARLVL, ("returning ERROR_MORE_DATA, *res_num_records=%ld\n",
            (long)*res_num_records));
        status = ERROR_MORE_DATA;
    }

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

    args->buffer_overflow = FALSE;
    args->returned_size = 0;

    size_t res_num_records = 0;

    status = query_sparsefile_datasections(state,
        args->inrange.FileOffset.QuadPart,
        args->inrange.FileOffset.QuadPart+args->inrange.Length.QuadPart,
        outbuffer,
        num_records,
        &res_num_records);

    /*
     * Return buffer size, either on success, or to return the size
     * of the buffer which would be needed.
     */
    args->returned_size =
        (ULONG)res_num_records*sizeof(FILE_ALLOCATED_RANGE_BUFFER);

    if (status == ERROR_MORE_DATA) {
        status = NO_ERROR;
        args->buffer_overflow = TRUE;
    }

    DPRINTF(QARLVL,
        ("<-- handle_queryallocatedranges(args->buffer_overflow=%d, args->returned_size=%ld), "
        "status=0x%lx\n",
        (int)args->buffer_overflow,
        (long)args->returned_size,
        status));
    return status;
}

static int marshall_queryallocatedranges(unsigned char *buffer,
    uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    queryallocatedranges_upcall_args *args = &upcall->args.queryallocatedranges;

    status = safe_write(&buffer, length, &args->buffer_overflow, sizeof(args->buffer_overflow));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->returned_size, sizeof(args->returned_size));

out:
    return status;
}

const nfs41_upcall_op nfs41_op_queryallocatedranges = {
    .parse = parse_queryallocatedranges,
    .handle = handle_queryallocatedranges,
    .marshall = marshall_queryallocatedranges,
    .arg_size = sizeof(queryallocatedranges_upcall_args)
};

static int parse_setzerodata(unsigned char *buffer,
    uint32_t length, nfs41_upcall *upcall)
{
    int status;
    setzerodata_upcall_args *args = &upcall->args.setzerodata;

    status = safe_read(&buffer, &length, &args->setzerodata,
        sizeof(args->setzerodata));
    if (status) goto out;

    DPRINTF(SZDLVL, ("parse_setzerodata: "
        "parsing '%s' setzerodata=(FileOffset=%lld BeyondFinalZero=%lld)\n",
        opcode2string(upcall->opcode),
        (long long)args->setzerodata.FileOffset.QuadPart,
        (long long)args->setzerodata.BeyondFinalZero.QuadPart));
out:
    return status;
}


static
int handle_setzerodata(void *daemon_context,
    nfs41_upcall *upcall)
{
    int status = ERROR_INVALID_PARAMETER;
    setzerodata_upcall_args *args = &upcall->args.setzerodata;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_session *session = state->session;
    nfs41_path_fh *file = &state->file;
    nfs41_file_info info;
    int64_t offset_start; /* signed! */
    int64_t offset_end; /* signed! */
    int64_t len; /* signed! */
    stateid_arg stateid;

    (void)memset(&info, 0, sizeof(info));

    offset_start = args->setzerodata.FileOffset.QuadPart;
    offset_end = args->setzerodata.BeyondFinalZero.QuadPart;
    len = offset_end - offset_start;

    DPRINTF(SZDLVL,
        ("--> handle_setzerodata("
            "state->path.path='%s', "
            "offset_start=%lld, "
            "offset_end=%lld, "
            "len=%lld)\n",
            state->path.path,
            offset_start,
            offset_end,
            len));

    /* NFS DEALLOCATE requires NFSv4.2 */
    if (state->session->client->root->nfsminorvers < 2) {
        status = ERROR_NOT_SUPPORTED;
        goto out;
    }

    if (len < 0) {
        status = ERROR_INVALID_PARAMETER;
        DPRINTF(SZDLVL, ("handle_setzerodata: invalid len\b"));
        goto out;
    }

    if (len == 0) {
        status = NO_ERROR;
        DPRINTF(SZDLVL, ("handle_setzerodata: len == 0, NOP\n"));
        goto out;
    }

    nfs41_open_stateid_arg(state, &stateid);

    status = nfs42_deallocate(session, file, &stateid,
         offset_start, len, &info);
     if (status) {
        DPRINTF(SZDLVL, ("handle_setzerodata(state->path.path='%s'): "
            "DEALLOCATE failed with status=0x%x\n",
            state->path.path,
            status));
        goto out;
     }

    /* Update ctime on success */
    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;

    DPRINTF(SZDLVL,
        ("handle_setzerodata(state->path.path='%s'): args->ctime=%llu\n",
        state->path.path,
        args->ctime));

out:
    DPRINTF(SZDLVL,
        ("<-- handle_setzerodata(), status=0x%lx\n",
        status));

    return status;
}

static int marshall_setzerodata(unsigned char *buffer,
    uint32_t *length, nfs41_upcall *upcall)
{
    setzerodata_upcall_args *args = &upcall->args.setzerodata;
    int status;
    status = safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
    return status;
}

const nfs41_upcall_op nfs41_op_setzerodata = {
    .parse = parse_setzerodata,
    .handle = handle_setzerodata,
    .marshall = marshall_setzerodata,
    .arg_size = sizeof(setzerodata_upcall_args)
};
