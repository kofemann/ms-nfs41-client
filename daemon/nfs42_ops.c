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
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nfs41_build_features.h"
#include "nfs41_daemon.h"
#include "nfs41_ops.h"
#include "nfs41_compound.h"
#include "nfs41_xdr.h"
#include "name_cache.h"
#include "delegation.h"
#include "daemon_debug.h"
#include "util.h"

int nfs42_allocate(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN uint64_t offset,
    IN uint64_t length,
    OUT nfs41_file_info *cinfo)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs42_allocate_args allocate_args;
    nfs42_allocate_res allocate_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res = {0};
    bitmap4 attr_request;
    nfs41_file_info info, *pinfo;

    nfs41_superblock_getattr_mask(file->fh.superblock, &attr_request);

    /* FIXME: What about DS in pNFS case ? */
    compound_init(&compound, session->client->root->nfsminorvers,
        argops, resops, "allocate");

    compound_add_op(&compound, OP_SEQUENCE,
        &sequence_args, &sequence_res);
    nfs41_session_sequence(&sequence_args, session, 0);

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_ALLOCATE,
        &allocate_args, &allocate_res);
    allocate_args.stateid = stateid;
    allocate_args.offset = offset;
    allocate_args.length = length;

    if (cinfo) {
        pinfo = cinfo;
    }
    else {
        (void)memset(&info, 0, sizeof(info));
        pinfo = &info;
    }

    /*
     * NFSv4.2 ALLOCATE is some kind of "write" operation and
     * affects the number of physical bytes allocated, so we have
     * to do a GETATTR after ALLOCATE to get updates for our cache
     */
    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = pinfo;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attribute cache */
    bitmap4_cpy(&pinfo->attrmask, &getattr_res.obj_attributes.attrmask);
    nfs41_attr_cache_update(session_name_cache(session),
        file->fh.fileid, pinfo);

    nfs41_superblock_space_changed(file->fh.superblock);

out:
    return status;
}

int nfs42_deallocate(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN uint64_t offset,
    IN uint64_t length,
    OUT nfs41_file_info *cinfo)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs42_deallocate_args deallocate_args;
    nfs42_deallocate_res deallocate_res;
    nfs41_getattr_args getattr_args;
    nfs41_getattr_res getattr_res = {0};
    bitmap4 attr_request;
    nfs41_file_info info, *pinfo;

    nfs41_superblock_getattr_mask(file->fh.superblock, &attr_request);

    /* FIXME: What about DS in pNFS case ? */
    compound_init(&compound, session->client->root->nfsminorvers,
        argops, resops, "deallocate");

    compound_add_op(&compound, OP_SEQUENCE,
        &sequence_args, &sequence_res);
    nfs41_session_sequence(&sequence_args, session, 0);

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_DEALLOCATE,
        &deallocate_args, &deallocate_res);
    deallocate_args.stateid = stateid;
    deallocate_args.offset = offset;
    deallocate_args.length = length;

    if (cinfo) {
        pinfo = cinfo;
    }
    else {
        (void)memset(&info, 0, sizeof(info));
        pinfo = &info;
    }

    /*
     * NFSv4.2 DEALLOCATE is some kind of "write" operation and
     * affects the number of physical bytes allocated, so we have
     * to do a GETATTR after DEALLOCATE to get updates for our cache
     */
    compound_add_op(&compound, OP_GETATTR, &getattr_args, &getattr_res);
    getattr_args.attr_request = &attr_request;
    getattr_res.obj_attributes.attr_vals_len = NFS4_OPAQUE_LIMIT;
    getattr_res.info = pinfo;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    /* update the attribute cache */
    bitmap4_cpy(&pinfo->attrmask, &getattr_res.obj_attributes.attrmask);
    nfs41_attr_cache_update(session_name_cache(session),
        file->fh.fileid, pinfo);

    nfs41_superblock_space_changed(file->fh.superblock);

out:
    return status;
}

int nfs42_read_plus(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN uint64_t offset,
    IN uint32_t count,
    OUT unsigned char *data_out,
    OUT uint32_t *data_len_out,
    OUT bool_t *eof_out)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs42_read_plus_args read_plus_args;
    nfs42_read_plus_res read_plus_res;

    compound_init(&compound, session->client->root->nfsminorvers,
        argops, resops,
        stateid->stateid.seqid == 0 ? "ds read_plus" : "read_plus");

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    nfs41_session_sequence(&sequence_args, session, 0);

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_READ_PLUS, &read_plus_args, &read_plus_res);
    read_plus_args.stateid = stateid;
    read_plus_args.offset = offset;
    read_plus_args.count = count;
    read_plus_res.resok4.args_offset = offset; /* hack */
    read_plus_res.resok4.data_len = count;
    read_plus_res.resok4.data = data_out;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    *data_len_out = read_plus_res.resok4.data_len;
    *eof_out = read_plus_res.resok4.eof;

    /* we shouldn't ever see this, but a buggy server could
     * send us into an infinite loop. return NFS4ERR_IO */
    if (!read_plus_res.resok4.data_len && !read_plus_res.resok4.eof) {
        status = NFS4ERR_IO;
        eprintf("READ_PLUS succeeded with len=0 and eof=0; returning '%s'\n",
            nfs_error_string(status));
    }
out:
    return status;
}

int nfs42_seek(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN stateid_arg *stateid,
    IN uint64_t offset,
    IN data_content4 what,
    OUT bool_t *eof_out,
    OUT uint64_t *offset_out)
{
    int status;
    nfs41_compound compound;
    nfs_argop4 argops[4];
    nfs_resop4 resops[4];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args;
    nfs41_putfh_res putfh_res;
    nfs42_seek_args seek_args;
    nfs42_seek_res  seek_res;

    compound_init(&compound, session->client->root->nfsminorvers,
        argops, resops,
        "seek");

    compound_add_op(&compound, OP_SEQUENCE,
        &sequence_args, &sequence_res);
    nfs41_session_sequence(&sequence_args, session, 0);

    compound_add_op(&compound, OP_PUTFH, &putfh_args, &putfh_res);
    putfh_args.file = file;
    putfh_args.in_recovery = 0;

    compound_add_op(&compound, OP_SEEK, &seek_args, &seek_res);
    seek_args.stateid = stateid;
    seek_args.offset = offset;
    seek_args.what = what;

    status = compound_encode_send_decode(session, &compound, TRUE);
    if (status)
        goto out;

    if (compound_error(status = compound.res.status))
        goto out;

    *eof_out = seek_res.resok4.eof;
    *offset_out = seek_res.resok4.offset;
out:
    return status;
}
