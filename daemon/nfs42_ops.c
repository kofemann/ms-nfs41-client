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
