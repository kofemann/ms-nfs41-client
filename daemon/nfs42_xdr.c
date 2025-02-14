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

#include "nfs41_compound.h"
#include "nfs41_ops.h"
#include "nfs41_xdr.h"
#include "util.h"
#include "daemon_debug.h"
#include "rpc/rpc.h"

/* fixme: copy from nfs41_xdr.c */
static __inline int unexpected_op(uint32_t op, uint32_t expected)
{
    if (op == expected)
        return 0;

    eprintf("Op table mismatch. Got '%s' (%d), expected '%s' (%d).\n",
        nfs_opnum_to_string(op), op,
        nfs_opnum_to_string(expected), expected);
    return 1;
}

/*
 * OP_ALLOCATE
 */
bool_t encode_op_allocate(
    XDR *xdr,
    nfs_argop4 *argop)
{
    nfs42_allocate_args *args = (nfs42_allocate_args *)argop->arg;

    if (unexpected_op(argop->op, OP_ALLOCATE))
        return FALSE;

    if (!xdr_stateid4(xdr, &args->stateid->stateid))
        return FALSE;

    if (!xdr_u_hyper(xdr, &args->offset))
        return FALSE;

    return xdr_u_hyper(xdr, &args->length);
}


bool_t decode_op_allocate(
    XDR *xdr,
    nfs_resop4 *resop)
{
    nfs42_allocate_res *res = (nfs42_allocate_res *)resop->res;

    if (unexpected_op(resop->op, OP_ALLOCATE))
        return FALSE;

    if (!xdr_u_int32_t(xdr, &res->status))
        return FALSE;

    return TRUE;
}

/*
 * OP_DEALLOCATE
 */
bool_t encode_op_deallocate(
    XDR *xdr,
    nfs_argop4 *argop)
{
    nfs42_deallocate_args *args = (nfs42_deallocate_args *)argop->arg;

    if (unexpected_op(argop->op, OP_DEALLOCATE))
        return FALSE;

    if (!xdr_stateid4(xdr, &args->stateid->stateid))
        return FALSE;

    if (!xdr_u_hyper(xdr, &args->offset))
        return FALSE;

    return xdr_u_hyper(xdr, &args->length);
}


bool_t decode_op_deallocate(
    XDR *xdr,
    nfs_resop4 *resop)
{
    nfs42_deallocate_res *res = (nfs42_deallocate_res *)resop->res;

    if (unexpected_op(resop->op, OP_DEALLOCATE))
        return FALSE;

    if (!xdr_u_int32_t(xdr, &res->status))
        return FALSE;

    return TRUE;
}


/*
 * OP_READ_PLUS
 */
bool_t encode_op_read_plus(
    XDR *xdr,
    nfs_argop4 *argop)
{
    nfs42_read_plus_args *args = (nfs42_read_plus_args *)argop->arg;

    if (unexpected_op(argop->op, OP_READ_PLUS))
        return FALSE;

    if (!xdr_stateid4(xdr, &args->stateid->stateid))
        return FALSE;

    if (!xdr_u_hyper(xdr, &args->offset))
        return FALSE;

    return xdr_u_int32_t(xdr, &args->count);
}

static bool_t decode_read_plus_res_ok(
    XDR *xdr,
    nfs42_read_plus_res_ok *res)
{
    nfs42_read_plus_content *contents = NULL;
    uint64_t read_data_len = 0ULL;

    if (!xdr_bool(xdr, &res->eof)) {
        DPRINTF(0, ("decode eof failed\n"));
        return FALSE;
    }

    if (!xdr_u_int32_t(xdr, &res->count)) {
        DPRINTF(0, ("decode count failed\n"));
        return FALSE;
    }

    /*
     * Note that |res->count==0| is a valid value for "READ_PLUS"
     * replies
     */
    if (res->count == 0) {
        res->data_len = 0L;
        return TRUE;
    }

    contents = _alloca(res->count * sizeof(nfs42_read_plus_content));

    uint32_t i, co;

    for (i = 0 ; i < res->count ; i++) {
        if (!xdr_u_int32_t(xdr, &co)) {
            DPRINTF(0, ("i=%d, decode co failed\n", (int)i));
            return FALSE;
        }
        contents[i].content = co;

        switch(co) {
            case NFS4_CONTENT_DATA:
                if (!xdr_u_hyper(xdr, &contents[i].data.offset)) {
                    DPRINTF(0,
                        ("i=%d, decoding 'offset' failed\n", (int)i));
                    return FALSE;
                }
                if (!xdr_u_int32_t(xdr, &contents[i].data.count)) {
                    DPRINTF(0,
                        ("i=%d, decoding 'count' failed\n", (int)i));
                    return FALSE;
                }

                contents[i].data.data = res->data +
                    (contents[i].data.offset - res->args_offset);
                contents[i].data.data_len = contents[i].data.count;

                EASSERT(((contents[i].data.data - res->data) +
                    contents[i].data.data_len) <= res->data_len);
                if (!xdr_opaque(xdr,
                    (char *)contents[i].data.data,
                    contents[i].data.data_len)) {
                    DPRINTF(0,
                        ("i=%d, decoding 'bytes' failed\n", (int)i));
                    return FALSE;
                }
                read_data_len = __max(read_data_len,
                    ((size_t)(contents[i].data.data - res->data) +
                        contents[i].data.data_len));
                break;
            case NFS4_CONTENT_HOLE:
                unsigned char *hole_buff;
                uint64_t hole_length;

                DPRINTF(0,
                    ("i=%d, 'NFS4_CONTENT_HOLE' content\n", (int)i));
                if (!xdr_u_hyper(xdr, &contents[i].hole.offset))
                    return FALSE;
                if (!xdr_u_hyper(xdr, &contents[i].hole.length))
                    return FALSE;


                hole_buff = res->data +
                    (contents[i].hole.offset - res->args_offset);
                hole_length = contents[i].hole.length;

                /*
                 * NFSv4.2 "READ_PLUS" is required to return the
                 * whole hole even if |hole.length| is bigger than
                 * the requested size
                 */
                if (((hole_buff - res->data) + hole_length) >
                    res->data_len) {
                    hole_length = res->data_len;
                }

                EASSERT(hole_length < UINT_MAX);
                (void)memset(hole_buff, 0, (size_t)hole_length);

                read_data_len = __max(read_data_len,
                    ((hole_buff - res->data) + hole_length));
                break;
            default:
                eprintf("decode_read_plus_res_ok: unknown co=%d\n",
                    (int)co);
                return FALSE;
        }
    }

    EASSERT(read_data_len < UINT_MAX);
    res->data_len = (uint32_t)read_data_len;
    return TRUE;
}

bool_t decode_op_read_plus(
    XDR *xdr,
    nfs_resop4 *resop)
{
    nfs42_read_plus_res *res = (nfs42_read_plus_res *)resop->res;

    if (unexpected_op(resop->op, OP_READ_PLUS))
        return FALSE;

    if (!xdr_u_int32_t(xdr, &res->status))
        return FALSE;

    if (res->status == NFS4_OK)
        return decode_read_plus_res_ok(xdr, &res->resok4);

    return TRUE;
}

/*
 * OP_SEEK
 */
bool_t encode_op_seek(
    XDR *xdr,
    nfs_argop4 *argop)
{
    nfs42_seek_args *args = (nfs42_seek_args *)argop->arg;

    if (unexpected_op(argop->op, OP_SEEK))
        return FALSE;

    if (!xdr_stateid4(xdr, &args->stateid->stateid))
        return FALSE;

    if (!xdr_u_hyper(xdr, &args->offset))
        return FALSE;

    uint32_t args_what = args->what;
    EASSERT((args_what == NFS4_CONTENT_DATA) ||
        (args_what == NFS4_CONTENT_HOLE));
    return xdr_u_int32_t(xdr, &args_what);
}

static bool_t decode_seek_res_ok(
    XDR *xdr,
    nfs42_seek_res_ok *res)
{
    if (!xdr_bool(xdr, &res->eof)) {
        DPRINTF(0, ("decode eof failed\n"));
        return FALSE;
    }

    if (!xdr_u_hyper(xdr, &res->offset)) {
        return FALSE;
    }

    return TRUE;
}

bool_t decode_op_seek(
    XDR *xdr,
    nfs_resop4 *resop)
{
    nfs42_seek_res *res = (nfs42_seek_res *)resop->res;

    if (unexpected_op(resop->op, OP_SEEK))
        return FALSE;

    if (!xdr_u_int32_t(xdr, &res->status))
        return FALSE;

    if (res->status == NFS4_OK)
        return decode_seek_res_ok(xdr, &res->resok4);

    return TRUE;
}
