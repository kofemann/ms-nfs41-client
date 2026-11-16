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

#ifndef __NFS41_NFS_XDR_H__
#define __NFS41_NFS_XDR_H__ 1

#include "nfs41_types.h"
#include "nfs41_compound.h"

struct nfsencodedecodecontext {
    nfs41_compound_args *args;
    nfs41_compound_res  *res;
};

bool_t nfs_encode_compound(XDR *restrict xdr, caddr_t *restrict args);
bool_t nfs_decode_compound(XDR *restrict xdr, caddr_t *restrict res);

void nfsacl41_free(nfsacl41 *restrict acl);
bool_t xdr_count4(XDR *restrict xdr, count4 *restrict count);
bool_t xdr_mode4(XDR *restrict xdr, mode4 *restrict mode);
bool_t xdr_length4(XDR *restrict xdr, length4 *restrict length);
bool_t xdr_offset4(XDR *restrict xdr, offset4 *restrict offset);
enum limit_by4;
bool_t xdr_limit_by4(XDR *restrict xdr, enum limit_by4 *restrict limitby);
bool_t xdr_stateid4(XDR *restrict xdr, stateid4 *restrict si);
bool_t xdr_verifier4(XDR *restrict xdr, verifier4 *restrict verf);
bool_t xdr_sessionid4(XDR *restrict xdr, sessionid4 *restrict sessionid);
bool_t xdr_fh(XDR *restrict xdr, nfs41_fh *restrict fh);
bool_t xdr_fsid(XDR *restrict xdr, nfs41_fsid *restrict fsid);
enum stable_how4;
bool_t xdr_stable_how4(XDR *restrict xdr, enum stable_how4 *restrict sh);
bool_t xdr_state_owner4(XDR *restrict xdr, state_owner4 *restrict so);

/* NFSv4.2 ops */
bool_t encode_op_allocate(XDR *restrict xdr,
    const nfs_argop4 *restrict argop);
bool_t decode_op_allocate(XDR *restrict xdr,
    const nfs_argop4 *restrict argop, nfs_resop4 *restrict resop);
bool_t encode_op_copy(XDR *restrict xdr,
    const nfs_argop4 *restrict argop);
bool_t decode_op_copy(XDR *restrict xdr,
    const nfs_argop4 *restrict argop, nfs_resop4 *restrict resop);
bool_t encode_op_deallocate(XDR *restrict xdr,
    const nfs_argop4 *restrict argop);
bool_t decode_op_deallocate(XDR *restrict xdr,
    const nfs_argop4 *restrict argop, nfs_resop4 *restrict resop);
bool_t encode_op_read_plus(XDR *restrict xdr,
    const nfs_argop4 *restrict argop);
bool_t decode_op_read_plus(XDR *restrict xdr,
    const nfs_argop4 *restrict argop, nfs_resop4 *restrict resop);
bool_t encode_op_seek(XDR *restrict xdr,
    const nfs_argop4 *restrict argop);
bool_t decode_op_seek(XDR *restrict xdr,
    const nfs_argop4 *restrict argop, nfs_resop4 *restrict resop);
bool_t encode_op_clone(XDR *restrict xdr,
    const nfs_argop4 *restrict argop);
bool_t decode_op_clone(XDR *restrict xdr,
    const nfs_argop4 *restrict argop, nfs_resop4 *restrict resop);

#endif /* !__NFS41_NFS_XDR_H__ */
