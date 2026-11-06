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

bool_t nfs_encode_compound(XDR *xdr, caddr_t *args);
bool_t nfs_decode_compound(XDR *xdr, caddr_t *res);

void nfsacl41_free(nfsacl41 *acl);
enum limit_by4;
bool_t xdr_count4(XDR *restrict xdr, count4 *restrict count);
bool_t xdr_length4(XDR *restrict xdr, length4 *restrict length);
bool_t xdr_offset4(XDR *restrict xdr, offset4 *restrict offset);
bool_t xdr_limit_by4(XDR *xdr, enum limit_by4 *limitby);
bool_t xdr_stateid4(XDR *xdr, stateid4 *si);
bool_t xdr_verifier4(XDR *xdr, verifier4 *verf);
bool_t xdr_fh(XDR *xdr, nfs41_fh *fh);
bool_t xdr_fsid(XDR *xdr, nfs41_fsid *fsid);
enum stable_how4;
bool_t xdr_stable_how4(XDR *xdr, enum stable_how4 *sh);
bool_t xdr_state_owner4(XDR *xdr, state_owner4 *so);

/* NFSv4.2 ops */
bool_t encode_op_allocate(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_allocate(XDR *xdr, const nfs_argop4 *argop, nfs_resop4 *resop);
bool_t encode_op_copy(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_copy(XDR *xdr, const nfs_argop4 *argop, nfs_resop4 *resop);
bool_t encode_op_deallocate(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_deallocate(XDR *xdr, const nfs_argop4 *argop, nfs_resop4 *resop);
bool_t encode_op_read_plus(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_read_plus(XDR *xdr, const nfs_argop4 *argop, nfs_resop4 *resop);
bool_t encode_op_seek(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_seek(XDR *xdr, const nfs_argop4 *argop, nfs_resop4 *resop);
bool_t encode_op_clone(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_clone(XDR *xdr, const nfs_argop4 *argop, nfs_resop4 *resop);

#endif /* !__NFS41_NFS_XDR_H__ */
