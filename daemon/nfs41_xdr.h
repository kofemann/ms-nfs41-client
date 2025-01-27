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

#ifndef __NFS41_NFS_XDR_H__
#define __NFS41_NFS_XDR_H__

#include "nfs41_types.h"
#include "nfs41_compound.h"

bool_t nfs_encode_compound(XDR *xdr, caddr_t *args);
bool_t nfs_decode_compound(XDR *xdr, caddr_t *res);

void nfsacl41_free(nfsacl41 *acl);
bool_t xdr_stateid4(XDR *xdr, stateid4 *si);

/* NFSv4.2 ops */
bool_t encode_op_read_plus(XDR *xdr, nfs_argop4 *argop);
bool_t decode_op_read_plus(XDR *xdr, nfs_resop4 *resop);

#endif /* !__NFS41_NFS_XDR_H__ */
