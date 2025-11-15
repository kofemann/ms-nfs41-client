/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
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

#ifndef __NFS41_DAEMON_ACLUTIL_H__
#define __NFS41_DAEMON_ACLUTIL_H__ 1

#include "nfs41_build_features.h"
#include "nfs41_daemon.h"

/* |DPRINTF()| levels for acl logging */
#define ACLLVL1 1
#define ACLLVL2 2
#define ACLLVL3 3

void free_sids(PSID *sids, int count);
int map_sid2nfs4ace_who(PSID sid, PSID owner_sid, PSID group_sid,
    char *who_out, char *domain, SID_NAME_USE *sid_type_out);
void convert_nfs4name_2_user_domain(LPSTR nfs4name,
    LPSTR *domain);
int convert_nfs4acl_2_dacl(nfs41_daemon_globals *nfs41dg,
    nfsacl41 *acl, int file_type, PACL *dacl_out, PSID **sids_out,
    bool named_attr_support);
int map_dacl_2_nfs4acl(PACL acl, PSID sid, PSID gsid, nfsacl41 *nfs4_acl,
    int file_type, bool named_attr_support, char *domain);

#endif /* !__NFS41_DAEMON_ACLUTIL_H__ */
