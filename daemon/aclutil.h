/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2026 Roland Mainz <roland.mainz@nrubsig.org>
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
#include "nfs41_types.h"
#include "idmap.h"

/* |DPRINTF()| levels for acl logging */
#define ACLLVL1 1
#define ACLLVL2 2
#define ACLLVL3 3

void free_sids(PSID *sids, int count);
#ifdef NFS41_DRIVER_WS2022_HACKS
char *build_well_known_localised_nfs_grouplist(struct idmap_context *context);
#endif /* NFS41_DRIVER_WS2022_HACKS */
int map_sid2nfs4ace_who(
    IN OUT struct idmap_context *idmapper,
    IN PSID sid,
    IN PSID owner_sid,
    IN PSID group_sid,
    IN bool nfs_namedattr_support,
    OUT char *who_out,
    IN const char *domain,
    OUT SID_NAME_USE *sid_type_out);
int convert_nfs4acl_2_dacl(
    IN OUT struct idmap_context *idmapper,
    IN nfsacl41 *restrict acl,
    IN int file_type,
    OUT PACL *dacl_out,
    OUT PSID **sids_out,
    IN bool nfs_namedattr_support);
int map_dacl_2_nfs4acl(
    IN OUT struct idmap_context *idmapper,
    IN PACL acl,
    IN PSID sid,
    IN PSID gsid,
    OUT nfsacl41 *nfs4_acl,
    IN int file_type,
    IN bool nfs_namedattr_support,
    IN const char *domain);

#endif /* !__NFS41_DAEMON_ACLUTIL_H__ */
