/* NFSv4.1 client for Windows
 * Copyright � 2012 The Regents of the University of Michigan
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

#ifndef __NFS41_DAEMON_H_
#define __NFS41_DAEMON_H_ 1

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

#include "nfs41_build_features.h"
#include "idmap.h"

/*
 * Global data of the daemon process
 */
typedef struct __nfs41_daemon_globals {
    struct idmap_context *idmapper;
    char localdomain_name[NFS41_HOSTNAME_LEN];
    int default_uid;
    int default_gid;
    ssize_t num_worker_threads;
    int crtdbgmem_flags;
    char nfs41_nii_name[256];
} nfs41_daemon_globals;

#define NFS41D_GLOBALS_CRTDBGMEM_FLAGS_NOT_SET (-1)

#endif /* !__NFS41_DAEMON_H_ */
