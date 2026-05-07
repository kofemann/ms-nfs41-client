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

#ifndef IDMAP_H
#define IDMAP_H 1

#include <stdbool.h>
#include "nfs41_const.h"

typedef struct idmap_context nfs41_idmapper;

int nfs41_idmap_create(
    IN const char *configname,
    OUT struct idmap_context **context_out);
void nfs41_idmap_free(
    nfs41_idmapper *context);
int nfs41_idmap_map_nfsserverspec2idmappercfgname(
    IN const char *restrict hostname,
    IN unsigned short port,
    IN bool ispubnfs,
    OUT char *restrict res_idmappercfgname);
int nfs41_idmap_get_idmapconfig(
    IN const char *restrict idmappercfgname,
    OUT int *restrict res_cache_ttl);

#define IDMAPCACHE_MAXNAME_LEN 256

/*
 * Public API for idmapper cache
 */
typedef signed long idmapcache_idnumber;

typedef struct _idmap_namestr {
    const char *buf; /* ptr to buffer in the idmapper provider private data */
    size_t len;
} idmap_namestr;

/* from "daemon/util.h" */
#ifndef UTIL_RELTIMESTAMP_DEFINED
#define UTIL_RELTIMESTAMP_DEFINED 1
typedef ULONGLONG util_reltimestamp;
#endif /* !UTIL_RELTIMESTAMP_DEFINED */

typedef struct _idmapcache_entry {
    idmap_namestr win32name;
    idmapcache_idnumber localid;

    idmap_namestr nfsname;
    idmapcache_idnumber nfsid;

    util_reltimestamp last_updated;
} idmapcache_entry;

typedef struct _idmapcache_context idmapcache_context;

idmapcache_context *idmapcache_context_create(int cache_ttl);
void idmapcache_context_destroy(idmapcache_context *restrict ctx);
idmapcache_entry *idmapcache_add(idmapcache_context *restrict ctx,
    const char *restrict win32name,
    idmapcache_idnumber localid,
    const char *restrict nfsname,
    idmapcache_idnumber nfsid);
idmapcache_entry *idmapcache_lookup_by_win32name(
    idmapcache_context *restrict ctx,
    const char *restrict win32name);
idmapcache_entry *idmapcache_lookup_by_localid(
    idmapcache_context *restrict ctx,
    idmapcache_idnumber search_localid);
idmapcache_entry *idmapcache_lookup_by_nfsname(
    idmapcache_context *restrict ctx,
    const char *restrict nfsname);
idmapcache_entry *idmapcache_lookup_by_nfsid(idmapcache_context *restrict ctx,
    idmapcache_idnumber search_nfslid);
void idmapcache_entry_refcount_inc(idmapcache_entry *restrict e);
void idmapcache_entry_refcount_dec(idmapcache_entry *restrict e);

enum nfsserver_acl_capabilities {
    NFSSRVACLCAPS_AUTO = 1,
    NFSSRVACLCAPS_FULL_ACL4_SUPPORT = 2,
    NFSSRVACLCAPS_USE_LINUX_ACL_WORKAROUNDS = 3
};

struct idmap_config {
    char configname[256];

    int cache_ttl;
    bool use_numeric_uidgid;

    /*
     * |acl_capabilities| - There is no way to detect whether the filesystem
     * exported by the NFS server supports full NFSv4/ZFS ACLs, or only the
     * POSIX-draft ACLs. Therefore we provide a idmapper setting, and
     * the "default" we select based on the support for NFS named
     * attributes, because typically filesystems which support NFS named
     * attributes also have full NFSv4 ACL support
     * The exception is WindowsServer, which supports full NFSv4 ACLs,
     * but currenly has no NFS named attribute support (yet).
     */
    enum nfsserver_acl_capabilities acl_capabilities;

    /* uid/gids to use if a user/group cannot be mapped */
    idmapcache_idnumber default_nfs_uid;
    idmapcache_idnumber default_nfs_gid;
    idmapcache_idnumber default_local_uid;
    idmapcache_idnumber default_local_gid;
};

struct idmap_context {
    struct idmap_config config;

    idmapcache_context *usercache;
    idmapcache_context *groupcache;

    char *well_known_lgrouplist;
};

/*
 * User lookup functions
 * If an entry does not exists the idmapper script will be called to create it
 */
idmapcache_entry *nfs41_idmap_user_lookup_by_win32name(
    struct idmap_context *context,
    const char *restrict win32name);
idmapcache_entry *nfs41_idmap_user_lookup_by_localid(
    struct idmap_context *context,
    idmapcache_idnumber search_localid);
idmapcache_entry *nfs41_idmap_user_lookup_by_nfsname(
    struct idmap_context *context,
    const char *restrict nfsname);
idmapcache_entry *nfs41_idmap_user_lookup_by_nfsid(
    struct idmap_context *context,
    idmapcache_idnumber search_nfslid);

/*
 * User lookup functions
 * If an entry does not exists the idmapper script will be called to create it
 */
idmapcache_entry *nfs41_idmap_group_lookup_by_win32name(
    struct idmap_context *context,
    const char *restrict win32name);
idmapcache_entry *nfs41_idmap_group_lookup_by_localid(
    struct idmap_context *context,
    idmapcache_idnumber search_localid);
idmapcache_entry *nfs41_idmap_group_lookup_by_nfsname(
    struct idmap_context *context,
    const char *restrict nfsname);
idmapcache_entry *nfs41_idmap_group_lookup_by_nfsid(
    struct idmap_context *context,
    idmapcache_idnumber search_nfslid);

#endif /* !IDMAP_H */
