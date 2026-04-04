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

#include "nfs41_types.h"


/* idmap.c */
typedef struct idmap_context nfs41_idmapper;

int nfs41_idmap_create(
    nfs41_idmapper **context_out, const char *localdomain_name);
void nfs41_idmap_free(
    nfs41_idmapper *context);

/* idmap_cygwin.c */
#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
int cygwin_local_getent_passwd(
    const char *restrict name,
    char *restrict res_localaccountname,
    uid_t *restrict res_localuid,
    char *restrict res_nfsowner,
    uid_t *restrict res_nfsuid);
int cygwin_nfsserver_getent_passwd(
    const char *restrict name,
    char *restrict res_localaccountname,
    uid_t *restrict res_localuid,
    char *restrict res_nfsowner,
    uid_t *restrict res_nfsuid);
int cygwin_local_getent_group(
    const char *restrict name,
    char *restrict res_localgroupname,
    gid_t *restrict res_localgid,
    char *restrict res_nfsownergroup,
    gid_t *restrict res_nfsgid);
int cygwin_nfsserver_getent_group(
    const char *restrict name,
    char *restrict res_localgroupname,
    gid_t *restrict res_localgid,
    char *restrict res_nfsownergroup,
    gid_t *restrict res_nfsgid);
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */

#define IDMAPCACHE_TTL_SECONDS (60*5)
#define IDMAPCACHE_MAXNAME_LEN 256

/*
 * Public API for idmapper cache
 */
typedef signed long idmapcache_idnumber;

typedef struct _idmap_namestr {
    char buf[IDMAPCACHE_MAXNAME_LEN];
    size_t len;
} idmap_namestr;

typedef struct _idmapcache_entry {
    idmap_namestr win32name;
    idmapcache_idnumber localid;

    idmap_namestr nfsname;
    idmapcache_idnumber nfsid;

    time_t last_updated;
} idmapcache_entry;

typedef struct _idmapcache_context idmapcache_context;

idmapcache_context *idmapcache_context_create(void);
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

struct idmap_config {
    UINT timeout;

    bool use_numeric_uidgid;

    /* caching configuration */
    INT cache_ttl;
};

struct idmap_context {
    struct idmap_config config;

    idmapcache_context *usercache;
    idmapcache_context *groupcache;

    void *ldap;
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
