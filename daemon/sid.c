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

#include <Windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <strsafe.h>
#include <sddl.h>

#include "nfs41_ops.h"
#include "nfs41_build_features.h"
#include "nfs41_daemon.h"
#include "delegation.h"
#include "daemon_debug.h"
#include "util.h"
#include "upcall.h"
#include "nfs41_xdr.h"
#include "idmap.h"
#include "sid.h"

#define ACLLVL 2 /* dprintf level for acl logging */


int create_unknownsid(
    IN WELL_KNOWN_SID_TYPE type,
    OUT PSID *restrict sid,
    OUT DWORD *restrict sid_len)
{
    BOOL success;
    int status;

    *sid_len = MAX_SID_BUFFER_SIZE;
    *sid = malloc(*sid_len);
    if (*sid == NULL) {
        status = ERROR_INSUFFICIENT_BUFFER;
        goto err;
    }

    success = CreateWellKnownSid(type, NULL, *sid, sid_len);
    if (success) {
        *sid_len = GetLengthSid(*sid);

        DPRINTF(ACLLVL,
            ("create_unknownsid(type=%d): CreateWellKnownSid() "
            "returned type=%d *sid_len=%d\n",
            (int)type, (int)*sid_len));

        return ERROR_SUCCESS;
    }

    status = GetLastError();
    free(*sid);
err:
    *sid = NULL;
    *sid_len = 0;
    eprintf("create_unknownsid(type=%d): "
        "CreateWellKnownSid failed, status=%d\n",
        (int)type, status);
    return status;
}

#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
/*
 * Allocate a SID from SECURITY_SAMBA_UNIX_AUTHORITY, which encodes an
 * UNIX/POSIX uid directly into a SID.
 *
 * Examples:
 * UID 1616 gets mapped to "Unix_User+1616", encoding the UID into the
 * SID as "S-1-22-1-1616":
 * $ getent passwd Unix_User+1616
 * Unix_User+1616:*:4278191696:4278191696:U-Unix_User\1616,S-1-22-1-1616:/:/sbin/nologin
 *
 * GID 1984 gets mapped to "Unix_Group+1984", encoding the GID into the
 * SID as "S-1-22-2-1984":
 * $ getent group Unix_Group+1984
 * Unix_Group+1984:S-1-22-2-1984:4278192064:
 *
 */

#define SECURITY_SAMBA_UNIX_AUTHORITY { { 0,0,0,0,0,22 } }
SID_IDENTIFIER_AUTHORITY sid_id_auth = SECURITY_SAMBA_UNIX_AUTHORITY;

static
bool allocate_unixuser_sid(IN unsigned long uid, OUT PSID *pSid)
{
    PSID sid = NULL;
    DWORD sid_len;
    UCHAR sub_auth_count = 2; /* Two sub-authorities: '1' and 'uid' */

    sid_len = GetSidLengthRequired(sub_auth_count);

    sid = malloc(sid_len);
    if (sid == NULL) {
        DPRINTF(ACLLVL,
            ("allocate_unixuser_sid(): Failed to malloc() "
            "SID memory for Unix_User+%lu\n",
            uid));
        return false;
    }

    if (!InitializeSid(sid, &sid_id_auth, sub_auth_count)) {
        eprintf("allocate_unixuser_sid(): "
            "InitializeSid() failed for Unix_User+%lu:, status=%d\n",
            uid, (int)GetLastError());
        free(sid);
        return false;
    }

    /*
     * First sub-authority is 1 (indicating an "Unix_User")
     * Second sub-authority is the actual UID
     */
    *GetSidSubAuthority(sid, 0) = 1;
    *GetSidSubAuthority(sid, 1) = (DWORD)uid;

    *pSid = sid;
    return true;
}

static
bool allocate_unixgroup_sid(IN unsigned long gid, OUT PSID *pSid)
{
    PSID sid = NULL;
    DWORD sid_len;
    UCHAR sub_auth_count = 2; /* Two sub-authorities: '1' and 'gid' */

    sid_len = GetSidLengthRequired(sub_auth_count);

    sid = malloc(sid_len);
    if (sid == NULL) {
        DPRINTF(ACLLVL,
            ("allocate_unixgroup_sid(): Failed to malloc() "
            "SID memory for Unix_Group+%lu\n",
            gid));
        return false;
    }

    if (!InitializeSid(sid, &sid_id_auth, sub_auth_count)) {
        eprintf("allocate_unixgroup_sid(): "
            "InitializeSid() failed for Unix_Group+%lu:, status=%d\n",
            gid, (int)GetLastError());
        free(sid);
        return false;
    }

    /*
     * First sub-authority is 2 (indicating an "Unix_Group")
     * Second sub-authority is the actual UID
     */
    *GetSidSubAuthority(sid, 0) = 2;
    *GetSidSubAuthority(sid, 1) = (DWORD)gid;

    *pSid = sid;
    return true;
}

bool unixuser_sid2uid(IN SID *restrict psid, OUT uid_t *restrict puid)
{
    if (psid == NULL)
        return false;

    PSID_IDENTIFIER_AUTHORITY psia = GetSidIdentifierAuthority(psid);
    if ((*GetSidSubAuthorityCount(psid) == 2) &&
        (psia->Value[0] == 0) &&
        (psia->Value[1] == 0) &&
        (psia->Value[2] == 0) &&
        (psia->Value[3] == 0) &&
        (psia->Value[4] == 0) &&
        (psia->Value[5] == 22) &&
        (*GetSidSubAuthority(psid, 0) == 1)) {
        *puid = *GetSidSubAuthority(psid, 1);
        return true;
    }

    return false;
}

bool unixgroup_sid2gid(IN SID *restrict psid, OUT gid_t *restrict pgid)
{
    if (psid == NULL)
        return false;

    PSID_IDENTIFIER_AUTHORITY psia = GetSidIdentifierAuthority(psid);
    if ((*GetSidSubAuthorityCount(psid) == 2) &&
        (psia->Value[0] == 0) &&
        (psia->Value[1] == 0) &&
        (psia->Value[2] == 0) &&
        (psia->Value[3] == 0) &&
        (psia->Value[4] == 0) &&
        (psia->Value[5] == 22) &&
        (*GetSidSubAuthority(psid, 0) == 2)) {
        *pgid = *GetSidSubAuthority(psid, 1);
        return true;
    }

    return false;
}
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */


#ifdef NFS41_DRIVER_SID_CACHE
/*
 * |SIDCACHE_SIZE| - size of SID cache
 * We should at least use the maximum size of ACL entries plus { owner,
 * owner_group, other, nobody, world, ... } entries multiplied by two to
 * make sure two concurrent icacls queries cannot trash the whole cache
 */
#define SIDCACHE_SIZE 384
#define SIDCACHE_TTL 600

/* Safety/performance checks */
#if SIDCACHE_SIZE < ((NFS41_ACL_MAX_ACE_ENTRIES+8)*2)
#error SIDCACHE_SIZE should be at least ((NFS41_ACL_MAX_ACE_ENTRIES+8)*2)
#endif

typedef struct _sidcache_entry
{
#define SIDCACHE_ENTRY_NAME_SIZE (UTF8_PRINCIPALLEN + 1)
    char    win32name[SIDCACHE_ENTRY_NAME_SIZE];
    PSID    sid;
    DWORD   sid_len;
#pragma warning( push )
#pragma warning (disable : 4324)
    DECLARE_SID_BUFFER(sid_buffer);
#pragma warning( pop )
    util_reltimestamp  timestamp;
} sidcache_entry;

typedef struct _sidcache
{
    CRITICAL_SECTION    lock;
    sidcache_entry      entries[SIDCACHE_SIZE];
    ssize_t             cacheIndex;
} sidcache;

/* fixme: need function to deallocate this */
sidcache user_sidcache = { 0 };
sidcache group_sidcache = { 0 };


void sidcache_init(void)
{
    InitializeCriticalSection(&user_sidcache.lock);
    InitializeCriticalSection(&group_sidcache.lock);
}

/* copy SID |value| into cache */
void sidcache_add(IN OUT sidcache *cache, IN const char *win32name, IN PSID value)
{
    int i;
    ssize_t freeEntryIndex;
    util_reltimestamp currentTimestamp;

    EASSERT(win32name[0] != '\0');
    EASSERT_MSG(IS_PRINCIPAL_NAME(win32name),
        ("name='%s' is not a principal\n", win32name));

    EnterCriticalSection(&cache->lock);
    currentTimestamp = UTIL_GETRELTIME();

    /* purge obsolete entries */
    for (i = 0; i < SIDCACHE_SIZE; i++) {
        sidcache_entry *e = &cache->entries[i];

        if ((e->sid != NULL) &&
            ((currentTimestamp - e->timestamp) >= SIDCACHE_TTL)) {
            e->sid = NULL;
            e->win32name[0] = '\0';
            e->sid_len = 0;
        }
    }

    /* Find the oldest valid cache entry */
    freeEntryIndex = -1;
    for (i = 0; i < SIDCACHE_SIZE; i++) {
        sidcache_entry *e = &cache->entries[i];
        if (e->sid) {
            /* Same name ? Then reuse this slot... */
            if (!strcmp(e->win32name, win32name)) {
                freeEntryIndex = i;
                break;
            }
        }
        else {
            /* (cache->entries[i].sid == NULL) --> empty slot... */
            freeEntryIndex = i;
            break;
        }
    }

    /* If no valid entry was found, overwrite the oldest entry */
    if (freeEntryIndex == -1) {
        freeEntryIndex = cache->cacheIndex;
    }

    /* Replace the cache entry */
    sidcache_entry *e = &cache->entries[freeEntryIndex];
    DWORD sid_len = GetLengthSid(value);
    EASSERT_MSG((sid_len <= MAX_SID_BUFFER_SIZE),
        ("sid_len=%ld\n", (long)sid_len));
    e->sid = (PSID)e->sid_buffer;
    if (!CopySid(sid_len, e->sid, value)) {
        e->sid = NULL;
        e->win32name[0] = '\0';
        e->sid_len = 0;
        goto done;
    }

    e->sid_len = sid_len;
    (void)strcpy(e->win32name, win32name);
    e->timestamp = currentTimestamp;

    cache->cacheIndex = (cache->cacheIndex + 1) % SIDCACHE_SIZE;

done:
    LeaveCriticalSection(&cache->lock);
}

/* return |malloc()|'ed copy of SID from cache entry */
PSID *sidcache_getcached_byname(IN OUT sidcache *cache, IN const char *win32name)
{
    int i;
    util_reltimestamp currentTimestamp;
    sidcache_entry *e;
    PSID *ret_sid = NULL;

    EnterCriticalSection(&cache->lock);
    currentTimestamp = UTIL_GETRELTIME();

    for (i = 0; i < SIDCACHE_SIZE; i++) {
        e = &cache->entries[i];

        if ((e->sid != NULL) &&
            (strcmp(e->win32name, win32name) == 0) &&
            ((currentTimestamp - e->timestamp) < SIDCACHE_TTL)) {
            PSID malloced_sid = malloc(e->sid_len);
            if (!malloced_sid)
                goto done;

            if (!CopySid(e->sid_len, malloced_sid, e->sid)) {
                free(malloced_sid);
                goto done;
            }

            ret_sid = malloced_sid;
            goto done;
        }
    }

done:
    LeaveCriticalSection(&cache->lock);
    return ret_sid;
}

bool sidcache_getcached_bysid(
    IN OUT sidcache *cache,
    IN PSID sid,
    OUT char *out_win32name)
{
    int i;
    util_reltimestamp currentTimestamp;
    sidcache_entry *e;
    bool ret = false;

    EnterCriticalSection(&cache->lock);
    currentTimestamp = UTIL_GETRELTIME();

    for (i = 0; i < SIDCACHE_SIZE; i++) {
        e = &cache->entries[i];

        if ((e->sid != NULL) &&
            (EqualSid(sid, e->sid) &&
            ((currentTimestamp - e->timestamp) < SIDCACHE_TTL))) {
            (void)strcpy(out_win32name, e->win32name);

            ret = true;
            goto done;
        }
    }

done:
    LeaveCriticalSection(&cache->lock);
    return ret;
}
#endif /* NFS41_DRIVER_SID_CACHE */


int map_nfs4servername_2_sid(
    nfs41_daemon_globals *nfs41dg,
    int query,
    DWORD *sid_len,
    PSID *sid,
    LPCSTR nfsname)
{
    const char *win32name = NULL;

    int status = ERROR_INTERNAL_ERROR;
    BOOL success;
    SID_NAME_USE sid_type = 0;
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    signed long user_uid = -1;
    signed long group_gid = -1;
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */
    idmapcache_entry *nfs_ie = NULL;

    DPRINTF(ACLLVL,
        ("--> map_nfs4servername_2_sid(query=0x%x,nfsname='%s')\n",
        query, nfsname));

    if (isdigit(nfsname[0])) {
        idmapcache_idnumber nfs_id;

        errno = 0;
        nfs_id = strtol(nfsname, NULL, 10);
        if (errno != 0) {
            DPRINTF(0,
                ("map_nfs4servername_2_sid(nfsname='%s'): "
                "strtol() failed to map string to number, errno=%d\n",
                nfsname, (int)errno));
            status = ERROR_NOT_FOUND;
            goto out;
        }

        if ((nfs_ie == NULL) && (query & OWNER_SECURITY_INFORMATION)) {
            nfs_ie = nfs41_idmap_user_lookup_by_nfsid(nfs41dg->idmapper,
                nfs_id);
        }
        if ((nfs_ie == NULL) && (query & GROUP_SECURITY_INFORMATION)) {
            nfs_ie = nfs41_idmap_group_lookup_by_nfsid(nfs41dg->idmapper,
                nfs_id);
        }
    }
    else {
        EASSERT_MSG(IS_PRINCIPAL_NAME(nfsname),
            ("nfsname='%s' is not a principal\n", nfsname));

        if ((nfs_ie == NULL) && (query & OWNER_SECURITY_INFORMATION)) {
            nfs_ie = nfs41_idmap_user_lookup_by_nfsname(nfs41dg->idmapper,
                nfsname);
        }
        if ((nfs_ie == NULL) && (query & GROUP_SECURITY_INFORMATION)) {
            nfs_ie = nfs41_idmap_group_lookup_by_nfsname(nfs41dg->idmapper,
                nfsname);
        }
    }

    if (nfs_ie == NULL) {
        DPRINTF(0,
            ("map_nfs4servername_2_sid(nfsname='%s'): "
            "nfs41_idmap_group_lookup_by_nfsname() failed\n",
            nfsname));
        status = ERROR_NOT_FOUND;
        goto out;
    }
    win32name = nfs_ie->win32name.buf;

#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    if (query & OWNER_SECURITY_INFORMATION) {
#ifdef NFS41_DRIVER_SID_CACHE
        *sid = sidcache_getcached_byname(&user_sidcache, win32name);
        if (*sid) {
            *sid_len = GetLengthSid(*sid);
            DPRINTF(1,
                ("map_nfs4servername_2_sid: "
                "returning cached user sid for win32name='%s'\n",
                win32name));
            status = ERROR_SUCCESS;
            goto out;
        }
#endif /* NFS41_DRIVER_SID_CACHE */
    }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */


#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    if (query & GROUP_SECURITY_INFORMATION) {
#ifdef NFS41_DRIVER_SID_CACHE
        *sid = sidcache_getcached_byname(&group_sidcache, win32name);
        if (*sid) {
            *sid_len = GetLengthSid(*sid);
            DPRINTF(1,
                ("map_nfs4servername_2_sid: "
                "returning cached group sid for win32name='%s'\n",
                win32name));
            status = ERROR_SUCCESS;
            goto out;
        }
#endif /* NFS41_DRIVER_SID_CACHE */
    }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

    *sid = malloc(MAX_SID_BUFFER_SIZE);
    if (*sid == NULL) {
        status = GetLastError();
        goto out;
    }
    *sid_len = MAX_SID_BUFFER_SIZE;

    success = lookupprincipalnameutf8(NULL, win32name, *sid, sid_len,
        &sid_type);

    if (success) {
        /* |lookupprincipalnameutf8()| success */

        DPRINTF(ACLLVL,
            ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
            "lookupprincipalnameutf8() returned success, *sid_len=%d\n",
            query, win32name, *sid_len));

        status = ERROR_SUCCESS;
        *sid_len = GetLengthSid(*sid);
        goto out_cache;
    }

    status = GetLastError();
    /* |lookupprincipalnameutf8()| failed... */
    DPRINTF(ACLLVL,
        ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
        "lookupprincipalnameutf8() failed, status=%d\n",
        query, win32name, status));

    switch(status) {
    case ERROR_INSUFFICIENT_BUFFER:
        /*
         * This should never happen, as |MAX_SID_BUFFER_SIZE| should be
         * larger than the largest possible SID buffer size for Windows
         */
        eprintf("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                "lookupprincipalnameutf8() failed with "
                "ERROR_INSUFFICIENT_BUFFER\n", query, win32name);

        status = ERROR_INTERNAL_ERROR;
        goto out;
        break;
    case ERROR_NONE_MAPPED:
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
        DPRINTF(1,
            ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
            "none mapped, "
            "trying Unix_User+/Unix_Group+ mapping\n",
            query, win32name));

        if ((user_uid == -1) && (query & OWNER_SECURITY_INFORMATION)) {
           user_uid = nfs_ie->localid;
        }

        if ((group_gid == -1) && (query & GROUP_SECURITY_INFORMATION)) {
           group_gid = nfs_ie->localid;
        }

        if (user_uid != -1) {
            if (allocate_unixuser_sid(user_uid, sid)) {
                DPRINTF(ACLLVL,
                    ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                    "allocate_unixuser_sid(uid=%ld) success\n",
                    query, win32name, user_uid));
                status = ERROR_SUCCESS;
                sid_type = SidTypeUser;
                goto out_cache;
            }

            status = GetLastError();
            DPRINTF(ACLLVL,
                ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                "allocate_unixuser_sid(uid=%ld) failed, status=%d\n",
                query, win32name, user_uid, status));
            goto out;
        }

        if (group_gid != -1) {
            if (allocate_unixgroup_sid(group_gid, sid)) {
                DPRINTF(ACLLVL,
                    ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                    "allocate_unixgroup_sid(gid=%ld) success\n",
                    query, win32name, group_gid));
                status = ERROR_SUCCESS;
                sid_type = SidTypeGroup;
                goto out_cache;
            }

            status = GetLastError();
            DPRINTF(ACLLVL,
                ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                "allocate_unixgroup_sid(gid=%ld) failed, status=%d\n",
                query, win32name, group_gid, status));
            goto out;
        }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

        DPRINTF(1,
            ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
            "none mapped, using WinNullSid mapping\n",
            query, win32name));

        status = create_unknownsid(WinNullSid, sid, sid_len);
        if (status)
            goto out_free_sid;
        break;
    default:
        DPRINTF(1,
            ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
            "error=%d not handled\n",
            query, win32name, (int)GetLastError()));
        break;
    }
out_cache:
#ifdef NFS41_DRIVER_SID_CACHE
    if ((status == ERROR_SUCCESS) && (*sid != NULL)) {
        if ((query & GROUP_SECURITY_INFORMATION) &&
            (sid_type == SidTypeAlias)) {
            /*
             * Treat |SidTypeAlias| as (local) group
             *
             * It seems that |lookupprincipalnameutf8()| will always return
             * |SidTypeAlias| for local groups created with
             * $ net localgroup cygwingrp1 /add #
             *
             * References:
             * - https://stackoverflow.com/questions/39373188/lookupaccountnamew-returns-sidtypealias-but-expected-sidtypegroup
             */
            DPRINTF(1,
                ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                "SID_TYPE='SidTypeAlias' mapped to 'SidTypeGroup'\n",
                query, win32name));
            sid_type = SidTypeGroup;
        }

#ifdef NFS41_DRIVER_WS2022_HACKS
        if ((query & OWNER_SECURITY_INFORMATION) &&
            (sid_type == SidTypeWellKnownGroup)) {
            if (IsWellKnownSid(*sid, WinLocalSystemSid)) {
                DPRINTF(1,
                    ("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                    "SID_TYPE='SidTypeWellKnownGroup' mapped to 'SidTypeUser' "
                    "for account 'SYSTEM'\n",
                    query, win32name));
                sid_type = SidTypeUser;
            }
        }
#endif /* NFS41_DRIVER_WS2022_HACKS */

        switch (sid_type) {
            case SidTypeUser:
                sidcache_add(&user_sidcache, win32name, *sid);
                break;
            case SidTypeGroup:
                sidcache_add(&group_sidcache, win32name, *sid);
                break;
            default:
                eprintf("map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                    "Unknown SID_TYPE=%d\n",
                    query, win32name, sid_type);
                break;
        }
    }
#endif /* NFS41_DRIVER_SID_CACHE */

out:
    if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
        if (status != ERROR_SUCCESS) {
            dprintf_out("<-- map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                "status=%d\n", query, win32name, status);
        }
        else {
            PSTR sidstr = NULL;
            char errsidstrbuf[128];

            if (!ConvertSidToStringSidA(*sid, &sidstr)) {
                (void)snprintf(errsidstrbuf, sizeof(errsidstrbuf),
                    "<ConvertSidToStringSidA() failed, "
                    "GetLastError()=%d>", (int)GetLastError());
                sidstr = errsidstrbuf;
            }

            dprintf_out("<-- map_nfs4servername_2_sid(query=0x%x,win32name='%s'): "
                "status=%d sidstr='%s' *sid_len=%d\n",
                query, win32name, status, sidstr, *sid_len);

            if (sidstr && (sidstr != errsidstrbuf))
                LocalFree(sidstr);
        }
    }

    if (nfs_ie)
        idmapcache_entry_refcount_dec(nfs_ie);

    return status;

out_free_sid:
    /* We assume |status| has been set */
    free(*sid);
    *sid = NULL;
    goto out;
}


/*
 * |lookupaccountnameutf8()| - UTF-8 version of |LookupAccountNameA()|
 *
 * We need this because Windows user+group names can contain Unicode
 * characters, and |*A()| functions depend on the current code page,
 * which might not cover all code points needed
 */
BOOL lookupaccountnameutf8(
    const char *restrict pSystemNameUTF8,
    const char *restrict pAccountNameUTF8,
    PSID restrict pSid,
    LPDWORD restrict pSidSize,
    char *restrict pReferencedDomainNameUTF8,
    LPDWORD restrict pReferencedDomainNameUTF8size,
    PSID_NAME_USE restrict peUse)
{
#ifdef NO_UTF8_ACCOUNT_CONV
    return LookupAccountNameA(
        pSystemNameUTF8,
        pAccountNameUTF8,
        pSid,
        pSidSize,
        pReferencedDomainNameUTF8,
        pReferencedDomainNameUTF8size,
        peUse);
#else
    if ((pAccountNameUTF8 == NULL) ||
        (pReferencedDomainNameUTF8size == NULL) ||
        (pSidSize == NULL) || (peUse == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    LPWSTR pSystemNameW;

    if (pSystemNameUTF8) {
        DWORD systemNameWsize;

        /*
         * Use |strlen()| here as optimisation, saving one around of
         * |MultiByteToWideChar()|
         */
        systemNameWsize = (DWORD)strlen(pSystemNameUTF8)+1;
        pSystemNameW = (LPWSTR)_alloca(systemNameWsize * sizeof(wchar_t));

        if (MultiByteToWideChar(CP_UTF8,
            0,
            pSystemNameUTF8,
            -1,
            pSystemNameW,
            systemNameWsize) == 0) {
            if (GetLastError() == ERROR_SUCCESS) {
                SetLastError(ERROR_INVALID_DATA);
            }
            return FALSE;
        }
    }
    else {
        pSystemNameW = NULL;
    }

    LPWSTR pAccountNameW;
    DWORD accountNameWsize;

    /*
     * Use |strlen()| here as optimisation, saving one around of
     * |MultiByteToWideChar()|
     */
    accountNameWsize = (DWORD)strlen(pAccountNameUTF8)+1;
    pAccountNameW = (LPWSTR)_alloca(accountNameWsize * sizeof(wchar_t));

    if (MultiByteToWideChar(CP_UTF8,
        0,
        pAccountNameUTF8,
        -1,
        pAccountNameW,
        accountNameWsize) == 0) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }

    DWORD referencedDomainNameWsize =
        (DWORD)*pReferencedDomainNameUTF8size / sizeof(wchar_t);
    LPWSTR pReferencedDomainNameW = NULL;

    if ((pReferencedDomainNameUTF8 == NULL) ||
        (*pReferencedDomainNameUTF8size == 0)) {
        referencedDomainNameWsize = 256;
    }

    pReferencedDomainNameW =
        (LPWSTR)_alloca(referencedDomainNameWsize * sizeof(wchar_t));

    BOOL success = LookupAccountNameW(
        pSystemNameW,
        pAccountNameW,
        pSid,
        pSidSize,
        pReferencedDomainNameW,
        &referencedDomainNameWsize,
        peUse);

    if (!success) {
        DWORD lastError = GetLastError();

        if (lastError == ERROR_INSUFFICIENT_BUFFER) {
            int requiredDomainNameUTF8Size = WideCharToMultiByte(CP_UTF8,
                0,
                pReferencedDomainNameW,
                referencedDomainNameWsize+1,
                NULL,
                0,
                NULL,
                NULL);
            if (requiredDomainNameUTF8Size == 0) {
                if (GetLastError() == ERROR_SUCCESS) {
                    SetLastError(ERROR_INVALID_DATA);
                }
                return FALSE;
            }

            *pReferencedDomainNameUTF8size =
                (size_t)requiredDomainNameUTF8Size+1;
        } else if (lastError == ERROR_NONE_MAPPED) {
            *pReferencedDomainNameUTF8size = 0;
            *pSidSize = 0;
            *peUse = SidTypeUnknown;
        } else {
            *pReferencedDomainNameUTF8size = 0;
            *pSidSize = 0;
            *peUse = SidTypeUnknown;
        }

        return FALSE;
    }

    int domainNameUTF8size = WideCharToMultiByte(CP_UTF8,
        0,
        pReferencedDomainNameW,
        referencedDomainNameWsize+1,
        NULL,
        0,
        NULL,
        NULL);
    if (domainNameUTF8size == 0) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }

    if (*pReferencedDomainNameUTF8size < (size_t)domainNameUTF8size) {
        *pReferencedDomainNameUTF8size = (size_t)domainNameUTF8size;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    (void)WideCharToMultiByte(CP_UTF8,
        0,
        pReferencedDomainNameW,
        referencedDomainNameWsize+1,
        pReferencedDomainNameUTF8,
        domainNameUTF8size,
        NULL,
        NULL);
    *pReferencedDomainNameUTF8size = (size_t)domainNameUTF8size-1;

    SetLastError(ERROR_SUCCESS);
    return TRUE;
#endif /* NO_UTF8_ACCOUNT_CONV */
}


/*
 * |lookupaccountsidutf8()| - UTF-8 version of |LookupAccountSidA()|
 *
 * We need this because Windows user+group names can contain Unicode
 * characters, and |*A()| functions depend on the current code page,
 * which might not cover all code points needed
 */
BOOL lookupaccountsidutf8(
    const char *restrict pSystemNameUTF8,
    PSID restrict Sid,
    char *restrict pNameUTF8,
    LPDWORD restrict pNameSize,
    char *restrict pReferencedDomainNameUTF8,
    LPDWORD restrict pReferencedDomainNameUTF8Size,
    PSID_NAME_USE restrict peUse)
{
#ifdef NO_UTF8_ACCOUNT_CONV
    return LookupAccountSidA(pSystemNameUTF8,
        Sid, pNameUTF8, pNameSize,
        pReferencedDomainNameUTF8, pReferencedDomainNameUTF8Size,
        peUse);
#else
    if ((Sid == NULL) ||
        (pNameUTF8 == NULL) ||
        (pNameSize == NULL) ||
        (pReferencedDomainNameUTF8 == NULL) ||
        (pReferencedDomainNameUTF8Size == NULL) ||
        (peUse == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    wchar_t *systemNameW;
    wchar_t *nameW;
    wchar_t *referencedDomainNameW;

    if (pSystemNameUTF8) {
        DWORD wide_len = (DWORD)strlen(pSystemNameUTF8)+1;

        systemNameW = (wchar_t *)_alloca(wide_len * sizeof(wchar_t));

        if (MultiByteToWideChar(CP_UTF8,
            0,
            pSystemNameUTF8,
            -1,
            systemNameW,
            wide_len) == 0) {
            if (GetLastError() == ERROR_SUCCESS) {
                SetLastError(ERROR_INVALID_DATA);
            }
            return FALSE;
        }
    }
    else {
        systemNameW = NULL;
    }

    nameW = (wchar_t *)_alloca(((size_t)*pNameSize+1) * sizeof(wchar_t));
    referencedDomainNameW =
        (wchar_t *)_alloca(((size_t)*pReferencedDomainNameUTF8Size+1) *
            sizeof(wchar_t));

    DWORD nameSizeW = *pNameSize;
    DWORD referencedDomainNameSizeW =
        *pReferencedDomainNameUTF8Size;

    if (!LookupAccountSidW(
        systemNameW,
        Sid,
        nameW,
        &nameSizeW,
        referencedDomainNameW,
        &referencedDomainNameSizeW,
        peUse))
    {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            /* Assume that each |wchar_t| needs a maximum of 5 bytes */
            *pNameSize = nameSizeW * MAX_UTF8_BYTES_PER_WCHAR_T;
            *pReferencedDomainNameUTF8Size =
                referencedDomainNameSizeW * MAX_UTF8_BYTES_PER_WCHAR_T;
        }
        return FALSE;
    }

    int required_name_utf8_bytes = WideCharToMultiByte(CP_UTF8,
        0,
        nameW,
        nameSizeW+1,
        NULL,
        0,
        NULL,
        NULL);
    if (required_name_utf8_bytes == 0) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }

    int required_domain_utf8_bytes = WideCharToMultiByte(CP_UTF8,
        0,
        referencedDomainNameW,
        referencedDomainNameSizeW+1,
        NULL,
        0,
        NULL,
        NULL);
    if (required_domain_utf8_bytes == 0) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }

    if ((*pNameSize < (DWORD)required_name_utf8_bytes) ||
        (*pReferencedDomainNameUTF8Size < (DWORD)required_domain_utf8_bytes)) {
        *pNameSize = (DWORD)required_name_utf8_bytes;
        *pReferencedDomainNameUTF8Size = (DWORD)required_domain_utf8_bytes;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    int bytes_written_name = WideCharToMultiByte(CP_UTF8,
        0,
        nameW,
        nameSizeW+1,
        pNameUTF8,
        *pNameSize,
        NULL,
        NULL);
    if (bytes_written_name == 0) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }

    int bytes_written_domain = WideCharToMultiByte(CP_UTF8,
        0,
        referencedDomainNameW,
        referencedDomainNameSizeW+1,
        pReferencedDomainNameUTF8,
        *pReferencedDomainNameUTF8Size,
        NULL,
        NULL);
    if (bytes_written_domain == 0) {
        if (GetLastError() == ERROR_SUCCESS) {
            SetLastError(ERROR_INVALID_DATA);
        }
        return FALSE;
    }

    *pReferencedDomainNameUTF8Size = (DWORD)bytes_written_domain-1;
    *pNameSize = (DWORD)bytes_written_name-1;

    return TRUE;
#endif /* NO_UTF8_ACCOUNT_CONV */
}


BOOL lookupprincipalnameutf8(
    const char *restrict pSystemNameUTF8,
    const char *restrict pAccountNameUTF8,
    PSID restrict pSid,
    LPDWORD restrict pSidSize,
    PSID_NAME_USE restrict peUse)
{
    if ((pAccountNameUTF8 == NULL) || (pSidSize == 0) || (peUse == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    EASSERT_MSG(IS_PRINCIPAL_NAME(pAccountNameUTF8),
        ("pAccountNameUTF8='%s' is not a principal\n", pAccountNameUTF8));

    char searchName[512];
    const char* atSign = strchr(pAccountNameUTF8, '@');

    if (atSign) {
        int userLen = (int)(atSign - pAccountNameUTF8);

        (void)snprintf(searchName, sizeof(searchName), "%s\\%.*s", atSign + 1, userLen, pAccountNameUTF8);
    } else {
        (void)snprintf(searchName, sizeof(searchName), "%s", pAccountNameUTF8);
    }

    char refDomain[256];
    DWORD cchRefDomain = sizeof(refDomain);

    return lookupaccountnameutf8(
        pSystemNameUTF8,
        searchName,
        pSid,
        pSidSize,
        refDomain,
        &cchRefDomain,
        peUse
    );
}


BOOL lookupprincipalsidutf8(
    const char *restrict pSystemNameUTF8,
    PSID restrict Sid,
    char *restrict pNameUTF8,
    LPDWORD restrict pNameSize,
    PSID_NAME_USE restrict peUse)
{
    if ((Sid == NULL) || (pNameSize == NULL) || (peUse == NULL)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    char name[256];
    char domain[256];
    DWORD cchName = sizeof(name);
    DWORD cchDomain = sizeof(domain);

    if (!lookupaccountsidutf8(pSystemNameUTF8, Sid, name, &cchName, domain, &cchDomain, peUse)) {
        return FALSE;
    }

    DWORD requiredSize = cchName + cchDomain + 2;

    if ((pNameUTF8 == NULL) || (*pNameSize < requiredSize)) {
        *pNameSize = requiredSize;
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    int written = snprintf(pNameUTF8, (size_t)*pNameSize, "%s@%s", name, domain);

    if (written < 0) {
        return FALSE;
    }

    *pNameSize = (DWORD)written;
    return TRUE;
}
