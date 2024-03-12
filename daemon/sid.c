/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
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
#include <time.h>
#include <strsafe.h>
#include <sddl.h>
#include <Lmcons.h>

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


int create_unknownsid(WELL_KNOWN_SID_TYPE type, PSID *sid, DWORD *sid_len)
{
    int status;
    int lasterr;

    *sid_len = SECURITY_MAX_SID_SIZE+1;
    *sid = malloc(*sid_len);
    if (*sid == NULL) {
        status = ERROR_INSUFFICIENT_BUFFER;
        goto err;
    }

    status = CreateWellKnownSid(type, NULL, *sid, sid_len);
    lasterr = GetLastError();
    if (status) {
        *sid_len = GetLengthSid(*sid);

        DPRINTF(ACLLVL,
            ("create_unknownsid(type=%d): CreateWellKnownSid() "
            "returned %d GetLastError=%d *sid_len=%d\n",
            (int)type, status, lasterr, (int)*sid_len));

        return ERROR_SUCCESS;
    }

    status = lasterr;
    free(*sid);
err:
    *sid = NULL;
    *sid_len = 0;
    eprintf("create_unknownsid(type=%d): "
        "CreateWellKnownSid failed with %d\n",
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
BOOL allocate_unixuser_sid(unsigned long uid, PSID *pSid)
{
    PSID sid = NULL;
    PSID malloced_sid = NULL;
    DWORD sid_len;

    if (AllocateAndInitializeSid(&sid_id_auth, 2, 1, (DWORD)uid,
        0, 0, 0, 0, 0, 0, &sid)) {
        sid_len = GetLengthSid(sid);

        malloced_sid = malloc(sid_len);

        if (malloced_sid) {
            /*
             * |AllocateAndInitializeSid()| has an own memory
             * allocator, but we need the sid in memory from
             * |malloc()|
             */
            if (CopySid(sid_len, malloced_sid, sid)) {
                FreeSid(sid);
                *pSid = malloced_sid;
                DPRINTF(ACLLVL, ("allocate_unixuser_sid(): Allocated "
                    "Unix_User+%lu: success, len=%ld\n",
                    uid, (long)sid_len));
                return TRUE;
            }
        }
    }

    FreeSid(sid);
    free(malloced_sid);
    DPRINTF(ACLLVL, ("allocate_unixuser_sid(): Failed to allocate "
        "SID for Unix_User+%lu: error code %d\n",
        uid, GetLastError()));
    return FALSE;
}

static
BOOL allocate_unixgroup_sid(unsigned long gid, PSID *pSid)
{
    PSID sid = NULL;
    PSID malloced_sid = NULL;
    DWORD sid_len;

    if (AllocateAndInitializeSid(&sid_id_auth, 2, 2, (DWORD)gid,
        0, 0, 0, 0, 0, 0, &sid)) {
        sid_len = GetLengthSid(sid);

        malloced_sid = malloc(sid_len);

        if (malloced_sid) {
            /*
             * |AllocateAndInitializeSid()| has an own memory
             * allocator, but we need the sid in memory from
             * |malloc()|
             */
            if (CopySid(sid_len, malloced_sid, sid)) {
                FreeSid(sid);
                *pSid = malloced_sid;
                DPRINTF(ACLLVL, ("allocate_unixgroup_sid(): Allocated "
                    "Unix_Group+%lu: success, len=%ld\n",
                    gid, (long)sid_len));
                return TRUE;
            }
        }
    }

    FreeSid(sid);
    free(malloced_sid);
    DPRINTF(ACLLVL, ("allocate_unixgroup_sid(): Failed to allocate "
        "SID for Unix_Group+%lu: error code %d\n",
        gid, GetLastError()));
    return FALSE;
}
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */


#ifdef NFS41_DRIVER_SID_CACHE
#define SIDCACHE_SIZE 20
#define SIDCACHE_TTL 600

typedef struct _sidcache_entry
{
#define SIDCACHE_ENTRY_NAME_SIZE (UNLEN + 1)
    char    win32name[SIDCACHE_ENTRY_NAME_SIZE]; /* must fit something like "user@domain" */
    PSID    sid;
    DWORD   sid_len;
    char    sid_buffer[SECURITY_MAX_SID_SIZE+1];
    time_t  timestamp;
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
    DPRINTF(1, ("SID cache init\n"));
    InitializeCriticalSection(&user_sidcache.lock);
    InitializeCriticalSection(&group_sidcache.lock);
}

/* copy SID |value| into cache */
void sidcache_add(sidcache *cache, const char* win32name, PSID value)
{
    int i;
    ssize_t freeEntryIndex;
    time_t currentTimestamp;

    EnterCriticalSection(&cache->lock);
    currentTimestamp = time(NULL);

    /* purge obsolete entries */
    for (i = 0; i < SIDCACHE_SIZE; i++) {
        sidcache_entry *e = &cache->entries[i];

        if ((e->sid != NULL) &&
            (e->timestamp < (currentTimestamp - SIDCACHE_TTL))) {
            e->sid = NULL;
            e->win32name[0] = '\0';
            e->sid_len = 0;
        }
    }

    /* Find the oldest valid cache entry */
    freeEntryIndex = -1;
    for (i = 0; i < SIDCACHE_SIZE; i++) {
        if (cache->entries[i].sid == NULL) {
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
    EASSERT(sid_len <= SECURITY_MAX_SID_SIZE);
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
PSID *sidcache_getcached(sidcache *cache, const char *win32name)
{
    int i;
    time_t currentTimestamp;
    sidcache_entry *e;
    PSID *ret_sid = NULL;

    EnterCriticalSection(&cache->lock);
    currentTimestamp = time(NULL);

    for (i = 0; i < SIDCACHE_SIZE; i++) {
        e = &cache->entries[i];

        if ((e->sid != NULL) &&
            (!strcmp(e->win32name, win32name)) &&
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
#endif /* NFS41_DRIVER_SID_CACHE */


int map_nfs4servername_2_sid(nfs41_daemon_globals *nfs41dg, int query, DWORD *sid_len, PSID *sid, LPCSTR nfsname)
{
    const char *orig_nfsname = nfsname;

    int status = ERROR_INTERNAL_ERROR;
    SID_NAME_USE sid_type = 0;
    char nfsname_buff[UNLEN+1];
    char domain_buff[UNLEN+1];
    DWORD domain_len = 0;
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    signed long user_uid = -1;
    signed long group_gid = -1;
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

    DPRINTF(ACLLVL, ("--> map_nfs4servername_2_sid(query=%x,nfsname='%s')\n",
        query, nfsname));

#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    /* use our own idmapper script to map nfsv4 owner string to local Windows account */
    if (query & OWNER_SECURITY_INFORMATION) {
        uid_t udummy = -1;
        gid_t gdummy = -1;

#ifdef NFS41_DRIVER_SID_CACHE
        if (*sid = sidcache_getcached(&user_sidcache, nfsname)) {
            *sid_len = GetLengthSid(*sid);
            DPRINTF(1, ("map_nfs4servername_2_sid: returning cached sid for user '%s'\n", nfsname));
            status = 0;
            goto out;
        }
#endif /* NFS41_DRIVER_SID_CACHE */

#ifndef NFS41_DRIVER_SID_CACHE
        /* gisburn: fixme: We must cache this, or the performance impact will be devastating!! */
#endif /* !NFS41_DRIVER_SID_CACHE */
        if (!cygwin_getent_passwd(nfsname, nfsname_buff, &udummy, &gdummy)) {
            if (strcmp(nfsname, nfsname_buff)) {
                DPRINTF(1,
                    ("map_nfs4servername_2_sid: remap user '%s' --> '%s'\n",
                    nfsname,
                    nfsname_buff));
                nfsname = nfsname_buff;
            }
        }
    }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */


#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    /* use our own idmapper script to map nfsv4 owner string to local Windows account */
    if (query & GROUP_SECURITY_INFORMATION) {
        gid_t gdummy = -1;

#ifdef NFS41_DRIVER_SID_CACHE
        if (*sid = sidcache_getcached(&group_sidcache, nfsname)) {
            *sid_len = GetLengthSid(*sid);
            DPRINTF(1, ("map_nfs4servername_2_sid: returning cached sid for group '%s'\n", nfsname));
            status = 0;
            goto out;
        }
#endif /* NFS41_DRIVER_SID_CACHE */

#ifndef NFS41_DRIVER_SID_CACHE
        /* gisburn: fixme: We must cache this, or the performance impact will be devastating!! */
#endif /* !NFS41_DRIVER_SID_CACHE */
        if (!cygwin_getent_group(nfsname, nfsname_buff, &gdummy)) {
            if (strcmp(nfsname, nfsname_buff)) {
                DPRINTF(1,
                    ("map_nfs4servername_2_sid: remap group '%s' --> '%s'\n",
                    nfsname,
                    nfsname_buff));
                nfsname = nfsname_buff;
            }
        }
    }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

    *sid = malloc(SECURITY_MAX_SID_SIZE+1);
    if (*sid == NULL) {
        status = GetLastError();
        goto out;
    }
    *sid_len = SECURITY_MAX_SID_SIZE;
    domain_len = sizeof(domain_buff);

    status = LookupAccountNameA(NULL, nfsname, *sid, sid_len,
        domain_buff, &domain_len, &sid_type);

    if (status) {
        /* |LookupAccountNameA()| success */

        DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
            "LookupAccountNameA() returned status=%d "
            "GetLastError=%d *sid_len=%d domain_buff='%s' domain_len=%d\n",
            query, nfsname, status, GetLastError(), *sid_len, domain_buff,
            domain_len));

        status = 0;
        *sid_len = GetLengthSid(*sid);
        goto out_cache;
    }

    /* |LookupAccountNameA()| failed... */
    DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
        "LookupAccountNameA() returned status=%d "
        "GetLastError=%d\n",
        query, nfsname, status, GetLastError()));

    status = GetLastError();
    switch(status) {
    case ERROR_INSUFFICIENT_BUFFER:
        /*
         * This should never happen, as |SECURITY_MAX_SID_SIZE| is
         * the largest possible SID buffer size for Windows
         */
        eprintf("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                "LookupAccountName failed with "
                "ERROR_INSUFFICIENT_BUFFER\n", query, nfsname);

        status = ERROR_INTERNAL_ERROR;
        goto out;
        break;
    case ERROR_NONE_MAPPED:
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
        DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
            "none mapped, "
            "trying Unix_User+/Unix_Group+ mapping\n",
            query, nfsname));

        if ((user_uid == -1) && (query & OWNER_SECURITY_INFORMATION)) {
            uid_t map_uid = -1;
            gid_t gid_dummy = -1;

            if (nfs41_idmap_name_to_ids(
                nfs41dg->idmapper,
                nfsname,
                &map_uid,
                &gid_dummy) == 0) {
                user_uid = map_uid;
            }
            else {
                DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,name='%s'): nfs41_idmap_name_to_ids() failed\n",
                    query, nfsname));
                /* fixme: try harder here, "1234" should to to |atol()| */
            }
        }

        if ((group_gid == -1) && (query & GROUP_SECURITY_INFORMATION)) {
            gid_t map_gid = -1;

            if (nfs41_idmap_group_to_gid(
                nfs41dg->idmapper,
                nfsname,
                &map_gid) == 0) {
                group_gid = map_gid;
            }
            else {
                DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): nfs41_idmap_group_to_gid() failed\n",
                    query, nfsname));
                /* fixme: try harder here, "1234" should to to |atol()| */
            }
        }

        if (user_uid != -1) {
            if (allocate_unixuser_sid(user_uid, sid)) {
                DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                    "allocate_unixuser_sid(uid=%ld) success\n",
                    query, nfsname, user_uid));
                status = ERROR_SUCCESS;
                sid_type = SidTypeUser;
                goto out_cache;
            }

            status = GetLastError();
            DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                "allocate_unixuser_sid(uid=%ld) failed, error=%d\n",
                query, nfsname, user_uid, status));
            goto out;
        }

        if (group_gid != -1) {
            if (allocate_unixgroup_sid(group_gid, sid)) {
                DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                    "allocate_unixgroup_sid(gid=%ld) success\n",
                    query, nfsname, group_gid));
                status = ERROR_SUCCESS;
                sid_type = SidTypeGroup;
                goto out_cache;
            }

            status = GetLastError();
            DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                "allocate_unixgroup_sid(gid=%ld) failed, error=%d\n",
                query, nfsname, group_gid, status));
            goto out;
        }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

        DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): none mapped, "
            "using WinNullSid mapping\n",
            query, nfsname));

        status = create_unknownsid(WinNullSid, sid, sid_len);
        if (status)
            goto out_free_sid;
        break;
    default:
        DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): error %d not handled\n",
            query, nfsname, GetLastError()));
        break;
    }
out_cache:
#ifdef NFS41_DRIVER_SID_CACHE
    if ((status == 0) && *sid) {
        if ((query & GROUP_SECURITY_INFORMATION) &&
            (sid_type == SidTypeAlias)) {
            /*
             * Treat |SidTypeAlias| as (local) group
             *
             * It seems that |LookupAccountNameA()| will always return
             * |SidTypeAlias| for local groups created with
             * $ net localgroup cygwingrp1 /add #
             *
             * References:
             * - https://stackoverflow.com/questions/39373188/lookupaccountnamew-returns-sidtypealias-but-expected-sidtypegroup
             */
            DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                "SID_TYPE='SidTypeAlias' mapped to 'SidTypeGroup'\n",
                query, orig_nfsname, sid_type));
            sid_type = SidTypeGroup;
        }

        switch (sid_type) {
            case SidTypeUser:
                sidcache_add(&user_sidcache, orig_nfsname, *sid);
                break;
            case SidTypeGroup:
                sidcache_add(&group_sidcache, orig_nfsname, *sid);
                break;
            default:
                eprintf("map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                    "Unknown SID_TYPE=%d\n",
                    query, orig_nfsname, sid_type);
                break;
        }
    }
#endif /* NFS41_DRIVER_SID_CACHE */

out:
    if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
        if (status) {
            dprintf_out("<-- map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                "status=%d\n", query, nfsname, status);
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

            dprintf_out("<-- map_nfs4servername_2_sid(query=%x,nfsname='%s'): "
                "status=%d sidstr='%s' *sid_len=%d\n",
                query, nfsname, status, sidstr, *sid_len);

            if (sidstr && (sidstr != errsidstrbuf))
                LocalFree(sidstr);
        }
    }

    return status;

out_free_sid:
    status = GetLastError();
    free(*sid);
    *sid = NULL;
    goto out;
}
