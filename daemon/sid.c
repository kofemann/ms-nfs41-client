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

//#define DEBUG_ACLS
#define ACLLVL 2 /* dprintf level for acl logging */


int create_unknownsid(WELL_KNOWN_SID_TYPE type, PSID *sid, DWORD *sid_len)
{
    int status;
    *sid_len = 0;
    *sid = NULL;

    status = CreateWellKnownSid(type, NULL, *sid, sid_len);
    DPRINTF(ACLLVL,
        ("create_unknownsid: CreateWellKnownSid(type=%d) returned %d "
        "GetLastError %d sid len %d needed\n", (int)type, status,
        GetLastError(), *sid_len));
    if (status) {
        status = ERROR_INTERNAL_ERROR;
        goto err;
    }
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER)
        goto err;

    *sid = malloc(*sid_len);
    if (*sid == NULL) {
        status = ERROR_INSUFFICIENT_BUFFER;
        goto err;
    }
    status = CreateWellKnownSid(type, NULL, *sid, sid_len);
    if (status)
        return ERROR_SUCCESS;
    free(*sid);
    *sid = NULL;
    status = GetLastError();
err:
    eprintf("create_unknownsid: CreateWellKnownSid(type=%d) failed with %d\n",
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


/* fixme: should be in sys/nfs41_build_features.h */
#define USE_SID_CACHE 1


#ifdef USE_SID_CACHE
#define SIDCACHE_SIZE 20
#define SIDCACHE_TTL 600

typedef struct _sidcache_entry
{
    char    name[128]; /* must fit something like "user@domain" */
    PSID    sid;
    DWORD   sid_len;
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


void sidcache_init(void)
{
    DPRINTF(1, ("SID cache init\n"));
    InitializeCriticalSection(&user_sidcache.lock);
}

/* copy SID |value| into cache */
void sidcache_add(sidcache *cache, const char* name, PSID value)
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
            free(e->sid);
            e->sid = NULL;
            e->name[0] = '\0';
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
    DWORD sid_len = GetLengthSid(value);
    PSID malloced_sid = malloc(sid_len);
    if (!malloced_sid)
        goto done;
    if (!CopySid(sid_len, malloced_sid, value)) {
        free(malloced_sid);
        goto done;
    }

    sidcache_entry *e = &cache->entries[freeEntryIndex];

    e->sid_len = sid_len;
    if (e->sid)
        free(e->sid);
    e->sid = malloced_sid;
    (void)strcpy_s(e->name, sizeof(e->name), name);
    e->timestamp = currentTimestamp;

    cache->cacheIndex = (cache->cacheIndex + 1) % SIDCACHE_SIZE;

done:
    LeaveCriticalSection(&cache->lock);
}

/* return |malloc()|'ed copy of SID from cache entry */
PSID *sidcache_getcached(sidcache *cache, const char *name)
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
            (!strcmp(e->name, name)) &&
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
#endif /* USE_SID_CACHE */


int map_nfs4servername_2_sid(nfs41_daemon_globals *nfs41dg, int query, DWORD *sid_len, PSID *sid, LPCSTR name)
{
    const char *orig_name = name;

    int status = ERROR_INTERNAL_ERROR;
    SID_NAME_USE sid_type;
    char name_buff[256+2];
    LPSTR tmp_buf = NULL;
    DWORD tmp = 0;
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    signed long user_uid = -1;
    signed long group_gid = -1;
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
    /* use our own idmapper script to map nfsv4 owner string to local Windows account */
    if (query & OWNER_SECURITY_INFORMATION) {
        uid_t udummy = -1;
        gid_t gdummy = -1;

#ifdef USE_SID_CACHE
        if (*sid = sidcache_getcached(&user_sidcache, name)) {
            *sid_len = GetLengthSid(*sid);
            DPRINTF(1, ("map_nfs4servername_2_sid: returning cached sid for '%s'\n", name));
            return 0;
        }
#endif /* USE_SID_CACHE */

#ifndef USE_SID_CACHE
        /* gisburn: fixme: We must cache this, or the performance impact will be devastating!! */
#endif /* !USE_SID_CACHE */
        if (!cygwin_getent_passwd(name, name_buff, &udummy, &gdummy)) {
            if (strcmp(name, name_buff)) {
                DPRINTF(1,
                    ("map_nfs4servername_2_sid: remap '%s' --> '%s'\n",
                    name,
                    name_buff));
                name = name_buff;
            }
        }
    }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

    status = LookupAccountNameA(NULL, name, NULL, sid_len, NULL, &tmp, &sid_type);
    DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,name='%s'): "
        "LookupAccountName returned %d "
        "GetLastError %d name len %d domain len %d\n",
        query, name, status, GetLastError(), *sid_len, tmp));
    if (status)
        return ERROR_INTERNAL_ERROR;

    status = GetLastError();
    switch(status) {
    case ERROR_INSUFFICIENT_BUFFER:
        *sid = malloc(*sid_len);
        if (*sid == NULL) {
            status = GetLastError();
            goto out;
        }
        tmp_buf = (LPSTR) malloc(tmp);
        if (tmp_buf == NULL)
            goto out_free_sid;
        status = LookupAccountNameA(NULL, name, *sid, sid_len, tmp_buf,
                                    &tmp, &sid_type);
        free(tmp_buf);
        if (!status) {
            eprintf("map_nfs4servername_2_sid(query=%x,name='%s'): LookupAccountName failed "
                    "with %d\n", query, name, GetLastError());
            goto out_free_sid;
        } else {
#ifdef DEBUG_ACLS
            LPSTR ssid = NULL;
            if (IsValidSid(*sid))
                if (ConvertSidToStringSidA(*sid, &ssid)) {
                    DPRINTF(1, ("map_nfs4servername_2_sid: sid_type = %d SID '%s'\n",
                        sid_type, ssid));
                }
                else {
                    DPRINTF(1, ("map_nfs4servername_2_sid: ConvertSidToStringSidA failed "
                        "with %d\n", GetLastError()));
                }
            else {
                DPRINTF(1, ("map_nfs4servername_2_sid: Invalid Sid ?\n"));
            }
            if (ssid)
                LocalFree(ssid);
#endif
        }
        status = ERROR_SUCCESS;
        break;
    case ERROR_NONE_MAPPED:
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
        DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,name='%s'): "
            "none mapped, "
            "trying Unix_User+/Unix_Group+ mapping\n",
            query, name));

        if ((user_uid == -1) && (query & OWNER_SECURITY_INFORMATION)) {
            uid_t map_uid = -1;
            gid_t gid_dummy = -1;

            if (nfs41_idmap_name_to_ids(
                nfs41dg->idmapper,
                name,
                &map_uid,
                &gid_dummy) == 0) {
                user_uid = map_uid;
            }
            else {
                DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,name='%s'): nfs41_idmap_name_to_ids() failed\n",
                    query, name));
                /* fixme: try harder here, "1234" should to to |atol()| */
            }
        }

        if ((group_gid == -1) && (query & GROUP_SECURITY_INFORMATION)) {
            gid_t map_gid = -1;

            if (nfs41_idmap_group_to_gid(
                nfs41dg->idmapper,
                name,
                &map_gid) == 0) {
                group_gid = map_gid;
            }
            else {
                DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,name='%s'): nfs41_idmap_group_to_gid() failed\n",
                    query, name));
                /* fixme: try harder here, "1234" should to to |atol()| */
            }
        }

        if (user_uid != -1) {
            if (allocate_unixuser_sid(user_uid, sid)) {
                DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,name='%s'): "
                    "allocate_unixuser_sid(uid=%ld) success\n",
                    query, name, user_uid));
                status = ERROR_SUCCESS;
                goto out;
            }

            status = GetLastError();
            DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,name='%s'): "
                "allocate_unixuser_sid(uid=%ld) failed, error=%d\n",
                query, name, user_uid, status));
            return status;
        }

        if (group_gid != -1) {
            if (allocate_unixgroup_sid(group_gid, sid)) {
                DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,name='%s'): "
                    "allocate_unixgroup_sid(gid=%ld) success\n",
                    query, name, group_gid));
                status = ERROR_SUCCESS;
                goto out;
            }

            status = GetLastError();
            DPRINTF(ACLLVL, ("map_nfs4servername_2_sid(query=%x,name='%s'): "
                "allocate_unixgroup_sid(gid=%ld) failed, error=%d\n",
                query, name, group_gid, status));
            return status;
        }
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

        DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,name='%s'): none mapped, "
            "using WinNullSid mapping\n",
            query, name));

        status = create_unknownsid(WinNullSid, sid, sid_len);
        if (status)
            goto out_free_sid;
        break;
    default:
        DPRINTF(1, ("map_nfs4servername_2_sid(query=%x,name='%s'): error %d not handled\n",
            query, name, GetLastError()));
        break;
    }
out:
#ifdef USE_SID_CACHE
    if (*sid) {
        /* fixme: No other flags in |query| must be set!! */
        if (query & OWNER_SECURITY_INFORMATION) {
            sidcache_add(&user_sidcache, orig_name, *sid);
        }
    }
#endif /* USE_SID_CACHE */

    return status;
out_free_sid:
    status = GetLastError();
    free(*sid);
    *sid = NULL;
    goto out;
}
