
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

#ifndef __NFS41_DAEMON_SID_H
#define __NFS41_DAEMON_SID_H 1

#include "nfs41_build_features.h"
#include "nfs41_daemon.h"
#include <stdbool.h>
#include <Lmcons.h> /* for |UNLEN| and |GNLEN| */

typedef struct _sidcache sidcache;

extern sidcache user_sidcache;
extern sidcache group_sidcache;

/* Maximum number of bytes required to store one |wchar_t| as UTF-8 */
#define MAX_UTF8_BYTES_PER_WCHAR_T (5)

/*
 * |UNLEN|+|GNLEN| count in codepage characters, but since we store
 * our user and group names as UTF-8 we need buffer sizes which can
 * hold the maximum length in UTF-8
 */
#define UTF8_UNLEN (UNLEN*MAX_UTF8_BYTES_PER_WCHAR_T)
#define UTF8_GNLEN (GNLEN*MAX_UTF8_BYTES_PER_WCHAR_T)


/*
 * DECLARE_SID_BUFFER - declare a buffer for a SID value
 * Note that buffers with SID values must be 16byte aligned
 * on Windows 10/32bit, othewise the kernel might return
 * |ERROR_NOACCESS|(=998) - "Invalid access to memory location".
 */
#ifdef _MSC_BUILD
/* Visual Studio */
#define DECLARE_SID_BUFFER(varname) \
    __declspec(align(16)) char (varname)[MAX_SID_BUFFER_SIZE]
#else
/* clang */
#define DECLARE_SID_BUFFER(varname) \
    char (varname)[MAX_SID_BUFFER_SIZE] __attribute__((aligned(16)))
#endif /* _MSC_BUILD */


/* prototypes */
int create_unknownsid(WELL_KNOWN_SID_TYPE type, PSID *sid, DWORD *sid_len);
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID
bool unixuser_sid2uid(PSID psid, uid_t *puid);
bool unixgroup_sid2gid(PSID psid, gid_t *pgid);
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */
void sidcache_init(void);
void sidcache_add(sidcache *cache, const char* win32name, PSID value);
void sidcache_addwithalias(sidcache *cache, const char *win32name, const char *aliasname, PSID value);
PSID *sidcache_getcached_byname(sidcache *cache, const char *win32name);
bool sidcache_getcached_bysid(sidcache *cache, PSID sid, char *out_win32name);

int map_nfs4servername_2_sid(nfs41_daemon_globals *nfs41dg, int query, DWORD *sid_len, PSID *sid, LPCSTR name);

/* UTF-8 version of |LookupAccountNameA()| */
BOOL lookupaccountnameutf8(
    const char *restrict pSystemNameUTF8,
    const char *restrict pAccountNameUTF8,
    PSID restrict pSid,
    LPDWORD restrict pSidSize,
    char *restrict pReferencedDomainNameUTF8,
    LPDWORD restrict pReferencedDomainNameUTF8size,
    PSID_NAME_USE restrict peUse);
/* UTF-8 version of |LookupAccountSidA()| */
BOOL lookupaccountsidutf8(
    const char *restrict pSystemNameUTF8,
    PSID restrict Sid,
    char *restrict pNameUTF8,
    LPDWORD restrict pNameSize,
    char *restrict pReferencedDomainNameUTF8,
    LPDWORD restrict pReferencedDomainNameSize,
    PSID_NAME_USE restrict peUse);

#endif /* !__NFS41_DAEMON_SID_H */
