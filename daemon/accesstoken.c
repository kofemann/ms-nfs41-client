/*
 * NFSv4.1 client for Windows
 * Copyright (C) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
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

#include "nfs41_build_features.h"
#include "accesstoken.h"
#include "sid.h"
#include "daemon_debug.h"
#include "nfs41_daemon.h"
#include <Lmcons.h>

#ifndef _NFS41_DRIVER_BUILDFEATURES_
#error NFS41 build config not included
#endif

/*
 * Performance hack:
 * GETTOKINFO_EXTRA_BUFFER - extra space for more data
 * |GetTokenInformation()| for |TOKEN_USER|, |TOKEN_PRIMARY_GROUP|
 * and |TOKEN_GROUPS_AND_PRIVILEGES| always fails in Win10 with
 * |ERROR_INSUFFICIENT_BUFFER| if you just pass the |sizeof(TOKEN_*)|
 * value.
 * Instead of calling |GetTokenInformation()| with |NULL| arg to
 * obtain the size to allocate we just provide 8192 bytes of extra
 * space after the |TOKEN_*| size, and pray it is enough.
 */
#define GETTOKINFO_EXTRA_BUFFER (8192)

bool get_token_user_name(HANDLE tok, char *out_buffer)
{
    DWORD tokdatalen;
    PTOKEN_USER ptuser;
    PSID pusid;
    DWORD namesize = UNLEN+1;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_USER)+GETTOKINFO_EXTRA_BUFFER;
    ptuser = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenUser, ptuser,
        tokdatalen, &tokdatalen)) {
        eprintf("get_token_username: "
            "GetTokenInformation(tok=0x%p, TokenUser) failed, "
            "status=%d\n",
            (void *)tok, (int)GetLastError());
        return false;
    }

    pusid = ptuser->User.Sid;

#ifdef NFS41_DRIVER_SID_CACHE
    if (sidcache_getcached_bysid(&user_sidcache, pusid, out_buffer)) {
        return true;
    }
#endif /* NFS41_DRIVER_SID_CACHE */

    if (!LookupAccountSidA(NULL, pusid, out_buffer, &namesize,
        domainbuffer, &domainbuffer_size, &name_use)) {
        eprintf("get_token_user_name: "
            "LookupAccountSidA() failed, status=%d\n",
            (int)GetLastError());
        return false;
    }

#ifdef NFS41_DRIVER_SID_CACHE
    sidcache_add(&user_sidcache, out_buffer, pusid);
#endif /* NFS41_DRIVER_SID_CACHE */

    return true;
}

bool get_token_primarygroup_name(HANDLE tok, char *out_buffer)
{
    DWORD tokdatalen;
    PTOKEN_PRIMARY_GROUP ptpgroup;
    PSID pgsid;
    DWORD namesize = GNLEN+1;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_PRIMARY_GROUP)+GETTOKINFO_EXTRA_BUFFER;
    ptpgroup = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenPrimaryGroup, ptpgroup,
        tokdatalen, &tokdatalen)) {
        eprintf("get_token_primarygroup_name: "
            "GetTokenInformation(tok=0x%p, TokenPrimaryGroup) failed, "
            "status=%d\n",
            (void *)tok, (int)GetLastError());
        return false;
    }

    pgsid = ptpgroup->PrimaryGroup;

#ifdef NFS41_DRIVER_SID_CACHE
    if (sidcache_getcached_bysid(&group_sidcache, pgsid, out_buffer)) {
        return true;
    }
#endif /* NFS41_DRIVER_SID_CACHE */

    if (!LookupAccountSidA(NULL, pgsid, out_buffer, &namesize,
        domainbuffer, &domainbuffer_size, &name_use)) {
        eprintf("get_token_primarygroup_name: "
            "LookupAccountSidA() failed, status=%d\n",
            (int)GetLastError());
        return false;
    }

#ifdef NFS41_DRIVER_SID_CACHE
    sidcache_add(&group_sidcache, out_buffer, pgsid);
#endif /* NFS41_DRIVER_SID_CACHE */

    return true;
}

bool fill_auth_unix_aup_gids(HANDLE tok,
    gid_t *aup_gids, int *num_aup_gids)
{
    char group_names_buff[RPC_AUTHUNIX_AUP_MAX_NUM_GIDS*(GNLEN+1)];
    char *group_names[RPC_AUTHUNIX_AUP_MAX_NUM_GIDS];
    char *s;
    int i;
    int num_groups;

    /* fixme: This should be a function argument */
    extern nfs41_daemon_globals nfs41_dg;

    /*
     * VS2019 |_alloca()| cannot be used in a loop, so we use multiple
     * pointers into one buffer instead
     */
    for (s=group_names_buff,i=0 ; i < RPC_AUTHUNIX_AUP_MAX_NUM_GIDS ; i++) {
        group_names[i] = s;
        s += GNLEN+1;
    }

    if (!get_token_groups_names(tok,
        RPC_AUTHUNIX_AUP_MAX_NUM_GIDS, group_names, &num_groups)) {
        eprintf("fill_auth_unix_aup_gids: "
            "get_token_groups_names() failed\n");
        *num_aup_gids = 0;
        return false;
    }

    gid_t map_gid;
    *num_aup_gids = 0;

    for (i=0 ; i < num_groups ; i++) {
        if (nfs41_idmap_group_to_gid(
            nfs41_dg.idmapper,
            group_names[i],
            &map_gid) == 0) {
            aup_gids[(*num_aup_gids)++] = map_gid;
        }
        else {
            eprintf("fill_auth_unix_aup_gids: "
                "no group mapping for '%s'\n",
                group_names[i]);
        }
    }

    return true;
}

bool get_token_groups_names(HANDLE tok,
    int num_out_buffers, char *out_buffers[],
    int *out_buffers_count)
{
    DWORD tokdatalen;
    PTOKEN_GROUPS ptgroups;
    char namebuffer[GNLEN+1];
    DWORD namesize;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size;
    SID_NAME_USE name_use;
    bool retval = false;

    DPRINTF(1,
        ("--> get_token_groups_names"
        "(tok=0x%p,num_out_buffers=%d,out_buffers=0x%p)\n",
        (void *)tok, num_out_buffers, out_buffers));

    tokdatalen = sizeof(TOKEN_GROUPS)+GETTOKINFO_EXTRA_BUFFER;
    ptgroups = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenGroups, ptgroups,
        tokdatalen, &tokdatalen)) {
        DPRINTF(0, ("get_token_groups_names: "
            "GetTokenInformation(tok=0x%p, TokenGroups) failed, "
            "status=%d.\n",
            (void *)tok, (int)GetLastError()));
        retval = false;
        goto done;
    }

    DWORD i;
    int iob = 0; /* index in |out_buffers| */

    DPRINTF(1, ("get_token_groups_names: got %d groups\n",
            (int)ptgroups->GroupCount));

    for (i = 0 ; i < ptgroups->GroupCount ; i++) {
        if (!(ptgroups->Groups[i].Attributes & SE_GROUP_ENABLED)) {
            continue;
        }

        /*
         * Filter out groups which cannot be used as normal user or
         * group account names (e.g. cannot be mapped by the idmapper)
         */
        if (IsWellKnownSid(ptgroups->Groups[i].Sid, WinNullSid)) {
            DPRINTF(1, ("get_token_groups_names: rejecting WinNullSid\n"));
            continue;
        }
        if (IsWellKnownSid(ptgroups->Groups[i].Sid, WinWorldSid)) {
            DPRINTF(1, ("get_token_groups_names: rejecting WinWorldSid\n"));
            continue;
        }
        if (IsWellKnownSid(ptgroups->Groups[i].Sid, WinLogonIdsSid)) {
            DPRINTF(1, ("get_token_groups_names: rejecting WinLogonIdsSid\n"));
            continue;
        }

        namesize = sizeof(namebuffer)-1;
        domainbuffer_size = sizeof(domainbuffer)-1;

        if (!LookupAccountSidA(NULL, ptgroups->Groups[i].Sid,
            namebuffer, &namesize, domainbuffer, &domainbuffer_size, &name_use)) {
            DPRINTF(0, ("get_token_groups_names: "
                "LookupAccountSidA() failed, status=%d.\n",
                (int)GetLastError()));
            continue;
        }

        if (iob < num_out_buffers) {
            DPRINTF(1,
                ("get_token_groups_names: adding group='%s', domain='%s'\n",
                namebuffer, domainbuffer));
            (void)strcpy(out_buffers[iob], namebuffer);
            iob++;
        }
        else {
            DPRINTF(0,
                ("get_token_groups_names: "
                "buffer full, skip group='%s', domain='%s'\n",
                namebuffer, domainbuffer));
        }
    }

    *out_buffers_count = iob;
    retval = true;

done:
    if (retval) {
        /* success */
        DPRINTF(1,
            ("<-- get_token_groups_names"
            "(tok=0x%p,num_out_buffers=%d,out_buffers=0x%p,*out_buffers_count=%d), retval=%d\n",
            (void *)tok,
            num_out_buffers,
            out_buffers,
            *out_buffers_count,
            (int)retval));
    }
    else {
        /* failure */
        DPRINTF(1,
            ("<-- get_token_groups_names"
            "(tok=0x%p,num_out_buffers=%d,out_buffers=0x%p) failed, retval=%d\n",
            (void *)tok,
            num_out_buffers,
            out_buffers,
            (int)retval));
    }

    return retval;
}

bool get_token_authenticationid(HANDLE tok, LUID *out_authenticationid)
{
    DWORD tokdatalen;
    PTOKEN_GROUPS_AND_PRIVILEGES ptgp;

    tokdatalen = sizeof(TOKEN_GROUPS_AND_PRIVILEGES)+GETTOKINFO_EXTRA_BUFFER;
    ptgp = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenGroupsAndPrivileges, ptgp,
        tokdatalen, &tokdatalen)) {
        eprintf("get_token_authenticationid: "
            "GetTokenInformation(tok=0x%p, TokenGroupsAndPrivileges) failed, "
            "status=%d\n",
            (void *)tok, (int)GetLastError());
        return false;
    }

    *out_authenticationid = ptgp->AuthenticationId;

    return true;
}

bool set_token_privilege(HANDLE tok, const char *seprivname, bool enable_priv)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    bool res;

    if(!LookupPrivilegeValueA(NULL, seprivname, &luid)) {
        DPRINTF(1, ("set_token_privilege: "
            "LookupPrivilegeValue(seprivname='%s') failed, "
            "status=%d\n",
            seprivname,
            (int)GetLastError()));
        res = false;
        goto out;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable_priv?(SE_PRIVILEGE_ENABLED):0;

    if(!AdjustTokenPrivileges(tok,
        FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        NULL, NULL)) {
        DPRINTF(1, ("set_token_privilege: "
            "AdjustTokenPrivileges() for '%s' failed, status=%d\n",
            seprivname,
            (int)GetLastError()));
        res = false;
        goto out;
    }

    res = true;
out:
    DPRINTF(0,
        ("set_token_privilege(seprivname='%s',enable_priv=%d), res=%d\n",
        seprivname, (int)enable_priv, (int)res));

    return res;
}
