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
#include <strsafe.h>
#include <sddl.h>

#include "nfs41_build_features.h"
#include "aclutil.h"
#include "nfs41_daemon.h"
#include "daemon_debug.h"
#include "util.h"
#include "sid.h"

#define MAP_WIN32GENERIC2ACE4GENERIC 1
#define WORKAROUND_FOR_LINUX_NFSD_NOT_SETTING_ACE4_WRITE_ATTRIBUTES 1

#define ACE4_RW_NAMED_ATTRS \
    (ACE4_READ_NAMED_ATTRS|ACE4_WRITE_NAMED_ATTRS)

/* Local prototypes */
static void map_winace2nfs4aceflags(BYTE win_aceflags, uint32_t *nfs4_aceflags);
static void map_nfs4aceflags2winaceflags(uint32_t nfs4_aceflags, DWORD *win_aceflags);
static void map_winaccessmask2nfs4acemask(ACCESS_MASK win_mask,
    int file_type, bool nfs_namedattr_support, uint32_t *nfs4_mask);
static void map_nfs4acemask2winaccessmask(uint32_t nfs4_mask,
    int file_type, bool nfs_namedattr_support, ACCESS_MASK *win_mask);

void free_sids(PSID *sids, int count)
{
    int i;
    for(i = 0; i < count; i++)
        free(sids[i]);
    free(sids);
}

static
int check_4_special_nfs4_identifiers(const char *restrict who,
    PSID *restrict sid,
    DWORD *restrict sid_len,
    bool *restrict flag)
{
    int status = ERROR_SUCCESS;
    WELL_KNOWN_SID_TYPE type = 0;
    *flag = true;

    /*
     * Compare |who| against known constant strings defined in the
     * NFSv4.1 RFC.
     * Note that |ACE4_NOBODY| does not have a '@
     */
    if (strcmp(who, ACE4_OWNER) == 0)
        type = WinCreatorOwnerSid;
    else if (strcmp(who, ACE4_GROUP) == 0)
        type = WinCreatorGroupSid;
    else if (strcmp(who, ACE4_EVERYONE) == 0)
        type = WinWorldSid;
    else if (strcmp(who, ACE4_NOBODY) == 0)
        type = WinNullSid;
    else
        *flag = false;
    if (*flag)
        status = create_unknownsid(type, sid, sid_len);
    return status;
}

#ifdef NFS41_DRIVER_WS2022_HACKS
static
char *append_str_comma(
    OUT char *restrict str,
    IN const char *restrict append_str)
{
    if (append_str == NULL) {
        return str;
    }

    size_t str_len = str ? strlen(str) : 0;
    size_t append_len = strlen(append_str);
    size_t new_size = str_len + append_len + (str ? 2 : 1);

    char *new_str = realloc(str, new_size);
    if (!new_str) {
        return NULL;
    }

    char *dest = new_str + str_len;

    if (str) {
        *dest++ = ',';
    }

    (void)stpcpy(dest, append_str);

    return new_str;
}

static
char *get_account_from_sid(
    OUT char *restrict buf,
    IN WELL_KNOWN_SID_TYPE sid_type)
{
    BYTE sid_buffer[SECURITY_MAX_SID_SIZE];
    DWORD sid_size = sizeof(sid_buffer);
    PSID sid = (PSID)sid_buffer;

    if (!CreateWellKnownSid(sid_type, NULL, sid, &sid_size)) {
        return NULL;
    }

    SID_NAME_USE sid_use;
    DWORD assumed_buf_size = UTF8_PRINCIPALLEN;

    if (!lookupprincipalsidutf8(NULL, sid, buf, &assumed_buf_size, &sid_use)) {
        return NULL;
    }

    return buf;
}

char *build_well_known_localised_nfs_grouplist(struct idmap_context *context)
{
    /* fixme: This should be a function argument */
    extern nfs41_daemon_globals nfs41_dg;

    char *joined_str = NULL;
    char principal_buf[UTF8_PRINCIPALLEN+1];

    const WELL_KNOWN_SID_TYPE group_sids[] = {
        WinLocalSystemSid,
        WinBuiltinUsersSid,
        WinBuiltinAdministratorsSid,
        WinWorldSid,
        WinCreatorGroupSid,
        WinNullSid
    };

    const size_t num_sids = sizeof(group_sids) / sizeof(group_sids[0]);

    for (size_t i = 0; i < num_sids; i++) {
        char *acc = get_account_from_sid(principal_buf, group_sids[i]);

        if (acc == NULL)
            continue;

        idmapcache_entry *ie;
        ie = nfs41_idmap_group_lookup_by_win32name(context, acc);
        if (ie == NULL) {
            eprintf("build_well_known_localised_nfs_grouplist: "
                "Cannot map entry for acc='%s'\n", acc);
            continue;
        }

        char *temp = append_str_comma(joined_str, ie->nfsname.buf);

        if (temp != NULL)
            joined_str = temp;

        idmapcache_entry_refcount_dec(ie);
    }

    return joined_str;
}
#endif /* NFS41_DRIVER_WS2022_HACKS */

int convert_nfs4acl_2_dacl(
    IN OUT struct idmap_context *idmapper,
    IN nfsacl41 *restrict acl,
    IN int file_type,
    OUT PACL *dacl_out,
    OUT PSID **sids_out,
    IN bool nfs_namedattr_support)
{
    int status = ERROR_NOT_SUPPORTED;
    BOOL success;
    int size = 0;
    uint32_t nfs_i = 0, win_i = 0;
    DWORD sid_len;
    PSID *sids;
    PACL dacl;

    DPRINTF(ACLLVL2, ("--> convert_nfs4acl_2_dacl(acl=0x%p,"
        "file_type='%s'(=%d), nfs_namedattr_support=%d)\n",
        acl, map_nfs_ftype2str(file_type), file_type,
        (int)nfs_namedattr_support));

    bool *skip_aces = _alloca(acl->count * sizeof(bool));

    /*
     * We use |calloc()| here to get |NULL| pointer for unallocated
     * slots in case of error codepaths below...
     */
    sids = calloc(acl->count, sizeof(PSID));
    if (sids == NULL) {
        status = GetLastError();
        goto out;
    }
    for (nfs_i = win_i = 0; nfs_i < acl->count; nfs_i++) {
        nfsace4 *curr_nfsace = &acl->aces[nfs_i];

        skip_aces[nfs_i] = false;

        DPRINTF(ACLLVL2,
            ("convert_nfs4acl_2_dacl: for user='%s'\n",
            curr_nfsace->who));

#ifdef NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES
        /*
         * Skip "nobody" ACEs - Cygwin uses |WinNullSid| ACEs (mapped
         * to NFS user "nobody") to store special data.
         * We skip these here, because we cannot use them, as Linux nfsd
         * only supports POSIX ACLs translated to NFSv4 ACLs, which
         * corrupts the Cygwin data.
         */
        if ((strcmp(curr_nfsace->who, ACE4_NOBODY) == 0) ||
            ((strcmp(curr_nfsace->who, "65534") == 0))) {
            DPRINTF(ACLLVL3, ("Skipping 'nobody' ACE, "
                "win_i=%d nfs_i=%d\n", (int)win_i, (int)nfs_i));
            skip_aces[nfs_i] = true;
            continue;
        }
#endif /* NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES */

        bool is_special_identifier = false;
        status = check_4_special_nfs4_identifiers(curr_nfsace->who, &sids[win_i],
            &sid_len, &is_special_identifier);
        if (status) {
            free_sids(sids, win_i);
            goto out;
        }
        if (is_special_identifier)
            goto sid_mapped;

        bool isgroupacl =
            (curr_nfsace->aceflag & ACE4_IDENTIFIER_GROUP)?true:false;
        bool checked_for_groups = false;

        if (isgroupacl == false) {
            if ((strcmp(curr_nfsace->who, ACE4_EVERYONE) == 0) ||
                (strcmp(curr_nfsace->who, ACE4_GROUP) == 0)) {
                DPRINTF(ACLLVL1,
                    ("convert_nfs4acl_2_dacl: "
                    "force isgroupacl=true for for user='%s'\n",
                    curr_nfsace->who));
                isgroupacl = true;
                checked_for_groups = true;
            }
            else if (strcmp(curr_nfsace->who, ACE4_OWNER) == 0) {
                checked_for_groups = true;
            }
        }

#ifdef NFS41_DRIVER_WS2022_HACKS
        if (checked_for_groups == false) {
            /*
             * Check whether any of the localised account names should be
             * treated like a group
             */
            if (strstr(idmapper->well_known_lgrouplist,
                curr_nfsace->who) != NULL) {
                DPRINTF(ACLLVL1,
                    ("convert_nfs4acl_2_dacl: "
                    "force isgroupacl=true for well_known account='%s'\n",
                    curr_nfsace->who));
                isgroupacl = true;
            }
        }
#endif /* NFS41_DRIVER_WS2022_HACKS */

        if (isgroupacl) {
            DPRINTF(ACLLVL2,
                ("convert_nfs4acl_2_dacl: aces[%d].who='%s': "
                "Setting group flag\n",
                nfs_i, curr_nfsace->who));
        }

        status = map_nfs4servername_2_sid(idmapper,
            (isgroupacl?GROUP_SECURITY_INFORMATION:OWNER_SECURITY_INFORMATION),
            &sid_len, &sids[win_i], curr_nfsace->who);
        if (status != ERROR_SUCCESS) {
            free_sids(sids, win_i);
            goto out;
        }

sid_mapped:
        size += sid_len - sizeof(DWORD);

        win_i++;
    }
    size += sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE)*win_i);
    size = align4(size); /* align size on |DWORD| boundry */
    dacl = malloc(size);
    if (dacl == NULL)
        goto out_free_sids;

    success = InitializeAcl(dacl, size, ACL_REVISION);
    if (!success) {
        eprintf("convert_nfs4acl_2_dacl: InitializeAcl() failed with status=%d\n", status);
        goto out_free_dacl;
    }

    ACCESS_MASK mask;
    DWORD win_aceflags;

    for (nfs_i = win_i = 0; nfs_i < acl->count; nfs_i++) {
        nfsace4 *curr_nfsace = &acl->aces[nfs_i];

        if (skip_aces[nfs_i])
            continue;

        map_nfs4aceflags2winaceflags(curr_nfsace->aceflag,
            &win_aceflags);
        map_nfs4acemask2winaccessmask(curr_nfsace->acemask,
            file_type, nfs_namedattr_support, &mask);

        if (DPRINTF_LEVEL_ENABLED(ACLLVL1)) {
            dprintf_out("nfs2win: acl->aces[%d].who='%s': "
                "acetype='%s', "
                "nfs_acemask=0x%lx, win_mask=0x%lx, "
                "win_aceflags=0x%lx\n",
                nfs_i, curr_nfsace->who,
                map_nfs_acetype2str(curr_nfsace->acetype),
                (long)curr_nfsace->acemask,
                (long)mask,
                (long)win_aceflags);

            print_nfs_access_mask(curr_nfsace->who,
                curr_nfsace->acemask);
            print_windows_access_mask(curr_nfsace->who, mask);
        }

        if (curr_nfsace->acetype == ACE4_ACCESS_ALLOWED_ACE_TYPE) {
            success = AddAccessAllowedAceEx(dacl, ACL_REVISION,
                win_aceflags, mask, sids[win_i]);
            if (!success) {
                eprintf("convert_nfs4acl_2_dacl: "
                    "AddAccessAllowedAceEx"
                    "(dacl=0x%p,win_aceflags=0x%x,mask=0x%x,who='%s') "
                    "failed with status=%d\n",
                    dacl, (int)win_aceflags, (int)mask,
                    curr_nfsace->who, (int)GetLastError());
                status = ERROR_INTERNAL_ERROR;
                goto out_free_dacl;
            }
            status = ERROR_SUCCESS;
        } else if (curr_nfsace->acetype == ACE4_ACCESS_DENIED_ACE_TYPE) {
            success = AddAccessDeniedAceEx(dacl, ACL_REVISION,
                win_aceflags, mask, sids[win_i]);
            if (!success) {
                eprintf("convert_nfs4acl_2_dacl: "
                    "AddAccessDeniedAceEx"
                    "(dacl=0x%p,win_aceflags=0x%x,mask=0x%x,who='%s') "
                    "failed with status=%d\n",
                    dacl, (int)win_aceflags, (int)mask,
                    curr_nfsace->who, (int)GetLastError());
                status = ERROR_INTERNAL_ERROR;
                goto out_free_dacl;
            }
            status = ERROR_SUCCESS;
        } else {
            eprintf("convert_nfs4acl_2_dacl: unknown acetype %d\n",
                    curr_nfsace->acetype);
            status = ERROR_INTERNAL_ERROR;
            free(dacl);
            free_sids(sids, win_i);
            goto out;
        }

        win_i++;
    }

    status = ERROR_SUCCESS;
    *sids_out = sids;
    *dacl_out = dacl;
out:
    DPRINTF(ACLLVL2, ("<-- convert_nfs4acl_2_dacl("
        "acl=0x%p,file_type='%s'(=%d)) returning status=%d\n",
        acl, map_nfs_ftype2str(file_type), file_type, status));
    return status;
out_free_dacl:
    free(dacl);
out_free_sids:
    free_sids(sids, win_i);
    status = GetLastError();
    goto out;
}

static int is_well_known_sid(PSID sid, char *who, SID_NAME_USE *snu_out)
{
    const WELL_KNOWN_SID_TYPE test_types[] = {
        WinCreatorOwnerSid,
        WinCreatorGroupSid,
        WinNullSid,
        WinAnonymousSid,
        WinWorldSid,
        WinAuthenticatedUserSid,
        WinDialupSid,
        WinNetworkSid,
        WinBatchSid,
        WinInteractiveSid,
        WinNetworkServiceSid,
        WinLocalServiceSid,
        WinServiceSid
    };
    const size_t test_types_count = ARRAYSIZE(test_types);

    BOOL ismatch;
    size_t i;

#ifdef xxxDEBUG
    static bool once = true;

    if (once) {
        once = false;
        EASSERT(test_types_count == 14);
        /* Safeguards if someone tampers with the #defines for this */
        EASSERT(strlen(ACE4_OWNER) == ACE4_OWNER_LEN);
        EASSERT(strlen(ACE4_GROUP) == ACE4_GROUP_LEN);
        EASSERT(strlen(ACE4_NOBODY) == ACE4_NOBODY_LEN);
        EASSERT(strlen(ACE4_ANONYMOUS) == ACE4_ANONYMOUS_LEN);
        EASSERT(strlen(ACE4_EVERYONE) == ACE4_EVERYONE_LEN);
    }
#endif /* xxxDEBUG */

    for (i = 0; i < test_types_count ; i++) {
        WELL_KNOWN_SID_TYPE tt = test_types[i];

        ismatch = IsWellKnownSid(sid, tt);
        if (!ismatch) {
            continue;
        }

        DPRINTF(ACLLVL3, ("WELL_KNOWN_SID_TYPE=%d\n", (int)tt));
        switch(tt) {
            case WinCreatorOwnerSid:
                (void)memcpy(who, ACE4_OWNER, ACE4_OWNER_LEN+1);
                *snu_out = SidTypeUser;
                return TRUE;
            case WinCreatorGroupSid:
                (void)memcpy(who, ACE4_GROUP, ACE4_GROUP_LEN+1);
                *snu_out = SidTypeGroup;
                return TRUE;
            case WinNullSid:
                (void)memcpy(who, ACE4_NOBODY, ACE4_NOBODY_LEN+1);
                *snu_out = SidTypeUser;
                return TRUE;
            case WinAnonymousSid:
                (void)memcpy(who, ACE4_ANONYMOUS, ACE4_ANONYMOUS_LEN+1);
                return TRUE;
            case WinWorldSid:
                (void)memcpy(who, ACE4_EVERYONE, ACE4_EVERYONE_LEN+1);
                *snu_out = SidTypeGroup;
                return TRUE;
            case WinAuthenticatedUserSid:
                (void)memcpy(who, ACE4_AUTHENTICATED, ACE4_AUTHENTICATED_LEN+1);
                return TRUE;
            case WinDialupSid:
                (void)memcpy(who, ACE4_DIALUP, ACE4_DIALUP_LEN+1);
                return TRUE;
            case WinNetworkSid:
                (void)memcpy(who, ACE4_NETWORK, ACE4_NETWORK_LEN+1);
                return TRUE;
            case WinBatchSid:
                (void)memcpy(who, ACE4_BATCH, ACE4_BATCH_LEN+1);
                return TRUE;
            case WinInteractiveSid:
                (void)memcpy(who, ACE4_INTERACTIVE, ACE4_INTERACTIVE_LEN+1);
                return TRUE;
            case WinNetworkServiceSid:
            case WinLocalServiceSid:
            case WinServiceSid:
                (void)memcpy(who, ACE4_SERVICE, ACE4_SERVICE_LEN+1);
                return TRUE;
            default:
                eprintf("is_well_known_sid: unknown tt=%d\n", (int)tt);
                return FALSE;
        }
    }
    return FALSE;
}

static void map_winace2nfs4aceflags(BYTE win_aceflags, uint32_t *nfs4_aceflags)
{
    *nfs4_aceflags = 0;

    if (win_aceflags & OBJECT_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_FILE_INHERIT_ACE;
    if (win_aceflags & CONTAINER_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_DIRECTORY_INHERIT_ACE;
    if (win_aceflags & NO_PROPAGATE_INHERIT_ACE)
        *nfs4_aceflags |= ACE4_NO_PROPAGATE_INHERIT_ACE;
    if (win_aceflags & INHERIT_ONLY_ACE)
        *nfs4_aceflags |= ACE4_INHERIT_ONLY_ACE;
    if (win_aceflags & INHERITED_ACE)
        *nfs4_aceflags |= ACE4_INHERITED_ACE;
    DPRINTF(ACLLVL3,
        ("map_winace2nfs4aceflags: win_aceflags=0x%x nfs4_aceflags=0x%x\n",
        (int)win_aceflags, (int)*nfs4_aceflags));
}

static void map_nfs4aceflags2winaceflags(uint32_t nfs4_aceflags, DWORD *win_aceflags)
{
    *win_aceflags = 0;

    if (nfs4_aceflags & ACE4_FILE_INHERIT_ACE)
        *win_aceflags |= OBJECT_INHERIT_ACE;
    if (nfs4_aceflags & ACE4_DIRECTORY_INHERIT_ACE)
        *win_aceflags |= CONTAINER_INHERIT_ACE;
    if (nfs4_aceflags & ACE4_NO_PROPAGATE_INHERIT_ACE)
        *win_aceflags |= NO_PROPAGATE_INHERIT_ACE;
    if (nfs4_aceflags & ACE4_INHERIT_ONLY_ACE)
        *win_aceflags |= INHERIT_ONLY_ACE;
    if (nfs4_aceflags & ACE4_INHERITED_ACE)
        *win_aceflags |= INHERITED_ACE;
    DPRINTF(ACLLVL3,
        ("map_nfs4aceflags2winace: nfs4_aceflags=0x%x win_aceflags=0x%x\n",
        (int)nfs4_aceflags, (int)*win_aceflags));
}

static
void map_winaccessmask2nfs4acemask(ACCESS_MASK win_mask,
    int file_type, bool nfs_namedattr_support, uint32_t *nfs4_mask)
{
    *nfs4_mask = 0;

    /* check if any GENERIC bits set */
    if (win_mask & 0xf000000) {
        /* Filtered |ACE4_GENERIC_*| masks */
        uint32_t ace4_generic_read_filt = ACE4_GENERIC_READ;
        uint32_t ace4_generic_write_filt =  ACE4_GENERIC_WRITE;
        uint32_t ace4_generic_execute_filt = ACE4_GENERIC_EXECUTE;
        uint32_t ace4_all_file_filt = ACE4_ALL_FILE;
        uint32_t ace4_all_dir_filt = ACE4_ALL_DIR;

#ifdef MAP_WIN32GENERIC2ACE4GENERIC
        if (!nfs_namedattr_support) {
            /*
             * Filter out unsupported features for
             * |GENERIC_*| --> |ACE_*ATTR| conversion.
             * Do not filter out explicit individual flags below!
             */
            ace4_generic_read_filt &= ~ACE4_RW_NAMED_ATTRS;
            ace4_generic_write_filt &= ~ACE4_RW_NAMED_ATTRS;
            ace4_generic_execute_filt &= ~ACE4_RW_NAMED_ATTRS;
            ace4_all_file_filt &= ~ACE4_RW_NAMED_ATTRS;
            ace4_all_dir_filt &= ~ACE4_RW_NAMED_ATTRS;
        }
#endif /* MAP_WIN32GENERIC2ACE4GENERIC */

        if (win_mask & GENERIC_ALL) {
            if (file_type == NF4DIR)
                *nfs4_mask |= ace4_all_dir_filt;
            else
                *nfs4_mask |= ace4_all_file_filt;
        } else {
            if (win_mask & GENERIC_READ)
                *nfs4_mask |= ace4_generic_read_filt;
            if (win_mask & GENERIC_WRITE)
                *nfs4_mask |= ace4_generic_write_filt;
            if (win_mask & GENERIC_EXECUTE)
                *nfs4_mask |= ace4_generic_execute_filt;
        }
    }

    /* Individual flags */
    if (file_type == NF4DIR) {
        if (win_mask & FILE_LIST_DIRECTORY) {
            *nfs4_mask |= ACE4_LIST_DIRECTORY;
        }
        if (win_mask & FILE_ADD_FILE) {
            *nfs4_mask |= ACE4_ADD_FILE;
        }
        if (win_mask & FILE_ADD_SUBDIRECTORY) {
            *nfs4_mask |= ACE4_ADD_SUBDIRECTORY;
        }
        if (win_mask & FILE_DELETE_CHILD) {
            *nfs4_mask |= ACE4_DELETE_CHILD;
        }
        if (win_mask & FILE_TRAVERSE) {
            *nfs4_mask |= ACE4_EXECUTE;
        }
    }
    else {
        if (win_mask & FILE_READ_DATA) {
            *nfs4_mask |= ACE4_READ_DATA;
        }
        if (win_mask & FILE_WRITE_DATA) {
            *nfs4_mask |= ACE4_WRITE_DATA;
        }
        if (win_mask & FILE_APPEND_DATA) {
            *nfs4_mask |= ACE4_APPEND_DATA;
        }
        if (win_mask & FILE_EXECUTE) {
            *nfs4_mask |= ACE4_EXECUTE;
        }
        /*
         * gisburn: Why does Win10 set |FILE_DELETE_CHILD| for
         * plain files ?
         */
        if (win_mask & FILE_DELETE_CHILD) {
            *nfs4_mask |= ACE4_DELETE_CHILD;
        }
    }

    if (win_mask & FILE_READ_EA) {
        *nfs4_mask |= ACE4_READ_NAMED_ATTRS;
    }
    if (win_mask & FILE_WRITE_EA) {
        *nfs4_mask |= ACE4_WRITE_NAMED_ATTRS;
    }
    if (win_mask & FILE_READ_ATTRIBUTES) {
        *nfs4_mask |= ACE4_READ_ATTRIBUTES;
    }
    if (win_mask & FILE_WRITE_ATTRIBUTES) {
        *nfs4_mask |= ACE4_WRITE_ATTRIBUTES;
    }
    if (win_mask & READ_CONTROL) {
        *nfs4_mask |= ACE4_READ_ACL;
    }
    if (win_mask & WRITE_DAC) {
        *nfs4_mask |= ACE4_WRITE_ACL;
    }
    if (win_mask & WRITE_OWNER) {
        *nfs4_mask |= ACE4_WRITE_OWNER;
    }
    if (win_mask & SYNCHRONIZE) {
        *nfs4_mask |= ACE4_SYNCHRONIZE;
    }
    if (win_mask & DELETE) {
        *nfs4_mask |= ACE4_DELETE;
    }

#if 1
    /* DEBUG: Compare old and new code */
    DASSERT_MSG(0,
        ((long)*nfs4_mask == (long)(win_mask & 0x00ffffff)),
        ("map_winaccessmask2nfs4acemask: "
        "new code nfs4_mask=0x%lx, "
        "old code nfs4_mask=0x%lx\n",
        (long)*nfs4_mask, (long)(win_mask & 0x00ffffff)));
#endif
}

static
void map_nfs4acemask2winaccessmask(uint32_t nfs4_mask,
    int file_type, bool nfs_namedattr_support, ACCESS_MASK *win_mask)
{
    *win_mask = 0;

#ifdef MAP_WIN32GENERIC2ACE4GENERIC
    bool is_generic = false;

    /* Filtered |ACE4_GENERIC_*| masks */
    uint32_t ace4_generic_read_filt = ACE4_GENERIC_READ;
    uint32_t ace4_generic_write_filt =  ACE4_GENERIC_WRITE;
    uint32_t ace4_generic_execute_filt = ACE4_GENERIC_EXECUTE;
    uint32_t ace4_all_file_filt = ACE4_ALL_FILE;
    uint32_t ace4_all_dir_filt = ACE4_ALL_DIR;

    if (!nfs_namedattr_support) {
        /*
         * Filter out unsupported features for
         * |ACE_*ATTR| --> |GENERIC_*| conversion.
         * Do not filter out explicit individual flags below!
         */
        ace4_generic_read_filt &= ~ACE4_RW_NAMED_ATTRS;
        ace4_generic_write_filt &= ~ACE4_RW_NAMED_ATTRS;
        ace4_generic_execute_filt &= ~ACE4_RW_NAMED_ATTRS;
        ace4_all_file_filt &= ~ACE4_RW_NAMED_ATTRS;
        ace4_all_dir_filt &= ~ACE4_RW_NAMED_ATTRS;

#ifdef WORKAROUND_FOR_LINUX_NFSD_NOT_SETTING_ACE4_WRITE_ATTRIBUTES
        /*
         * BUG(?): Linux 6.6.32-RT32 does not return
         * |ACE4_WRITE_ATTRIBUTES| even when the attributes are
         * writeable.
         *
         * Since |ACE4_GENERIC_WRITE| includes the
         * |ACE4_WRITE_ATTRIBUTES| bit an attempt to set
         * |GENERIC_WRITE| will succeed, but we can never get all
         * the |ACE4_*| bits in |ACE4_GENERIC_WRITE| back when
         * reading the ACL, so without this workaround we could
         * never match |GENERIC_WRITE| when constructing the Win32
         * ACLs.
         *
         * Testcase:
         * ---- snip ----
         * $ ksh93 -c 'rm -f test1.txt
         * touch test1.txt
         * icacls test1.txt /grant "siegfried_wulsch:(GW)"
         * icacls test1.txt'
         * ---- snip ----
         * Second icacls should return "GW" for user "siegfried_wulsch".
         */
        ace4_generic_read_filt &= ~ACE4_WRITE_ATTRIBUTES;
        ace4_generic_write_filt &= ~ACE4_WRITE_ATTRIBUTES;
        ace4_generic_execute_filt &= ~ACE4_WRITE_ATTRIBUTES;
        ace4_all_file_filt &= ~ACE4_WRITE_ATTRIBUTES;
        ace4_all_dir_filt &= ~ACE4_WRITE_ATTRIBUTES;
#endif /* WORKAROUND_FOR_LINUX_NFSD_NOT_SETTING_ACE4_WRITE_ATTRIBUTES */
    }

    /*
     * Generic masks
     * (|ACE4_GENERIC_*| contain multiple bits)
     */
#define ACEMASK_TEST_MASK(value, mask) (((value)&(mask)) == (mask))
    if (file_type == NF4DIR) {
        if (ACEMASK_TEST_MASK(nfs4_mask, ace4_all_dir_filt)) {
            *win_mask |= GENERIC_ALL;
            is_generic = true;
        }
    }
    else {
        if (ACEMASK_TEST_MASK(nfs4_mask, ace4_all_file_filt)) {
            *win_mask |= GENERIC_ALL;
            is_generic = true;
        }
    }

    if (!(*win_mask & GENERIC_ALL)) {
        if (ACEMASK_TEST_MASK(nfs4_mask, ace4_generic_read_filt)) {
            *win_mask |= GENERIC_READ;
            is_generic = true;
        }
        if (ACEMASK_TEST_MASK(nfs4_mask, ace4_generic_write_filt)) {
            *win_mask |= GENERIC_WRITE;
            is_generic = true;
        }
        if (ACEMASK_TEST_MASK(nfs4_mask, ace4_generic_execute_filt)) {
            *win_mask |= GENERIC_EXECUTE;
            is_generic = true;
        }
    }
#endif /* MAP_WIN32GENERIC2ACE4GENERIC */

    /* Individual flags */
    if (file_type == NF4DIR) {
        if (nfs4_mask & ACE4_LIST_DIRECTORY) {
            *win_mask |= FILE_LIST_DIRECTORY;
        }
        if (nfs4_mask & ACE4_ADD_FILE) {
            *win_mask |= FILE_ADD_FILE;
        }
        if (nfs4_mask & ACE4_ADD_SUBDIRECTORY) {
            *win_mask |= FILE_ADD_SUBDIRECTORY;
        }
        if (nfs4_mask & ACE4_DELETE_CHILD) {
            *win_mask |= FILE_DELETE_CHILD;
        }
        if (nfs4_mask & ACE4_EXECUTE) {
            *win_mask |= FILE_TRAVERSE;
        }
    }
    else {
        if (nfs4_mask & ACE4_READ_DATA) {
            *win_mask |= FILE_READ_DATA;
        }
        if (nfs4_mask & ACE4_WRITE_DATA) {
            *win_mask |= FILE_WRITE_DATA;
        }
        if (nfs4_mask & ACE4_APPEND_DATA) {
            *win_mask |= FILE_APPEND_DATA;
        }
        if (nfs4_mask & ACE4_EXECUTE) {
            *win_mask |= FILE_EXECUTE;
        }
    }

    if (nfs4_mask & ACE4_READ_NAMED_ATTRS) {
        *win_mask |= FILE_READ_EA;
    }
    if (nfs4_mask & ACE4_WRITE_NAMED_ATTRS) {
        *win_mask |= FILE_WRITE_EA;
    }
    if (nfs4_mask & ACE4_READ_ATTRIBUTES) {
        *win_mask |= FILE_READ_ATTRIBUTES;
    }
    if (nfs4_mask & ACE4_WRITE_ATTRIBUTES) {
        *win_mask |= FILE_WRITE_ATTRIBUTES;
    }
    if (nfs4_mask & ACE4_READ_ACL) {
        *win_mask |= READ_CONTROL;
    }
    if (nfs4_mask & ACE4_WRITE_ACL) {
        *win_mask |= WRITE_DAC;
    }
    if (nfs4_mask & ACE4_WRITE_OWNER) {
        *win_mask |= WRITE_OWNER;
    }
    if (nfs4_mask & ACE4_SYNCHRONIZE) {
        *win_mask |= SYNCHRONIZE;
    }
    if (nfs4_mask & ACE4_DELETE) {
        *win_mask |= DELETE;
    }

#if 1
    /* DEBUG: Compare old and new code */
#ifdef MAP_WIN32GENERIC2ACE4GENERIC
    if (!is_generic)
#endif /* MAP_WIN32GENERIC2ACE4GENERIC */
    {
        DASSERT_MSG(0,
            ((long)*win_mask == (long)(nfs4_mask /*& 0x00ffffff*/)),
            ("#### map_nfs4acemask2winaccessmask: "
            "new code win_mask=0x%lx, "
            "old code win_mask=0x%lx\n",
            (long)*win_mask, (long)(nfs4_mask /*& 0x00ffffff*/)));
    }
#endif
}

int map_sid2nfs4ace_who(
    IN OUT struct idmap_context *idmapper,
    IN PSID sid,
    IN PSID owner_sid,
    IN PSID group_sid,
    IN bool nfs_namedattr_support,
    OUT char *who_out,
    IN const char *domain,
    OUT SID_NAME_USE *sid_type_out)
{
    int status;
    BOOL success;
    SID_NAME_USE sid_type = 0;
    /* |who_buf| needs space for user+domain */
    char who_buf[UTF8_PRINCIPALLEN+1];
    DWORD who_size = sizeof(who_buf);
    LPSTR sidstr = NULL;

    /* fixme: This should be a function argument */
    extern nfs41_daemon_globals nfs41_dg;

    DPRINTF(ACLLVL2, ("--> map_sid2nfs4ace_who("
        "sid=0x%p,owner_sid=0x%p, group_sid=0x%p)\n",
        sid, owner_sid, group_sid));

    if (DPRINTF_LEVEL_ENABLED(ACLLVL2)) {
        print_sid("sid", sid);
        print_sid("owner_sid", owner_sid);
        print_sid("group_sid", group_sid);
    }

    status = ERROR_SUCCESS;

    if (nfs_namedattr_support == false) {
        /*
         * for ace mapping, we want to map owner's sid into "owner@"
         * but for set_owner attribute we want to map owner into a user name
         * same applies to group
         */
        if (owner_sid) {
            if (EqualSid(sid, owner_sid)) {
                DPRINTF(ACLLVL2, ("this is owner's sid\n"));
                (void)memcpy(who_out, ACE4_OWNER, ACE4_OWNER_LEN+1);
                sid_type = SidTypeUser;
                status = ERROR_SUCCESS;
                goto out;
            }
        }
        if (group_sid) {
            if (EqualSid(sid, group_sid)) {
                DPRINTF(ACLLVL2, ("this is group's sid\n"));
                (void)memcpy(who_out, ACE4_GROUP, ACE4_GROUP_LEN+1);
                sid_type = SidTypeGroup;
                status = ERROR_SUCCESS;
                goto out;
            }
        }
    }

    success = is_well_known_sid(sid, who_out, &sid_type);
    if (success) {
        if (!strncmp(who_out, ACE4_NOBODY, ACE4_NOBODY_LEN)) {
            who_size = (DWORD)ACE4_NOBODY_LEN;
            goto add_domain;
        }

        /* fixme: What about |sid_type| ? */
        status = ERROR_SUCCESS;
        goto out;
    }

    if (!ConvertSidToStringSidA(sid, &sidstr)) {
        status = GetLastError();
        eprintf("map_sid2nfs4ace_who: ConvertSidToStringSidA() "
            "failed, error=%d\n", status);
        goto out;
    }

    success = lookupprincipalsidutf8(NULL, sid, who_buf, &who_size, &sid_type);

    if (success) {
        DPRINTF(ACLLVL2, ("map_sid2nfs4ace_who: "
            "LookupAccountSid(sidtostr(sid)='%s', who_buf='%s', "
            "who_size=%d) "
            "returned success\n",
            sidstr, who_buf, who_size));
        idmapcache_entry *ie;

#ifdef NFS41_DRIVER_WS2022_HACKS
        if (sid_type == SidTypeWellKnownGroup) {
            /* FIXME: This does not handle Win32 localised account names */
            if (strncmp(who_buf, "SYSTEM@", 7) == 0) {
                DPRINTF(1,
                    ("map_sid2nfs4ace_who: "
                    "who_buf='%s' SID_TYPE='SidTypeWellKnownGroup' mapped to 'SidTypeUser' for user\n",
                    who_buf));
                sid_type = SidTypeUser;
            }
        }
#endif /* NFS41_DRIVER_WS2022_HACKS */

        switch (sid_type) {
            case SidTypeUser:
                ie = nfs41_idmap_user_lookup_by_win32name(idmapper, who_buf);
                if (ie != NULL) {
                    if (idmapper->config.use_numeric_uidgid) {
                        (void)_ltoa(ie->nfsid, who_out, 10);
                        who_size = (DWORD)strlen(who_out);
                    }
                    else {
                        strmemcpy(who_out, ie->nfsname.buf, ie->nfsname.len);
                        who_size = (DWORD)ie->nfsname.len;
                    }

                    status = ERROR_SUCCESS;

                    DPRINTF(ACLLVL1, ("map_sid2nfs4ace_who: "
                        "win32name='%s' mapped to user '%s'\n",
                        who_buf, who_out));
                    idmapcache_entry_refcount_dec(ie);
                    goto out;
                }
                else {
                    DPRINTF(0,
                        ("map_sid2nfs4ace_who: "
                        "nfs41_idmap_user_lookup_by_win32name(who_buf='%s') failed\n",
                        who_buf));
                    status = ERROR_NOT_FOUND; /* FIXME: We need a better error code */
                    goto out;
                }
                break;
            case SidTypeGroup:
            case SidTypeAlias: /* Treat |SidTypeAlias| as (local) group */
                ie = nfs41_idmap_group_lookup_by_win32name(idmapper, who_buf);
                if (ie != NULL) {
                    if (idmapper->config.use_numeric_uidgid) {
                        (void)_ltoa(ie->nfsid, who_out, 10);
                        who_size = (DWORD)strlen(who_out);
                    }
                    else {
                        strmemcpy(who_out, ie->nfsname.buf, ie->nfsname.len);
                        who_size = (DWORD)ie->nfsname.len;
                    }

                    status = ERROR_SUCCESS;

                    DPRINTF(ACLLVL1, ("map_sid2nfs4ace_who: "
                        "win32name='%s' mapped to group '%s'\n",
                        who_buf, who_out));
                    idmapcache_entry_refcount_dec(ie);
                    goto out;
                }
                else {
                    DPRINTF(0,
                        ("map_sid2nfs4ace_who: "
                        "nfs41_idmap_group_lookup_by_win32name(who_buf='%s') failed\n",
                        who_buf));
                    status = ERROR_NOT_FOUND; /* FIXME: We need a better error code */
                    goto out;
                }
                break;
            default:
                DPRINTF(0,
                    ("map_sid2nfs4ace_who: "
                    "ERROR: Unsupported sid_type=%d for who_buf='%s'\n",
                    (int)sid_type, who_buf));
                status = ERROR_NOT_FOUND; /* FIXME: We need a better error code */
                goto out;
                break;
        }

        /* NOTREACHED */
    }
    else {
        status = GetLastError();

        DPRINTF(ACLLVL2, ("map_sid2nfs4ace_who: "
            "LookupAccountSid(sidtostr(sid)='%s', who_size=%d "
            "returned failure, status=%d\n",
            sidstr, who_size, status));

        /*
         * No SID to local account mapping. Can happen for some system
         * SIDs, and Unix_User+<uid> or Unix_Group+<gid> SIDs
         */
        switch (status) {
            /*
             * This happens for Unix_User+<uid> or Unix_Group+<gid>
             * SIDs
             */
            case ERROR_NONE_MAPPED:
                /*
                 * This can happen for two reasons:
                 * 1. Someone copied a file from a NFS(v3) filesystem,
                 * and Cygwin generated an Unix_User+<uid> or
                 * Unix_Group+<gid> SID for the source file, which
                 * tools like Cygwin cp(1) just copy.
                 * 2. We have an uid/gid for which we do not have
                 * a user-/group-name mapped.
                 */
#ifdef NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID

                uid_t unixuser_uid = ~0U;
                gid_t unixgroup_gid = ~0U;

                if (unixuser_sid2uid(sid, &unixuser_uid)) {
                    idmapcache_entry *ie;

                    ie = nfs41_idmap_user_lookup_by_localid(idmapper,
                        unixuser_uid);
                    if (ie != NULL) {
                        strmemcpy(who_out, ie->nfsname.buf, ie->nfsname.len);
                        who_size = (DWORD)ie->nfsname.len;
                        sid_type = SidTypeUser;
                        status = ERROR_SUCCESS;

                        DPRINTF(ACLLVL1, ("map_sid2nfs4ace_who: "
                            "Unix_User+%d SID "
                            "mapped to user '%s'\n",
                            unixuser_uid, who_out));
                        idmapcache_entry_refcount_dec(ie);
                        goto out;
                    }

                    eprintf("map_sid2nfs4ace_who: "
                        "unixuser_sid2uid(sid='%s',unixuser_uid=%d) "
                        "returned no mapping.\n",
                        sidstr, (int)unixuser_uid);
                    goto err_none_mapped;
                }

                if (unixgroup_sid2gid(sid, &unixgroup_gid)) {
                    idmapcache_entry *ie;

                    ie = nfs41_idmap_group_lookup_by_localid(idmapper,
                        unixgroup_gid);
                    if (ie != NULL) {
                        strmemcpy(who_out, ie->nfsname.buf, ie->nfsname.len);
                        who_size = (DWORD)ie->nfsname.len;
                        sid_type = SidTypeGroup;
                        status = ERROR_SUCCESS;

                        DPRINTF(ACLLVL1, ("map_sid2nfs4ace_who: "
                            "Unix_Group+%d SID "
                            "mapped to group '%s'\n",
                            unixgroup_gid, who_out));
                        idmapcache_entry_refcount_dec(ie);
                        goto out;
                    }

                    eprintf("map_sid2nfs4ace_who: "
                        "unixgroup_sid2gid(sid='%s',unixgroup_gid=%d) "
                        "returned no mapping.\n",
                        sidstr, (int)unixgroup_gid);
                    goto err_none_mapped;
                }

                eprintf("map_sid2nfs4ace_who: lookupprincipalsidutf8() "
                    "returned ERROR_NONE_MAPPED+no "
                    "Unix_@(User|Group)+ mapping for sidstr='%s'\n",
                    sidstr);
err_none_mapped:
                status = ERROR_NONE_MAPPED;
#else
                DPRINTF(ACLLVL2,
                    ("map_sid2nfs4ace_who: lookupprincipalsidutf8() "
                    "returned ERROR_NONE_MAPPED for sidstr='%s'\n",
                    sidstr));
                goto out;
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

            /* Catch other cases */
            case ERROR_NO_SUCH_USER:
            case ERROR_NO_SUCH_GROUP:
                eprintf("map_sid2nfs4ace_who: lookupprincipalsidutf8() "
                    "returned ERROR_NO_SUCH_@(USER|GROUP) for "
                    "sidstr='%s'\n",
                    sidstr);
                goto out;
            default:
                eprintf("map_sid2nfs4ace_who: Internal error, "
                    "lookupprincipalsidutf8() returned unexpected ERROR_%d "
                    "for sidstr='%s'\n",
                    status, sidstr);
                status = ERROR_INTERNAL_ERROR;
                goto out;
        }
    }

    /* NOTREACHED */

add_domain:
    /*
     * Complain if we attempt to add a domain suffix to an UID/GID
     * value
     */
    EASSERT(!isdigit(who_out[0]));

    char *wp;
    char *at_s;

    at_s = strchr(who_out, '@');
    if (at_s != NULL) {
        /* Override domain */
        wp = at_s + 1;
    }
    else {
        /* Append domain */
        wp = mempcpy(who_out+who_size, "@", sizeof(char));
    }

    (void)memcpy(wp, domain, strlen(domain)+1);

out:
    if (status != ERROR_SUCCESS) {
        DPRINTF(ACLLVL2,
            ("<-- map_sid2nfs4ace_who() returns status=%d\n", status));
    }
    else {
        DPRINTF(ACLLVL2,
            ("<-- map_sid2nfs4ace_who(who_out='%s', sid_type='%s'/%d) "
            "returns status=%d\n",
            who_out,
            map_SID_NAME_USE2str(sid_type), sid_type,
            status));
        if (sid_type_out) {
            *sid_type_out = sid_type;
        }
    }
    if (sidstr)
        LocalFree(sidstr);
    return status;
}

int map_dacl_2_nfs4acl(
    IN OUT struct idmap_context *idmapper,
    IN PACL acl,
    IN PSID sid,
    IN PSID gsid,
    OUT nfsacl41 *nfs4_acl,
    IN int file_type,
    IN bool nfs_namedattr_support,
    IN const char *domain)
{
    int status;
    BOOL success;
    if (acl == NULL) {
        DPRINTF(ACLLVL2, ("this is a NULL dacl: all access to an object\n"));
        nfs4_acl->count = 1;
        nfs4_acl->aces = calloc(1, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        (void)memcpy(nfs4_acl->aces->who, ACE4_EVERYONE, ACE4_EVERYONE_LEN+1);
        nfs4_acl->aces->acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;

        if (file_type == NF4DIR) {
            uint32_t ace4_all_dir_filt = ACE4_ALL_DIR;
#ifdef MAP_WIN32GENERIC2ACE4GENERIC
            /* Filter out unsupported features */
            if (!nfs_namedattr_support) {
                ace4_all_dir_filt &= ~ACE4_RW_NAMED_ATTRS;
            }
#endif /* MAP_WIN32GENERIC2ACE4GENERIC */
            nfs4_acl->aces->acemask = ace4_all_dir_filt;
        }
        else {
            uint32_t ace4_all_file_filt = ACE4_ALL_FILE;
#ifdef MAP_WIN32GENERIC2ACE4GENERIC
            /* Filter out unsupported features */
            if (!nfs_namedattr_support) {
                ace4_all_file_filt &= ~ACE4_RW_NAMED_ATTRS;
            }
#endif /* MAP_WIN32GENERIC2ACE4GENERIC */
            nfs4_acl->aces->acemask = ace4_all_file_filt;
        }
        nfs4_acl->aces->aceflag = 0;
    } else {
        int win_i, nfs_i;
        PACE_HEADER ace;
        PBYTE tmp_pointer;
        SID_NAME_USE who_sid_type = 0;
        ACCESS_MASK win_mask;

        DPRINTF(ACLLVL2, ("NON-NULL dacl with %d ACEs\n", acl->AceCount));
        if (DPRINTF_LEVEL_ENABLED(ACLLVL3)) {
            print_hexbuf_no_asci("ACL\n",
                (const unsigned char *)acl, acl->AclSize);
        }

        nfs4_acl->aces = calloc(acl->AceCount, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        for (win_i = nfs_i = 0; win_i < acl->AceCount; win_i++) {
            nfsace4 *curr_nfsace = &nfs4_acl->aces[nfs_i];
            PSID ace_sid;

            success = GetAce(acl, win_i, (LPVOID *)&ace);
            if (!success) {
                status = GetLastError();
                eprintf("map_dacl_2_nfs4acl: "
                    "GetAce() failed with status=%d\n", status);
                goto out_free;
            }
            tmp_pointer = (PBYTE)ace;
            if (DPRINTF_LEVEL_ENABLED(ACLLVL3)) {
                print_hexbuf_no_asci("ACE\n",
                    (const unsigned char *)ace, ace->AceSize);
            }
            DPRINTF(ACLLVL3, ("ACE TYPE: 0x%x\n", ace->AceType));
            if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
                curr_nfsace->acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
            else if (ace->AceType == ACCESS_DENIED_ACE_TYPE)
                curr_nfsace->acetype = ACE4_ACCESS_DENIED_ACE_TYPE;
            else {
                eprintf("map_dacl_2_nfs4acl: unsupported ACE type %d\n",
                    ace->AceType);
                status = ERROR_NOT_SUPPORTED;
                goto out_free;
            }

            tmp_pointer += sizeof(ACCESS_MASK) + sizeof(ACE_HEADER);
            ace_sid = tmp_pointer;

#ifdef NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES
            if (IsWellKnownSid(ace_sid, WinNullSid)) {
                /*
                 * Skip ACEs with SID==|WinNullSid|
                 *
                 * Cygwin generates artificial ACEs with SID user
                 * |WinNullSid| to encode permission information
                 * (see |CYG_ACE_ISBITS_TO_POSIX()| in
                 * Cygwin newlib-cygwin/winsup/cygwin/sec/acl.cc
                 *
                 * This assumes that the filesystem which stores
                 * the ACL data leaves them 1:1 intact - which is
                 * not the case for the Linux NFSv4.1 server
                 * (tested with Linux 6.6.32), which transforms the
                 * NFSv4.1 ACLs into POSIX ACLs at setacl time,
                 * and the POSIX ACLs back to NFSv4 ACLs at getacl
                 * time.
                 * And this lossy transformation screws-up Cygwin
                 * completly.
                 * The best we can do for now is to skip such
                 * ACEs, as we have no way to detect whether
                 * the NFS server supports full NFSv4 ACLs, or
                 * only POSIX ACLs disguised as NFSv4 ACLs.
                 */
                DPRINTF(ACLLVL3, ("Skipping WinNullSid ACE, "
                    "win_i=%d nfs_i=%d\n", (int)win_i, (int)nfs_i));
                continue;
            }
#endif /* NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES */

            status = map_sid2nfs4ace_who(idmapper, ace_sid,
                sid, gsid, nfs_namedattr_support,
                curr_nfsace->who, domain, &who_sid_type);
            if (status != ERROR_SUCCESS)
                goto out_free;

            win_mask = *(PACCESS_MASK)(ace + 1);

            map_winace2nfs4aceflags(ace->AceFlags,
                &curr_nfsace->aceflag);
            map_winaccessmask2nfs4acemask(win_mask,
                file_type, nfs_namedattr_support,
                &curr_nfsace->acemask);

            /*
             * Clear |ACE4_INHERITED_ACE|
             *
             * (See RFC 8884 Section-6.2.1.4.1:
             * ACE4_INHERITED_ACE
             * Indicates that this ACE is inherited from a parent
             * directory. A server that supports automatic inheritance
             * will place this flag on any ACEs inherited from the
             * parent directory when creating a new object.
             * Client applications will use this to perform automatic
             * inheritance. Clients and servers MUST clear this bit in
             * the acl attribute; it may only be used in the dacl and
             * sacl attributes.
             * ---- snip ----
             * )
             *
             * If we do not clear this bit Linux 6.6.32-RT32 nfsd
             * will reject setting ACLs |NFS4ERR_ATTRNOTSUPP| via
             * icacls(1win) if the parent directory has inheritance
             * ACLs.
             */
            if (curr_nfsace->aceflag & ACE4_INHERITED_ACE) {
                curr_nfsace->aceflag &= ~ACE4_INHERITED_ACE;
                DPRINTF(ACLLVL3, ("clearning ACE4_INHERITED_ACE\n"));
            }

            /*
             * Treat |SidTypeAlias| as (local) group
             *
             * It seems that |LookupAccount*A()| will always return
             * |SidTypeAlias| for local groups created with
             * $ net localgroup cygwingrp1 /add #
             *
             * References:
             * - https://stackoverflow.com/questions/39373188/lookupaccountnamew-returns-sidtypealias-but-expected-sidtypegroup
             */
            if ((who_sid_type == SidTypeGroup) ||
                (who_sid_type == SidTypeAlias)) {
                DPRINTF(ACLLVL3, ("map_dacl_2_nfs4acl: who_sid_type='%s': "
                    "aces[%d].who='%s': "
                    "setting group flag\n",
                    map_SID_NAME_USE2str(who_sid_type),
                    nfs_i, curr_nfsace->who));
                curr_nfsace->aceflag |= ACE4_IDENTIFIER_GROUP;
            }

            if (DPRINTF_LEVEL_ENABLED(ACLLVL1)) {
                dprintf_out("win2nfs: nfs4_acl->aces[%d]=(who='%s', "
                    "acetype='%s', "
                    "aceflag='%s'/0x%lx, "
                    "acemask='%s'/0x%lx(=win_mask=0x%lx)), "
                    "who_sid_type='%s', "
                    "win_i=%d\n",
                    nfs_i,
                    curr_nfsace->who,
                    map_nfs_acetype2str(curr_nfsace->acetype),
                    nfs_aceflag2shortname(curr_nfsace->aceflag),
                    curr_nfsace->aceflag,
                    nfs_mask2shortname(curr_nfsace->acemask),
                    (long)curr_nfsace->acemask,
                    (long)win_mask,
                    map_SID_NAME_USE2str(who_sid_type),
                    (int)win_i);
                if (DPRINTF_LEVEL_ENABLED(ACLLVL2)) {
                    print_windows_access_mask(curr_nfsace->who,
                        win_mask);
                    print_nfs_access_mask(curr_nfsace->who,
                        curr_nfsace->acemask);
                }
            }

            nfs_i++;
        }

        nfs4_acl->count = nfs_i;
    }

    status = ERROR_SUCCESS;
out:
    return status;

out_free:
    free(nfs4_acl->aces);
    nfs4_acl->aces = NULL;
    goto out;
}
