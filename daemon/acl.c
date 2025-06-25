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

#include <Windows.h>
#include <stdio.h>
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
#include "sid.h"

#define MAP_WIN32GENERIC2ACE4GENERIC 1
#define WORKAROUND_FOR_LINUX_NFSD_NOT_SETTING_ACE4_WRITE_ATTRIBUTES 1

/* |DPRINTF()| levels for acl logging */
#define ACLLVL1 1
#define ACLLVL2 2
#define ACLLVL3 3

#define ACE4_RW_NAMED_ATTRS \
    (ACE4_READ_NAMED_ATTRS|ACE4_WRITE_NAMED_ATTRS)

/* Local prototypes */
static void map_winace2nfs4aceflags(BYTE win_aceflags, uint32_t *nfs4_aceflags);
static void map_nfs4aceflags2winaceflags(uint32_t nfs4_aceflags, DWORD *win_aceflags);
static void map_winaccessmask2nfs4acemask(ACCESS_MASK win_mask,
    int file_type, bool named_attr_support, uint32_t *nfs4_mask);
static void map_nfs4acemask2winaccessmask(uint32_t nfs4_mask,
    int file_type, bool named_attr_support, ACCESS_MASK *win_mask);

static int parse_getacl(unsigned char *buffer, uint32_t length,
                        nfs41_upcall *upcall)
{
    int status;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;

    DPRINTF(1, ("parsing NFS41_SYSOP_ACL_QUERY: info_class=%d\n", args->query));
out:
    return status;
}

static void convert_nfs4name_2_user_domain(LPSTR nfs4name,
                                           LPSTR *domain)
{
    LPSTR p = nfs4name;
    for(; p[0] != '\0'; p++) {
        if (p[0] == '@') {
            p[0] = '\0';

            *domain = &p[1];
            break;
        }
    }
}

static void free_sids(PSID *sids, int count)
{
    int i;
    for(i = 0; i < count; i++)
        free(sids[i]);
    free(sids);
}

static int check_4_special_identifiers(char *who, PSID *sid, DWORD *sid_len, 
                                       BOOLEAN *flag)
{
    int status = ERROR_SUCCESS;
    WELL_KNOWN_SID_TYPE type = 0;
    *flag = TRUE;
    if (!strncmp(who, ACE4_OWNER, strlen(ACE4_OWNER)-1))
        type = WinCreatorOwnerSid;
#ifdef NFS41_DRIVER_WS2022_HACKS
    else if (!strncmp(who, "CREATOR OWNER@", strlen("CREATOR OWNER@")-1))
        type = WinCreatorOwnerSid;
#endif /* NFS41_DRIVER_WS2022_HACKS */
    else if (!strncmp(who, ACE4_GROUP, strlen(ACE4_GROUP)-1))
        type = WinCreatorGroupSid;
    else if (!strncmp(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)-1))
        type = WinWorldSid;
#ifdef NFS41_DRIVER_WS2022_HACKS
    else if (!strncmp(who, "Everyone@", strlen("Everyone@")-1))
        type = WinWorldSid;
#endif /* NFS41_DRIVER_WS2022_HACKS */
    else if (!strncmp(who, ACE4_NOBODY, strlen(ACE4_NOBODY)))
        type = WinNullSid;
#ifdef NFS41_DRIVER_WS2022_HACKS
    else if (!strncmp(who, "NULL SID", strlen("NULL SID")))
        type = WinNullSid;
#endif /* NFS41_DRIVER_WS2022_HACKS */
    else
        *flag = FALSE;
    if (*flag)
        status = create_unknownsid(type, sid, sid_len);
    return status;
}

static int convert_nfs4acl_2_dacl(nfs41_daemon_globals *nfs41dg,
    nfsacl41 *acl, int file_type, PACL *dacl_out, PSID **sids_out,
    bool named_attr_support)
{
    int status = ERROR_NOT_SUPPORTED, size = 0;
    uint32_t nfs_i = 0, win_i = 0;
    DWORD sid_len;
    PSID *sids;
    PACL dacl;
    LPSTR domain = NULL;
    BOOLEAN flag;

    DPRINTF(ACLLVL2, ("--> convert_nfs4acl_2_dacl(acl=0x%p,"
        "file_type='%s'(=%d), named_attr_support=%d)\n",
        acl, map_nfs_ftype2str(file_type), file_type,
        (int)named_attr_support));

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

        convert_nfs4name_2_user_domain(curr_nfsace->who, &domain);
        DPRINTF(ACLLVL2, ("convert_nfs4acl_2_dacl: for user='%s' domain='%s'\n",
                curr_nfsace->who, domain?domain:"<null>"));

        EASSERT_MSG(!isdigit(curr_nfsace->who[0]),
            ("convert_nfs4acl_2_dacl: aces[%d]->who='%s' uses numeric id",
            (int)nfs_i, curr_nfsace->who));

#ifdef NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES
        /*
         * Skip "nobody" ACEs - Cygwin uses |WinNullSid| ACEs (mapped
         * to NFS user "nobody") to store special data.
         * We skip these here, because we cannot use them, as Linux nfsd
         * only supports POSIX ACLs translated to NFSv4 ACLs, which
         * corrupts the Cygwin data.
         */
        if (!strcmp(curr_nfsace->who, ACE4_NOBODY)) {
            DPRINTF(ACLLVL3, ("Skipping 'nobody' ACE, "
                "win_i=%d nfs_i=%d\n", (int)win_i, (int)nfs_i));
            skip_aces[nfs_i] = true;
            continue;
        }
#endif /* NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES */

        status = check_4_special_identifiers(curr_nfsace->who, &sids[win_i],
                                             &sid_len, &flag);
        if (status) {
            free_sids(sids, win_i);
            goto out;
        }
        if (!flag) {
            bool isgroupacl = (curr_nfsace->aceflag & ACE4_IDENTIFIER_GROUP)?true:false;


#ifdef NFS41_DRIVER_WS2022_HACKS
            if ((isgroupacl == false) && domain &&
                (!strcmp(domain, "BUILTIN"))) {
                if ((!strcmp(curr_nfsace->who, "Users")) ||
                    (!strcmp(curr_nfsace->who, "Administrators"))) {
                    DPRINTF(1, ("convert_nfs4acl_2_dacl: "
                        "force isgroupacl=true for for user='%s'\n",
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

            status = map_nfs4servername_2_sid(nfs41dg,
                (isgroupacl?GROUP_SECURITY_INFORMATION:OWNER_SECURITY_INFORMATION),
                &sid_len, &sids[win_i], curr_nfsace->who);
            if (status) {
                free_sids(sids, win_i);
                goto out;
            }
        }
        size += sid_len - sizeof(DWORD);

        win_i++;
    }
    size += sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE)*win_i);
    size = align8(size); // align size on |DWORD| boundry
    dacl = malloc(size);
    if (dacl == NULL)
        goto out_free_sids;

    if (InitializeAcl(dacl, size, ACL_REVISION)) {
        ACCESS_MASK mask;
        DWORD win_aceflags;

        for (nfs_i = win_i = 0; nfs_i < acl->count; nfs_i++) {
            nfsace4 *curr_nfsace = &acl->aces[nfs_i];

            if (skip_aces[nfs_i])
                continue;

            map_nfs4aceflags2winaceflags(curr_nfsace->aceflag,
                &win_aceflags);
            map_nfs4acemask2winaccessmask(curr_nfsace->acemask,
                file_type, named_attr_support, &mask);

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
                status = AddAccessAllowedAceEx(dacl, ACL_REVISION,
                    win_aceflags, mask, sids[win_i]);
                if (!status) {
                    eprintf("convert_nfs4acl_2_dacl: "
                        "AddAccessAllowedAceEx(dacl=0x%p,win_aceflags=0x%x,mask=0x%x) failed "
                        "with status=%d\n",
                        dacl, (int)win_aceflags, (int)mask, status);
                    goto out_free_dacl;
                }
                else status = ERROR_SUCCESS;
            } else if (curr_nfsace->acetype == ACE4_ACCESS_DENIED_ACE_TYPE) {
                status = AddAccessDeniedAceEx(dacl, ACL_REVISION,
                    win_aceflags, mask, sids[win_i]);
                if (!status) {
                    eprintf("convert_nfs4acl_2_dacl: "
                        "AddAccessDeniedAceEx(dacl=0x%p,win_aceflags=0x%x,mask=0x%x) failed "
                        "with status=%d\n",
                        dacl, (int)win_aceflags, (int)mask, status);
                    goto out_free_dacl;
                }
                else status = ERROR_SUCCESS;
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
    } else {
        eprintf("convert_nfs4acl_2_dacl: InitializeAcl failed with %d\n", status);
        goto out_free_dacl;
    }
    status = ERROR_SUCCESS;
    *sids_out = sids;
    *dacl_out = dacl;
out:
    DPRINTF(ACLLVL2, ("<-- convert_nfs4acl_2_dacl("
        "acl=0x%p,file_type='%s'(=%d)) returning %d\n",
        acl, map_nfs_ftype2str(file_type), file_type, status));
    return status;
out_free_dacl:
    free(dacl);
out_free_sids:
    free_sids(sids, win_i);
    status = GetLastError();
    goto out;
}

static int handle_getacl(void *daemon_context, nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    nfs41_daemon_globals *nfs41dg = daemon_context;
    getacl_upcall_args *args = &upcall->args.getacl;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_file_info info;
    LPSTR domain = NULL;
    SECURITY_DESCRIPTOR sec_desc;
    PACL dacl = NULL;
    PSID *sids = NULL;
    PSID osid = NULL, gsid = NULL;
    DWORD sid_len;
    char owner[NFS4_FATTR4_OWNER_LIMIT+1], group[NFS4_FATTR4_OWNER_LIMIT+1];
    bitmap4 owner_group_acl_bitmap = {
        .count = 2,
        .arr[0] = 0,
        .arr[1] = FATTR4_WORD1_OWNER|FATTR4_WORD1_OWNER_GROUP
    };
    nfsacl41 acl = { 0 };

    DPRINTF(ACLLVL1, ("--> handle_getacl(state->path.path='%s')\n",
        state->path.path));

    if (args->query & DACL_SECURITY_INFORMATION) {
        owner_group_acl_bitmap.arr[0] |= FATTR4_WORD0_ACL;
    }

    (void)memset(&info, 0, sizeof(nfs41_file_info));
    info.owner = owner;
    info.owner_group = group;
    info.acl = &acl;

    /*
     * |nfs41_cached_getattr()| will first try to get all information from
     * the cache. But if bits are missing (e.g. |FATTR4_WORD0_ACL|, then
     * this will do a server roundtrip to get the missing data
     */
    status = nfs41_cached_getattr(state->session,
        &state->file, &owner_group_acl_bitmap, &info);
    if (status) {
        eprintf("handle_getacl: nfs41_cached_getattr() failed with %d\n",
            status);
        goto out;
    }

    EASSERT(info.attrmask.count > 1);
    if (args->query & DACL_SECURITY_INFORMATION) {
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_ACL) == true);
    }
    if (args->query & OWNER_SECURITY_INFORMATION) {
        EASSERT(bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_OWNER) == true);
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        EASSERT(bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_OWNER_GROUP) == true);
    }

    status = InitializeSecurityDescriptor(&sec_desc,
                                          SECURITY_DESCRIPTOR_REVISION);
    if (!status) {
        status = GetLastError();
        eprintf("handle_getacl: InitializeSecurityDescriptor failed with %d\n",
                status);
        goto out;
    }
     /* can't (re)use the same sid variable for both owner and group sids 
      * because security descriptor is created in absolute-form and it just
      * stores pointers to the sids. thus each owner and group needs its own
      * memory. free them after creating self-relative security descriptor. 
      */
    if (args->query & OWNER_SECURITY_INFORMATION) {
        // parse user@domain. currently ignoring domain part XX
        convert_nfs4name_2_user_domain(info.owner, &domain);
        DPRINTF(ACLLVL2, ("handle_getacl: OWNER_SECURITY_INFORMATION: for user='%s' "
                "domain='%s'\n", info.owner, domain?domain:"<null>"));
        sid_len = 0;
        status = map_nfs4servername_2_sid(nfs41dg,
            OWNER_SECURITY_INFORMATION, &sid_len, &osid, info.owner);
        if (status)
            goto out;
        status = SetSecurityDescriptorOwner(&sec_desc, osid, TRUE);
        if (!status) {
            status = GetLastError();
            eprintf("handle_getacl: SetSecurityDescriptorOwner failed with "
                    "%d\n", status);
            goto out;
        }
    }

    if (args->query & GROUP_SECURITY_INFORMATION) {
        convert_nfs4name_2_user_domain(info.owner_group, &domain);
        DPRINTF(ACLLVL2, ("handle_getacl: GROUP_SECURITY_INFORMATION: for '%s' "
                "domain='%s'\n", info.owner_group, domain?domain:"<null>"));
        sid_len = 0;
        status = map_nfs4servername_2_sid(nfs41dg,
            GROUP_SECURITY_INFORMATION, &sid_len, &gsid, info.owner_group);
        if (status)
            goto out;
        status = SetSecurityDescriptorGroup(&sec_desc, gsid, TRUE);
        if (!status) {
            status = GetLastError();
            eprintf("handle_getacl: SetSecurityDescriptorGroup failed with "
                    "%d\n", status);
            goto out;
        }
    }

    if (args->query & DACL_SECURITY_INFORMATION) {
        DPRINTF(ACLLVL2, ("handle_getacl: DACL_SECURITY_INFORMATION\n"));
        status = convert_nfs4acl_2_dacl(nfs41dg,
            info.acl, state->type, &dacl, &sids,
            state->file.fh.superblock->ea_support?true:false);
        if (status)
            goto out;
        status = SetSecurityDescriptorDacl(&sec_desc, TRUE, dacl, TRUE);
        if (!status) {
            status = GetLastError();
            eprintf("handle_getacl: SetSecurityDescriptorDacl failed with "
                    "%d\n", status);
            goto out;
        }
    }

    args->sec_desc_len = 0;
    status = MakeSelfRelativeSD(&sec_desc, args->sec_desc, &args->sec_desc_len);
    if (status) {
        eprintf("handle_getacl: MakeSelfRelativeSD() failed.\n");
        status = ERROR_INTERNAL_ERROR;
        goto out;
    }
    status = GetLastError();
    if (status != ERROR_INSUFFICIENT_BUFFER) {
        eprintf("handle_getacl: MakeSelfRelativeSD failes with %d\n", status);
        goto out;
    }
    args->sec_desc = malloc(args->sec_desc_len);
    if (args->sec_desc == NULL) {
        status = GetLastError();
        goto out;
    }
    status = MakeSelfRelativeSD(&sec_desc, args->sec_desc, &args->sec_desc_len);
    if (!status) {
        status = GetLastError();
        eprintf("handle_getacl: MakeSelfRelativeSD failes with %d\n", status);
        free(args->sec_desc);
        goto out;
    } else status = ERROR_SUCCESS;

out:
    if (args->query & OWNER_SECURITY_INFORMATION) {
        if (osid) free(osid);
    }
    if (args->query & GROUP_SECURITY_INFORMATION) {
        if (gsid) free(gsid);
    }
    if (args->query & DACL_SECURITY_INFORMATION) {
        if (sids) free_sids(sids, info.acl->count);
        free(dacl);
        nfsacl41_free(info.acl);
    }

    DPRINTF(ACLLVL1, ("<-- handle_getacl(state->path.path='%s') "
        "returning %d\n",
        state->path.path, status));

    return status;
}

static int marshall_getacl(unsigned char *buffer, uint32_t *length, 
                           nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_write(&buffer, length, &args->sec_desc_len, sizeof(DWORD));
    if (status) goto out;
    status = safe_write(&buffer, length, args->sec_desc, args->sec_desc_len);
    free(args->sec_desc);
    if (status) goto out;
out:
    return status;
}

const nfs41_upcall_op nfs41_op_getacl = {
    .parse = parse_getacl,
    .handle = handle_getacl,
    .marshall = marshall_getacl,
    .arg_size = sizeof(getacl_upcall_args)
};

static int parse_setacl(unsigned char *buffer, uint32_t length,
                        nfs41_upcall *upcall)
{
    int status;
    setacl_upcall_args *args = &upcall->args.setacl;
    ULONG sec_desc_len;

    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;
    status = safe_read(&buffer, &length, &sec_desc_len, sizeof(ULONG));
    if (status) goto out;
    args->sec_desc = (PSECURITY_DESCRIPTOR)buffer;

    DPRINTF(1, ("parsing NFS41_SYSOP_ACL_SET: info_class=%d sec_desc_len=%d\n",
            args->query, sec_desc_len));
out:
    return status;
}

static int is_well_known_sid(PSID sid, char *who, SID_NAME_USE *snu_out)
{
    int status, i;
    for (i = 0; i < 78; i++) {
        status = IsWellKnownSid(sid, (WELL_KNOWN_SID_TYPE)i);
        if (!status) continue;
        else {
            DPRINTF(ACLLVL3, ("WELL_KNOWN_SID_TYPE %d\n", i));
            switch((WELL_KNOWN_SID_TYPE)i) {
            case WinCreatorOwnerSid:
                memcpy(who, ACE4_OWNER, strlen(ACE4_OWNER)+1);
                *snu_out = SidTypeUser;
                return TRUE;
            case WinCreatorGroupSid:
            case WinBuiltinUsersSid:
                memcpy(who, ACE4_GROUP, strlen(ACE4_GROUP)+1);
                *snu_out = SidTypeGroup;
                return TRUE;
            case WinNullSid:
                memcpy(who, ACE4_NOBODY, strlen(ACE4_NOBODY)+1);
                *snu_out = SidTypeUser;
                return TRUE;
            case WinAnonymousSid:
                memcpy(who, ACE4_ANONYMOUS, strlen(ACE4_ANONYMOUS)+1);
                return TRUE;
            case WinWorldSid:
                memcpy(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1);
                *snu_out = SidTypeGroup;
                return TRUE;
            case WinAuthenticatedUserSid:
                memcpy(who, ACE4_AUTHENTICATED, strlen(ACE4_AUTHENTICATED)+1);
                return TRUE;
            case WinDialupSid:
                memcpy(who, ACE4_DIALUP, strlen(ACE4_DIALUP)+1); 
                return TRUE;
            case WinNetworkSid:
                memcpy(who, ACE4_NETWORK, strlen(ACE4_NETWORK)+1); 
                return TRUE;
            case WinBatchSid:
                memcpy(who, ACE4_BATCH, strlen(ACE4_BATCH)+1); 
                return TRUE;
            case WinInteractiveSid:
                memcpy(who, ACE4_INTERACTIVE, strlen(ACE4_INTERACTIVE)+1); 
                return TRUE;
            case WinNetworkServiceSid:
            case WinLocalServiceSid:
            case WinServiceSid:
                memcpy(who, ACE4_SERVICE, strlen(ACE4_SERVICE)+1); 
                return TRUE;
            default: return FALSE;
            }
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
    int file_type, bool named_attr_support, uint32_t *nfs4_mask)
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
        if (!named_attr_support) {
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
    int file_type, bool named_attr_support, ACCESS_MASK *win_mask)
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

    if (!named_attr_support) {
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

static
int map_sid2nfs4ace_who(PSID sid, PSID owner_sid, PSID group_sid,
    char *who_out, char *domain, SID_NAME_USE *sid_type_out)
{
    int status, lasterr;
    SID_NAME_USE sid_type = 0;
    /* |(UTF8_UNLEN+sizeof('\0'))*2| so we have space for user+domain */
    char who_buf[(UTF8_UNLEN+1)*2];
    char domain_buf[UTF8_UNLEN+1];
    DWORD who_size = sizeof(who_buf), domain_size = sizeof(domain_buf);
    LPSTR sidstr = NULL;

    DPRINTF(ACLLVL2, ("--> map_sid2nfs4ace_who("
        "sid=0x%p,owner_sid=0x%p, group_sid=0x%p)\n",
        sid, owner_sid, group_sid));

    if (DPRINTF_LEVEL_ENABLED(ACLLVL2)) {
        print_sid("sid", sid);
        print_sid("owner_sid", owner_sid);
        print_sid("group_sid", group_sid);
    }

    /* for ace mapping, we want to map owner's sid into "owner@"
     * but for set_owner attribute we want to map owner into a user name
     * same applies to group
     */
    status = 0;
    if (owner_sid) {
        if (EqualSid(sid, owner_sid)) {
            DPRINTF(ACLLVL2, ("this is owner's sid\n"));
            memcpy(who_out, ACE4_OWNER, strlen(ACE4_OWNER)+1);
            sid_type = SidTypeUser;
            status = ERROR_SUCCESS;
            goto out;
        }
    }
    if (group_sid) {
        if (EqualSid(sid, group_sid)) {
            DPRINTF(ACLLVL2, ("this is group's sid\n"));
            memcpy(who_out, ACE4_GROUP, strlen(ACE4_GROUP)+1);
            sid_type = SidTypeGroup;
            status = ERROR_SUCCESS;
            goto out;
        }
    }
    status = is_well_known_sid(sid, who_out, &sid_type);
    if (status) {
        if (!strncmp(who_out, ACE4_NOBODY, strlen(ACE4_NOBODY))) {
            who_size = (DWORD)strlen(ACE4_NOBODY);
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

    status = lookupaccountsidutf8(NULL, sid, who_buf, &who_size, domain_buf,
        &domain_size, &sid_type);
    lasterr = GetLastError();

    if (status) {
        DPRINTF(ACLLVL2, ("map_sid2nfs4ace_who: "
            "LookupAccountSid(sidtostr(sid)='%s', who_buf='%s', "
            "who_size=%d, domain='%s', domain_size=%d) "
            "returned success, status=%d, GetLastError=%d\n",
            sidstr, who_buf, who_size,
            domain_buf, domain_size, status, lasterr));
    }
    else {
        DPRINTF(ACLLVL2, ("map_sid2nfs4ace_who: "
            "LookupAccountSid(sidtostr(sid)='%s', who_size=%d, "
            "domain_size=%d) returned failure, status=%d, "
            "GetLastError=%d\n",
            sidstr, who_size, domain_size, status, lasterr));

        /*
         * No SID to local account mapping. Can happen for some system
         * SIDs, and Unix_User+<uid> or Unix_Group+<gid> SIDs
         */
        switch (lasterr) {
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
                /* fixme: This should be a function argument */
                extern nfs41_daemon_globals nfs41_dg;

                uid_t unixuser_uid = ~0U;
                gid_t unixgroup_gid = ~0U;

                if (unixuser_sid2uid(sid, &unixuser_uid)) {
                    if (!nfs41_idmap_uid_to_name(nfs41_dg.idmapper,
                        unixuser_uid, who_out, UTF8_UNLEN)) {
                        who_size = (DWORD)strlen(who_out);
                        sid_type = SidTypeUser;
                        status = ERROR_SUCCESS;

                        DPRINTF(ACLLVL1, ("map_sid2nfs4ace_who: "
                            "Unix_User+%d SID "
                            "mapped to user '%s'\n",
                            unixuser_uid, who_out));
                        goto add_domain;
                    }

                    eprintf("map_sid2nfs4ace_who: "
                        "unixuser_sid2uid(sid='%s',unixuser_uid=%d) "
                        "returned no mapping.\n",
                        sidstr, (int)unixuser_uid);
                    goto err_none_mapped;
                }

                if (unixgroup_sid2gid(sid, &unixgroup_gid)) {
                    if (!nfs41_idmap_gid_to_group(nfs41_dg.idmapper,
                        unixgroup_gid, who_out, UTF8_GNLEN)) {
                        who_size = (DWORD)strlen(who_out);
                        sid_type = SidTypeGroup;
                        status = ERROR_SUCCESS;

                        DPRINTF(ACLLVL1, ("map_sid2nfs4ace_who: "
                            "Unix_Group+%d SID "
                            "mapped to group '%s'\n",
                            unixgroup_gid, who_out));
                        goto add_domain;
                    }

                    eprintf("map_sid2nfs4ace_who: "
                        "unixgroup_sid2gid(sid='%s',unixgroup_gid=%d) "
                        "returned no mapping.\n",
                        sidstr, (int)unixgroup_gid);
                    goto err_none_mapped;
                }

                eprintf("map_sid2nfs4ace_who: lookupaccountsidutf8() "
                    "returned ERROR_NONE_MAPPED+no "
                    "Unix_@(User|Group)+ mapping for sidstr='%s'\n",
                    sidstr);
err_none_mapped:
                status = ERROR_NONE_MAPPED;
#else
                DPRINTF(ACLLVL2,
                    ("map_sid2nfs4ace_who: lookupaccountsidutf8() "
                    "returned ERROR_NONE_MAPPED for sidstr='%s'\n",
                    sidstr));
                status = lasterr;
                goto out;
#endif /* NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID */

            /* Catch other cases */
            case ERROR_NO_SUCH_USER:
            case ERROR_NO_SUCH_GROUP:
                eprintf("map_sid2nfs4ace_who: lookupaccountsidutf8() "
                    "returned ERROR_NO_SUCH_@(USER|GROUP) for "
                    "sidstr='%s'\n",
                    sidstr);
                status = lasterr;
                goto out;
            default:
                eprintf("map_sid2nfs4ace_who: Internal error, "
                    "lookupaccountsidutf8() returned unexpected ERROR_%d "
                    "for sidstr='%s'\n",
                    status, sidstr);
                status = ERROR_INTERNAL_ERROR;
                goto out;
        }
    }

    (void)memcpy(who_out, who_buf, who_size);
add_domain:
    /*
     * Complain if we attempt to add a domain suffix to an UID/GID
     * value
     */
    EASSERT(!isdigit(who_out[0]));

    char *wp;

    wp = mempcpy(who_out+who_size, "@", sizeof(char));

#ifdef NFS41_DRIVER_WS2022_HACKS
    /* Fixup |domain| for Windows Sever 2022 NFSv4.1 server */
    if ((!strncmp(who_out, "Users@", (size_t)who_size+1)) ||
        (!strncmp(who_out, "Administrators@", (size_t)who_size+1))) {
        domain = "BUILTIN";
        DPRINTF(1,
            ("map_sid2nfs4ace_who: Fixup '%.*s' domain='%s'\n",
            (int)who_size+1, who_out, domain));
    }
    else if (!strncmp(who_out, "SYSTEM@", (size_t)who_size+1)) {
        domain = "NT AUTHORITY";
        DPRINTF(1,
            ("map_sid2nfs4ace_who: Fixup '%.*s' domain='%s'\n",
            (int)who_size+1, who_out, domain));
    }
#endif /* NFS41_DRIVER_WS2022_HACKS */
    (void)memcpy(wp, domain, strlen(domain)+1);

/* no_add_domain: */
    status = ERROR_SUCCESS;
out:
    if (status) {
        DPRINTF(ACLLVL2,
            ("<-- map_sid2nfs4ace_who() returns %d\n", status));
    }
    else {
        DPRINTF(ACLLVL2,
            ("<-- map_sid2nfs4ace_who(who_out='%s', sid_type='%s'/%d) "
            "returns %d\n",
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

static int map_dacl_2_nfs4acl(PACL acl, PSID sid, PSID gsid, nfsacl41 *nfs4_acl,
    int file_type, bool named_attr_support, char *domain)
{
    int status;
    if (acl == NULL) {
        DPRINTF(ACLLVL2, ("this is a NULL dacl: all access to an object\n"));
        nfs4_acl->count = 1;
        nfs4_acl->aces = calloc(1, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        memcpy(nfs4_acl->aces->who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1);
        nfs4_acl->aces->acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;

        if (file_type == NF4DIR) {
            uint32_t ace4_all_dir_filt = ACE4_ALL_DIR;
#ifdef MAP_WIN32GENERIC2ACE4GENERIC
            /* Filter out unsupported features */
            if (!named_attr_support)
                ace4_all_dir_filt &= ~ACE4_RW_NAMED_ATTRS;
#endif /* MAP_WIN32GENERIC2ACE4GENERIC */
            nfs4_acl->aces->acemask = ace4_all_dir_filt;
        }
        else {
            uint32_t ace4_all_file_filt = ACE4_ALL_FILE;
#ifdef MAP_WIN32GENERIC2ACE4GENERIC
            /* Filter out unsupported features */
            if (!named_attr_support)
                ace4_all_file_filt &= ~ACE4_RW_NAMED_ATTRS;
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

            status = GetAce(acl, win_i, &ace);
            if (!status) {
                status = GetLastError();
                eprintf("map_dacl_2_nfs4acl: GetAce failed with %d\n", status);
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

            status = map_sid2nfs4ace_who(ace_sid, sid, gsid,
                curr_nfsace->who, domain, &who_sid_type);
            if (status)
                goto out_free;

            win_mask = *(PACCESS_MASK)(ace + 1);

            map_winace2nfs4aceflags(ace->AceFlags,
                &curr_nfsace->aceflag);
            map_winaccessmask2nfs4acemask(win_mask,
                file_type, named_attr_support,
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
    goto out;
}

static int handle_setacl(void *daemon_context, nfs41_upcall *upcall)
{
    int status = ERROR_NOT_SUPPORTED;
    nfs41_daemon_globals *nfs41dg = daemon_context;
    setacl_upcall_args *args = &upcall->args.setacl;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_file_info info = { 0 };
    stateid_arg stateid;
    nfsacl41 nfs4_acl = { 0 };
    PSID sid = NULL, gsid = NULL;
    BOOL sid_default, gsid_default;
    char ownerbuf[NFS4_FATTR4_OWNER_LIMIT+1];
    char groupbuf[NFS4_FATTR4_OWNER_LIMIT+1];

    DPRINTF(ACLLVL1, ("--> handle_setacl(state->path.path='%s')\n",
        state->path.path));

    if (args->query & OWNER_SECURITY_INFORMATION) {
        DPRINTF(ACLLVL2, ("handle_setacl: OWNER_SECURITY_INFORMATION\n"));
        status = GetSecurityDescriptorOwner(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("handle_setacl: GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }

        status = map_sid2nfs4ace_who(sid, NULL, NULL, ownerbuf,
            nfs41dg->localdomain_name, NULL);
        if (status)
            goto out;

        info.owner = ownerbuf;
        info.attrmask.arr[1] |= FATTR4_WORD1_OWNER;
        info.attrmask.count = 2;

        EASSERT_MSG(info.owner[0] != '\0',
            ("info.owner='%s'\n", info.owner));
    }

    if (args->query & GROUP_SECURITY_INFORMATION) {
        DPRINTF(ACLLVL2, ("handle_setacl: GROUP_SECURITY_INFORMATION\n"));
        status = GetSecurityDescriptorGroup(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("handle_setacl: GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }

        status = map_sid2nfs4ace_who(sid, NULL, NULL, groupbuf,
            nfs41dg->localdomain_name, NULL);
        if (status)
            goto out;

        info.owner_group = groupbuf;
        info.attrmask.arr[1] |= FATTR4_WORD1_OWNER_GROUP;
        info.attrmask.count = 2;

        EASSERT_MSG(info.owner_group[0] != '\0',
            ("info.owner_group='%s'\n", info.owner_group));
    }

    if (args->query & DACL_SECURITY_INFORMATION) {
        BOOL dacl_present, dacl_default;
        PACL acl;
        DPRINTF(ACLLVL2, ("handle_setacl: DACL_SECURITY_INFORMATION\n"));
        status = GetSecurityDescriptorDacl(args->sec_desc, &dacl_present,
                                            &acl, &dacl_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorDacl failed with %d\n", status);
            goto out;
        }
        status = GetSecurityDescriptorOwner(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }
        status = GetSecurityDescriptorGroup(args->sec_desc, &gsid, &gsid_default);
        if (!status) {
            status = GetLastError();
            eprintf("GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }
        status = map_dacl_2_nfs4acl(acl, sid, gsid, &nfs4_acl,
             state->type,
             state->file.fh.superblock->ea_support?true:false,
            nfs41dg->localdomain_name);
        if (status)
            goto out;

        info.acl = &nfs4_acl;
        info.attrmask.arr[0] |= FATTR4_WORD0_ACL;
        if (!info.attrmask.count)
            info.attrmask.count = 1;
    }

    /* break read delegations before SETATTR */
    nfs41_delegation_return(state->session, &state->file,
        OPEN_DELEGATE_WRITE, FALSE);

    nfs41_open_stateid_arg(state, &stateid);
    if (DPRINTF_LEVEL_ENABLED(ACLLVL2)) {
        print_nfs41_file_info("handle_setacl: nfs41_setattr() info IN:", &info);
    }
    status = nfs41_setattr(state->session, &state->file, &stateid, &info);
    if (status) {
        DPRINTF(ACLLVL1, ("handle_setacl: nfs41_setattr() failed with error '%s'.\n",
                nfs_error_string(status)));
        status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
    }
    else {
        args->ctime = info.change;

        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));

        if (DPRINTF_LEVEL_ENABLED(ACLLVL1)) {
            print_nfs41_file_info("handle_setacl: nfs41_setattr() success info OUT:", &info);
        }
    }

    if (args->query & DACL_SECURITY_INFORMATION)
        free(nfs4_acl.aces);
out:
    DPRINTF(ACLLVL1, ("<-- handle_setacl() returning %d\n", status));
    return status;
}

static int marshall_setacl(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    setacl_upcall_args *args = &upcall->args.setacl;
    return safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
}

const nfs41_upcall_op nfs41_op_setacl = {
    .parse = parse_setacl,
    .handle = handle_setacl,
    .marshall = marshall_setacl,
    .arg_size = sizeof(setacl_upcall_args)
};
