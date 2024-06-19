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
#include "sid.h"

#define ACLLVL 2 /* dprintf level for acl logging */

/* Local prototypes */
static void map_winace2nfs4aceflags(BYTE win_aceflags, uint32_t *nfs4_aceflags);
static void map_nfs4aceflags2winaceflags(uint32_t nfs4_aceflags, DWORD *win_aceflags);
static void map_winaccessmask2nfs4acemask(ACCESS_MASK win_mask,
    int file_type, uint32_t *nfs4_mask);
static void map_nfs4acemask2winaccessmask(uint32_t nfs4_mask,
    int file_type, ACCESS_MASK *win_mask);

static int parse_getacl(unsigned char *buffer, uint32_t length,
                        nfs41_upcall *upcall)
{
    int status;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_read(&buffer, &length, &args->query, sizeof(args->query));
    if (status) goto out;

    DPRINTF(1, ("parsing NFS41_ACL_QUERY: info_class=%d\n", args->query));
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
    else if (!strncmp(who, ACE4_GROUP, strlen(ACE4_GROUP)-1))
        type = WinCreatorGroupSid;
    else if (!strncmp(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)-1))
        type = WinWorldSid;
    else if (!strncmp(who, ACE4_NOBODY, strlen(ACE4_NOBODY)))
        type = WinNullSid;
    else 
        *flag = FALSE;
    if (*flag) 
        status = create_unknownsid(type, sid, sid_len);
    return status;
}

static int convert_nfs4acl_2_dacl(nfs41_daemon_globals *nfs41dg,
    nfsacl41 *acl, int file_type, PACL *dacl_out, PSID **sids_out)
{
    int status = ERROR_NOT_SUPPORTED, size = 0;
    uint32_t i;
    DWORD sid_len;
    PSID *sids;
    PACL dacl;
    LPSTR domain = NULL;
    BOOLEAN flag;

    DPRINTF(ACLLVL, ("--> convert_nfs4acl_2_dacl(acl=0x%p,file_type='%s'(=%d))\n",
        acl, map_nfs_ftype2str(file_type), file_type));

    sids = malloc(acl->count * sizeof(PSID));
    if (sids == NULL) {
        status = GetLastError();
        goto out;
    }
    for (i = 0; i < acl->count; i++) {
        convert_nfs4name_2_user_domain(acl->aces[i].who, &domain);
        DPRINTF(ACLLVL, ("convert_nfs4acl_2_dacl: for user='%s' domain='%s'\n",
                acl->aces[i].who, domain?domain:"<null>"));
        status = check_4_special_identifiers(acl->aces[i].who, &sids[i],
                                             &sid_len, &flag);
        if (status) {
            free_sids(sids, i);
            goto out;
        }
        if (!flag) {
            bool isgroupacl = (acl->aces[i].aceflag & ACE4_IDENTIFIER_GROUP)?true:false;

            if (isgroupacl) {
                DPRINTF(ACLLVL,
                    ("convert_nfs4acl_2_dacl: aces[%d].who='%s': "
                    "Setting group flag\n",
                    i, acl->aces[i].who));
            }

            status = map_nfs4servername_2_sid(nfs41dg,
                (isgroupacl?GROUP_SECURITY_INFORMATION:OWNER_SECURITY_INFORMATION),
                &sid_len, &sids[i], acl->aces[i].who);
            if (status) {
                free_sids(sids, i);
                goto out;
            }
        }
        size += sid_len - sizeof(DWORD);
    }
    size += sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE)*acl->count);
    size = align8(size); // align size on |DWORD| boundry
    dacl = malloc(size);
    if (dacl == NULL)
        goto out_free_sids;

    if (InitializeAcl(dacl, size, ACL_REVISION)) {
        ACCESS_MASK mask;
        DWORD win_aceflags;

        for (i = 0; i < acl->count; i++) {
            win_aceflags = 0;
            mask = 0;

            map_nfs4aceflags2winaceflags(acl->aces[i].aceflag,
                &win_aceflags);
            map_nfs4acemask2winaccessmask(acl->aces[i].acemask,
                file_type, &mask);

            if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
                dprintf_out("nfs2win: acl->aces[%d].who='%s': "
                    "acetype='%s', "
                    "nfs_acemask=0x%lx, win_mask=0x%lx, "
                    "win_aceflags=0x%lx\n",
                    i, acl->aces[i].who,
                    map_nfs_acetype2str(acl->aces[i].acetype),
                    (long)acl->aces[i].acemask,
                    (long)mask,
                    (long)win_aceflags);

                print_nfs_access_mask(acl->aces[i].who,
                    acl->aces[i].acemask);
                print_windows_access_mask(acl->aces[i].who, mask);
            }

            if (acl->aces[i].acetype == ACE4_ACCESS_ALLOWED_ACE_TYPE) {
                status = AddAccessAllowedAceEx(dacl, ACL_REVISION, win_aceflags, mask, sids[i]);
                if (!status) {
                    eprintf("convert_nfs4acl_2_dacl: "
                        "AddAccessAllowedAceEx(dacl=0x%p,win_aceflags=0x%x,mask=0x%x) failed "
                        "with status=%d\n",
                        dacl, (int)win_aceflags, (int)mask, status);
                    goto out_free_dacl;
                }
                else status = ERROR_SUCCESS;
            } else if (acl->aces[i].acetype == ACE4_ACCESS_DENIED_ACE_TYPE) {
                status = AddAccessDeniedAceEx(dacl, ACL_REVISION, win_aceflags, mask, sids[i]);
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
                        acl->aces[i].acetype);
                status = ERROR_INTERNAL_ERROR;
                free(dacl);
                free_sids(sids, acl->count);
                goto out;
            }
        }
    } else {
        eprintf("convert_nfs4acl_2_dacl: InitializeAcl failed with %d\n", status);
        goto out_free_dacl;
    }
    status = ERROR_SUCCESS;
    *sids_out = sids;
    *dacl_out = dacl;
out:
    DPRINTF(ACLLVL, ("<-- convert_nfs4acl_2_dacl("
        "acl=0x%p,file_type='%s'(=%d)) returning %d\n",
        acl, map_nfs_ftype2str(file_type), file_type, status));
    return status;
out_free_dacl:
    free(dacl);
out_free_sids:
    free_sids(sids, acl->count);
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
    char owner[NFS4_OPAQUE_LIMIT+1], group[NFS4_OPAQUE_LIMIT+1];
    nfsacl41 acl = { 0 };

    DPRINTF(ACLLVL, ("--> handle_getacl(state->path.path='%s')\n",
        state->path.path));

    if (args->query & DACL_SECURITY_INFORMATION) {
use_nfs41_getattr:
        bitmap4 attr_request = { 0 };
        (void)memset(&info, 0, sizeof(nfs41_file_info));
        info.owner = owner;
        info.owner_group = group;

        attr_request.count = 2;
        attr_request.arr[0] = FATTR4_WORD0_ACL;
        attr_request.arr[1] = FATTR4_WORD1_OWNER | FATTR4_WORD1_OWNER_GROUP;
        info.acl = &acl;
        status = nfs41_getattr(state->session, &state->file, &attr_request, &info);
        if (status) {
            eprintf("handle_getacl: nfs41_getattr() failed with %d\n",
                status);
            goto out;
        }
    }
    else {
        (void)memset(&info, 0, sizeof(nfs41_file_info));
        info.owner = owner;
        info.owner_group = group;

        status = nfs41_cached_getattr(state->session, &state->file, &info);
        if (status) {
            eprintf("handle_getacl: nfs41_cached_getattr() failed with %d\n",
                status);
            goto out;
        }

        EASSERT(info.attrmask.count >= 2);

        /*
         * In rare cases owner/owner_group are not in the cache
         * (usually for new files). In this case do a full
         * roundtrip to the NFS server to get the data...
         */
        if ((info.attrmask.arr[1] &
            (FATTR4_WORD1_OWNER|FATTR4_WORD1_OWNER_GROUP)) != (FATTR4_WORD1_OWNER|FATTR4_WORD1_OWNER_GROUP)) {
            DPRINTF(ACLLVL, ("handle_getattr: owner/owner_group not in cache, doing full lookup...\n"));
            goto use_nfs41_getattr;
        }
    }

    EASSERT(info.attrmask.count >= 2);
    EASSERT((info.attrmask.arr[1] & (FATTR4_WORD1_OWNER|FATTR4_WORD1_OWNER_GROUP)) == (FATTR4_WORD1_OWNER|FATTR4_WORD1_OWNER_GROUP));
    if (args->query & DACL_SECURITY_INFORMATION) {
        EASSERT((info.attrmask.arr[0] & (FATTR4_WORD0_ACL)) == (FATTR4_WORD0_ACL));
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
        DPRINTF(ACLLVL, ("handle_getacl: OWNER_SECURITY_INFORMATION: for user='%s' "
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
        DPRINTF(ACLLVL, ("handle_getacl: GROUP_SECURITY_INFORMATION: for '%s' "
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
        DPRINTF(ACLLVL, ("handle_getacl: DACL_SECURITY_INFORMATION\n"));
        status = convert_nfs4acl_2_dacl(nfs41dg,
            info.acl, state->type, &dacl, &sids);
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

    DPRINTF(ACLLVL, ("<-- handle_getacl() returning %d\n", status));

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

    DPRINTF(1, ("parsing NFS41_ACL_SET: info_class=%d sec_desc_len=%d\n",
            args->query, sec_desc_len));
out:
    return status;
}

static int is_well_known_sid(PSID sid, char *who) 
{
    int status, i;
    for (i = 0; i < 78; i++) {
        status = IsWellKnownSid(sid, (WELL_KNOWN_SID_TYPE)i);
        if (!status) continue;
        else {
            DPRINTF(ACLLVL, ("WELL_KNOWN_SID_TYPE %d\n", i));
            switch((WELL_KNOWN_SID_TYPE)i) {
            case WinCreatorOwnerSid:
                memcpy(who, ACE4_OWNER, strlen(ACE4_OWNER)+1);
                return TRUE;
            case WinNullSid:
                memcpy(who, ACE4_NOBODY, strlen(ACE4_NOBODY)+1); 
                return TRUE;
            case WinAnonymousSid:
                memcpy(who, ACE4_ANONYMOUS, strlen(ACE4_ANONYMOUS)+1); 
                return TRUE;
            case WinWorldSid:
                memcpy(who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1); 
                return TRUE;
            case WinCreatorGroupSid:
            case WinBuiltinUsersSid:
                memcpy(who, ACE4_GROUP, strlen(ACE4_GROUP)+1); 
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
    DPRINTF(ACLLVL,
        ("map_winace2nfs4aceflags: win_aceflags=0x%x nfs4_aceflags=0x%x\n",
        (int)win_aceflags, (int)*nfs4_aceflags));
}

static void map_nfs4aceflags2winaceflags(uint32_t nfs4_aceflags, DWORD *win_aceflags)
{
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
    DPRINTF(ACLLVL,
        ("map_nfs4aceflags2winace: nfs4_aceflags=0x%x win_aceflags=0x%x\n",
        (int)nfs4_aceflags, (int)*win_aceflags));
}

static
void map_winaccessmask2nfs4acemask(ACCESS_MASK win_mask,
    int file_type, uint32_t *nfs4_mask)
{
    /* check if any GENERIC bits set */
    if (win_mask & 0xf000000) {
        if (win_mask & GENERIC_ALL) {
            if (file_type == NF4DIR)
                *nfs4_mask |= ACE4_ALL_DIR;
            else
                *nfs4_mask |= ACE4_ALL_FILE;
        } else {
            if (win_mask & GENERIC_READ)
                *nfs4_mask |= ACE4_GENERIC_READ;
            if (win_mask & GENERIC_WRITE)
                *nfs4_mask |= ACE4_GENERIC_WRITE;
            if (win_mask & GENERIC_EXECUTE)
                *nfs4_mask |= ACE4_GENERIC_EXECUTE;
        }
    }
    else {
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
    /* Compare old and new code */
    EASSERT_MSG(((long)*nfs4_mask == (long)(win_mask /*& 0x00ffffff*/)),
        ("map_winaccessmask2nfs4acemask: "
        "new code nfs4_mask=0x%lx, "
        "old code nfs4_mask=0x%lx\n",
        (long)*nfs4_mask, (long)(win_mask /*& 0x00ffffff*/)));
#endif
}

static
void map_nfs4acemask2winaccessmask(uint32_t nfs4_mask,
    int file_type, ACCESS_MASK *win_mask)
{
#ifdef GENERIC_DISABLED_FOR_NOW
    bool is_generic = false;

    /*
     * Generic masks
     * (|ACE4_GENERIC_*| contain multiple bits
     */
    if ((nfs4_mask & ACE4_GENERIC_READ) == ACE4_GENERIC_READ) {
        *win_mask |= GENERIC_READ;
        is_generic = true;
    }
    if ((nfs4_mask & ACE4_GENERIC_WRITE) == ACE4_GENERIC_WRITE) {
        *win_mask |= GENERIC_WRITE;
        is_generic = true;
    }
    if ((nfs4_mask & ACE4_GENERIC_EXECUTE) == ACE4_GENERIC_EXECUTE) {
        *win_mask |= GENERIC_EXECUTE;
        is_generic = true;
    }

    if (file_type == NF4DIR) {
        if ((nfs4_mask & ACE4_ALL_DIR) == ACE4_ALL_DIR) {
            *win_mask |= GENERIC_ALL;
            is_generic = true;
        }
    }
    else {
        if ((nfs4_mask & ACE4_ALL_FILE) == ACE4_ALL_FILE) {
            *win_mask |= GENERIC_ALL;
            is_generic = true;
        }
    }
#if 0
    if (is_generic)
        goto mapping_done;
#endif
#endif /* GENERIC_DISABLED_FOR_NOW */

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

#ifdef GENERIC_DISABLED_FOR_NOW
mapping_done:
#endif

#if 1
    /* Compare old and new code */
    EASSERT_MSG(((long)*win_mask == (long)(nfs4_mask /*& 0x00ffffff*/)),
        ("#### map_nfs4acemask2winaccessmask: "
        "new code win_mask=0x%lx, "
        "old code win_mask=0x%lx\n",
        (long)*win_mask, (long)(nfs4_mask /*& 0x00ffffff*/)));
#endif
}

static int map_nfs4ace_who(PSID sid, PSID owner_sid, PSID group_sid, char *who_out, char *domain, SID_NAME_USE *sid_type_out)
{
    int status, lasterr;
    SID_NAME_USE sid_type = 0;
    /* |(UNLEN+sizeof('\0'))*2| so we have space for user+domain */
    char who_buf[(UNLEN+1)*2];
    char domain_buf[UNLEN+1];
    DWORD who_size = sizeof(who_buf), domain_size = sizeof(domain_buf);
    LPSTR sidstr = NULL;

    DPRINTF(ACLLVL, ("--> map_nfs4ace_who(sid=0x%p,owner_sid=0x%p, group_sid=0x%p)\n"));

    /* for ace mapping, we want to map owner's sid into "owner@"
     * but for set_owner attribute we want to map owner into a user name
     * same applies to group
     */
    status = 0;
    if (owner_sid) {
        if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
            print_sid("owner_sid", owner_sid);
        }

        if (EqualSid(sid, owner_sid)) {
            DPRINTF(ACLLVL, ("map_nfs4ace_who: this is owner's sid\n"));
            memcpy(who_out, ACE4_OWNER, strlen(ACE4_OWNER)+1);
            sid_type = SidTypeUser;
            status = ERROR_SUCCESS;
            goto out;
        }
    }
    if (group_sid) {
        if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
            print_sid("group_sid", group_sid);
        }

        if (EqualSid(sid, group_sid)) {
            DPRINTF(ACLLVL, ("map_nfs4ace_who: this is group's sid\n"));
            memcpy(who_out, ACE4_GROUP, strlen(ACE4_GROUP)+1);
            sid_type = SidTypeGroup;
            status = ERROR_SUCCESS;
            goto out;
        }
    }
    status = is_well_known_sid(sid, who_out);
    if (status) {
        if (!strncmp(who_out, ACE4_NOBODY, strlen(ACE4_NOBODY))) {
            who_size = (DWORD)strlen(ACE4_NOBODY);
            sid_type = SidTypeUser;
            goto add_domain;
        }

        /* fixme: What about |sid_type| ? */
        status = ERROR_SUCCESS;
        goto out;
    }

    if (!ConvertSidToStringSidA(sid, &sidstr)) {
        status = GetLastError();
        eprintf("map_nfs4ace_who: ConvertSidToStringSidA() failed, "
            "error=%d\n", status);
        goto out;
    }

    status = LookupAccountSidA(NULL, sid, who_buf, &who_size, domain_buf,
                                &domain_size, &sid_type);
    lasterr = GetLastError();

    if (status) {
        DPRINTF(ACLLVL, ("map_nfs4ace_who: "
            "LookupAccountSid(sidtostr(sid)='%s', who_buf='%s', "
            "who_size=%d, domain='%s', domain_size=%d) "
            "returned success, status=%d, GetLastError=%d\n",
            sidstr, who_buf, who_size,
            domain_buf, domain_size, status, lasterr));
    }
    else {
        DPRINTF(ACLLVL, ("map_nfs4ace_who: "
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
                DPRINTF(ACLLVL, ("map_nfs4ace_who: LookupAccountSidA() "
                    "returned ERROR_NONE_MAPPED for sidstr='%s'\n",
                    sidstr));
                status = lasterr;
                goto out;
            /* Catch other cases */
            case ERROR_NO_SUCH_USER:
            case ERROR_NO_SUCH_GROUP:
                eprintf("map_nfs4ace_who: LookupAccountSidA() "
                    "returned ERROR_NO_SUCH_@(USER|GROUP) for "
                    "sidstr='%s'\n",
                    sidstr);
                status = lasterr;
                goto out;
            default:
                eprintf("map_nfs4ace_who: Internal error, "
                    "LookupAccountSidA() returned unexpected ERROR_%d "
                    "for sidstr='%s'\n",
                    status, sidstr);
                status = ERROR_INTERNAL_ERROR;
                goto out;
        }
    }

    (void)memcpy(who_out, who_buf, who_size);
add_domain:
    (void)memcpy(who_out+who_size, "@", sizeof(char));
    (void)memcpy(who_out+who_size+1, domain, strlen(domain)+1);
    status = ERROR_SUCCESS;
out:
    if (status) {
        DPRINTF(ACLLVL,
            ("<-- map_nfs4ace_who() returns %d\n", status));
    }
    else {
        DPRINTF(ACLLVL,
            ("<-- map_nfs4ace_who(who_out='%s', sid_type=%d) "
            "returns %d\n",
            who_out, sid_type, status));
        if (sid_type_out) {
            *sid_type_out = sid_type;
        }
    }
    if (sidstr)
        LocalFree(sidstr);
    return status;
}

static int map_dacl_2_nfs4acl(PACL acl, PSID sid, PSID gsid, nfsacl41 *nfs4_acl,
                                int file_type, char *domain)
{
    int status;
    if (acl == NULL) {
        DPRINTF(ACLLVL, ("this is a NULL dacl: all access to an object\n"));
        nfs4_acl->count = 1;
        nfs4_acl->aces = calloc(1, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        memcpy(nfs4_acl->aces->who, ACE4_EVERYONE, strlen(ACE4_EVERYONE)+1);
        nfs4_acl->aces->acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
        if (file_type == NF4DIR)
            nfs4_acl->aces->acemask = ACE4_ALL_DIR;
        else
            nfs4_acl->aces->acemask = ACE4_ALL_FILE;
        nfs4_acl->aces->aceflag = 0;
    } else {
        int i;
        PACE_HEADER ace;
        PBYTE tmp_pointer;
        SID_NAME_USE who_sid_type = 0;
        ACCESS_MASK win_mask;

        DPRINTF(ACLLVL, ("NON-NULL dacl with %d ACEs\n", acl->AceCount));
        if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
            print_hexbuf_no_asci("ACL\n",
                (const unsigned char *)acl, acl->AclSize);
        }
        nfs4_acl->count = acl->AceCount;
        nfs4_acl->aces = calloc(nfs4_acl->count, sizeof(nfsace4));
        if (nfs4_acl->aces == NULL) {
            status = GetLastError();
            goto out;
        }
        nfs4_acl->flag = 0;
        for (i = 0; i < acl->AceCount; i++) {
            status = GetAce(acl, i, &ace);
            if (!status) {
                status = GetLastError();
                eprintf("map_dacl_2_nfs4acl: GetAce failed with %d\n", status);
                goto out_free;
            }
            tmp_pointer = (PBYTE)ace;
            if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
                print_hexbuf_no_asci("ACE\n",
                    (const unsigned char *)ace, ace->AceSize);
            }
            DPRINTF(ACLLVL, ("ACE TYPE: %x\n", ace->AceType));
            if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE)
                nfs4_acl->aces[i].acetype = ACE4_ACCESS_ALLOWED_ACE_TYPE;
            else if (ace->AceType == ACCESS_DENIED_ACE_TYPE)
                nfs4_acl->aces[i].acetype = ACE4_ACCESS_DENIED_ACE_TYPE;
            else {
                eprintf("map_dacl_2_nfs4acl: unsupported ACE type %d\n",
                    ace->AceType);
                status = ERROR_NOT_SUPPORTED;
                goto out_free;
            }

            tmp_pointer += sizeof(ACCESS_MASK) + sizeof(ACE_HEADER);

            status = map_nfs4ace_who(tmp_pointer, sid, gsid, nfs4_acl->aces[i].who,
                                     domain, &who_sid_type);
            if (status)
                goto out_free;

            win_mask = *(PACCESS_MASK)(ace + 1);

            map_winace2nfs4aceflags(ace->AceFlags,
                &nfs4_acl->aces[i].aceflag);
            map_winaccessmask2nfs4acemask(win_mask,
                file_type, &nfs4_acl->aces[i].acemask);

            if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
                dprintf_out("win2nfs: nfs4_acl->aces[%d].who='%s', "
                    "acetype='%s', "
                    "win_mask=0x%lx, nfs_acemask=0x%lx\n",
                    i, nfs4_acl->aces[i].who,
                    (nfs4_acl->aces[i].acetype?
                        "DENIED ACE":"ALLOWED ACE"),
                    (long)win_mask, (long)nfs4_acl->aces[i].acemask);
                print_windows_access_mask(nfs4_acl->aces[i].who,
                    win_mask);
                print_nfs_access_mask(nfs4_acl->aces[i].who,
                    nfs4_acl->aces[i].acemask);
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
                DPRINTF(ACLLVL, ("map_dacl_2_nfs4acl: who_sid_type=%d: "
                    "aces[%d].who='%s': "
                    "setting group flag\n",
                    (int)who_sid_type,
                    i, nfs4_acl->aces[i].who));
                nfs4_acl->aces[i].aceflag |= ACE4_IDENTIFIER_GROUP;
            }
        }
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
    char ownerbuf[NFS4_OPAQUE_LIMIT+1];
    char groupbuf[NFS4_OPAQUE_LIMIT+1];

    DPRINTF(ACLLVL, ("--> handle_setacl(state->path.path='%s')\n",
        state->path.path));

    if (args->query & OWNER_SECURITY_INFORMATION) {
        DPRINTF(ACLLVL, ("handle_setacl: OWNER_SECURITY_INFORMATION\n"));
        status = GetSecurityDescriptorOwner(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("handle_setacl: GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }

        status = map_nfs4ace_who(sid, NULL, NULL, ownerbuf,
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
        DPRINTF(ACLLVL, ("handle_setacl: GROUP_SECURITY_INFORMATION\n"));
        status = GetSecurityDescriptorGroup(args->sec_desc, &sid, &sid_default);
        if (!status) {
            status = GetLastError();
            eprintf("handle_setacl: GetSecurityDescriptorOwner failed with %d\n", status);
            goto out;
        }

        status = map_nfs4ace_who(sid, NULL, NULL, groupbuf,
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
        DPRINTF(ACLLVL, ("handle_setacl: DACL_SECURITY_INFORMATION\n"));
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
        status = map_dacl_2_nfs4acl(acl, sid, gsid, &nfs4_acl, state->type,
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
    if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
        print_nfs41_file_info("handle_setacl: nfs41_setattr() info IN:", &info);
    }
    status = nfs41_setattr(state->session, &state->file, &stateid, &info);
    if (status) {
        DPRINTF(ACLLVL, ("handle_setacl: nfs41_setattr() failed with error '%s'.\n",
                nfs_error_string(status)));
        status = nfs_to_windows_error(status, ERROR_NOT_SUPPORTED);
    }
    else {
        if (DPRINTF_LEVEL_ENABLED(ACLLVL)) {
            print_nfs41_file_info("handle_setacl: nfs41_setattr() success info OUT:", &info);
        }
    }
    args->ctime = info.change;
    if (args->query & DACL_SECURITY_INFORMATION)
        free(nfs4_acl.aces);
out:
    DPRINTF(ACLLVL, ("<-- handle_setacl() returning %d\n", status));
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
