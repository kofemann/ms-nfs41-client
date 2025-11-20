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
#include "aclutil.h"
#include "nfs41_daemon.h"
#include "delegation.h"
#include "daemon_debug.h"
#include "util.h"
#include "upcall.h"
#include "nfs41_xdr.h"
#include "sid.h"

static int parse_getacl(
    const unsigned char *restrict buffer,
    uint32_t length,
    nfs41_upcall *upcall)
{
    int status;
    getacl_upcall_args *args = &upcall->args.getacl;

    status = safe_read(&buffer, &length, &args->query_secinfo,
        sizeof(args->query_secinfo));
    if (status) goto out;

    EASSERT(length == 0);

    DPRINTF(1, ("parsing NFS41_SYSOP_ACL_QUERY: secinfo=0xlx\n",
        (long)args->query_secinfo));
out:
    return status;
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

    if (args->query_secinfo & DACL_SECURITY_INFORMATION) {
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
    if (args->query_secinfo & DACL_SECURITY_INFORMATION) {
        EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_ACL) == true);
    }
    if (args->query_secinfo & OWNER_SECURITY_INFORMATION) {
        EASSERT(bitmap_isset(&info.attrmask, 1, FATTR4_WORD1_OWNER) == true);
    }
    if (args->query_secinfo & GROUP_SECURITY_INFORMATION) {
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
    if (args->query_secinfo & OWNER_SECURITY_INFORMATION) {
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

    if (args->query_secinfo & GROUP_SECURITY_INFORMATION) {
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

    if (args->query_secinfo & DACL_SECURITY_INFORMATION) {
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
    if (args->query_secinfo & OWNER_SECURITY_INFORMATION) {
        if (osid) free(osid);
    }
    if (args->query_secinfo & GROUP_SECURITY_INFORMATION) {
        if (gsid) free(gsid);
    }
    if (args->query_secinfo & DACL_SECURITY_INFORMATION) {
        if (sids) free_sids(sids, info.acl->count);
        free(dacl);
        nfsacl41_free(info.acl);
    }

    DPRINTF(ACLLVL1, ("<-- handle_getacl(state->path.path='%s') "
        "returning %d\n",
        state->path.path, status));

    return status;
}

static int marshall_getacl(
    unsigned char *restrict buffer,
    uint32_t *restrict length,
    nfs41_upcall *restrict upcall)
{
    int status;
    const getacl_upcall_args *args = &upcall->args.getacl;

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

static int parse_setacl(
    const unsigned char *restrict buffer,
    uint32_t length,
    nfs41_upcall *upcall)
{
    int status;
    setacl_upcall_args *args = &upcall->args.setacl;
    const void *sec_desc_ptr;
    ULONG sec_desc_len;

    status = safe_read(&buffer, &length, &args->query_secinfo,
        sizeof(args->query_secinfo));
    if (status) goto out;
    status = safe_read(&buffer, &length, &sec_desc_len, sizeof(ULONG));
    if (status) goto out;
    status = get_safe_read_bufferpos(&buffer, &length, sec_desc_len, &sec_desc_ptr);
    if (status) goto out;

    args->sec_desc = (PSECURITY_DESCRIPTOR)sec_desc_ptr;

    EASSERT(length == 0);

    DPRINTF(1, ("parsing NFS41_SYSOP_ACL_SET: secinfo=0x%lx sec_desc_len=%d\n",
        (long)args->query_secinfo, sec_desc_len));
out:
    return status;
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

    if (args->sec_desc == NULL) {
        eprintf("handle_setacl: args->sec_desc==NULL\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    if (args->query_secinfo & OWNER_SECURITY_INFORMATION) {
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
        info.attrmask.count = __max(info.attrmask.count, 2);

        EASSERT_MSG(info.owner[0] != '\0',
            ("info.owner='%s'\n", info.owner));
    }

    if (args->query_secinfo & GROUP_SECURITY_INFORMATION) {
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
        info.attrmask.count = __max(info.attrmask.count, 2);

        EASSERT_MSG(info.owner_group[0] != '\0',
            ("info.owner_group='%s'\n", info.owner_group));
    }

    if (args->query_secinfo & DACL_SECURITY_INFORMATION) {
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
        info.attrmask.count = __max(info.attrmask.count, 1);
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

    if (args->query_secinfo & DACL_SECURITY_INFORMATION)
        free(nfs4_acl.aces);
out:
    DPRINTF(ACLLVL1, ("<-- handle_setacl() returning %d\n", status));
    return status;
}

static int marshall_setacl(
    unsigned char *restrict buffer,
    uint32_t *restrict length,
    nfs41_upcall *restrict upcall)
{
    const setacl_upcall_args *args = &upcall->args.setacl;
    return safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
}

const nfs41_upcall_op nfs41_op_setacl = {
    .parse = parse_setacl,
    .handle = handle_setacl,
    .marshall = marshall_setacl,
    .arg_size = sizeof(setacl_upcall_args)
};
