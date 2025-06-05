/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
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
#include <strsafe.h>
#include <stdio.h>

#include "nfs41_build_features.h"
#include "daemon_debug.h"
#include "nfs41_ops.h"
#include "upcall.h"
#include "util.h"
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
#include "accesstoken.h"
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */


/* NFS41_SYSOP_MOUNT */
static int parse_mount(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    mount_upcall_args *args = &upcall->args.mount;

    status = get_name(&buffer, &length, &args->hostport);
    if(status) goto out;
    status = get_name(&buffer, &length, &args->path);
    if(status) goto out;
    status = safe_read(&buffer, &length, &args->sec_flavor, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->rsize, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->wsize, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->use_nfspubfh, sizeof(DWORD));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->nfsvers, sizeof(DWORD));
    if (status) goto out;

    DPRINTF(1, ("parsing NFS41_SYSOP_MOUNT: hostport='%s' root='%s' "
        "sec_flavor='%s' rsize=%d wsize=%d use_nfspubfh=%d "
        "nfsvers=%d\n",
        args->hostport, args->path, secflavorop2name(args->sec_flavor),
        args->rsize, args->wsize, args->use_nfspubfh,
        args->nfsvers));
    return status;
out:
    DPRINTF(1, ("parsing NFS41_SYSOP_MOUNT: failed %d\n", status));
    return status;
}

static int handle_mount(void *daemon_context, nfs41_upcall *upcall)
{
    int status;
    mount_upcall_args *args = &upcall->args.mount;
    char hostname[NFS41_HOSTNAME_LEN+1+32]; /* sizeof(hostname+'@'+integer) */
    char *s;
    int port = 0;
    nfs41_abs_path path;
    multi_addr4 addrs = { 0 };
    nfs41_root *root = NULL;
    nfs41_client *client;
    nfs41_path_fh file;

    EASSERT(args->hostport != NULL);

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID authenticationid = { .LowPart = 0, .HighPart = 0L };

    /* We ignore errors here since this is for logging only */
    (void)get_token_authenticationid(upcall->currentthread_token,
        &authenticationid);

    logprintf("mount(hostport='%s', "
        "use_nfspubfh=%d, path='%s', "
        "authid=(0x%lx.0x%lx)) request\n",
        args->hostport?args->hostport:"<NULL>",
        (int)args->use_nfspubfh,
        args->path?args->path:"<NULL>",
        (long)authenticationid.HighPart,
        (long)authenticationid.LowPart);
#else
    logprintf("mount(hostport='%s', path='%s') request\n",
        args->hostport?args->hostport:"<NULL>",
        args->path?args->path:"<NULL>");
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    if (upcall->currentthread_token == INVALID_HANDLE_VALUE){
        eprintf("handle_mount: Thread has no impersonation token\n");
        status = ERROR_NO_IMPERSONATION_TOKEN;
        goto out;
    }

    if ((args->path == NULL) || (strlen(args->path) == 0)) {
        DPRINTF(1, ("handle_mount: empty mount root\n"));
        status = ERROR_BAD_NETPATH;
        goto out;
    }

    (void)strcpy_s(hostname, sizeof(hostname), args->hostport);
    s = strchr(hostname, '@');
    if (s) {
        *s++ = '\0';
	port = atoi(s);
	if ((port < 1) || (port > 65535)) {
            status = ERROR_BAD_ARGUMENTS;
            eprintf("handle_mount: bad port number %d specified in "
                "hostport '%s'\n",
                port, args->hostport);
            goto out;
	}

	DPRINTF(1, ("handle_mount: hostname='%s', port=%d\n",
            hostname, port));
    } else {
        eprintf("handle_mount: port not specified in hostport '%s'\n",
            args->hostport);
        status = ERROR_BAD_NETPATH;
        goto out;
    }

    // resolve hostname,port
    status = nfs41_server_resolve(hostname, (unsigned short)port, &addrs);
    if (status) {
        eprintf("nfs41_server_resolve(hostname='%s', port=%d) failed with %d\n",
            hostname, port, status);
        goto out;
    }

    if (upcall->root_ref != INVALID_HANDLE_VALUE) {
        /* use an existing root from a previous mount, but don't take an
         * extra reference; we'll only get one UNMOUNT upcall for each root */
        root = upcall->root_ref;
    } else {
        // create root
        status = nfs41_root_create(hostname, port,
            args->use_nfspubfh?true:false,
            args->nfsvers,
            args->sec_flavor,
            args->wsize + WRITE_OVERHEAD, args->rsize + READ_OVERHEAD, &root);
        if (status) {
            eprintf("nfs41_root_create(hostname='%s', port=%d) failed %d\n",
                hostname, port, status);
            goto out;
        }
        root->uid = upcall->uid;
        root->gid = upcall->gid;
    }

    // find or create the client/session
    status = nfs41_root_mount_addrs(root, &addrs, 0, 0, &client);
    if (status) {
        eprintf("nfs41_root_mount_addrs() failed with %d\n", status);
        goto out_err;
    }

    // make a copy of the path for nfs41_lookup()
    InitializeSRWLock(&path.lock);
    if (FAILED(StringCchCopyA(path.path, NFS41_MAX_PATH_LEN, args->path))) {
        status = ERROR_FILENAME_EXCED_RANGE;
        goto out_err;
    }
    path.len = (unsigned short)strlen(path.path);

    // look up the mount path, and fail if it doesn't exist
    status = nfs41_lookup(root, client->session,
        &path, NULL, &file, NULL, NULL);
    if (status) {
        eprintf("nfs41_lookup('%s') failed with %d\n", path.path, status);
        status = ERROR_BAD_NETPATH;
        goto out_err;
    }

    nfs41_superblock_fs_attributes(file.fh.superblock, &args->FsAttrs);

    if (upcall->root_ref == INVALID_HANDLE_VALUE)
        nfs41_root_ref(root);
    upcall->root_ref = root;
    args->lease_time = client->session->lease_time;
out:
    if (status == 0) {
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
        logprintf("mount(hostport='%s', use_nfspubfh=%d, path='%s', "
            "authid=(0x%lx.0x%lx)) success, root=0x%p, NFS version=4.%d\n",
            args->hostport?args->hostport:"<NULL>",
            (int)args->use_nfspubfh,
            args->path?args->path:"<NULL>",
            (long)authenticationid.HighPart,
            (long)authenticationid.LowPart,
            root,
            (int)root->nfsminorvers);
#else
        logprintf("mount(hostport='%s', use_nfspubfh=%d, path='%s') success, "
            "root=0x%p, NFS version=4.%d\n",
            args->hostport?args->hostport:"<NULL>",
            (int)args->use_nfspubfh,
            args->path?args->path:"<NULL>",
            root,
            (int)root->nfsminorvers);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
    }
    else {
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
        logprintf("mount(hostport='%s', use_nfspubfh=%d, path='%s', "
            "authid=(0x%lx.0x%lx))) failed, status=%d\n",
            args->hostport?args->hostport:"<NULL>",
            (int)args->use_nfspubfh,
            args->path?args->path:"<NULL>",
            (long)authenticationid.HighPart,
            (long)authenticationid.LowPart,
            (int)status);
#else
        logprintf("mount(hostport='%s', use_nfspubfh=%d, path='%s') "
            "failed, status=%d\n",
            args->hostport?args->hostport:"<NULL>",
            (int)args->use_nfspubfh,
            args->path?args->path:"<NULL>",
            (int)status);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
    }
    return status;

out_err:
    if (upcall->root_ref == INVALID_HANDLE_VALUE)
        nfs41_root_deref(root);
    goto out;
}

static int marshall_mount(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    mount_upcall_args *args = &upcall->args.mount;
    int status;
    DPRINTF(2, ("NFS41_SYSOP_MOUNT: writing pointer to nfs41_root 0x%p, version %d, "
        "lease_time %d\n", upcall->root_ref, NFS41D_VERSION, args->lease_time));
    status = safe_write(&buffer, length, &upcall->root_ref, sizeof(HANDLE));
    if (status) goto out;
    status = safe_write(&buffer, length, &NFS41D_VERSION, sizeof(DWORD));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->lease_time, sizeof(DWORD));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->FsAttrs, sizeof(args->FsAttrs));
out:
    return status;
}

static void cancel_mount(IN nfs41_upcall *upcall)
{
    if (upcall->root_ref != INVALID_HANDLE_VALUE)
        nfs41_root_deref(upcall->root_ref);
}

const nfs41_upcall_op nfs41_op_mount = {
    .parse = parse_mount,
    .handle = handle_mount,
    .marshall = marshall_mount,
    .cancel = cancel_mount,
    .arg_size = sizeof(mount_upcall_args)
};


/* NFS41_SYSOP_UNMOUNT */
static int parse_unmount(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    DPRINTF(1, ("parsing NFS41_SYSOP_UNMOUNT: root=0x%p\n", upcall->root_ref));
    return ERROR_SUCCESS;
}

static int handle_unmount(void *daemon_context, nfs41_upcall *upcall)
{
    /* release the original reference from nfs41_root_create() */
    nfs41_root_deref(upcall->root_ref);

    logprintf("umount(root='0x%p') success\n", upcall->root_ref);

    return ERROR_SUCCESS;
}

const nfs41_upcall_op nfs41_op_unmount = {
    .parse = parse_unmount,
    .handle = handle_unmount,
    .arg_size = 0
};
