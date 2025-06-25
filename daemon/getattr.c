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

#include "nfs41_build_features.h"
#include "nfs41_ops.h"
#include "name_cache.h"
#include "nfs41_driver.h" /* only for |NFS41_SYSOP_FILE_QUERY*| */
#include "upcall.h"
#include "fileinfoutil.h"
#include "daemon_debug.h"


int nfs41_cached_getattr(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    IN OPTIONAL bitmap4 *extra_attr_request,
    OUT nfs41_file_info *info)
{
    int status;
    bool bits_missing = false;

    /* first look for cached attributes */
    status = nfs41_attr_cache_lookup(session_name_cache(session),
        file->fh.fileid, info);

    if ((status == 0) && extra_attr_request) {
        uint32_t i;

        /* Check if bits are missing... */
        for (i=0 ; i < extra_attr_request->count ; i++) {
            if ((extra_attr_request->arr[i] != 0) &&
                ((((i < info->attrmask.count)?(info->attrmask.arr[i]):0) &
                    extra_attr_request->arr[i]) == 0)) {
                bits_missing = true;
                DPRINTF(1, ("nfs41_cached_getattr: bits missing %d\n", i));
                break;
            }
        }
    }

    if (status || bits_missing) {
        /* fetch attributes from the server */
        bitmap4 attr_request;
        nfs41_superblock_getattr_mask(file->fh.superblock, &attr_request);

        if (extra_attr_request) {
            bitmap_or(&attr_request, extra_attr_request);
        }

        status = nfs41_getattr(session, file, &attr_request, info);
        if (status) {
            eprintf("nfs41_cached_getattr: "
                "nfs41_getattr() failed with '%s'\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        }
    }
    return status;
}

/* NFS41_SYSOP_FILE_QUERY, NFS41_SYSOP_FILE_QUERY_TIME_BASED_COHERENCY */
static int parse_getattr(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;

    getattr_upcall_args *args = &upcall->args.getattr;
    status = safe_read(&buffer, &length, &args->query_class, sizeof(args->query_class));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;

    DPRINTF(1, ("parsing '%s': "
        "info_class=%d buf_len=%d file='%.*s'\n",
        opcode2string(upcall->opcode),
        args->query_class, args->buf_len, upcall->state_ref->path.len,
        upcall->state_ref->path.path));
out:
    return status;
}

static int handle_getattr(void *daemon_context, nfs41_upcall *upcall)
{
    int status;
    getattr_upcall_args *args = &upcall->args.getattr;
    nfs41_open_state *state = upcall->state_ref;
    nfs41_file_info info = { 0 };

    status = nfs41_cached_getattr(state->session, &state->file, NULL, &info);
    if (status) {
        eprintf("handle_getattr(state->path.path='%s'): "
            "nfs41_cached_getattr() failed with %d\n",
            state->path.path,
            status);
        goto out;
    }

    if (info.type == NF4LNK) {
        nfs41_file_info target_info = { 0 };
        int target_status = nfs41_symlink_follow(upcall->root_ref,
            state->session, &state->file, &target_info);
        if (target_status == NO_ERROR) {
            info.symlink_dir = target_info.type == NF4DIR;
        }
        else {
#ifdef NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS
            info.symlink_dir = TRUE;
#else
            info.symlink_dir = FALSE;
#endif /* NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS */
        }
    }

    EASSERT(bitmap_isset(&info.attrmask, 0, FATTR4_WORD0_CHANGE));
    args->ctime = info.change;

    switch (args->query_class) {
    case FileBasicInformation:
        nfs_to_basic_info(state->file.name.name,
            state->file.fh.superblock,
            &info,
            &args->basic_info);
        break;
    case FileStandardInformation:
        nfs_to_standard_info(state->file.fh.superblock,
            &info,
            &args->std_info);
        break;
    case FileAttributeTagInformation:
        args->tag_info.FileAttributes =
            nfs_file_info_to_attributes(state->file.fh.superblock,
                &info);
        args->tag_info.ReparseTag = info.type == NF4LNK ?
            IO_REPARSE_TAG_SYMLINK : 0;
        break;
    case FileInternalInformation:
        args->intr_info.IndexNumber.QuadPart = info.fileid;
        break;
    case FileNetworkOpenInformation:
        nfs_to_network_openinfo(state->file.name.name,
            state->file.fh.superblock,
            &info,
            &args->network_info);
        break;
    case FileRemoteProtocolInformation:
        /*
         * |FileRemoteProtocolInformation| does not use |info|, but
         * we have to do the |nfs41_cached_getattr()| anyway to fill
         * out |info.change| to return the proper |args->ctime|
         */
        nfs_to_remote_protocol_info(state,
            &args->remote_protocol_info);
        break;
    case FileIdInformation:
        nfs41_file_info_to_FILE_ID_128(&info, &args->id_info.FileId);
        args->id_info.VolumeSerialNumber = 0xBABAFACE; /* 64bit! */
        break;
#ifdef NFS41_DRIVER_WSL_SUPPORT
    case FileStatInformation:
        nfs_to_stat_info(state->file.name.name,
            state->file.fh.superblock,
            &info,
            &args->stat_info);
        break;
    case FileStatLxInformation:
        nfs_to_stat_lx_info(daemon_context,
            state->file.name.name,
            state->file.fh.superblock,
            &info,
            &args->stat_lx_info);
        break;
#endif /* NFS41_DRIVER_WSL_SUPPORT */
    default:
        eprintf("handle_getattr(state->path.path='%s'): "
            "unhandled file query class %d\n",
            state->path.path,
            args->query_class);
        status = ERROR_INVALID_PARAMETER;
        break;
    }
out:
    return status;
}

static int marshall_getattr(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    getattr_upcall_args *args = &upcall->args.getattr;
    uint32_t info_len;

    switch (args->query_class) {
    case FileBasicInformation:
        info_len = sizeof(args->basic_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->basic_info, info_len);
        if (status) goto out;
        break;
    case FileStandardInformation:
        info_len = sizeof(args->std_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->std_info, info_len);
        if (status) goto out;
        break;
    case FileAttributeTagInformation:
        info_len = sizeof(args->tag_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->tag_info, info_len);
        if (status) goto out;
        break;
    case FileInternalInformation:
        info_len = sizeof(args->intr_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->intr_info, info_len);
        if (status) goto out;
        break;
    case FileNetworkOpenInformation:
        info_len = sizeof(args->network_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->network_info, info_len);
        if (status) goto out;
        break;
    case FileRemoteProtocolInformation:
        info_len = sizeof(args->remote_protocol_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length,
            &args->remote_protocol_info, info_len);
        if (status) goto out;
        break;
    case FileIdInformation:
        info_len = sizeof(args->id_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->id_info, info_len);
        if (status) goto out;
        break;
#ifdef NFS41_DRIVER_WSL_SUPPORT
    case FileStatInformation:
        info_len = sizeof(args->stat_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->stat_info, info_len);
        if (status) goto out;
        break;
    case FileStatLxInformation:
        info_len = sizeof(args->stat_lx_info);
        status = safe_write(&buffer, length, &info_len, sizeof(info_len));
        if (status) goto out;
        status = safe_write(&buffer, length, &args->stat_lx_info, info_len);
        if (status) goto out;
        break;
#endif /* NFS41_DRIVER_WSL_SUPPORT */
    default:
        eprintf("marshall_getattr: unknown file query class %d\n",
            args->query_class);
        status = 103;
        goto out;
    }
    status = safe_write(&buffer, length, &args->ctime, sizeof(args->ctime));
    if (status) goto out;
    DPRINTF(1, ("NFS41_SYSOP_FILE_QUERY: downcall changattr=%llu\n", args->ctime));
out:
    return status;
}


const nfs41_upcall_op nfs41_op_getattr = {
    .parse = parse_getattr,
    .handle = handle_getattr,
    .marshall = marshall_getattr,
    .arg_size = sizeof(getattr_upcall_args)
};
