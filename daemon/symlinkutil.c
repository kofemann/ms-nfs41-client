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
#include <strsafe.h>
#include <stdlib.h>

#include "nfs41_driver.h"
#include "nfs41_ops.h"
#include "upcall.h"
#include "upcallutil.h"
#include "util.h"
#include "daemon_debug.h"


/* |DPRINTF()| levels for reparse logging */
#define REPLVL1 1
#define REPLVL2 2

static int abs_path_link(
    OUT nfs41_abs_path *path,
    IN char *path_pos,
    IN const char *link,
    IN uint32_t link_len)
{
    nfs41_component name;
    const char *path_max = path->path + NFS41_MAX_PATH_LEN;
    const char *link_pos = link;
    const char *link_end = link + link_len;
    int status = NO_ERROR;

    DPRINTF(REPLVL2,
        ("--> abs_path_link(path_pos='%s', link='%.*s', link_len=%d)\n",
        path_pos, (int)link_len, link, (int)link_len));

    /* UNC path ? Make sure we return \\... */
    if ((link_len > 2) && (!memcmp(link, "//", 2))) {
        path->path[0] = '\\';
        path->path[1] = '\\';
        path_pos = path->path+2;
        link_pos += 2;
    }
    /* if link is an absolute path, start path_pos at the beginning */
    else if (is_delimiter(*link)) {
        if (link_len == 0) {
            /* This should never happen... */
            eprintf("abs_path_link(path_pos='%s', link='%.*s', link_len=%d): "
                "Invalid path, link_len==0\n",
                path_pos, (int)link_len, link, (int)link_len);
            status = ERROR_BAD_NETPATH;
            goto out;
        }
        else if (link_len == 1) {
            /* Special case for $ ln -s '/' mysymlinktoroot # */
            path_pos = path->path+1;
            path->path[0] = '\\';
            path->path[1] = '\0';
            goto out;
        }
        else {
            /* Normal absolute path... */
            path_pos = path->path;
        }
    }

    /* copy each component of link into the path */
    while (next_component(link_pos, link_end, &name)) {
        link_pos = name.name + name.len;

        if (is_delimiter(*path_pos))
            path_pos++;

        /* handle special components . and .. */
        if (name.len == 1 && name.name[0] == '.')
            continue;
        if (name.len == 2 && name.name[0] == '.' && name.name[1] == '.') {
            /* back path_pos up by one component */
            if (!last_component(path->path, path_pos, &name)) {
                eprintf("symlink with .. that points below server root!\n");
                status = ERROR_BAD_NETPATH;
                goto out;
            }
            path_pos = (char*)prev_delimiter(name.name, path->path);
            continue;
        }

        /* copy the component and add a \ */
        if (FAILED(StringCchCopyNA(path_pos, path_max-path_pos, name.name,
                name.len))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
        path_pos += name.len;
        if (FAILED(StringCchCopyNA(path_pos, path_max-path_pos, "\\", 1))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
    }

    /* make sure the path is null terminated */
    if (path_pos == path_max) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    *path_pos = '\0';
out:
    path->len = (unsigned short)(path_pos - path->path);

    if (status) {
        DPRINTF(REPLVL2,
            ("<-- abs_path_link(), status=%d\n",
            status));
    }
    else {
        DPRINTF(REPLVL2,
            ("<-- abs_path_link(path='%.*s'), status=%d\n",
            (int)path->len, path->path, status));
    }

    return status;
}

int nfs41_symlink_target(
    IN nfs41_session *session,
    IN nfs41_path_fh *file,
    OUT nfs41_abs_path *target)
{
    char link[NFS41_MAX_PATH_LEN];
    const nfs41_abs_path *path = file->path;
    ptrdiff_t path_offset;
    uint32_t link_len;
    int status;

    /* read the link */
    status = nfs41_readlink(session, file, NFS41_MAX_PATH_LEN, link, &link_len);
    if (status) {
        eprintf("nfs41_readlink() for '%s' failed with '%s'\n", file->path->path,
            nfs_error_string(status));
        status = ERROR_PATH_NOT_FOUND;
        goto out;
    }

    DPRINTF(REPLVL2, ("--> nfs41_symlink_target('%s', '%s')\n", path->path, link));

    /* append any components after the symlink */
    if (FAILED(StringCchCatA(link, NFS41_MAX_PATH_LEN,
            file->name.name + file->name.len))) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    link_len = (uint32_t)strlen(link);

    /* overwrite the last component of the path; get the starting offset */
    path_offset = file->name.name - path->path;

    /* copy the path and update it with the results from link */
    if (target != path) {
        target->len = path->len;
        if (FAILED(StringCchCopyNA(target->path, NFS41_MAX_PATH_LEN,
                path->path, path->len))) {
            status = ERROR_BUFFER_OVERFLOW;
            goto out;
        }
    }
    status = abs_path_link(target, target->path + path_offset, link, link_len);
    if (status) {
        eprintf("abs_path_link() for path '%s' with link '%s' failed with %d\n",
            target->path, link, status);
        goto out;
    }
out:
    DPRINTF(REPLVL2, ("<-- nfs41_symlink_target('%s') returning %d\n",
        target->path, status));
    return status;
}

int nfs41_symlink_follow(
    IN nfs41_root *root,
    IN nfs41_session *session,
    IN nfs41_path_fh *symlink,
    OUT nfs41_file_info *info)
{
    nfs41_abs_path path;
    nfs41_path_fh file;
    uint32_t depth = 0;
    int status = NO_ERROR;

    file.path = &path;
    InitializeSRWLock(&path.lock);

    DPRINTF(REPLVL2, ("--> nfs41_symlink_follow('%s')\n", symlink->path->path));

    do {
        if (++depth > NFS41_MAX_SYMLINK_DEPTH) {
            status = ERROR_TOO_MANY_LINKS;
            goto out;
        }

        /* construct the target path */
        status = nfs41_symlink_target(session, symlink, &path);
        if (status) goto out;

        DPRINTF(REPLVL2, ("looking up '%s'\n", path.path));

        last_component(path.path, path.path + path.len, &file.name);

        /* get attributes for the target */
        status = nfs41_lookup(root, session,
            BIT2BOOL(symlink->fh.superblock->case_insensitive),
            &path, NULL, &file, info, &session);
        if (status) goto out;

        symlink = &file;
    } while (info->type == NF4LNK);
out:
    DPRINTF(REPLVL2, ("<-- nfs41_symlink_follow() returning %d\n", status));
    return status;
}

int map_symlink_errors(int status)
{
    switch (status) {
    case NFS4ERR_BADCHAR:
    case NFS4ERR_BADNAME:       return ERROR_INVALID_REPARSE_DATA;
    case NFS4ERR_WRONG_TYPE:    return ERROR_NOT_A_REPARSE_POINT;
    case NFS4ERR_ACCESS:        return ERROR_ACCESS_DENIED;
    case NFS4ERR_NOTEMPTY:      return ERROR_DIR_NOT_EMPTY;
    default: return nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
    }
}
