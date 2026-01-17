/* NFSv4.1 client for Windows
 * Copyright (C) 2024-2026 Roland Mainz <roland.mainz@nrubsig.org>
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

#ifndef __NFS41_DAEMON_WINSTREAMS_H__
#define __NFS41_DAEMON_WINSTREAMS_H__ 1

#include <stdlib.h>
#include <stdbool.h>

#include "nfs41_build_features.h"
#include "nfs41_types.h"
#include "from_kernel.h"

#define STREAMINFO_NEXT_ENTRY(str) \
    ((PFILE_STREAM_INFORMATION)((PBYTE)(str) + (str)->NextEntryOffset))

static __inline
bool is_stream_path(const nfs41_abs_path *restrict path)
{
    if (memchr(path->path, ':', path->len) != NULL)
        return true;
    return false;
}

static __inline
bool is_stream_path_fh(const nfs41_path_fh *restrict path)
{
    if (memchr(path->name.name, ':', path->name.len) != NULL)
        return true;
    return false;
}

static __inline
bool is_stream_component(const nfs41_component *restrict comp)
{
    if (memchr(comp->name, ':', comp->len) != NULL)
        return true;
    return false;
}

#ifdef NFS41_WINSTREAMS_SUPPORT

int parse_win32stream_name(
    IN const char *restrict path,
    IN bool allow_empty_base_name,
    OUT bool *restrict is_stream,
    OUT char *restrict base_name,
    OUT char *restrict stream_name);

typedef struct __nfs41_open_state nfs41_open_state;

int get_streaminformation(
    IN OUT nfs41_open_state *state,
    IN const nfs41_file_info *basefile_info,
    OUT FILE_STREAM_INFORMATION *restrict *restrict streamlist_out,
    OUT ULONG *streamlist_out_size);
void free_streaminformation(
    IN FILE_STREAM_INFORMATION *restrict streamlist);
#endif /* NFS41_WINSTREAMS_SUPPORT */

#endif /* !__NFS41_DAEMON_WINSTREAMS_H__ */
