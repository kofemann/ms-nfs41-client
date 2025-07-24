/* NFSv4.1 client for Windows
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

#ifndef __NFS41_DAEMON_FILEINFOUTIL_H__
#define __NFS41_DAEMON_FILEINFOUTIL_H__ 1

#include <stdlib.h>
#include <stdbool.h>

#include "nfs41_build_features.h"
#include "nfs41_types.h"
#include "from_kernel.h"

typedef struct _FILE_ID_128 FILE_ID_128, *PFILE_ID_128;
typedef struct __nfs41_superblock nfs41_superblock;
typedef struct __nfs41_open_state nfs41_open_state;

void nfs41_file_info_to_FILE_ID_128(
    IN const nfs41_file_info *restrict info,
    OUT FILE_ID_128 *restrict out_fid128);
ULONG nfs_file_info_to_attributes(
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info);
void nfs_to_basic_info(
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_BASIC_INFORMATION restrict basic_out);
void nfs_to_standard_info(
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_STANDARD_INFORMATION restrict std_out);
void nfs_to_network_openinfo(
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_NETWORK_OPEN_INFORMATION restrict std_out);
void nfs_to_remote_protocol_info(
    IN nfs41_open_state *state,
    OUT PFILE_REMOTE_PROTOCOL_INFORMATION restrict rpi_out);
#ifdef NFS41_DRIVER_WSL_SUPPORT
void nfs_to_stat_info(
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_STAT_INFORMATION restrict stat_out);
void nfs_to_stat_lx_info(
    IN void *daemon_context,
    IN const char *restrict name,
    IN const nfs41_superblock *restrict superblock,
    IN const nfs41_file_info *restrict info,
    OUT PFILE_STAT_LX_INFORMATION restrict stat_lx_out);
#endif /* NFS41_DRIVER_WSL_SUPPORT */

/* Copy |info->symlink_dir| */
#define NFS41FILEINFOCPY_COPY_SYMLINK_DIR (1 << 0)
void nfs41_file_info_cpy(
    OUT nfs41_file_info *restrict dest,
    IN const nfs41_file_info *restrict src,
    IN int flags);

#endif /* !__NFS41_DAEMON_FILEINFOUTIL_H__ */
