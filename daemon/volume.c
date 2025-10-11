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
#include <strsafe.h>
#include <stdio.h>
#include <time.h>

#include "nfs41_ops.h"
#include "from_kernel.h"
#include "upcall.h"
#include "util.h"
#include "daemon_debug.h"


/* windows volume queries want size in 'units', so we have to
 * convert the nfs space_* attributes from bytes to units */
#define SECTORS_PER_UNIT    8
#define BYTES_PER_SECTOR    1024
#define BYTES_PER_UNIT      (SECTORS_PER_UNIT * BYTES_PER_SECTOR)

#define TO_UNITS(bytes) (bytes / BYTES_PER_UNIT)

#define VOLUME_CACHE_EXPIRATION 20


/* NFS41_SYSOP_VOLUME_QUERY */
static int parse_volume(
    const unsigned char *restrict buffer,
    uint32_t length,
    nfs41_upcall *upcall)
{
    int status;
    volume_upcall_args *args = &upcall->args.volume;

    status = safe_read(&buffer, &length, &args->query, sizeof(FS_INFORMATION_CLASS));
    if (status) goto out;

    EASSERT(length == 0);

    DPRINTF(1, ("parsing NFS41_SYSOP_VOLUME_QUERY: query=%d\n", args->query));
out:
    return status;
}

static int get_volume_size_info(
    IN nfs41_open_state *state,
    IN const char *query,
    OUT OPTIONAL PLONGLONG total_out,
    OUT OPTIONAL PLONGLONG user_out,
    OUT OPTIONAL PLONGLONG avail_out)
{
    nfs41_file_info info = { 0 };
    nfs41_superblock *superblock = state->file.fh.superblock;
    int status = ERROR_NOT_FOUND;

    AcquireSRWLockShared(&superblock->lock);
    /* check superblock for cached attributes */
    if (time(NULL) <= superblock->cache_expiration) {
        info.space_total = superblock->space_total;
        info.space_avail = superblock->space_avail;
        info.space_free = superblock->space_free;
        status = NO_ERROR;

        DPRINTF(2, ("'%s' cached: %llu user, %llu free of %llu total\n",
            query, info.space_avail, info.space_free, info.space_total));
    }
    ReleaseSRWLockShared(&superblock->lock);

    if (status) {
        bitmap4 attr_request = { 2, { 0, FATTR4_WORD1_SPACE_AVAIL |
            FATTR4_WORD1_SPACE_FREE | FATTR4_WORD1_SPACE_TOTAL } };

        /* query the space_ attributes of the filesystem */
        status = nfs41_getattr(state->session, &state->file,
            &attr_request, &info);
        if (status) {
            eprintf("get_volume_size_info: nfs41_getattr() failed with '%s'\n",
                nfs_error_string(status));
            status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
            goto out;
        }

        AcquireSRWLockExclusive(&superblock->lock);
        superblock->space_total = info.space_total;
        superblock->space_avail = info.space_avail;
        superblock->space_free = info.space_free;
        superblock->cache_expiration = time(NULL) + VOLUME_CACHE_EXPIRATION;
        ReleaseSRWLockExclusive(&superblock->lock);

        DPRINTF(2, ("'%s': %llu user, %llu free of %llu total\n",
            query, info.space_avail, info.space_free, info.space_total));
    }

    if (total_out) *total_out = TO_UNITS(info.space_total);
    if (user_out) *user_out = TO_UNITS(info.space_avail);
    if (avail_out) *avail_out = TO_UNITS(info.space_free);
out:
    return status;
}

static int handle_volume(void *daemon_context, nfs41_upcall *upcall)
{
    volume_upcall_args *args = &upcall->args.volume;
    nfs41_session *session = upcall->state_ref->session;
    int status = NO_ERROR;

    switch (args->query) {
    case FileFsVolumeInformation:
        PFILE_FS_VOLUME_INFORMATION vi = &args->info.volume_info;
        nfs41_superblock *superblock = upcall->state_ref->file.fh.superblock;

        vi->VolumeCreationTime.QuadPart = 0LL;
        /*
         * |FILE_FS_VOLUME_INFORMATION.VolumeSerialNumber| is a 32bit |ULONG|
         */
        vi->VolumeSerialNumber =
            nfs41_fsid2VolumeSerialNumber32(&superblock->fsid);
        EASSERT(vi->VolumeSerialNumber != 0UL);
        vi->SupportsObjects = FALSE;

        /*
         * |VolumeLabel| should be unique per volume, so we construct
         * a nfs://-URL (without path)
         *
         * FIXME:
         * - We should really work on |session->client->rpc->addrs| to
         * peel-off the port number
         */
        (void)swprintf(vi->VolumeLabel,
#if 1
            /*
             * Windows bug:
             * Windows Explorer can only handle up to 31 characters per label
             * FIXME:
             * Maybe a "workaround" would be to get the "naked" IPv4/IPv6 address
             * from libtirpc's universal address
             */
            31,
#else
            MAX_PATH,
#endif
            L"nfs://%s:%d/%s",
            session->client->rpc->server_name,
            2049,
            (session->client->root->use_nfspubfh?"public=1":""));
        vi->VolumeLabelLength = (ULONG)(wcslen(vi->VolumeLabel)*sizeof(wchar_t));
        args->len = sizeof(args->info.volume_info) +
            vi->VolumeLabelLength - 1*sizeof(wchar_t);
        break;

    case FileFsSizeInformation:
        args->len = sizeof(args->info.size);
        args->info.size.SectorsPerAllocationUnit = SECTORS_PER_UNIT;
        args->info.size.BytesPerSector = BYTES_PER_SECTOR;

        status = get_volume_size_info(upcall->state_ref,
            "FileFsSizeInformation",
            &args->info.size.TotalAllocationUnits.QuadPart,
            &args->info.size.AvailableAllocationUnits.QuadPart,
            NULL);
        break;

    case FileFsFullSizeInformation:
        args->len = sizeof(args->info.fullsize);
        args->info.fullsize.SectorsPerAllocationUnit = SECTORS_PER_UNIT;
        args->info.fullsize.BytesPerSector = BYTES_PER_SECTOR;

        status = get_volume_size_info(upcall->state_ref,
            "FileFsFullSizeInformation",
            &args->info.fullsize.TotalAllocationUnits.QuadPart,
            &args->info.fullsize.CallerAvailableAllocationUnits.QuadPart,
            &args->info.fullsize.ActualAvailableAllocationUnits.QuadPart);
        break;

    case FileFsAttributeInformation:
        nfs41_superblock_fs_attributes(upcall->state_ref->file.fh.superblock,
            &args->info.attribute);
        args->len = sizeof(FILE_FS_ATTRIBUTE_INFORMATION) +
            args->info.attribute.FileSystemNameLength-1*sizeof(wchar_t);
        break;

    case FileFsSectorSizeInformation:
        args->len = sizeof(args->info.sector_size);

        args->info.sector_size.LogicalBytesPerSector = BYTES_PER_SECTOR;
        args->info.sector_size.PhysicalBytesPerSectorForAtomicity =
            BYTES_PER_SECTOR;
        args->info.sector_size.PhysicalBytesPerSectorForPerformance =
            BYTES_PER_SECTOR;
        args->info.sector_size.FileSystemEffectivePhysicalBytesPerSectorForAtomicity =
            BYTES_PER_SECTOR;
        /*
         * |SSINFO_FLAGS_NO_SEEK_PENALTY| is required by
         * Cygwin/MSYS2/mingw to support sparse files
         */
        args->info.sector_size.Flags =
                SSINFO_FLAGS_ALIGNED_DEVICE |
                SSINFO_FLAGS_PARTITION_ALIGNED_ON_DEVICE |
                SSINFO_FLAGS_NO_SEEK_PENALTY;
        args->info.sector_size.ByteOffsetForSectorAlignment = 0;
        args->info.sector_size.ByteOffsetForPartitionAlignment = 0;
        break;

    default:
        eprintf("unhandled fs query class %d\n", args->query);
        status = ERROR_INVALID_PARAMETER;
        break;
    }
    return status;
}

static int marshall_volume(
    unsigned char *restrict buffer,
    uint32_t *restrict length,
    nfs41_upcall *restrict upcall)
{
    int status;
    const volume_upcall_args *args = &upcall->args.volume;

    status = safe_write(&buffer, length, &args->len, sizeof(args->len));
    if (status) goto out;
    status = safe_write(&buffer, length, &args->info, args->len);
out:
    return status;
}


const nfs41_upcall_op nfs41_op_volume = {
    .parse = parse_volume,
    .handle = handle_volume,
    .marshall = marshall_volume,
    .arg_size = sizeof(volume_upcall_args)
};
