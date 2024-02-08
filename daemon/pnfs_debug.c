/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
 *
 * Olga Kornievskaia <aglo@umich.edu>
 * Casey Bodley <cbodley@umich.edu>
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

#include <winsock2.h>
#include <strsafe.h>
#include "pnfs.h"
#include "daemon_debug.h"


const char* pnfs_error_string(enum pnfs_status status)
{
    switch (status) {
    case PNFS_SUCCESS:          return "PNFS_SUCCESS";
    case PNFS_PENDING:          return "PNFS_PENDING";
    case PNFS_READ_EOF:         return "PNFS_READ_EOF";
    case PNFSERR_NOT_SUPPORTED: return "PNFSERR_NOT_SUPPORTED";
    case PNFSERR_NOT_CONNECTED: return "PNFSERR_NOT_CONNECTED";
    case PNFSERR_IO:            return "PNFSERR_IO";
    case PNFSERR_NO_DEVICE:     return "PNFSERR_NO_DEVICE";
    case PNFSERR_NO_LAYOUT:     return "PNFSERR_NO_LAYOUT";
    case PNFSERR_INVALID_FH_LIST: return "PNFSERR_INVALID_FH_LIST";
    case PNFSERR_INVALID_DS_INDEX: return "PNFSERR_INVALID_DS_INDEX";
    case PNFSERR_RESOURCES:     return "PNFSERR_RESOURCES";
    case PNFSERR_LAYOUT_RECALLED: return "PNFSERR_LAYOUT_RECALLED";
    case PNFSERR_LAYOUT_CHANGED: return "PNFSERR_LAYOUT_CHANGED";
    default:                    return "Invalid pnfs status";
    }
}

const char* pnfs_layout_type_string(enum pnfs_layout_type type)
{
    switch (type) {
    case PNFS_LAYOUTTYPE_FILE:  return "PNFS_LAYOUTTYPE_FILE";
    case PNFS_LAYOUTTYPE_OBJECT: return "PNFS_LAYOUTTYPE_OBJECT";
    case PNFS_LAYOUTTYPE_BLOCK: return "PNFS_LAYOUTTYPE_BLOCK";
    default:                    return "Invalid layout type";
    }
}

const char* pnfs_iomode_string(enum pnfs_iomode iomode)
{
    switch (iomode) {
    case PNFS_IOMODE_READ:      return "PNFS_IOMODE_READ";
    case PNFS_IOMODE_RW:        return "PNFS_IOMODE_RW";
    case PNFS_IOMODE_ANY:       return "PNFS_IOMODE_ANY";
    default:                    return "Invalid io mode";
    }
}

static
void dprint_deviceid(
    IN const char *title,
    IN const unsigned char *deviceid)
{
    /* deviceid is 16 bytes, so print it as 4 uints */
    uint32_t *p = (uint32_t*)deviceid;
    dprintf_out("%s%08X.%08X.%08X.%08X\n",
        title, htonl(p[0]), htonl(p[1]), htonl(p[2]), htonl(p[3]));
}

void dprint_layout(
    IN int level,
    IN const pnfs_file_layout *layout)
{
    if (!DPRINTF_LEVEL_ENABLED(level))
        return;

    dprintf_out("  type:             '%s'\n", pnfs_layout_type_string(layout->layout.type));
    dprintf_out("  iomode:           '%s'\n", pnfs_iomode_string(layout->layout.iomode));
    dprint_deviceid("  deviceid:         ", layout->deviceid);
    dprintf_out("  offset:           %llu\n", layout->layout.offset);
    dprintf_out("  length:           %llu\n", layout->layout.length);
    dprintf_out("  pattern_offset:   %llu\n", layout->pattern_offset);
    dprintf_out("  first_index:      %u\n", layout->first_index);
    dprintf_out("  dense:            %u\n", is_dense(layout));
    dprintf_out("  commit_to_mds:    %u\n", should_commit_to_mds(layout));
    dprintf_out("  stripe_unit_size: %u\n", layout_unit_size(layout));
    dprintf_out("  file handles:     %u\n", layout->filehandles.count);
}

#define MULTI_ADDR_BUFFER_LEN \
    (NFS41_ADDRS_PER_SERVER*(NFS41_UNIVERSAL_ADDR_LEN+1)+1)

static void dprint_multi_addr(
    IN uint32_t index,
    IN const multi_addr4 *addrs)
{
    char buffer[MULTI_ADDR_BUFFER_LEN] = "";
    uint32_t i;
    for (i = 0; i < addrs->count; i++) {
        StringCchCatA(buffer, MULTI_ADDR_BUFFER_LEN, addrs->arr[i].uaddr);
        StringCchCatA(buffer, MULTI_ADDR_BUFFER_LEN, " ");
    }
    dprintf_out("  servers[%d]:       [ '%s']\n", index, buffer);
}

void dprint_device(
    IN int level,
    IN const pnfs_file_device *device)
{
    uint32_t i;

    if (!DPRINTF_LEVEL_ENABLED(level))
        return;

    dprint_deviceid("  deviceid:         ", device->device.deviceid);
    dprintf_out("  type:             '%s'\n", pnfs_layout_type_string(device->device.type));
    dprintf_out("  stripes:          %u\n", device->stripes.count);
    for (i = 0; i < device->servers.count; i++)
        dprint_multi_addr(i, &device->servers.arr[i].addrs);
}
