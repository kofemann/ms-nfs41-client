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

#include <Windows.h>
#include <stdio.h>

#include "nfs41_ops.h"
#include "name_cache.h"
#include "upcall.h"
#include "daemon_debug.h"
#include "util.h"

static int parse_queryallocatedranges(unsigned char *buffer,
    uint32_t length, nfs41_upcall *upcall)
{
    int status;
    queryallocatedranges_upcall_args *args = &upcall->args.queryallocatedranges;

    status = safe_read(&buffer, &length, &args->inrange, sizeof(args->inrange));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->outbuffersize, sizeof(args->outbuffersize));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->outbuffer, sizeof(args->outbuffer));
    if (status) goto out;

    DPRINTF(0, ("parse_queryallocatedranges: "
        "parsing '%s' inrange=(FileOffset=%lld Length=%lld) "
        "outbuffersize=%lu outbuffer=0x%p\n",
        opcode2string(upcall->opcode),
        args->inrange.FileOffset.QuadPart,
        args->inrange.Length.QuadPart,
        (unsigned long)args->outbuffersize,
        (void *)args->outbuffer));
out:
    return status;
}


static int handle_queryallocatedranges(void *daemon_context, nfs41_upcall *upcall)
{
    queryallocatedranges_upcall_args *args =
        &upcall->args.queryallocatedranges;
    nfs41_open_state *state = upcall->state_ref;
    PFILE_ALLOCATED_RANGE_BUFFER outbuffer =
        (PFILE_ALLOCATED_RANGE_BUFFER)args->outbuffer;
    int status = ERROR_INVALID_PARAMETER;
    nfs41_file_info info;

    DPRINTF(0,
        ("--> handle_queryallocatedranges("
            "state->path.path='%s')\n",
            state->path.path));

    DPRINTF(0,
        ("handle_queryallocatedranges:"
            "got space for %ld records\n",
            (int)((size_t)args->outbuffersize / sizeof(FILE_ALLOCATED_RANGE_BUFFER))));

    args->returned_size = 0;

    (void)memset(&info, 0, sizeof(info));

    status = nfs41_cached_getattr(state->session,
        &state->file, &info);
    if (status)
        goto out;

    if (args->outbuffersize < (1*sizeof(FILE_ALLOCATED_RANGE_BUFFER))) {
        /* FIXME: We should return the size of the required buffer */
        status = ERROR_INSUFFICIENT_BUFFER;
        goto out;
    }

    /* return size of file */
    outbuffer[0].FileOffset.QuadPart = 0;
    outbuffer[0].Length.QuadPart = info.size;
    args->returned_size = 1*sizeof(FILE_ALLOCATED_RANGE_BUFFER);
    status = NO_ERROR;

out:
    DPRINTF(0, ("<-- handle_queryallocatedranges(), status=0x%lx\n", status));
    return status;
}

static int marshall_queryallocatedranges(unsigned char *buffer,
    uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    queryallocatedranges_upcall_args *args = &upcall->args.queryallocatedranges;

    status = safe_write(&buffer, length, &args->returned_size, sizeof(args->returned_size));

    return status;
}

const nfs41_upcall_op nfs41_op_queryallocatedranges = {
    .parse = parse_queryallocatedranges,
    .handle = handle_queryallocatedranges,
    .marshall = marshall_queryallocatedranges,
    .arg_size = sizeof(queryallocatedranges_upcall_args)
};
