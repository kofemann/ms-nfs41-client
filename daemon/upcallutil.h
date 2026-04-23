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

#ifndef __NFS41_DAEMON_UPCALLUTIL_H__
#define __NFS41_DAEMON_UPCALLUTIL_H__ 1

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>

#include "daemon_debug.h"

/*
 * Force inlining of |memcpy()| for up-/downcall buffers
 */
#if defined(_MSC_BUILD)
#if defined(_M_IX86) || defined(_M_X64)
#pragma intrinsic(__movsb)
#define UPCALLUTIL_MEMCPY(dst, src, len) \
    __movsb((void *)(dst), (const void *)(src), (len))
#elif defined(_M_ARM) || defined(_M_ARM64)
#pragma intrinsic(memcpy)
#define UPCALLUTIL_MEMCPY(dst, src, len) \
    (void)memcpy((dst), (src), (len))
#else
#error Unsupported architecture
#endif
#elif defined(__clang__)
#define UPCALLUTIL_MEMCPY(dst, src, len) \
    (void)memcpy((dst), (src), (len))
#else
#error Compiler not supported yet
#endif

static __forceinline
int safe_read(const unsigned char *restrict *restrict pos,
    uint32_t *restrict remaining, void *dest, uint32_t dest_len)
{
    if (*remaining < dest_len)
        return ERROR_BUFFER_OVERFLOW;

    UPCALLUTIL_MEMCPY(dest, *pos, dest_len);
    *pos += dest_len;
    *remaining -= dest_len;
    return 0;
}

/*
 * |get_safe_read_bufferpos()| - like |safe_read()| but tests whether we
 * have enough buffer space left, and in that case return current buffer
 * position in |destbuffer|
 */
static __forceinline
int get_safe_read_bufferpos(const unsigned char *restrict *restrict pos,
    uint32_t *restrict remaining, uint32_t src_len, const void **destbuffer)
{
    if (*remaining < src_len)
        return ERROR_BUFFER_OVERFLOW;

    *destbuffer = (src_len == 0)?NULL:*pos;
    *pos += src_len;
    *remaining -= src_len;
    return ERROR_SUCCESS;
}

static __forceinline
int get_name(const unsigned char *restrict *restrict pos,
    uint32_t *restrict remaining, const char *restrict *restrict out_name)
{
    int status;
    USHORT len;
    const char *name;

    status = safe_read(pos, remaining, &len, sizeof(USHORT));
    if (status) goto out;
    if (*remaining < len) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }

    name = (const char *)*pos;

    EASSERT_MSG((name[len-1] == '\0'),
        ("name='%s', (len-1)=%d, expected 0x00, got 0x%x\n",
        name, (int)(len-1), (int)name[len-1]));

    *out_name = name;
    *pos += len;
    *remaining -= len;

out:
    return status;
}

static __forceinline
int safe_write(unsigned char *restrict *restrict pos,
    uint32_t *restrict remaining, const void *src, uint32_t src_len)
{
    if (*remaining < src_len)
        return ERROR_BUFFER_OVERFLOW;

    UPCALLUTIL_MEMCPY(*pos, src, src_len);
    *pos += src_len;
    *remaining -= src_len;
    return 0;
}

/*
 * |get_safe_write_bufferpos()| - like |safe_write()| but tests whether we
 * have enough buffer space left, and in that case return current buffer
 * position in |destbuffer|
 */
static __forceinline
int get_safe_write_bufferpos(unsigned char *restrict *restrict pos,
    uint32_t *restrict remaining, uint32_t src_len, void **destbuffer)
{
    if (*remaining < src_len)
        return ERROR_BUFFER_OVERFLOW;

    *destbuffer = (src_len == 0)?NULL:*pos;
    *pos += src_len;
    *remaining -= src_len;
    return ERROR_SUCCESS;
}

#endif /* !__NFS41_DAEMON_UPCALLUTIL_H__ */
