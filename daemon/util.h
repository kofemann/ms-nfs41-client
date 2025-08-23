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

#ifndef __NFS41_DAEMON_UTIL_H__
#define __NFS41_DAEMON_UTIL_H__ 1

#include <stdlib.h>
#include <stdbool.h>

#include "nfs41_build_features.h"
#include "nfs41_types.h"
#include "from_kernel.h"

extern DWORD NFS41D_VERSION;
struct __nfs41_session;
struct __nfs41_write_verf;
typedef struct __nfs41_open_state nfs41_open_state;
typedef struct __nfs41_file_info nfs41_file_info;
typedef struct __nfs41_superblock nfs41_superblock;
enum stable_how4;

/*
 * UTIL_GETRELTIME - Get a relative time stamp
 * |GetTickCount64()| is almost twice as fast as |time()|, and
 * cache code only needs a relative timestamp and not the
 * absolute time to implement cache element expiration.
 * |GetTickCount64()| also includes time spend in hibernation&co.,
 * so hibernation longer than |NAME_CACHE_EXPIRATION| will
 * automagically invalidate the cache
 */
#define UTIL_GETRELTIME() (GetTickCount64()/1000ULL)
#define UTIL_DIFFRELTIME(t1, t2) \
    (((signed long long)(t1))-((signed long long)(t2)))
typedef ULONGLONG util_reltimestamp;

#define PTR2PTRDIFF_T(p) ((ptrdiff_t)((char *)((void *)(p)) - ((char *)0)))
#define PTRDIFF_T2PTR(d) ((void *)(((char *)0) + (d)))

#define EA_NEXT_ENTRY(ea) ((PBYTE)(ea) + (ea)->NextEntryOffset)
#define EA_VALUE(ea) \
    ((void *)((unsigned char *)(ea)->EaName + (ea)->EaNameLength + 1))

char *stpcpy(char *restrict s1, const char *restrict s2);

static __inline
void *mempcpy(void *restrict dest, const void *restrict src, size_t n)
{
    (void)memcpy(dest, src, n);
    return (void *)((char *)dest + n);
}

static __inline
void *memrchr(const void * restrict s, int c, size_t n)
{
    const unsigned char *cp;

    if (n == 0UL)
        return NULL;

    cp = (const unsigned char *)s + n;
    do {
        if (*(--cp) == (unsigned char)c) {
            return((void *)cp);
        }
    } while (--n != 0UL);

    return NULL;
}

int safe_read(unsigned char **pos, uint32_t *remaining, void *dest, uint32_t dest_len);
int safe_write(unsigned char **pos, uint32_t *remaining, void *dest, uint32_t dest_len);
int get_safe_write_bufferpos(unsigned char **pos, uint32_t *remaining,
    uint32_t src_len, void **destbuffer);
int get_name(unsigned char **pos, uint32_t *remaining, const char **out_name);

const char* strip_path(
    IN const char *path,
    OUT uint32_t *len_out OPTIONAL);

uint32_t max_read_size(
    IN const struct __nfs41_session *session,
    IN const nfs41_fh *fh);
uint32_t max_write_size(
    IN const struct __nfs41_session *session,
    IN const nfs41_fh *fh);

bool_t verify_write(
    IN nfs41_write_verf *verf,
    IN OUT enum stable_how4 *stable);
bool_t verify_commit(
    IN nfs41_write_verf *verf);

/* bitmap4 */
static __inline bool bitmap_isset(
    IN const bitmap4 *restrict mask,
    IN uint32_t word,
    IN uint32_t flag)
{
    return ((mask->count > word) && (mask->arr[word] & flag))?true:false;
}
static __inline void bitmap_set(
    IN bitmap4 *restrict mask,
    IN uint32_t word,
    IN uint32_t flag)
{
    if (mask->count > word)
        mask->arr[word] |= flag;
    else {
        mask->count = word + 1;
        mask->arr[word] = flag;
    }
}
static __inline void bitmap_unset(
    IN bitmap4 *restrict mask,
    IN uint32_t word,
    IN uint32_t flag)
{
    if (mask->count > word) {
        mask->arr[word] &= ~flag;
        while (mask->count && mask->arr[mask->count-1] == 0)
            mask->count--;
    }
}
static __inline void bitmap_intersect(
    IN bitmap4 *restrict dst,
    IN const bitmap4 *restrict src)
{
    uint32_t i, count = 0;
    for (i = 0; i < BITMAP4_MAXCOUNT; i++) {
        dst->arr[i] = ((i < dst->count)?dst->arr[i]:0) & ((i < src->count)?src->arr[i]:0);
        if (dst->arr[i])
            count = i+1;
    }
    dst->count = min(dst->count, count);
}
static __inline void bitmap_or(
    IN bitmap4 *restrict dst,
    IN const bitmap4 *restrict src)
{
    uint32_t i, count = 0;
    for (i = 0; i < BITMAP4_MAXCOUNT; i++) {
        dst->arr[i] = ((i < dst->count)?dst->arr[i]:0) | ((i < src->count)?src->arr[i]:0);
        if (dst->arr[i])
            count = i+1;
    }
    dst->count = min(dst->count, count);
}

static __inline void bitmap4_cpy(
    OUT bitmap4 *restrict dst,
    IN  const bitmap4 *restrict src)
{
    uint32_t i;
    for (i = 0; i < src->count; i++) {
        dst->arr[i] = src->arr[i];
    }
    dst->count = src->count;
}

static __inline void bitmap4_clear(
    OUT bitmap4 *restrict dst)
{
    /*
     * gisburn: FIXME: Only set the count field to 0, and use
     * Rational Purify/DrMemory to see if someone does not play
     * by the rules
     */
    (void)memset(dst, 0, sizeof(bitmap4));
}

static __inline void stateid4_cpy(
    OUT stateid4 *restrict dst,
    IN  const stateid4 *restrict src)
{
    (void)memcpy(dst, src, sizeof(stateid4));
}

static __inline void stateid4_clear(
    OUT stateid4 *restrict dst)
{
    (void)memset(dst, 0, sizeof(stateid4));
}

static __inline int stateid4_cmp(
    IN  const stateid4 *restrict s1,
    IN  const stateid4 *restrict s2)
{
    if (s1->seqid > s2->seqid)
        return 1;
    else if (s1->seqid < s2->seqid)
        return -1;
    else
        return memcmp(s1->other, s2->other, NFS4_STATEID_OTHER);
}

static __inline int nfs41_fsid_cmp(
    IN const nfs41_fsid *restrict s1,
    IN const nfs41_fsid *restrict s2)
{
    if (s1->major > s2->major)
        return 1;
    else if (s1->major < s2->major)
        return -1;
    else if (s1->minor > s2->minor)
        return 1;
    else if (s1->minor < s2->minor)
        return -1;
    else
        return 0;
}

/*
 * |nfs41_fsid2VolumeSerialNumber32()| - used for
 * |FILE_FS_VOLUME_INFORMATION.VolumeSerialNumber|, which is a 32bit |ULONG|
 */
static __inline ULONG nfs41_fsid2VolumeSerialNumber32(
    IN const nfs41_fsid *restrict fsid)
{
    ULONG vsn;
#define XOR_UINT64_WORDS(value) (((value) >> 32UL) ^ ((value) & 0x00000000FFFFFFFF))
    vsn = (ULONG)(XOR_UINT64_WORDS(fsid->major) ^ XOR_UINT64_WORDS(fsid->minor));
    return vsn;
}

/*
 * |nfs41_fsid2VolumeSerialNumber64()| - used for
 * |FILE_ID_INFORMATION.VolumeSerialNumber|, which is a 64bit |ULONGLONG|
 */
static __inline ULONGLONG nfs41_fsid2VolumeSerialNumber64(
    IN const nfs41_fsid *restrict fsid)
{
    ULONGLONG vsn;
    vsn = fsid->major ^ fsid->minor;
    return vsn;
}

static __inline void open_delegation4_cpy(
    OUT open_delegation4 *restrict dst,
    IN  const open_delegation4 *restrict src)
{
    (void)memcpy(dst, src, sizeof(open_delegation4));
}

/* http://msdn.microsoft.com/en-us/library/ms724290%28VS.85%29.aspx:
 * A file time is a 64-bit value that represents the number of
 * 100-nanosecond intervals that have elapsed since 12:00 A.M.
 * January 1, 1601 Coordinated Universal Time (UTC). */
#define FILETIME_EPOCH 116444736000000000LL

static __inline void file_time_to_nfs_time(
    IN const PLARGE_INTEGER restrict file_time,
    OUT nfstime4 *restrict nfs_time)
{
    LONGLONG diff = file_time->QuadPart - FILETIME_EPOCH;
    nfs_time->seconds = diff / 10000000;
    nfs_time->nseconds = (uint32_t)((diff % 10000000)*100);
}

static __inline void nfs_time_to_file_time(
    IN const nfstime4 *restrict nfs_time,
    OUT PLARGE_INTEGER restrict file_time)
{
    file_time->QuadPart = FILETIME_EPOCH +
        nfs_time->seconds * 10000000 +
        nfs_time->nseconds / 100;
}

void get_file_time(
    OUT PLARGE_INTEGER restrict file_time);
void get_nfs_time(
    OUT nfstime4 *restrict nfs_time);

static __inline void nfstime_normalize(
    IN OUT nfstime4 *restrict nfstime)
{
    /* return time in normalized form (0 <= nsec < 1s) */
    while ((int32_t)nfstime->nseconds < 0) {
        nfstime->nseconds += 1000000000;
        nfstime->seconds--;
    }
}
static __inline void nfstime_diff(
    IN const nfstime4 *restrict lhs,
    IN const nfstime4 *restrict rhs,
    OUT nfstime4 *result)
{
    /* result = lhs - rhs */
    result->seconds = lhs->seconds - rhs->seconds;
    result->nseconds = lhs->nseconds - rhs->nseconds;
    nfstime_normalize(result);
}
static __inline void nfstime_abs(
    IN const nfstime4 *restrict nt,
    OUT nfstime4 *restrict result)
{
    if (nt->seconds < 0) {
        const nfstime4 zero = { .seconds=0LL, .nseconds=0UL };
        nfstime_diff(&zero, nt, result); /* result = 0 - nt */
    } else if (result != nt)
        memcpy(result, nt, sizeof(nfstime4));
}


int create_silly_rename(
    IN nfs41_abs_path *path,
    IN const nfs41_fh *fh,
    OUT nfs41_component *silly);

bool_t multi_addr_find(
    IN const multi_addr4 *addrs,
    IN const netaddr4 *addr,
    OUT OPTIONAL uint32_t *index_out);

/* nfs_to_windows_error
 *   Returns a windows ERROR_ code corresponding to the given NFS4ERR_ status.
 * If the status is outside the range of valid NFS4ERR_ values, it is returned
 * unchanged.  Otherwise, if the status does not match a value in the mapping,
 * a debug warning is generated and the default_error value is returned.
 */
int nfs_to_windows_error(int status, int default_error);

int map_symlink_errors(int status);

__inline uint32_t align8(uint32_t offset) {
    return 8 + ((offset - 1) & ~7);
}
__inline uint32_t align4(uint32_t offset) {
    return 4 + ((offset - 1) & ~3);
}

/* path parsing */
__inline int is_delimiter(char c) {
    return c == '\\' || c == '/' || c == '\0';
}
__inline const char* next_delimiter(const char *pos, const char *end) {
    while (pos < end && !is_delimiter(*pos))
        pos++;
    return pos;
}
__inline const char* prev_delimiter(const char *pos, const char *start) {
    while (pos > start && !is_delimiter(*pos))
        pos--;
    return pos;
}
__inline const char* next_non_delimiter(const char *pos, const char *end) {
    while (pos < end && is_delimiter(*pos))
        pos++;
    return pos;
}
__inline const char* prev_non_delimiter(const char *pos, const char *start) {
    while (pos > start && is_delimiter(*pos))
        pos--;
    return pos;
}

bool_t next_component(
    IN const char *path,
    IN const char *path_end,
    OUT nfs41_component *component);

bool_t last_component(
    IN const char *path,
    IN const char *path_end,
    OUT nfs41_component *component);

bool_t is_last_component(
    IN const char *path,
    IN const char *path_end);

void abs_path_copy(
    OUT nfs41_abs_path *dst,
    IN const nfs41_abs_path *src);

void path_fh_init(
    OUT nfs41_path_fh *file,
    IN nfs41_abs_path *path);

void fh_copy(
    OUT nfs41_fh *dst,
    IN const nfs41_fh *src);

void path_fh_copy(
    OUT nfs41_path_fh *dst,
    IN const nfs41_path_fh *src);

__inline int valid_handle(HANDLE handle) {
    return handle != INVALID_HANDLE_VALUE && handle != 0;
}

typedef struct _subcmd_popen_context {
    HANDLE hReadPipe;
    HANDLE hWritePipe;
    PROCESS_INFORMATION pi;
} subcmd_popen_context;

subcmd_popen_context *subcmd_popen(const char *command);
int subcmd_pclose(subcmd_popen_context *pinfo);
BOOL subcmd_readcmdoutput(subcmd_popen_context *pinfo, char *buff, size_t buff_size, DWORD *num_buff_read_ptr);

bool_t waitSRWlock(PSRWLOCK srwlock);
bool_t waitcriticalsection(LPCRITICAL_SECTION cs);

bool getwinntversionnnumbers(DWORD *MajorVersionPtr, DWORD *MinorVersionPtr, DWORD *BuildNumberPtr);

int nfs41_cached_getchangeattr(nfs41_open_state *state, nfs41_file_info *restrict info);

int parse_fs_location_server_address(IN const char *restrict inaddr,
    OUT char *restrict addr,
    OUT unsigned short *restrict port);

#endif /* !__NFS41_DAEMON_UTIL_H__ */
