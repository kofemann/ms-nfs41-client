/* NFSv4.1 client for Windows
 * Copyright © 2012 The Regents of the University of Michigan
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

#ifndef _DAEMON_DEBUG_
#define _DAEMON_DEBUG_

#ifdef _DEBUG
/* use visual studio's debug heap */
# define _CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <crtdbg.h>
#else
# include <stdlib.h>
#endif
#include <stdint.h>
#include <stdbool.h>

#define DEFAULT_DEBUG_LEVEL 1


/* 0xdd..dd is the filler by the debug memory allocator */
#ifdef _WIN64
#define DEBUG_IS_VALID_NON_NULL_PTR(ptr) \
    ( \
        (((char *)(ptr)) != ((char *)0xddddddddddddddddLL)) && \
        (((char *)(ptr)) != ((char *)0xffffffffffffffffLL)) && \
        ((ptr) != NULL) \
    )
#else
#define DEBUG_IS_VALID_NON_NULL_PTR(ptr) \
    ( \
        (((char *)(ptr)) != ((char *)0xddddddddL)) && \
        (((char *)(ptr)) != ((char *)0xffffffffL)) && \
        ((ptr) != NULL) \
    )
#endif /* _WIN64 */

#define EASSERT(exp) \
    if (!(exp)) { \
        DWORD d_saved_lasterr = GetLastError(); \
        eprintf("ASSERTION '%s' in '%s'/%ld failed.\n", \
            ""#exp"", __FILE__, (long)__LINE__); \
        SetLastError(d_saved_lasterr); \
    }
#define EASSERT_MSG(exp, msg) \
    if (!(exp)) { \
        DWORD d_saved_lasterr = GetLastError(); \
        eprintf("ASSERTION '%s' in '%s'/%ld failed, msg=", \
            ""#exp"", __FILE__, (long)__LINE__); \
        eprintf_out msg ; \
        SetLastError(d_saved_lasterr); \
    }
#define DASSERT(exp, level) \
    if (!(exp) && DPRINTF_LEVEL_ENABLED(level)) { \
        DWORD d_saved_lasterr = GetLastError(); \
        dprintf_out("ASSERTION '%s' in '%s'/%ld failed.\n", \
            ""#exp"", __FILE__, (long)__LINE__); \
        SetLastError(d_saved_lasterr); \
    }
#define DASSERT_MSG(exp, level, msg) \
    if (!(exp) && DPRINTF_LEVEL_ENABLED(level)) { \
        DWORD d_saved_lasterr = GetLastError(); \
        dprintf_out("ASSERTION '%s' in '%s'/%ld failed, msg=", \
            ""#exp"", __FILE__, (long)__LINE__); \
        dprintf_out msg ; \
        SetLastError(d_saved_lasterr); \
    }

#define DASSERT_IS_VALID_NON_NULL_PTR(exp, level) \
    if (!DEBUG_IS_VALID_NON_NULL_PTR(exp) && \
        DPRINTF_LEVEL_ENABLED(level)) { \
        DWORD d_saved_lasterr = GetLastError(); \
        dprintf_out("ASSERTION " \
            "!DEBUG_IS_VALID_NON_NULL_PTR('%s'=0x%p) " \
            "in '%s'/%ld failed.\n", \
            ""#exp"", (void *)(exp), __FILE__, (long)__LINE__); \
        SetLastError(d_saved_lasterr); \
    }

#define EASSERT_IS_VALID_NON_NULL_PTR(exp) \
    if (!DEBUG_IS_VALID_NON_NULL_PTR(exp)) { \
        DWORD d_saved_lasterr = GetLastError(); \
        eprintf("ASSERTION " \
            "!DEBUG_IS_VALID_NON_NULL_PTR('%s'=0x%p) " \
            "in '%s'/%ld failed.\n", \
            ""#exp"", (void *)(exp), __FILE__, (long)__LINE__); \
        SetLastError(d_saved_lasterr); \
    }

extern int g_debug_level;

#define DPRINTF_LEVEL_ENABLED(level) ((level) <= g_debug_level)
#define DPRINTF(level, args) \
    { \
        if (DPRINTF_LEVEL_ENABLED(level)) { \
            DWORD d_saved_lasterr = GetLastError(); \
            dprintf_out args; \
            SetLastError(d_saved_lasterr); \
        } \
    }

/* daemon_debug.h */
void set_debug_level(int level);
void logprintf(LPCSTR format, ...);
void dprintf_out(LPCSTR format, ...);
void eprintf_out(LPCSTR format, ...);
void eprintf(LPCSTR format, ...);

const char *map_nfs_ftype2str(int ftype);
const char *map_nfs_acetype2str(uint32_t ace_type);
void print_windows_access_mask(const char *label, ACCESS_MASK win_mask);
void print_nfs_access_mask(const char *label, uint32_t nfs_mask);
const char *nfs_mask2shortname(uint32_t nfs_mask);
const char *nfs_aceflag2shortname(uint32_t aceflag);
void print_hexbuf_no_asci(const char *title, const unsigned char *buf, int len);
void print_hexbuf(const char *title, const unsigned char *buf, int len);
void print_create_attributes(int level, DWORD create_opts);
void print_disposition(int level, DWORD disposition);
void print_access_mask(int level, DWORD access_mask);
void print_share_mode(int level, DWORD mode);
void print_file_id_both_dir_info(int level, const FILE_ID_BOTH_DIR_INFO *p);
void print_sid(const char *label, PSID sid);
typedef enum _nfs41_opcodes nfs41_opcodes;
const char* opcode2string(nfs41_opcodes opcode);
const char* nfs_opnum_to_string(int opnum);
const char* nfs_error_string(int status);
const char* rpc_error_string(int status);
const char* gssauth_string(int type);
const char* map_SID_NAME_USE2str(SID_NAME_USE snu);
const char *FILE_INFORMATION_CLASS2string(int fic);
void print_condwait_status(int level, int status);
void print_sr_status_flags(int level, int flags);
void open_log_files();
void close_log_files();
const char* secflavorop2name(DWORD sec_flavor);
void print_nfs41_file_info(const char *label, const void *vinfo);

/* pnfs_debug.c */
enum pnfs_status;
enum pnfs_layout_type;
enum pnfs_iomode;
struct __pnfs_file_layout;
struct __pnfs_file_device;

const char* pnfs_error_string(enum pnfs_status status);
const char* pnfs_layout_type_string(enum pnfs_layout_type type);
const char* pnfs_iomode_string(enum pnfs_iomode iomode);

void dprint_layout(int level, const struct __pnfs_file_layout *layout);
void dprint_device(int level, const struct __pnfs_file_device *device);

bool debug_ptr_was_recently_deleted(void *in_ptr);
void debug_ptr_add_recently_deleted(void *in_ptr);

void debug_delayed_free(void *in_ptr);

#endif
