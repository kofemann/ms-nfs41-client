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

#define DEFAULT_DEBUG_LEVEL 1


/* 0xdd..dd is the filler by the debug memory allocator */
#define DEBUG_IS_VALID_NON_NULL_PTR(ptr) \
    ( \
        (((char *)(ptr)) != ((char *)0xddddddddddddddddLL)) && \
        (((char *)(ptr)) != ((char *)0xffffffffffffffffLL)) && \
        ((ptr) != NULL) \
    )

#define EASSERT(exp) \
    if (!(exp)) { \
        eprintf("ASSERTION '%s' in '%s'/%ld failed.\n", \
            ""#exp"", __FILE__, (long)__LINE__); }
#define DASSERT(exp, level) \
    if (!(exp)) { \
        DPRINTF((level), ("ASSERTION '%s' in '%s'/%ld failed.\n", \
            ""#exp"", __FILE__, (long)__LINE__)); }

#define DASSERT_IS_VALID_NON_NULL_PTR(exp, level) \
    if (!DEBUG_IS_VALID_NON_NULL_PTR(exp)) { \
        DPRINTF((level), ("ASSERTION " \
            "!DEBUG_IS_VALID_NON_NULL_PTR('%s'=0x%p) " \
            "in '%s'/%ld failed.\n", \
            ""#exp"", (void *)(exp), __FILE__, (long)__LINE__)); }

#define EASSERT_IS_VALID_NON_NULL_PTR(exp) \
    if (!DEBUG_IS_VALID_NON_NULL_PTR(exp)) { \
        eprintf("ASSERTION " \
            "!DEBUG_IS_VALID_NON_NULL_PTR('%s'=0x%p) " \
            "in '%s'/%ld failed.\n", \
            ""#exp"", (void *)(exp), __FILE__, (long)__LINE__); }

extern int g_debug_level;

#define DPRINTF_LEVEL_ENABLED(level) ((level) <= g_debug_level)
#define DPRINTF(level, args) \
    { \
        if (DPRINTF_LEVEL_ENABLED(level)) { \
            dprintf_out args; \
        } \
    }

/* daemon_debug.h */
void set_debug_level(int level);
void logprintf(LPCSTR format, ...);
void dprintf_out(LPCSTR format, ...);
void eprintf(LPCSTR format, ...);

void print_windows_access_mask(int on, ACCESS_MASK m);
void print_nfs_access_mask(int on, int m);
void print_hexbuf_no_asci(int on, unsigned char *title, unsigned char *buf, int len);
void print_hexbuf(int level, unsigned char *title, unsigned char *buf, int len);
void print_create_attributes(int level, DWORD create_opts);
void print_disposition(int level, DWORD disposition);
void print_access_mask(int level, DWORD access_mask);
void print_share_mode(int level, DWORD mode);
void print_file_id_both_dir_info(int level, FILE_ID_BOTH_DIR_INFO *p);
void print_sid(const char *label, PSID sid);
const char* opcode2string(DWORD opcode);
const char* nfs_opnum_to_string(int opnum);
const char* nfs_error_string(int status);
const char* rpc_error_string(int status);
const char* gssauth_string(int type);
void print_condwait_status(int level, int status);
void print_sr_status_flags(int level, int flags);
void open_log_files();
void close_log_files();
const char* secflavorop2name(DWORD sec_flavor);

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

#endif
