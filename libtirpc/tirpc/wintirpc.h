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

#ifndef _TIRPC_WINTIRPC_H
#define _TIRPC_WINTIRPC_H

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif


/*
 * Eliminate warnings about possibly unsafe uses of snprintf and friends
 * XXX Think about cleaning these up and removing this later XXX
 */
#define _CRT_SECURE_NO_WARNINGS 1


#ifdef _DEBUG
/* use visual studio's debug heap */
# define _CRTDBG_MAP_ALLOC
# include <stdlib.h>
# include <stdbool.h>
# include <crtdbg.h>
#else
# include <stdlib.h>
# include <stdbool.h>
#endif

/* Common Windows includes */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#include <basetsd.h>
#include <fcntl.h>
#include <io.h>

/* warn about int to pointer */
#pragma warning (error : 4312)
/* conversion from 'int' to '_HFILE' of greater size */
#pragma warning (error : 4306)

//#define snprintf _snprintf
//#define vsnprintf _vsnprintf
#define strcasecmp _stricmp
/* ucrt/crtdbg.h might define |strdup()| to |_strdup_dbg()| */
#ifndef strdup
#define strdup _strdup
#endif
#define getpid _getpid

#define bcmp memcmp
#define bcopy(d,s,l) memcpy((d),(s),(l))
#define bzero(d,s) memset((d),0,(s))
#define strtok_r strtok_s

#define poll WSAPoll
#define ioctl ioctlsocket

#define __BEGIN_DECLS
#define __END_DECLS
#define __THROW

/*
 * Maximum integer value |_open()| and |_open_osfhandle()| can return
 *
 * Right now the Windows headers do not provide this as public value.
 *
 * https://github.com/ojdkbuild/tools_toolchain_sdk10_1607/blob/master/Source/10.0.14393.0/ucrt/inc/corecrt_internal_lowio.h#L94
 * defines it like this:
 * -- snip --
 * #define IOINFO_ARRAY_ELTS    (1 << IOINFO_L2E)
 * #define IOINFO_ARRAYS        128
 * #define _NHANDLE_            (IOINFO_ARRAYS * IOINFO_ARRAY_ELTS)
 * -- snip --
 * ... which makes |_NHANDLE_|==2^6*128==8192
 */
#define WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE (8192)

/* Safeguard */
#ifndef FD_SETSIZE
#error FD_SETSIZE not set
#endif
#if (FD_SETSIZE < 1024)
#error FD_SETSIZE should be at least 1024
#endif

/*
 * Functions imported from BSD
 */
struct timezone 
{
  int  tz_minuteswest; /* minutes W of Greenwich */
  int  tz_dsttime;     /* type of dst correction */
};

extern int gettimeofday(struct timeval *tv, struct timezone *tz);
extern int asprintf(char **str, const char *fmt, ...);

#ifndef _WIN32_WINNT
#error _WIN32_WINNT not defined
#endif /* !_WIN32_WINNT */

#if(_WIN32_WINNT < 0x0501)
#define SOL_IPV6 IPPROTO_IPV6
#endif

#define MAXHOSTNAMELEN 256

struct sockaddr_un {
	int sun_family;
	char sun_path[MAX_PATH];
};
/* Evaluate to actual length of the sockaddr_un structure */
/* XXX Should this return size_t or unsigned int ?? */
#define SUN_LEN(ptr) ((unsigned int)(sizeof(int) + strlen ((ptr)->sun_path)))

/*
 * Define our own version of signed |size_t| because Win32 does not
 * have |ssize_t|
 */
typedef SSIZE_T wintirpc_ssize_t;

/* Prototypes */
bool wintirpc_winsock_init(void);
int wintirpc_socket(int af,int type, int protocol);
int wintirpc_closesocket(int in_fd);
int wintirpc_close(int in_fd);
int wintirpc_listen(int in_s, int backlog);
int wintirpc_accept(int s_fd, struct sockaddr *addr, int *addrlen);
int wintirpc_bind(int s, const struct sockaddr *name, socklen_t namelen);
int wintirpc_connect(int s, const struct sockaddr *name, socklen_t namelen);
wintirpc_ssize_t wintirpc_send(int s, const char *buf, size_t len,
    int flags);
wintirpc_ssize_t wintirpc_sendto(int s, const char *buf, size_t len,
    int flags, const struct sockaddr *to, socklen_t tolen);
wintirpc_ssize_t wintirpc_recv(int socket, void *buffer, size_t length,
    int flags);
wintirpc_ssize_t wintirpc_recvfrom(int socket, void *restrict buffer,
    size_t length, int flags, struct sockaddr *restrict address,
    socklen_t *restrict address_len);
int wintirpc_getsockname(int s, struct sockaddr *name, int *namelen);
int wintirpc_getsockopt(int socket, int level, int option_name,
    void *restrict option_value, socklen_t *restrict option_len);
int wintirpc_setsockopt(int socket, int level, int option_name,
    const void *option_value, socklen_t option_len);
void wintirpc_setnfsclientsockopts(int sock);
void wintirpc_syslog(int prio, const char *format, ...);
void wintirpc_warnx(const char *format, ...);
void *wintirpc_mem_alloc(size_t s);
void wintirpc_mem_free(void *p);
void wintirpc_register_osfhandle_fd(SOCKET handle, int fd);
void wintirpc_unregister_osfhandle(SOCKET handle);
void wintirpc_unregister_osf_fd(int fd);
int wintirpc_sockethandle2fd(SOCKET handle);
SOCKET wintirpc_fd2sockethandle(int fd);

/* Debugging function */
void wintirpc_debug(char *fmt, ...);

/* Asserts */
#define assert(exp) \
    if (!(exp)) { \
        wintirpc_warnx("ASSERTION '%s' in '%s'/%ld failed.\n", \
            ""#exp"", __FILE__, (long)__LINE__); }

/* Mappings Windows API to |wintirpc_*()|-API */
#define warnx wintirpc_warnx
#define syslog wintirpc_syslog

/* syslog */
#ifndef LOG_EMERG
#define LOG_EMERG	0
#define LOG_ALERT	1
#define LOG_CRIT	2
#define LOG_ERR		3
#define LOG_WARNING	4
#define LOG_NOTICE	5
#define LOG_INFO	6
#define LOG_DEBUG	7
#endif /* !LOG_EMERG */

#define _LOG_PRIMASK     0x07

#define LOG_PRI(p)      ((p) & _LOG_PRIMASK)


#endif /* !_TIRPC_WINTIRPC_H */
