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

#include <wintirpc.h>
#include <rpc/rpc.h>
#include <stdio.h>
#include <winsock.h>

#include "../../nfs41_build_features.h"

WSADATA WSAData;

static int init = 0;
static DWORD dwTlsIndex;

extern void multithread_init(void);

void tirpc_criticalsection_init(void) {
	multithread_init();
}

bool wintirpc_winsock_init(void)
{
	int err;
	err = WSAStartup(MAKEWORD(2, 2), &WSAData);
	if (err != 0) {
		init = 0;
		(void)fprintf(stderr, "winsock_init: WSAStartup failed!\n");
		WSACleanup();
		return false;
	}
	return true;
}

BOOL winsock_fini(void)
{
	WSACleanup();
	return TRUE;
}

BOOL WINAPI DllMain/*tirpc_main*/(HINSTANCE hinstDLL,	// DLL module handle
					   DWORD fdwReason,	// reason called
					   LPVOID lpvReserved)	// reserved
{
	LPVOID lpvData; 
	BOOL fIgnore; 

//	if (init++)
//		return TRUE;

	// Deal with Thread Local Storage initialization!!
	switch (fdwReason) 
    {
		// The DLL is loading due to process
		// initialization or a call to LoadLibrary.
        case DLL_PROCESS_ATTACH:
            // Do NOT init WinSock here, it is not legal and AppVerifer will complain
            // Initialize CriticalSections
            tirpc_criticalsection_init();

            // Allocate a TLS index.
            if ((dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES)
                return FALSE; 
 
            // No break: Initialize the index for first thread.
 
        // The attached process creates a new thread. 
        case DLL_THREAD_ATTACH: 
 
            // Initialize the TLS index for this thread
            lpvData = (LPVOID) LocalAlloc(LPTR, 256); 
            if (lpvData != NULL) 
                fIgnore = TlsSetValue(dwTlsIndex, lpvData); 
 
            break; 
 
        // The thread of the attached process terminates.
        case DLL_THREAD_DETACH: 
 
            // Release the allocated memory for this thread.
            lpvData = TlsGetValue(dwTlsIndex); 
            if (lpvData != NULL) 
                LocalFree((HLOCAL) lpvData); 
 
            break; 
 
        // DLL unload due to process termination or FreeLibrary. 
        case DLL_PROCESS_DETACH: 
 
            // Release the allocated memory for this thread.
            lpvData = TlsGetValue(dwTlsIndex); 
            if (lpvData != NULL) 
                LocalFree((HLOCAL) lpvData); 
 
            // Release the TLS index.
            TlsFree(dwTlsIndex);

            // Clean up winsock stuff
	    // FIXME: This is not legal in DllMain, we should use
	    // recounting instead
            winsock_fini();

            break;

        default: 
            break; 
    } 


	return TRUE;
}

struct map_osfhandle_fd
{
	SOCKET	m_s;
	int	m_fd;
};

static
struct map_osfhandle_fd handle_fd_map[WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE];

void wintirpc_register_osfhandle_fd(SOCKET handle, int fd)
{
	assert(handle != 0);
	assert(handle != SOCKET_ERROR);
	assert(fd < WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE);

	handle_fd_map[fd].m_fd = fd;
	handle_fd_map[fd].m_s = handle;
}

void wintirpc_unregister_osfhandle(SOCKET handle)
{
	int i;

	assert(handle != 0);
	assert(handle != SOCKET_ERROR);

	if ((handle == 0) || (handle != SOCKET_ERROR))
		return;

	for (i=0 ; i < WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE ; i++) {
		if (handle_fd_map[i].m_s == handle) {
			handle_fd_map[i].m_s = SOCKET_ERROR;
			handle_fd_map[i].m_fd = -1;
			return;
		}
	}
	(void)fprintf(stderr, "wintirpc_unregister_osfhandle: failed\n");
}

void wintirpc_unregister_osf_fd(int fd)
{
	int i;

	assert(fd >= 0);
	if (fd < 0)
		return;

	for (i=0 ; i < WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE ; i++) {
		if (handle_fd_map[i].m_fd == fd) {
			handle_fd_map[i].m_s = SOCKET_ERROR;
			handle_fd_map[i].m_fd = -1;
			return;
		}
	}
	(void)fprintf(stderr, "wintirpc_unregister_osf_fd: failed\n");
}

int wintirpc_handle2fd(SOCKET handle)
{
	int i;

	assert(handle != 0);
	assert(handle != SOCKET_ERROR);

	for (i=0 ; i < WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE ; i++) {
		if ((handle_fd_map[i].m_s == handle) &&
			(handle_fd_map[i].m_fd != -1)) {
			return handle_fd_map[i].m_fd;
		}
	}

	(void)fprintf(stderr, "wintirpc_handle2fd: failed\n");
	return -1;
}

int wintirpc_socket(int af, int type, int protocol)
{
	SOCKET s;

	s = socket(af, type, protocol);
	if (s == INVALID_SOCKET) {
		(void)fprintf(stderr, "wintirpc_socket: INVALID_SOCKET\n");
		return -1;
	}

	int fd = _open_osfhandle(s, _O_BINARY);
	if (fd < 0) {
		(void)closesocket(s);
		/*
		 * |_open_osfhandle()| may not set |errno|, and
		 * |closesocket()| may override it
		 */
		(void)fprintf(stderr, "wintirpc_socket: failed\n");
		errno = ENOMEM;
		return -1;
	}

	if (fd >= WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE) {
		(void)_close(fd);
		(void)fprintf(stderr, "wintirpc_socket: fd overflow %d >= %d\n",
			fd,
			WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE);
		errno = ENOMEM;
		return -1;
	}

	wintirpc_register_osfhandle_fd(s, fd);

	(void)syslog(LOG_DEBUG, "wintirpc_socket: %s/%d: sock fd=%d",
		__FILE__, (int)__LINE__, fd);

	return fd;
}

int wintirpc_closesocket(int in_fd)
{
	SOCKET s = _get_osfhandle(in_fd);

	(void)syslog(LOG_DEBUG, "wintirpc_closesocket(in_fd=%d)", in_fd);

	wintirpc_unregister_osfhandle(s);

	return closesocket(s);
}

int wintirpc_close(int in_fd)
{
	(void)syslog(LOG_DEBUG, "wintirpc_close(in_fd=%d)", in_fd);

	wintirpc_unregister_osf_fd(in_fd);

	return _close(in_fd);
}

int wintirpc_listen(int in_s, int backlog)
{
	return listen(_get_osfhandle(in_s), backlog);
}

int wintirpc_accept(int in_s_fd, struct sockaddr *addr, int *addrlen)
{
	SOCKET in_s;
	SOCKET out_s;
	int out_s_fd;

	in_s = _get_osfhandle(in_s_fd);

	out_s = accept(in_s, addr, addrlen);

	out_s_fd = _open_osfhandle(out_s, _O_BINARY);
	if (out_s_fd < 0) {
		(void)closesocket(out_s);
		/*
		 * |_open_osfhandle()| may not set |errno|, and
		 * |closesocket()| may override it
		 */
		(void)fprintf(stderr, "wintirpc_accept: failed\n");
		errno = ENOMEM;
		return -1;
	}

	if (out_s_fd >= WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE) {
		(void)_close(out_s_fd);
		(void)fprintf(stderr, "wintirpc_accept: out_s_fd overflow %d >= %d\n",
			out_s_fd,
			WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE);
		errno = ENOMEM;
		return -1;
	}

	wintirpc_register_osfhandle_fd(out_s, out_s_fd);

	return out_s_fd;
}

int wintirpc_bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	return bind(_get_osfhandle(s), name, namelen);
}

int wintirpc_connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	return connect(_get_osfhandle(s), name, namelen);
}

wintirpc_ssize_t wintirpc_send(int s, const char *buf, size_t len, int flags)
{
	/* handle type overflow |size_t| ---> |int| */
	assert(len < INT_MAX);
	return send(_get_osfhandle(s), buf, (int)len, flags);
}

wintirpc_ssize_t wintirpc_sendto(int s, const char *buf, size_t len, int flags,
	const struct sockaddr *to, socklen_t tolen)
{
	/* handle type overflow |size_t| ---> |int| */
	assert(len < INT_MAX);
	return(sendto(_get_osfhandle(s), buf, (int)len, flags, to, tolen));
}

wintirpc_ssize_t wintirpc_recv(int socket, void *buffer, size_t length, int flags)
{
	/* handle type overflow |size_t| ---> |int| */
	assert(length < INT_MAX);
	return recv(_get_osfhandle(socket), buffer, (int)length, flags);
}

wintirpc_ssize_t wintirpc_recvfrom(int socket, void *restrict buffer, size_t length,
	int flags, struct sockaddr *restrict address,
	socklen_t *restrict address_len)
{
	/* handle type overflow |size_t| ---> |int| */
	assert(length < INT_MAX);
	return recvfrom(_get_osfhandle(socket), buffer, (int)length,
		flags, address, address_len);
}

int wintirpc_getsockname(int s, struct sockaddr *name, int *namelen)
{
	return getsockname(_get_osfhandle(s), name, namelen);
}

int wintirpc_getsockopt(int socket, int level, int option_name,
	void *restrict option_value, socklen_t *restrict option_len)
{
	return getsockopt(_get_osfhandle(socket), level, option_name,
		option_value, option_len);
}

int wintirpc_setsockopt(int socket, int level, int option_name,
	const void *option_value, socklen_t option_len)
{
	return setsockopt(_get_osfhandle(socket), level, option_name,
		option_value, option_len);
}

void wintirpc_setnfsclientsockopts(int sock)
{
	DWORD one;
	int rcvbufvalue;
	int sndbufvalue;
	socklen_t bufsize;

	one = 1;
	/* XXX fvdl - is this useful? */
	if (wintirpc_setsockopt(sock, IPPROTO_TCP, TCP_NODELAY,
		(const char *)&one, sizeof(one)))
		wintirpc_warnx("wintirpc_setnfsclientsockopts(sock=%d):"
			" Error setting TCP_NODELAY\n", sock);

	/* gisburn: Is this useful ? */
	one = 1;
	if (wintirpc_setsockopt(sock, IPPROTO_TCP, TCP_TIMESTAMPS,
		(const char *)&one, sizeof(one)))
		wintirpc_warnx("wintirpc_setnfsclientsockopts(sock=%d):"
			" Error setting TCP_TIMESTAMPS\n", sock);

#ifdef NFS41_DRIVER_USE_LARGE_SOCKET_RCVSND_BUFFERS
	/*
	 * Print default values
	 */
	rcvbufvalue = 0;
	bufsize = sizeof(rcvbufvalue);
	if (wintirpc_getsockopt(sock, SOL_SOCKET, SO_RCVBUF,
		(char *)&rcvbufvalue, &bufsize))
		wintirpc_warnx("wintirpc_setnfsclientsockopts(sock=%d):"
			" Error getting SO_RCVBUF\n", sock);

	sndbufvalue = 0;
	bufsize = sizeof(sndbufvalue);
	if (wintirpc_getsockopt(sock, SOL_SOCKET, SO_SNDBUF,
		(char *)&sndbufvalue, &bufsize))
		wintirpc_warnx("wintirpc_setnfsclientsockopts(sock=%d):"
			" Error getting SO_SNDBUF\n", sock);

#ifdef _DEBUG
	(void)printf("wintirpc_setnfsclientsockopts(sock=%d): "
		"SO_RCVBUF=%d\n", sock, (int)rcvbufvalue);
	(void)printf("wintirpc_setnfsclientsockopts(sock=%d): "
		"SO_SNDBUF=%d\n", sock, (int)sndbufvalue);
#endif

	/*
	 * Set socket rcv and snd buffer sizes to 8M if the current
	 * value is smaller
	 *
	 * Windows 10 defaults to 64k, which is far too small for most
	 * NFS read&&write requests, which causes significant delays
	 * for each request
	 *
	 * Using a large static buffer avoids the erratic behaviour
	 * caused by automatic scaling, and avoids that the code
	 * spends lots of time waiting for the data to be split into
	 * smaller chunks - this results in much reduced latency.
	 *
	 * Another benefit is that this gives a larger TCP window
	 * (as Windows has no public API to set the TCP window size
	 * per socket), resulting in better performance over WLAN
	 * connections.
	 */
#define NFSRV_TCPSOCKBUF (8 * 1024 * 1024)

	if (rcvbufvalue < NFSRV_TCPSOCKBUF) {
		rcvbufvalue = NFSRV_TCPSOCKBUF;
		bufsize = sizeof(rcvbufvalue);
		if (wintirpc_setsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			(const char *)&rcvbufvalue, sizeof(bufsize)))
			wintirpc_warnx(
				"wintirpc_setnfsclientsockopts(sock=%d): "
				"Error setting SO_RCVBUF\n", sock);

		rcvbufvalue = 0;
		bufsize = sizeof(rcvbufvalue);
		if (wintirpc_getsockopt(sock, SOL_SOCKET, SO_RCVBUF,
			(char *)&rcvbufvalue, &bufsize))
			wintirpc_warnx(
				"wintirpc_setnfsclientsockopts(sock=%d): "
				"Error getting SO_RCVBUF\n", sock);

		if (rcvbufvalue != NFSRV_TCPSOCKBUF) {
			wintirpc_warnx(
				"wintirpc_setnfsclientsockopts(sock=%d): "
				"SO_RCVBUF expected size=%d, got size=%d\n",
				sock,
				(int)NFSRV_TCPSOCKBUF, (int)rcvbufvalue);
		}

#ifdef _DEBUG
		(void)printf("wintirpc_setnfsclientsockopts(sock=%d): "
			"set SO_RCVBUF to %d\n", sock, (int)rcvbufvalue);
#endif
	}


	if (sndbufvalue < NFSRV_TCPSOCKBUF) {
		sndbufvalue = NFSRV_TCPSOCKBUF;
		bufsize = sizeof(sndbufvalue);
		if (wintirpc_setsockopt(sock, SOL_SOCKET, SO_SNDBUF,
			(const char *)&sndbufvalue, sizeof(bufsize)))
			wintirpc_warnx(
				"wintirpc_setnfsclientsockopts(sock=%d): "
				"Error setting SO_SNDBUF\n", sock);

		sndbufvalue = 0;
		bufsize = sizeof(sndbufvalue);
		if (wintirpc_getsockopt(sock, SOL_SOCKET, SO_SNDBUF,
			(char *)&sndbufvalue, &bufsize))
			wintirpc_warnx(
				"wintirpc_setnfsclientsockopts(sock=%d): "
				"Error getting SO_SNDBUF\n", sock);

		if (sndbufvalue != NFSRV_TCPSOCKBUF) {
			wintirpc_warnx(
				"wintirpc_setnfsclientsockopts(sock=%d): "
				"SO_SNDBUF expected size=%d, got size=%d\n",
				sock, (int)NFSRV_TCPSOCKBUF, (int)sndbufvalue);
		}

#ifdef _DEBUG
		(void)printf("wintirpc_setnfsclientsockopts(sock=%d): "
			"set SO_SNDBUF to %d\n", sock, (int)sndbufvalue);
#endif
	}
#endif /* NFS41_DRIVER_USE_LARGE_SOCKET_RCVSND_BUFFERS */
}

void wintirpc_syslog(int prio, const char *format, ...)
{
	const char *prio_s;
	va_list args;
	va_start(args, format);

	switch (LOG_PRI(prio)) {
		case LOG_EMERG:		prio_s = "EMERG";	break;
		case LOG_ALERT:		prio_s = "ALERT";	break;
		case LOG_CRIT:		prio_s = "CRIT";	break;
		case LOG_ERR:		prio_s = "ERR";		break;
		case LOG_WARNING:	prio_s = "WARNING";	break;
		case LOG_NOTICE:	prio_s = "NOTICE";	break;
		case LOG_INFO:		prio_s = "INFO";	break;
		case LOG_DEBUG:		prio_s = "DEBUG";	break;
		default:		prio_s = "UNKNOWN_ERROR"; break;
	}

	(void)fprintf(stderr, "%04x: %s: ", GetCurrentThreadId(), prio_s);
	(void)vfprintf(stderr, format, args);
	(void)fputc('\n', stderr);
	(void)fflush(stderr);
	va_end(args);
}


void wintirpc_warnx(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    (void)fprintf(stderr, "%04x: ", GetCurrentThreadId());
    (void)vfprintf(stderr, format, args);
    (void)fflush(stderr);
    va_end(args);
}

int tirpc_exit(void)
{
	if (init == 0 || --init > 0)
		return 0;

	return WSACleanup();
}

void wintirpc_debug(char *fmt, ...)
{
#ifdef _DEBUG
	char buffer[2048];
#else
	static int triedToOpen = 0;
	static FILE *dbgFile = NULL;
#endif

	va_list vargs;
	va_start(vargs, fmt);

#ifdef _DEBUG
	vsprintf(buffer, fmt, vargs);
	OutputDebugStringA(buffer);
#else
	if (dbgFile == NULL && triedToOpen == 0) {
		triedToOpen = 1;
		dbgFile = fopen("c:\\etc\\rpcsec_gss_debug.txt", "w");
	}
	if (dbgFile != NULL) {
		vfprintf(dbgFile, fmt, vargs);
		fflush(dbgFile);
	}
#endif

	va_end(vargs);
}
