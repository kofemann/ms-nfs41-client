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

WSADATA WSAData;

static int init = 0;
static DWORD dwTlsIndex;

extern void multithread_init(void);

VOID
tirpc_report(LPTSTR lpszMsg)
{
	WCHAR    chMsg[256];
	HANDLE   hEventSource;
	LPCWSTR  lpszStrings[2];

	// Use event logging to log the error.
	//
	hEventSource = RegisterEventSource(NULL,
									   TEXT("tirpc.dll"));

	swprintf_s(chMsg, sizeof(chMsg), L"tirpc report: %d", GetLastError());
	lpszStrings[0] = (LPCWSTR)chMsg;
	lpszStrings[1] = lpszMsg;

	if (hEventSource != NULL) {
		ReportEvent(hEventSource, // handle of event source
			EVENTLOG_WARNING_TYPE, // event type
			0,                    // event category
			0,                    // event ID
			NULL,                 // current user's SID
			2,                    // strings in lpszStrings
			0,                    // no bytes of raw data
			lpszStrings,          // array of error strings
			NULL);                // no raw data

		(VOID) DeregisterEventSource(hEventSource);
	}
}

void tirpc_criticalsection_init(void) {
	multithread_init();
}

BOOL winsock_init(void)
{
	int err;
	err = WSAStartup(MAKEWORD( 3, 3 ), &WSAData);	// XXX THIS SHOULD BE FAILING!!!!!!!!!!!!!!!!!
	if (err != 0) {
		init = 0;
		tirpc_report(L"WSAStartup failed!\n");
		WSACleanup();
		return FALSE;
	}
	return TRUE;
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
			
			// Initialize socket library
			if (winsock_init() == FALSE)
				return FALSE;

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

	for (i=0 ; i < WINTIRPC_MAX_OSFHANDLE_FD_NHANDLE_VALUE ; i++) {
		if (handle_fd_map[i].m_s == handle) {
			handle_fd_map[i].m_s = SOCKET_ERROR;
			handle_fd_map[i].m_fd = -1;
			return;
		}
	}
	(void)fprintf(stderr, "wintirpc_unregister_osfhandle: failed\n");
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

	wintirpc_unregister_osfhandle(s);

	return closesocket(s);
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

int wintirpc_send(int s, const char *buf, int len, int flags)
{
	return send(_get_osfhandle(s), buf, len, flags);
}

int wintirpc_sendto(int s, const char *buf, int len, int flags,
	const struct sockaddr *to, int tolen)
{
	return(sendto(_get_osfhandle(s), buf, len, flags, to, tolen));
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
