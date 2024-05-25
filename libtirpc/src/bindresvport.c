/*
 * Copyright (c) 2009, Sun Microsystems, Inc.
 * Copyright (c) 2024, Roland Mainz <roland.mainz@nrubsig.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * - Neither the name of Sun Microsystems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

//#include <sys/cdefs.h>

/*
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 *
 * Portions Copyright(C) 1996, Jason Downs.  All rights reserved.
 * Portions Copyright(C) 2024, Roland Mainz <roland.mainz@nrubsig.org>
 */

#include <wintirpc.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <rpc/rpc.h>

#ifdef _WIN32
#include <winsock2.h>
#include <mstcpip.h>
#include <ws2ipdef.h>
#endif

/*
 * Bind a socket to a privileged IP port
 */
int
bindresvport(sd, sin)
	int sd;
	struct sockaddr_in *sin;
{
	return bindresvport_sa(sd, (struct sockaddr *)sin);
}

#ifdef __linux__

#define STARTPORT 600
#define LOWPORT 512
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS  (ENDPORT - STARTPORT + 1)

int
bindresvport_sa(sd, sa)
        int sd;
        struct sockaddr *sa;
{
        int res, af;
        struct sockaddr_storage myaddr;
	struct sockaddr_in *sin;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif
	u_int16_t *portp;
	static u_int16_t port;
	static short startport = STARTPORT;
	socklen_t salen;
	int nports = ENDPORT - startport + 1;
	int endport = ENDPORT;
	int i;

        if (sa == NULL) {
                salen = sizeof(myaddr);
                sa = (struct sockaddr *)&myaddr;

                if (wintirpc_getsockname(sd, (struct sockaddr *)&myaddr, &salen) == -1)
                        return -1;      /* errno is correctly set */

                af = myaddr.ss_family;
        } else
                af = sa->sa_family;

        switch (af) {
        case AF_INET:
		sin = (struct sockaddr_in *)sa;
                salen = sizeof(struct sockaddr_in);
                port = ntohs(sin->sin_port);
		portp = &sin->sin_port;
		break;
#ifdef INET6
        case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sa;
                salen = sizeof(struct sockaddr_in6);
                port = ntohs(sin6->sin6_port);
                portp = &sin6->sin6_port;
                break;
#endif
        default:
                errno = EPFNOSUPPORT;
                return (-1);
        }
        sa->sa_family = af;

        if (port == 0) {
                port = (getpid() % NPORTS) + STARTPORT;
        }
        res = -1;
        errno = EADDRINUSE;
		again:
        for (i = 0; i < nports; ++i) {
                *portp = htons(port++);
                 if (port > endport) 
                        port = startport;
                res = wintirpc_bind(sd, sa, salen);
		if (res >= 0 || errno != EADDRINUSE)
	                break;
        }
	if (i == nports && startport != LOWPORT) {
	    startport = LOWPORT;
	    endport = STARTPORT - 1;
	    nports = STARTPORT - LOWPORT;
	    port = LOWPORT + port % (STARTPORT - LOWPORT);
	    goto again;
	}
        return (res);
}

#elif defined(_WIN32)

#define STARTPORT 600
#define ENDPORT (IPPORT_RESERVED - 1)
#define NPORTS  (ENDPORT - STARTPORT + 1)

/* Debug */
#if 0
#define BRP_D(x) x
#else
#define BRP_D(x)
#endif

/* fixme: not threadsafe, we should use |portnum_lock| */
static int bindresvport_sa_last_n = 0;

int
bindresvport_sa(int sd, struct sockaddr *sa)
{
	int res = 1;
	int ioctlres;
	int lasterr;
	SOCKET sd_sock;
	int currport;
	int n;

	INET_PORT_RANGE portRange;
	INET_PORT_RESERVATION_INSTANCE portRes;
	DWORD bytesReturned;

	BRP_D((void)fprintf(stdout,
		"--> bindresvport_sa(sd=%d,sa=0x%p): "
		"bindresvport_sa_last_n=%d\n",
		sd, sa, bindresvport_sa_last_n));

	sd_sock = _get_osfhandle(sd);

	for (n = 0 ; n < NPORTS ; n++) {
		currport = ((n+bindresvport_sa_last_n)%NPORTS)+STARTPORT;

		portRange.StartPort = htons((unsigned short)currport);
		portRange.NumberOfPorts = 1;

		(void)memset(&portRes, 0, sizeof(portRes));
		bytesReturned = 0;

		BRP_D((void)fprintf(stdout,
			"bindresvport_sa(sd=%d,sa=0x%p): "
			"trying n=%d, bindresvport_sa_last_n=%d, port=%d ...\n",
			sd, sa, n, bindresvport_sa_last_n,
			(int)ntohs(portRange.StartPort)));
		ioctlres = WSAIoctl(sd_sock,
			SIO_ACQUIRE_PORT_RESERVATION,
			(LPVOID)&portRange,
			sizeof(INET_PORT_RANGE),
			(LPVOID)&portRes,
			sizeof(INET_PORT_RESERVATION_INSTANCE),
			&bytesReturned, NULL, NULL);
		lasterr = WSAGetLastError();

		if ((ioctlres != 0) && (lasterr == WSAEADDRINUSE)) {
			BRP_D((void)fprintf(stderr,
				"bindresvport_sa(sd=%d,sa=0x%p): "
				"port=%d in use, trying next port...\n",
				sd, sa, currport));
			continue;
		}

		if (ioctlres != 0) {
			warnx("bindresvport_sa(sd=%d,sa=0x%p): "
				"SIO_ACQUIRE_PORT_RESERVATION failed "
				"with error = %d\n",
				sd, sa, lasterr);
			res = 1;
			bindresvport_sa_last_n = n+1;
			goto out;
		}

		/* Success */
		bindresvport_sa_last_n = n+1;
		break;
	}

	if (n == NPORTS) {
		warnx("bindresvport_sa(sd=%d,sa=0x%p): "
			"n(=%d) == NPORTS(=%d), "
			"no reserved port available\n", n, NPORTS);
		res = 1;
		goto out;
	}

	BRP_D((void)fprintf(stdout, "bindresvport_sa(sd=%d,sa=0x%p): "
		"SIO_ACQUIRE_PORT_RESERVATION succeeded, "
		"bytesReturned = %u, StartPort=%d, NumberOfPorts=%d, "
		"Token=0x%llx\n",
		sd, sa, bytesReturned, (int)ntohs(portRes.StartPort),
		portRes.NumberOfPorts, (long long)portRes.Token));

	bytesReturned = 0;
	ioctlres = WSAIoctl(sd_sock, SIO_ASSOCIATE_PORT_RESERVATION,
		(LPVOID)&portRes.Token, sizeof(ULONG64), NULL, 0,
		&bytesReturned, NULL, NULL);
	lasterr = WSAGetLastError();
	if (ioctlres != 0) {
		warnx("bindresvport_sa(sd=%d,sa=0x%p): "
			"WSAIoctl(SIO_ASSOCIATE_PORT_RESERVATION) "
			"failed with error = %d\n",
			sd, sa, lasterr);
		res = 1;
		goto out;
	}

	BRP_D((void)fprintf(stdout, "bindresvport_sa(sd=%d,sa=0x%p): "
		"WSAIoctl(SIO_ASSOCIATE_PORT_RESERVATION) succeeded, "
		"bytesReturned = %u\n",
		sd, sa, bytesReturned));
	res = 0;

	/*
	 * FIXME: We should call |SIO_RELEASE_PORT_RESERVATION|,
	 * but we cannot do that while |sd| is open and using the
	 * reservation.
	 * So basically we to store the token, and then use a second
	 * socket, with matching protocol&co attributes, just to
	 * release the reservation.
	 *
	 * A possible solution might be to derive a "control socket"
	 * from |sd|, and do the reservation ioctl using that socket.
	 *
	 * For now we ignore this, and assume noone will do more
	 * than |NPORTS| { mount, umount }-sequences during
	 * nfsd.exe/nfsd_debug.exe lifetime
	 */
out:
	BRP_D((void)fprintf(stdout,
		"<-- bindresvport_sa(sd=%d,sa=0x%p) returning res=%d\n",
		sd, sa, res));
	return res;
}
#else

#define IP_PORTRANGE 19
#define IP_PORTRANGE_LOW 2

/*
 * Bind a socket to a privileged IP port
 */
int
bindresvport_sa(sd, sa)
	int sd;
	struct sockaddr *sa;
{
#ifdef IPV6_PORTRANGE
	int old;
#endif
	int error, af;
	struct sockaddr_storage myaddr;
	struct sockaddr_in *sin;
#ifdef INET6
	struct sockaddr_in6 *sin6;
#endif
	int proto, portrange, portlow;
	u_int16_t *portp;
	socklen_t salen;

	if (sa == NULL) {
		salen = sizeof(myaddr);
		sa = (struct sockaddr *)&myaddr;

		if (wintirpc_getsockname(sd, sa, &salen) == -1)
			return -1;	/* errno is correctly set */

		af = sa->sa_family;
		memset(sa, 0, salen);
	} else
		af = sa->sa_family;

	switch (af) {
	case AF_INET:
		proto = IPPROTO_IP;
		portrange = IP_PORTRANGE;
		portlow = IP_PORTRANGE_LOW;
		sin = (struct sockaddr_in *)sa;
		salen = sizeof(struct sockaddr_in);
		portp = &sin->sin_port;
		break;
#ifdef INET6
	case AF_INET6:
		proto = IPPROTO_IPV6;
#ifdef IPV6_PORTRANGE
		portrange = IPV6_PORTRANGE;
		portlow = IPV6_PORTRANGE_LOW;
#endif
		sin6 = (struct sockaddr_in6 *)sa;
		salen = sizeof(struct sockaddr_in6);
		portp = &sin6->sin6_port;
		break;
#endif /* INET6 */
	default:
		errno = WSAEPFNOSUPPORT;
		return (-1);
	}
	sa->sa_family = (ADDRESS_FAMILY) af;

#ifdef IPV6_PORTRANGE
	if (*portp == 0) {
		socklen_t oldlen = sizeof(old);

		error = wintirpc_getsockopt(sd, proto, portrange, &old, &oldlen);
		if (error < 0)
			return (error);

		error = wintirpc_setsockopt(sd, proto, portrange, &portlow,
				sizeof(portlow));
		if (error < 0)
			return (error);
	}
#endif

	error = wintirpc_bind(sd, sa, salen);
	if (error) {
		int err = WSAGetLastError();
	}

#ifdef IPV6_PORTRANGE
	if (*portp == 0) {
		int saved_errno = errno;

		if (error < 0) {
			if (wintirpc_setsockopt(sd, proto, portrange, &old,
				sizeof(old)) < 0)
			errno = saved_errno;
			return (error);
		}

		if (sa != (struct sockaddr *)&myaddr) {
			/* Hmm, what did the kernel assign? */
			if (wintirpc_getsockname(sd, sa, &salen) < 0)
				errno = saved_errno;
			return (error);
		}
	}
#endif
	return (error);
}
#endif