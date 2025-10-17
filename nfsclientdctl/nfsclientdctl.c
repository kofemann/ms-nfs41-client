/*
 * NFSv4.1 client for Windows
 * Copyright (C) 2025 Roland Mainz
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

/*
 * nfsclientdctl.exe - Controls for NFS41 client daemon
 */

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <devioctl.h>
#include "../include/nfs41_driver.h"

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

#define DPRINTF(level, fmt) \
    if ((level) <= _dprintf_debug_level) { \
        (void)printf fmt; \
    }

static int _dprintf_debug_level = 0;

static
HANDLE create_nfs41sys_device_pipe(void)
{
    HANDLE pipe;
    pipe = CreateFileA(NFS41_USER_DEVICE_NAME_A,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    return pipe;
}

static
void close_nfs41sys_device_pipe(HANDLE pipe)
{
    (void)CloseHandle(pipe);
}

void usage(const char *progname)
{
    (void)fprintf(stderr,
        "Usage: %s "
        "[stopdaemon|setdaemondebuglevel <debuglevel>]",
        progname);
}

static
int cmd_stopdaemon(const char *progname)
{
    HANDLE pipe;
    DWORD status;
    DWORD dstatus;
    DWORD outbuf_len;

    pipe = create_nfs41sys_device_pipe();
    if (pipe == INVALID_HANDLE_VALUE) {
        status = GetLastError();
        (void)fprintf(stderr,
            "%s: stopdaemon: "
            "Unable to open nfs41_driver pipe, lasterr=%d\n",
            progname,
            (int)status);
        return EXIT_FAILURE;
    }
    dstatus = DeviceIoControl(pipe, IOCTL_NFS41_STOP,
        NULL, 0, NULL, 0, &outbuf_len, NULL);

    close_nfs41sys_device_pipe(pipe);
    return EXIT_SUCCESS;
}

static
int cmd_setdaemondebuglevel(const char *progname, const char *levelstr)
{
    HANDLE pipe;
    DWORD status;
    BOOL dstatus;
    DWORD outbuf_len;
    LONG debuglevel;

    if (levelstr == NULL) {
        (void)fprintf(stderr,
            "%s: setdaemondebuglevel: "
            "Missing <debuglevel> argument\n",
            progname);
        return EXIT_FAILURE;
    }

    debuglevel = atol(levelstr);

    pipe = create_nfs41sys_device_pipe();
    if (pipe == INVALID_HANDLE_VALUE) {
        status = GetLastError();
        (void)fprintf(stderr,
            "%s: setdaemondebuglevel: "
            "Unable to open nfs41_driver pipe, lasterr=%d\n",
            progname,
            (int)status);
        return EXIT_FAILURE;
    }

    dstatus = DeviceIoControl(pipe,
        IOCTL_NFS41_SET_DAEMON_DEBUG_LEVEL,
        &debuglevel, sizeof(debuglevel),
        NULL, 0,
        &outbuf_len, NULL);
    if (dstatus == FALSE) {
        status = GetLastError();
        (void)fprintf(stderr,
            "%s: stopdaemon: "
            "IOCTL_NFS41_SET_DAEMON_DEBUG_LEVEL failed with lasterr=%d\n",
            progname,
            (int)status);
    }

    close_nfs41sys_device_pipe(pipe);
    return EXIT_SUCCESS;
}

int main(int ac, char *av[])
{
    if (ac < 2) {
        usage(av[0]);
        return EXIT_USAGE;
    }

    if (!strcmp(av[1], "stopdaemon")) {
        return cmd_stopdaemon(av[0]);
    }
    else if (!strcmp(av[1], "setdaemondebuglevel")) {
        return cmd_setdaemondebuglevel(av[0], av[2]);
    }
    else {
        (void)fprintf(stderr, "%s: Unknown cmd '%s'\n",
            av[0], av[1]);
        return EXIT_FAILURE;
    }
}
