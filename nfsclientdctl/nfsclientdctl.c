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
 * nfsclientdctlexe - Controls for NFS41 client daemon
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


#define DPRINTF(level, fmt) \
    if ((level) <= _dprintf_debug_level) { \
        (void)printf fmt; \
    }

static int _dprintf_debug_level = 0;

int main(int ac, char *av[])
{
    (void)ac;
    (void)av;
    return EXIT_SUCCESS;
}
