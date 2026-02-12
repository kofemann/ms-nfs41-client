/* NFSv4.1 client for Windows
 * Copyright (C) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
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

#ifndef _NFS41SYS_BUILDCONFIG_H_
#define _NFS41SYS_BUILDCONFIG_H_ 1

#include "nfs41_build_features.h"

/* Driver build config */

/*
 * |FORCE_POSIX_SEMANTICS_DELETE| is for bug-by-bug compatibility with the
 * original Windows NFSv3 filesystem driver
 *
 * If we ever disable this e must make sure that this works and still returns
 * errors to the caller, e.g. rm -Rf on a readonly dir must return an
 * error.
 *
 * Example:
 * ---- snip ----
 * $ ksh93 -c 'mkdir d1 && touch d1/f1 && chmod -R a-w d1 &&
 *      if rm -Rf d1 ; then echo "# Test failed" ; else
 *      echo "# Test OK" ; fi'
 * rm: cannot remove 'd1': Permission denied
 * # Test OK
 * ---- snip ----
 */
#define FORCE_POSIX_SEMANTICS_DELETE 1

#define USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM 1

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
#define USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM 1
#define USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM 1
// #define LOOKASIDELISTS_STATS 1
#endif /* (NTDDI_VERSION >= NTDDI_WIN10_VB) */

#ifdef NFS41_DRIVER_COLLAPSEOPEN
#define WINBUG_NO_COLLAPSE_IF_PRIMARYGROUPS_DIFFER 1
#endif /* NFS41_DRIVER_COLLAPSEOPEN */

/* debugging printout defines */
#if defined(_DEBUG)
/* Debug build defines follow... */
#define DEBUG_MARSHAL_HEADER
#define DEBUG_MARSHAL_DETAIL
//#define DEBUG_MARSHAL_DETAIL_RW
//#define DEBUG_SECURITY_TOKEN
#define DEBUG_MOUNTCONFIG
//#define DEBUG_OPEN
//#define DEBUG_CLOSE
//#define DEBUG_CACHE
#define DEBUG_INVALIDATE_CACHE
//#define DEBUG_READ
//#define DEBUG_WRITE
//#define DEBUG_DIR_QUERY
//#define DEBUG_FILE_QUERY
//#define DEBUG_FILE_SET
//#define DEBUG_ACL_QUERY
//#define DEBUG_ACL_SET
//#define DEBUG_EA_QUERY
//#define DEBUG_EA_SET
//#define DEBUG_LOCK
#define DEBUG_FSCTL
//#define DEBUG_FSCTL_OFFLOAD_READWRITE
#define DEBUG_IOCTL
#define DEBUG_TIME_BASED_COHERENCY
#define DEBUG_MOUNT
//#define DEBUG_VOLUME_QUERY

//#define ENABLE_TIMINGS
//#define ENABLE_INDV_TIMINGS
#elif defined(NDEBUG)
/* Release build defines follow... */
#else
#error Neither _DEBUG NOR _NDEBUG defined
#endif

#endif /* !_NFS41SYS_BUILDCONFIG_H_ */
