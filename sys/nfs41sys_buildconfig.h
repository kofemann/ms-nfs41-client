/* NFSv4.1 client for Windows
 * Copyright (C) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
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

/* Driver build config */
#define USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM 1
#define USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM 1
// #define LOOKASIDELISTS_STATS 1

// #define USE_ENTIRE_PATH_FOR_NETROOT 1

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
