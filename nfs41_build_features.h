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

#ifndef _NFS41_DRIVER_BUILDFEATURES_
#define _NFS41_DRIVER_BUILDFEATURES_ 1

/*
 * NFS41_DRIVER_FEATURE_* - features for this build, we use this
 * for development to add new features which are "off" by default
 * until they are ready
 */

/*
 * NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES - return local uid/gid values
 */
#define NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES 1

/*
 * NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID - give NFS
 * files which do not map to a local account a SID in the
 * Unix_User+x/Unix_Group+x range
 */
#define NFS41_DRIVER_FEATURE_MAP_UNMAPPED_USER_TO_UNIXUSER_SID 1

/*
 * NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN - use Cygwin shell script
 * as to do the idmapping between NFS client and NFS server
 */
#define NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN 1

/*
 * Enable cache for username/groupname to SID
 */
#define NFS41_DRIVER_SID_CACHE 1

/*
 * NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX - nfs_mount.exe and
 * not nfs41_np does the \nfs4 prefix between servername and path
 * in UNC paths. As side-effect both normal and Windows UNC paths
 * always have \nfs4 in them (e.g. \\derfwnb4966_ipv4@2049\nfs4\bigdisk
 * (Windows UNC) and //derfwnb4966_ipv4@2049/nfs4/bigdisk (Cygwin UNC)
 * instead of just the the Cygwin UNC paths, which constantly confuses
 * users madly.
 */
#define NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX 1

/*
 * NFS41_DRIVER_STABILITY_HACKS - use horrible
 * hacks to improve stabilty
 */
#define NFS41_DRIVER_STABILITY_HACKS 1

/*
 * NFS41_DRIVER_WORKAROUND_FOR_GETATTR_AFTER_CLOSE_HACKS - use
 * horrible hacks to improve stabilty because sometimes we use
 * |nfs41_open_state| afer a file close in highly parallel
 * workloads (e.g. building the gcc compiler in parallel).
 *
 * #define NFS41_DRIVER_WORKAROUND_FOR_GETATTR_AFTER_CLOSE_HACKS 1
 */

/*
 * NFS41_DRIVER_USE_LARGE_SOCKET_RCVSND_BUFFERS - use
 * static, large buffer size for socket receive and send buffers
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
#define NFS41_DRIVER_USE_LARGE_SOCKET_RCVSND_BUFFERS 1

/*
 * Support /usr/bin/newgrp&co, which have a non-default
 * |TOKEN_PRIMARY_GROUP|
 */
#define NFS41_DRIVER_SETGID_NEWGRP_SUPPORT 1

/*
 * Disable 8DOT3 ShortName filename generation.
 * The current code is broken anyway,so we disable it until we
 * can implement it better..
 */
#define NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION 1

/*
 * NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE - use
 * |TOKEN_GROUPS_AND_PRIVILEGES.AuthenticationId| for
 * mount namespace separation between users.
 * This avoid that mounts from different users can interfere
 * with each other, e.g. if they are mounted with different
 * mount (e.g. "rw" vs. "ro") options.
 */
#define NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE 1

#endif /* !_NFS41_DRIVER_BUILDFEATURES_ */
