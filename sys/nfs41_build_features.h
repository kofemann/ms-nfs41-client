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
// #define NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES 1
// #define NFS41_DRIVER_FEATURE_LOCAL_UIDGID_TESTMAPPING 1

#endif /* !_NFS41_DRIVER_BUILDFEATURES_ */
