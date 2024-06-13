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

#ifndef __NFS41_NP_H__
#define __NFS41_NP_H__

#include "nfs41_build_features.h"

#define NFS41NP_MUTEX_NAME  "NFS41NPMUTEX"

/*
 * Maximum number of devices, 26 letters in alphabet, per user
 */
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
#define NFS41NP_MAX_USERS   (128)
#define NFS41NP_MAX_DEVICES (26*NFS41NP_MAX_USERS)
#else
#define NFS41NP_MAX_DEVICES (26)
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */


typedef struct __NFS41NP_NETRESOURCE {
    BOOL    InUse;
    USHORT  LocalNameLength;
    USHORT  RemoteNameLength;
    USHORT  ConnectionNameLength;
    DWORD   dwScope;
    DWORD   dwType;
    DWORD   dwDisplayType;
    DWORD   dwUsage;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID    MountAuthId;
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
    WCHAR   LocalName[NFS41_SYS_MAX_PATH_LEN];
    WCHAR   RemoteName[NFS41_SYS_MAX_PATH_LEN];
    WCHAR   ConnectionName[NFS41_SYS_MAX_PATH_LEN];
    WCHAR   Options[NFS41_SYS_MAX_PATH_LEN];
} NFS41NP_NETRESOURCE, *PNFS41NP_NETRESOURCE;

typedef struct __NFS41NP_SHARED_MEMORY {
    INT                 NextAvailableIndex;
    INT                 NumberOfResourcesInUse;
    NFS41NP_NETRESOURCE NetResources[NFS41NP_MAX_DEVICES];
} NFS41NP_SHARED_MEMORY, *PNFS41NP_SHARED_MEMORY;

#endif /* !__NFS41_NP_H__ */
