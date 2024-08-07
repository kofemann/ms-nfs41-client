/*
 * NFSv4.1 client for Windows
 * Copyright (C) 2024 Roland Mainz <roland.mainz@nrubsig.org>
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

#ifndef __NFS41_DAEMON_NFSV4_EA
#define __NFS41_DAEMON_NFSV4_EA 1

/*
 * ToDo: Add documentation how these EAs (extended attributes) work
 */

#define EA_NFSV3ATTRIBUTES "NfsV3Attributes"
#define EA_NFSV3ATTRIBUTES_LEN (15)

#define EA_NFSSYMLINKTARGETNAME "NfsSymlinkTargetName"
#define EA_NFSSYMLINKTARGETNAME_LEN (17)

#define EA_NFSACTONLINK "NfsActOnLink"
#define EA_NFSACTONLINK_LEN (11)

#endif /* !__NFS41_DAEMON_NFSV4_EA */
