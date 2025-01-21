/*
 * NFSv4.1 client for Windows
 * Copyright (C) 2024-2025 Roland Mainz <roland.mainz@nrubsig.org>
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

/*
 * "NfsV3Attributes" uses |nfs3_attrs| as content
 */
/*
 * Note that we cannot use <stdint.h> in the Windows kernel, so we
 * use Windows Types here
 */
typedef struct _nfs3_attrs_timestruc_t {
    INT32   tv_sec;
    UINT32  tv_nsec;
} nfs3_attrs_timestruc_t;

typedef struct _nfs3_attrs {
    UINT32 type, mode, nlink, uid, gid, filler1;
    UINT64 size, used;
    struct {
        UINT32 specdata1;
        UINT32 specdata2;
    } rdev;
    UINT64 fsid, fileid;
    nfs3_attrs_timestruc_t atime, mtime, ctime;
} nfs3_attrs;

enum ftype3 {
    NF3REG = 1,
    NF3DIR,
    NF3BLK,
    NF3CHR,
    NF3LNK,
    NF3SOCK,
    NF3FIFO
};

#endif /* !__NFS41_DAEMON_NFSV4_EA */
