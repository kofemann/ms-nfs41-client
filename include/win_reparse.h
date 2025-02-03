/* NFSv4.1 client for Windows
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

#ifndef _NFS41_WIN_REPARSE_
#define _NFS41_WIN_REPARSE_ 1

/*
 * Header for Windows reparse point info
 */

#ifndef IO_REPARSE_TAG_MOUNT_POINT
#define IO_REPARSE_TAG_MOUNT_POINT          (0xA0000003)
#endif
#ifndef IO_REPARSE_TAG_HSM
#define IO_REPARSE_TAG_HSM                  (0xC0000004)
#endif
#ifndef IO_REPARSE_TAG_DRIVE_EXTENDER
#define IO_REPARSE_TAG_DRIVE_EXTENDER       (0x80000005)
#endif
#ifndef IO_REPARSE_TAG_HSM2
#define IO_REPARSE_TAG_HSM2                 (0x80000006)
#endif
#ifndef IO_REPARSE_TAG_SIS
#define IO_REPARSE_TAG_SIS                  (0x80000007)
#endif
#ifndef IO_REPARSE_TAG_WIM
#define IO_REPARSE_TAG_WIM                  (0x80000008)
#endif
#ifndef IO_REPARSE_TAG_CSV
#define IO_REPARSE_TAG_CSV                  (0x80000009)
#endif
#ifndef IO_REPARSE_TAG_DFS
#define IO_REPARSE_TAG_DFS                  (0x8000000A)
#endif
#ifndef IO_REPARSE_TAG_FILTER_MANAGER
#define IO_REPARSE_TAG_FILTER_MANAGER       (0x8000000B)
#endif
#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK              (0xA000000C)
#endif
#ifndef IO_REPARSE_TAG_IIS_CACHE
#define IO_REPARSE_TAG_IIS_CACHE            (0xA0000010)
#endif
#ifndef IO_REPARSE_TAG_DFSR
#define IO_REPARSE_TAG_DFSR                 (0x80000012)
#endif
#ifndef IO_REPARSE_TAG_DEDUP
#define IO_REPARSE_TAG_DEDUP                (0x80000013)
#endif
#ifndef IO_REPARSE_TAG_APPXSTRM
#define IO_REPARSE_TAG_APPXSTRM             (0xC0000014)
#endif
#ifndef IO_REPARSE_TAG_NFS
#define IO_REPARSE_TAG_NFS                  (0x80000014)
#endif
#ifndef IO_REPARSE_TAG_FILE_PLACEHOLDER
#define IO_REPARSE_TAG_FILE_PLACEHOLDER     (0x80000015)
#endif
#ifndef IO_REPARSE_TAG_DFM
#define IO_REPARSE_TAG_DFM                  (0x80000016)
#endif
#ifndef IO_REPARSE_TAG_WOF
#define IO_REPARSE_TAG_WOF                  (0x80000017)
#endif
#ifndef IO_REPARSE_TAG_WCI
#define IO_REPARSE_TAG_WCI                  (0x80000018)
#endif
#ifndef IO_REPARSE_TAG_WCI_1
#define IO_REPARSE_TAG_WCI_1                (0x90001018)
#endif
#ifndef IO_REPARSE_TAG_GLOBAL_REPARSE
#define IO_REPARSE_TAG_GLOBAL_REPARSE       (0xA0000019)
#endif
#ifndef IO_REPARSE_TAG_CLOUD
#define IO_REPARSE_TAG_CLOUD                (0x9000001A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_1
#define IO_REPARSE_TAG_CLOUD_1              (0x9000101A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_2
#define IO_REPARSE_TAG_CLOUD_2              (0x9000201A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_3
#define IO_REPARSE_TAG_CLOUD_3              (0x9000301A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_4
#define IO_REPARSE_TAG_CLOUD_4              (0x9000401A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_5
#define IO_REPARSE_TAG_CLOUD_5              (0x9000501A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_6
#define IO_REPARSE_TAG_CLOUD_6              (0x9000601A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_7
#define IO_REPARSE_TAG_CLOUD_7              (0x9000701A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_8
#define IO_REPARSE_TAG_CLOUD_8              (0x9000801A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_9
#define IO_REPARSE_TAG_CLOUD_9              (0x9000901A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_A
#define IO_REPARSE_TAG_CLOUD_A              (0x9000A01A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_B
#define IO_REPARSE_TAG_CLOUD_B              (0x9000B01A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_C
#define IO_REPARSE_TAG_CLOUD_C              (0x9000C01A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_D
#define IO_REPARSE_TAG_CLOUD_D              (0x9000D01A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_E
#define IO_REPARSE_TAG_CLOUD_E              (0x9000E01A)
#endif
#ifndef IO_REPARSE_TAG_CLOUD_F
#define IO_REPARSE_TAG_CLOUD_F              (0x9000F01A)
#endif
#ifndef IO_REPARSE_TAG_APPEXECLINK
#define IO_REPARSE_TAG_APPEXECLINK          (0x8000001B)
#endif
#ifndef IO_REPARSE_TAG_PROJFS
#define IO_REPARSE_TAG_PROJFS               (0x9000001C)
#endif
#ifndef IO_REPARSE_TAG_LX_SYMLINK
#define IO_REPARSE_TAG_LX_SYMLINK           (0xA000001D)
#endif
#ifndef IO_REPARSE_TAG_STORAGE_SYNC
#define IO_REPARSE_TAG_STORAGE_SYNC         (0x8000001E)
#endif
#ifndef IO_REPARSE_TAG_STORAGE_SYNC_FOLDER
#define IO_REPARSE_TAG_STORAGE_SYNC_FOLDER  (0x90000027)
#endif
#ifndef IO_REPARSE_TAG_WCI_TOMBSTONE
#define IO_REPARSE_TAG_WCI_TOMBSTONE        (0xA000001F)
#endif
#ifndef IO_REPARSE_TAG_UNHANDLED
#define IO_REPARSE_TAG_UNHANDLED            (0x80000020)
#endif
#ifndef IO_REPARSE_TAG_ONEDRIVE
#define IO_REPARSE_TAG_ONEDRIVE             (0x80000021)
#endif
#ifndef IO_REPARSE_TAG_PROJFS_TOMBSTONE
#define IO_REPARSE_TAG_PROJFS_TOMBSTONE     (0xA0000022)
#endif
#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX              (0x80000023)
#endif
#ifndef IO_REPARSE_TAG_LX_FIFO
#define IO_REPARSE_TAG_LX_FIFO              (0x80000024)
#endif
#ifndef IO_REPARSE_TAG_LX_CHR
#define IO_REPARSE_TAG_LX_CHR               (0x80000025)
#endif
#ifndef IO_REPARSE_TAG_LX_BLK
#define IO_REPARSE_TAG_LX_BLK               (0x80000026)
#endif
#ifndef IO_REPARSE_TAG_WCI_LINK
#define IO_REPARSE_TAG_WCI_LINK             (0xA0000027)
#endif
#ifndef IO_REPARSE_TAG_WCI_LINK_1
#define IO_REPARSE_TAG_WCI_LINK_1           (0xA0001027)
#endif

#endif /* !_NFS41_WIN_REPARSE_ */
