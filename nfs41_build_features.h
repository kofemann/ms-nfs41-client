/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2025 Roland Mainz <roland.mainz@nrubsig.org>
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
 * NFS41_DRIVER_STABILITY_HACKS - use horrible
 * hacks to improve stabilty
 */
#define NFS41_DRIVER_STABILITY_HACKS 1

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

/*
 * NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL - mounts created
 * with user "SYSTEM" should be available for ALL users on
 * a machine.
 */
#define NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL 1

/*
 * Default POSIX permission mode bits for new files
 * and directories.
 * Notes:
 * - Can be overridden with a "NfsV3Attributes" EA, which Cygwin,
 * ServicesForUNIX, etc. do by default for all "NFS" filesystems.
 * - NFS41_DRIVER_DEFAULT_FILE_CREATE_MODE should really be
 * mode=0644, but in real life Windows installer software
 * creates *.(exe|dll|com|sys) files without "GENERIC_EXECUTE" ACL
 * entries, and without any |FILE_EXECUTE| set no binary (*.exe,
 * and *.ddl dependicies) will start.
 * Installers make it even worse by creating unpacked files with
 * temporary names like "XXfoo.tmp", and then rename it "foo.exe",
 * so there is no way to fix this at file creation time.
 */
#define NFS41_DRIVER_DEFAULT_DIR_CREATE_MODE (0755)
#define NFS41_DRIVER_DEFAULT_FILE_CREATE_MODE (0755)

/*
 * NFS41_DRIVER_DEBUG_FS_NAME - define which filesystem name should
 * be returned by |FileFsAttributeInfo|
 * 1 == "NFS" (like Microsoft, Exceed and OpenText NFS drivers)
 * 2 == "DEBUG-NFS41" (custom value, used for disabling
 *     hardcoded codepaths for "nfs" drivers, and just treat
 *     this like a normal non-NFS MiniRDR driver
 */
#define NFS41_DRIVER_DEBUG_FS_NAME 1

/*
 * NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES - Skip ACEs
 * with SID==|WinNullSid|
 *
 * Cygwin generates artificial ACEs with SID user |WinNullSid| to
 * encode permission information (follow |CYG_ACE_ISBITS_TO_POSIX()|
 * in Cygwin newlib-cygwin/winsup/cygwin/sec/acl.cc
 *
 * This assumes that the filesystem which storesthe ACL data leaves
 * them 1:1 intact - which is not the case for the Linux NFSv4.1
 * server (tested with Linux 6.6.32), which transforms the NFSv4.1
 * ACLs into POSIX ACLs at setacl time, and the POSIX ACLs back to
 * NFSv4 ACLs at getacl time.
 * And this lossy transformation screws-up Cygwin completly.
 * The best we can do for now is to skip such ACEs, as we have no
 * way to detect whether the NFS server supports full NFSv4 ACLs,
 * or only POSIX ACLs disguised as NFSv4 ACLs.
 */
#define NFS41_DRIVER_ACLS_SETACL_SKIP_WINNULLSID_ACES 1

/*
 * NFS41_DRIVER_WSL_SUPPORT - Enable WSL support
 */
#define NFS41_DRIVER_WSL_SUPPORT 1

/*
 * NFS41_DRIVER_WS2022_HACKS - Enable hacks for Windows Server 2022
 * compatibility
 */
#define NFS41_DRIVER_WS2022_HACKS 1

/*
 * NFS41_DRIVER_DEFAULT_NFS4MINORVERSION - set default NFSv4.x
 * protocol minor version used by protocol autonegotiation if no
 * minor version was given via $ nfs_mount -o vers= ... #
 * Value can be |1| or |2|
 */
#define NFS41_DRIVER_DEFAULT_NFS4MINORVERSION 2

/*
 * NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS - treat symlinks
 * which cannot be resolved within the NFS filesystem as dirs
 *
 * The idea is that such symlinks are UNC paths or drives (e.g. T:\),
 * and powershell+cmd.exe will only cd into such symlinks if
 * the flag |FILE_ATTRIBUTE_DIRECTORY| is set for them.
 *
 * ToDo: Maybe we should read the symlink value, and only set
 * |FILE_ATTRIBUTE_DIRECTORY| if the symlink value ends with
 * "/", "/." or "/.." ...
 */
#define NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS 1

/*
 * NFS41_DRIVER_HACK_DISABLE_FCB_ATTR_UPDATE_ON_OPEN -
 * disable updating of FCB attributes for an already
 * opened FCB
 * This is a hack for now, until we can figure out how
 * to do this correctly (best guess is not to update FCB
 * attributes if the file is opened for writing, because
 * the kernel keeps updating the FCB data. The userland
 * is not affected by this, they get all information from
 * |nfs41_fcb->BasicInfo| and |nfs41_fcb->StandardInfo|).
 *
 * We keep this as a build flag for further testing.
 *
 * Without this hack
 * $ '/cygdrive/c/Program Files/Git/cmd/git' clone ... # will
 * fail with read errors.
 *
 */
#define NFS41_DRIVER_HACK_DISABLE_FCB_ATTR_UPDATE_ON_OPEN 1


/*
 * |NFS41_DRIVER_HACK_LOCKING_STORAGE32_RANGELOCK_PROBING| - handle
 * rangelock probing for Storage32 API
 * (see https://doxygen.reactos.org/d6/d7b/storage32_8h_source.html#l00497)
 *
 * The Storage32 API uses locking outside a file's size in the
 * offset range of 0x7ffffe00 - 0x7fffffff for it's internal
 * machinery. Since NFSv4.1 locking API will return failure for
 * locking attempts outside a file's size we have to add a workaround
 * here, otherwise applications using the Storage32 API can fail.
 *
 * Without this hack
 * $ msiexec /i DrMemory-Windows-2.6.20167.msi # will
 * fail with read errors.
 *
 */
#define NFS41_DRIVER_HACK_LOCKING_STORAGE32_RANGELOCK_PROBING 1

/*
 * |NFS41_DRIVER_HACK_FORCE_FILENAME_CASE_MOUNTOPTIONS| - provide mount
 * options "forcecasepreserving=0/1" and "forcecaseinsensitive=0/1"
 * to override |FATTR4_WORD0_CASE_INSENSITIVE|/|FATTR4_WORD0_CASE_PRESERVING|
 * obtained by the NFS server.
 *
 * This is only a HACK to circumvent a Linux nfsd bug which always returns
 * |FATTR4_WORD0_CASE_INSENSITIVE==0|&&|FATTR4_WORD0_CASE_PRESERVING==1|,
 * even for FAT.
 * Since Windows file accesses via UNC path make mount options basically
 * per-server mounts from a single server can only have one set of
 * "forcecasepreserving=0/1" and "forcecaseinsensitive=0/1" options.
 *
 * As workaround you can use use the same hostname but a different port
 * number (as for ms-nfs41-client the port number of part of the UNC path),
 * e.g. ssh on the NFS server itself to forward port 2050 to 2049 to
 * pretent it is a different server:
 * $ ssh -L '*:2050:localhost:2049' root@localhost 'printf "# forwarding...\n" ; sleep $((60*60*24*366*99))' #
 * and then connect the NFS client to port 2050 on the NFS server.
 *
 * This build option should be removed as soon as the Linux nfsd has been
 * fixed.
 * THIS OPTION MUST NOT BE USED ON PRODUCTION SYSTEMS!!
 */
#define NFS41_DRIVER_HACK_FORCE_FILENAME_CASE_MOUNTOPTIONS 1

/*
 * |NFS41_DRIVER_HACK_HANDLE_NFS_DELAY_GRACE_WIP| - handle
 * |NFS4ERR_GRACE| and |NFS4ERR_DELAY|.
 * This code still requires some cleanup, as we do not
 * have a simple way that |compound_encode_send_decode()| can
 * access the current kernel XID. As hackish quickfix we
 * use a thread-local variable to store the current XID.
 */
#define NFS41_DRIVER_HACK_HANDLE_NFS_DELAY_GRACE_WIP 1

#endif /* !_NFS41_DRIVER_BUILDFEATURES_ */
