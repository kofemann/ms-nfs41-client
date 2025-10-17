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
#ifndef _NFS41_DRIVER_
#define _NFS41_DRIVER_ 1

#define NFS41_DEVICE_NAME L"\\Device\\nfs41_driver"
#define NFS41_SHADOW_DEVICE_NAME L"\\??\\nfs41_driver"
#define NFS41_USER_DEVICE_NAME L"\\\\.\\nfs41_driver"
#define NFS41_USER_DEVICE_NAME_A "\\\\.\\nfs41_driver"
#define NFS41_PROVIDER_NAME_U L"NFS41 Network"

#define NFS41_PIPE_NAME L"\\Device\\nfs41_pipe"
#define NFS41_SHADOW_PIPE_NAME L"\\??\\nfs41_pipe"
#define NFS41_USER_PIPE_NAME L"\\\\.\\nfs41_pipe"

#define NFS41_SHARED_MEMORY_NAME L"\\BaseNamedObjects\\nfs41_shared_memory"
#define NFS41_USER_SHARED_MEMORY_NAME "Global\\nfs41_shared_memory"

// See "Defining I/O Control Codes" in WDK docs
#define _RDR_CTL_CODE(code, method) \
    CTL_CODE(FILE_DEVICE_NETWORK_REDIRECTOR, \
    (0x800 | (code)), \
    (method), \
    FILE_ANY_ACCESS)

#define IOCTL_NFS41_START       _RDR_CTL_CODE(0, METHOD_BUFFERED)
#define IOCTL_NFS41_STOP        _RDR_CTL_CODE(1, METHOD_NEITHER)
#define IOCTL_NFS41_GETSTATE    _RDR_CTL_CODE(3, METHOD_NEITHER)
#define IOCTL_NFS41_ADDCONN     _RDR_CTL_CODE(4, METHOD_BUFFERED)
#define IOCTL_NFS41_DELCONN     _RDR_CTL_CODE(5, METHOD_BUFFERED)
#define IOCTL_NFS41_READ        _RDR_CTL_CODE(6, METHOD_BUFFERED)
#define IOCTL_NFS41_WRITE       _RDR_CTL_CODE(7, METHOD_BUFFERED)
#define IOCTL_NFS41_DELAYXID    _RDR_CTL_CODE(8, METHOD_BUFFERED)
#define IOCTL_NFS41_INVALCACHE  _RDR_CTL_CODE(9, METHOD_BUFFERED)
#define IOCTL_NFS41_SET_DAEMON_DEBUG_LEVEL  _RDR_CTL_CODE(10, METHOD_BUFFERED)

/*
 * NFS41_SYS_MAX_PATH_LEN - Maximum path length
 * Notes:
 * - Starting in Windows 10, version 1607, MAX_PATH limitations have
 * been removed from common Win32 file and directory functions
 * (see https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation)
 * - We limit this to 4096 for now, to match Cygwin
 * $ getconf PATH_MAX /cygdrive/c/Users #
 */
#define NFS41_SYS_MAX_PATH_LEN          4096

/* |_nfs41_opcodes| and |g_upcall_op_table| must be in sync! */
typedef enum _nfs41_opcodes {
    NFS41_SYSOP_INVALID_OPCODE0,
    NFS41_SYSOP_MOUNT,
    NFS41_SYSOP_UNMOUNT,
    NFS41_SYSOP_OPEN,
    NFS41_SYSOP_CLOSE,
    NFS41_SYSOP_READ,
    NFS41_SYSOP_WRITE,
    NFS41_SYSOP_LOCK,
    NFS41_SYSOP_UNLOCK,
    NFS41_SYSOP_DIR_QUERY,
    NFS41_SYSOP_FILE_QUERY,
    NFS41_SYSOP_FILE_QUERY_TIME_BASED_COHERENCY,
    NFS41_SYSOP_FILE_SET,
    NFS41_SYSOP_EA_GET,
    NFS41_SYSOP_EA_SET,
    NFS41_SYSOP_SYMLINK_GET,
    NFS41_SYSOP_SYMLINK_SET,
    NFS41_SYSOP_VOLUME_QUERY,
    NFS41_SYSOP_ACL_QUERY,
    NFS41_SYSOP_ACL_SET,
    NFS41_SYSOP_FSCTL_QUERYALLOCATEDRANGES,
    NFS41_SYSOP_FSCTL_SET_ZERO_DATA,
    NFS41_SYSOP_FSCTL_DUPLICATE_DATA,
    NFS41_SYSOP_FSCTL_OFFLOAD_DATACOPY,
    NFS41_SYSOP_SET_DAEMON_DEBUGLEVEL,
    NFS41_SYSOP_SHUTDOWN,
    NFS41_SYSOP_INVALID_OPCODE1
} nfs41_opcodes;

/*
 * Same as |FILE_FS_ATTRIBUTE_INFORMATION| but with inline buffer
 * for 32 characters
 */
typedef struct _NFS41_FILE_FS_ATTRIBUTE_INFORMATION {
    ULONG FileSystemAttributes;
    LONG MaximumComponentNameLength;
    ULONG FileSystemNameLength;
    WCHAR FileSystemName[32];
} NFS41_FILE_FS_ATTRIBUTE_INFORMATION;

/*
 * Symlink target path types returned by the |NFS41_SYSOP_OPEN|
 * downcall
 */
typedef enum _nfs41_sysop_open_symlinktarget_type {
    NFS41_SYMLINKTARGET_TYPE_UNDEFINED = 0,
    /*
     * Symlink within the same filesystem, but "absolute" from
     * mount root
     */
    NFS41_SYMLINKTARGET_FILESYSTEM_ABSOLUTE = 1,
    NFS41_SYMLINKTARGET_NTPATH = 2
} nfs41_sysop_open_symlinktarget_type;

enum rpcsec_flavors {
    RPCSEC_AUTH_UNDEFINED = 0,
    RPCSEC_AUTH_NONE,
    RPCSEC_AUTH_SYS,
    RPCSEC_AUTHGSS_KRB5,
    RPCSEC_AUTHGSS_KRB5I,
    RPCSEC_AUTHGSS_KRB5P
};

typedef enum _nfs41_init_driver_state {
   NFS41_INIT_DRIVER_STARTABLE,
   NFS41_INIT_DRIVER_START_IN_PROGRESS,
   NFS41_INIT_DRIVER_STARTED
} nfs41_init_driver_state;

typedef enum _nfs41_start_driver_state {
   NFS41_START_DRIVER_STARTABLE,
   NFS41_START_DRIVER_START_IN_PROGRESS,
   NFS41_START_DRIVER_STARTED,
   NFS41_START_DRIVER_STOPPED
} nfs41_start_driver_state;

#define NFS_VERSION_AUTONEGOTIATION (0xFFFF)

/*
 * LargeInteger.QuadPart value to indicate a time value was not
 * available
 *
 * gisburn: FIXME: We need a better header for this
 */
#define FILE_INFO_TIME_NOT_SET (0LL)

/*
 * Error/Status codes
 */
#define ERROR_NFS_VERSION_MISMATCH ERROR_REMOTE_FILE_VERSION_MISMATCH
#define STATUS_NFS_VERSION_MISMATCH STATUS_REMOTE_FILE_VERSION_MISMATCH

/* Boolean with three states to cover "not set" */
typedef signed char tristate_bool;
#define TRISTATE_BOOL_NOT_SET   (-1)
#define TRISTATE_BOOL_FALSE     (0)
#define TRISTATE_BOOL_TRUE      (1)

#endif /* !_NFS41_DRIVER_ */
