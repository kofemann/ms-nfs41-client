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

#ifndef _KERNEL_MODE
#error module requires kernel mode
#endif

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

#ifndef _NFS41SYS_DRIVER_H_
#define _NFS41SYS_DRIVER_H_ 1

#include "nfs_ea.h"

#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
#define EXALLOCATEPOOLWITHTAG_DEPRECATED 1
#endif /* (NTDDI_VERSION >= NTDDI_WIN10_VB) */

#ifdef EXALLOCATEPOOLWITHTAG_DEPRECATED
/*
 * Workaround for WDK11 issue: |ExAllocatePoolWithTag()| is
 * deprecated ('warning C4996: 'ExAllocatePoolWithTag':"
 * ExAllocatePoolWithTag is deprecated, use ExAllocatePool2.')
 * but |RxAllocatePoolWithTag()| is still mapped to
 * |ExAllocatePoolWithTag()|
 */
#undef RxAllocatePoolWithTag
#define RXALLOCATEPOOL_DEFAULT_ALLOCATEPOOL2FLAGS \
    (POOL_FLAG_UNINITIALIZED|POOL_FLAG_CACHE_ALIGNED)

#define RxAllocatePoolWithTag(rxallocpool, numbytes, tag) \
    ExAllocatePool2((( \
            ((rxallocpool) == PagedPool)?POOL_FLAG_PAGED: \
                (((rxallocpool) == NonPagedPoolNx)? \
                    POOL_FLAG_NON_PAGED:POOL_FLAG_NON_PAGED_EXECUTE)) | \
            RXALLOCATEPOOL_DEFAULT_ALLOCATEPOOL2FLAGS), \
        (numbytes), (tag))
#endif /* EXALLOCATEPOOLWITHTAG_DEPRECATED */

#define DECLARE_CONST_ANSI_STRING(_var, _string) \
    const CHAR _var ## _buffer[] = _string; \
    const ANSI_STRING _var = { sizeof(_string) - sizeof(CHAR), \
        sizeof(_string), (PCH) _var ## _buffer }

#define DECLARE_EXTERN_CONST_ANSI_STRING(_var) \
    extern const CHAR _var ## _buffer[]; \
    extern const ANSI_STRING _var;

#if _MSC_VER >= 1900
/*
 * gisburn: VS22 chokes on the original define for
 * |DECLARE_CONST_UNICODE_STRING|, so we use one
 * without the offending stuff
 */
#undef DECLARE_CONST_UNICODE_STRING
#define DECLARE_CONST_UNICODE_STRING(_var, _string) \
	const WCHAR _var ## _buffer[] = _string; \
	const UNICODE_STRING _var = { sizeof(_string) - sizeof(WCHAR), sizeof(_string), (PWCH) _var ## _buffer }
#endif /* _MSC_VER >= 1900 */

#define DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(_var) \
    extern const WCHAR _var ## _buffer[]; \
    extern const UNICODE_STRING _var;


#ifdef ENABLE_TIMINGS
typedef struct __nfs41_timings {
    LONG tops, sops;
    LONGLONG ticks, size;
} nfs41_timings;
#endif /* ENABLE_TIMINGS */

/* Windows SMB driver also uses |IO_NFS41FS_INCREMENT| */
#define IO_NFS41FS_INCREMENT IO_NETWORK_INCREMENT

#define DISABLE_CACHING 0
#define ENABLE_READ_CACHING 1
#define ENABLE_WRITE_CACHING 2
#define ENABLE_READWRITE_CACHING 3

#define NFS41_MM_POOLTAG        ('nfs4')
#define NFS41_MM_POOLTAG_ACL    ('acls')
#define NFS41_MM_POOLTAG_MOUNT  ('mnts')
#define NFS41_MM_POOLTAG_OPEN   ('open')
#define NFS41_MM_POOLTAG_UP     ('upca')
#define NFS41_MM_POOLTAG_DOWN   ('down')


DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(NfsPrefix);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(PubNfsPrefix);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(AUTH_NONE_NAME);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(AUTH_SYS_NAME);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5_NAME);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5I_NAME);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(AUTHGSS_KRB5P_NAME);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(SLASH);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(EMPTY_STRING);
DECLARE_EXTERN_DECLARE_CONST_UNICODE_STRING(NetRootIpc);

DECLARE_EXTERN_CONST_ANSI_STRING(NfsV3Attributes);
DECLARE_EXTERN_CONST_ANSI_STRING(NfsSymlinkTargetName);
DECLARE_EXTERN_CONST_ANSI_STRING(NfsActOnLink);

#ifdef USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM
extern NPAGED_LOOKASIDE_LIST updowncall_entry_upcall_lookasidelist;
#ifndef USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM
extern NPAGED_LOOKASIDE_LIST updowncall_entry_downcall_lookasidelist;
#endif /* !USE_STACK_FOR_DOWNCALL_UPDOWNCALLENTRY_MEM */
#endif /* USE_LOOKASIDELISTS_FOR_UPDOWNCALLENTRY_MEM */
#ifdef USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM
extern NPAGED_LOOKASIDE_LIST fcblistentry_lookasidelist;
#endif /* USE_LOOKASIDELISTS_FOR_FCBLISTENTRY_MEM */

#ifdef ENABLE_TIMINGS
extern nfs41_timings lookup;
extern nfs41_timings readdir;
extern nfs41_timings open;
extern nfs41_timings close;
extern nfs41_timings getattr;
extern nfs41_timings setattr;
extern nfs41_timings getacl;
extern nfs41_timings setacl;
extern nfs41_timings volume;
extern nfs41_timings read;
extern nfs41_timings write;
extern nfs41_timings lock;
extern nfs41_timings unlock;
extern nfs41_timings setexattr;
extern nfs41_timings getexattr;
#endif /* ENABLE_TIMINGS */

#define RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos) (((signed __int64)(nanos)) / 100LL)
#define MICROSECONDS(micros) (((signed __int64)(micros)) * NANOSECONDS(1000LL))
#define MILLISECONDS(milli) (((signed __int64)(milli)) * MICROSECONDS(1000LL))
#define SECONDS(seconds) (((signed __int64)(seconds)) * MILLISECONDS(1000LL))

typedef enum _nfs41_updowncall_state {
    NFS41_WAITING_FOR_UPCALL,
    NFS41_WAITING_FOR_DOWNCALL,
    NFS41_DONE_PROCESSING,
    NFS41_NOT_WAITING
} nfs41_updowncall_state;

typedef struct _updowncall_entry {
    DWORD version;
    LONGLONG xid;
    nfs41_opcodes opcode;
    NTSTATUS status;
    nfs41_updowncall_state state;
    FAST_MUTEX lock;
    LIST_ENTRY next;
    KEVENT cond;
#undef errno
    DWORD errno;
    BOOLEAN async_op;
    SECURITY_CLIENT_CONTEXT sec_ctx;
    PSECURITY_CLIENT_CONTEXT psec_ctx;
    /*
     * Refcount client token during lifetime of this |updowncall_entry|
     * to avoid crashes during |SeImpersonateClientEx()| if the
     * calling thread disappears.
     */
    PVOID psec_ctx_clienttoken;
    HANDLE open_state;
    HANDLE session;
    PUNICODE_STRING filename;
    PVOID buf;
    ULONG buf_len;
    ULONGLONG ChangeTime;
    union {
        struct {
            PUNICODE_STRING srv_name; /* hostname, or hostname@port */
            PUNICODE_STRING root;
            NFS41_FILE_FS_ATTRIBUTE_INFORMATION *FsAttrs;
            DWORD sec_flavor;
            DWORD rsize;
            DWORD wsize;
            DWORD lease_time;
            DWORD use_nfspubfh;
            DWORD nfsvers;
        } Mount;
        struct {
            PMDL MdlAddress;
            ULONGLONG offset;
            PRX_CONTEXT rxcontext;
        } ReadWrite;
        struct {
            LONGLONG offset;
            LONGLONG length;
            BOOLEAN exclusive;
            BOOLEAN blocking;
        } Lock;
        struct {
            ULONG count;
            LOWIO_LOCK_LIST locks;
        } Unlock;
        struct {
            FILE_BASIC_INFORMATION binfo;
            FILE_STANDARD_INFORMATION sinfo;
            ULONGLONG fileid;
            ULONGLONG fsid_major, fsid_minor;
            UNICODE_STRING symlink;
            BOOLEAN isvolumemntpt;
            ULONG access_mask;
            ULONG access_mode;
            ULONG attrs;
            ULONG copts;
            ULONG disp;
            ULONG cattrs;
            LONG open_owner_id;
            DWORD mode;
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
            DWORD owner_local_uid;
            DWORD owner_group_local_gid;
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
            HANDLE srv_open;
            DWORD deleg_type;
            BOOLEAN symlink_embedded;
            nfs41_sysop_open_symlinktarget_type symlinktarget_type;
            PMDL EaMdl;
            PVOID EaBuffer;
        } Open;
        struct {
            HANDLE srv_open;
            BOOLEAN remove;
            BOOLEAN renamed;
        } Close;
        struct {
            PUNICODE_STRING filter;
            FILE_INFORMATION_CLASS InfoClass;
            BOOLEAN restart_scan;
            BOOLEAN return_single;
            BOOLEAN initial_query;
            PMDL mdl;
            PVOID mdl_buf;
        } QueryFile;
        struct {
            FILE_INFORMATION_CLASS InfoClass;
        } SetFile;
        struct {
            DWORD mode;
        } SetEa;
        struct {
            PVOID EaList;
            ULONG EaListLength;
            ULONG Overflow;
            ULONG EaIndex;
            BOOLEAN ReturnSingleEntry;
            BOOLEAN RestartScan;
        } QueryEa;
        struct {
            PUNICODE_STRING target;
        } Symlink;
        struct {
            FS_INFORMATION_CLASS query;
        } Volume;
        struct {
            SECURITY_INFORMATION query;
        } Acl;
        struct {
            FILE_ALLOCATED_RANGE_BUFFER inrange;
            PMDL BufferMdl;
            ULONG BufferSize;
            PVOID Buffer;
            BOOLEAN buffer_overflow;
            ULONG returned_size;
        } QueryAllocatedRanges;
        struct {
            FILE_ZERO_DATA_INFORMATION setzerodata;
        } SetZeroData;
        struct {
            void        *src_state;
            LONGLONG    srcfileoffset;
            LONGLONG    destfileoffset;
            LONGLONG    bytecount;
        } DuplicateData;
    } u;

} nfs41_updowncall_entry;

typedef struct _updowncall_list {
    LIST_ENTRY head;
} nfs41_updowncall_list;
nfs41_updowncall_list upcall, downcall;


#define SERVER_NAME_BUFFER_SIZE         1024
#define MOUNT_CONFIG_RW_SIZE_MIN        8192
#define MOUNT_CONFIG_RW_SIZE_DEFAULT    (4*1024*1024)
#define MOUNT_CONFIG_RW_SIZE_MAX        (16*1024*1024)
#define MAX_SEC_FLAVOR_LEN              12
#define UPCALL_TIMEOUT_DEFAULT          50  /* in seconds */

typedef struct _NFS41_MOUNT_CREATEMODE {
    BOOLEAN use_nfsv3attrsea_mode;
    DWORD mode;
} NFS41_MOUNT_CREATEMODE;

typedef struct _NFS41_MOUNT_CONFIG {
    BOOLEAN use_nfspubfh;
    DWORD nfsvers;
    DWORD ReadSize;
    DWORD WriteSize;
    BOOLEAN ReadOnly;
    BOOLEAN write_thru;
    BOOLEAN nocache;
    BOOLEAN timebasedcoherency;
    WCHAR srv_buffer[SERVER_NAME_BUFFER_SIZE];
    UNICODE_STRING SrvName; /* hostname, or hostname@port */
    WCHAR mntpt_buffer[NFS41_SYS_MAX_PATH_LEN];
    UNICODE_STRING MntPt;
    WCHAR sec_flavor_buffer[MAX_SEC_FLAVOR_LEN];
    UNICODE_STRING SecFlavor;
    DWORD timeout;
    NFS41_MOUNT_CREATEMODE dir_createmode;
    NFS41_MOUNT_CREATEMODE file_createmode;
} NFS41_MOUNT_CONFIG, *PNFS41_MOUNT_CONFIG;

typedef struct _nfs41_mount_entry {
    LIST_ENTRY next;
    LUID login_id;
    HANDLE authnone_session;
    HANDLE authsys_session;
    HANDLE gss_session;
    HANDLE gssi_session;
    HANDLE gssp_session;
    NFS41_MOUNT_CONFIG Config;
} nfs41_mount_entry;

typedef struct _nfs41_mount_list {
    LIST_ENTRY head;
} nfs41_mount_list;

#define nfs41_AddEntry(lock,list,pEntry)                    \
            { \
            ExAcquireFastMutexUnsafe(&(lock));              \
            InsertTailList(&(list).head, &(pEntry)->next);  \
            ExReleaseFastMutexUnsafe(&(lock));              \
            }
#define nfs41_RemoveFirst(lock,list,pEntry)                 \
            { \
            ExAcquireFastMutexUnsafe(&(lock));              \
            (pEntry) = (IsListEmpty(&(list).head)           \
            ? NULL                                          \
            : RemoveHeadList(&(list).head));                \
            ExReleaseFastMutexUnsafe(&(lock));              \
            }
#define nfs41_RemoveEntry(lock,pEntry)                      \
            { \
            ExAcquireFastMutexUnsafe(&(lock));              \
            RemoveEntryList(&(pEntry)->next);               \
            ExReleaseFastMutexUnsafe(&(lock));              \
            }
#define nfs41_IsListEmpty(lock,list,flag)                   \
            { \
            ExAcquireFastMutexUnsafe(&(lock));              \
            (flag) = IsListEmpty(&(list).head);             \
            ExReleaseFastMutexUnsafe(&(lock));              \
            }
#define nfs41_GetFirstEntry(lock,list,pEntry)               \
            { \
            ExAcquireFastMutexUnsafe(&(lock));              \
            (pEntry) = (IsListEmpty(&(list).head)           \
             ? NULL                                         \
             : (nfs41_updowncall_entry *)                   \
               (CONTAINING_RECORD((list).head.Flink,        \
                                  nfs41_updowncall_entry,   \
                                  next)));                  \
            ExReleaseFastMutexUnsafe(&(lock));              \
            }
#define nfs41_GetFirstMountEntry(lock,list,pEntry)          \
            { \
            ExAcquireFastMutexUnsafe(&(lock));              \
            (pEntry) = (IsListEmpty(&(list).head)           \
             ? NULL                                         \
             : (nfs41_mount_entry *)                        \
               (CONTAINING_RECORD((list).head.Flink,        \
                                  nfs41_mount_entry,        \
                                  next)));                  \
            ExReleaseFastMutexUnsafe(&(lock));              \
            }


typedef struct _NFS41_NETROOT_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    DWORD                   nfs41d_version;
    BOOLEAN                 mounts_init;
    FAST_MUTEX              mountLock;
    nfs41_mount_list        mounts;
} NFS41_NETROOT_EXTENSION, *PNFS41_NETROOT_EXTENSION;
#define NFS41GetNetRootExtension(pNetRoot)      \
        (((pNetRoot) == NULL) ? NULL :          \
        (PNFS41_NETROOT_EXTENSION)((pNetRoot)->Context))

typedef struct _NFS41_V_NET_ROOT_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    HANDLE                  session;
    NFS41_FILE_FS_ATTRIBUTE_INFORMATION FsAttrs;
    DWORD                   sec_flavor;
    DWORD                   timeout;
    NFS41_MOUNT_CREATEMODE  dir_createmode;
    NFS41_MOUNT_CREATEMODE  file_createmode;
    WCHAR                   mntpt_buffer[NFS41_SYS_MAX_PATH_LEN];
    UNICODE_STRING          MntPt;
    DWORD                   nfsvers;
    BOOLEAN                 read_only;
    BOOLEAN                 write_thru;
    BOOLEAN                 nocache;
    BOOLEAN                 timebasedcoherency;
} NFS41_V_NET_ROOT_EXTENSION, *PNFS41_V_NET_ROOT_EXTENSION;
#define NFS41GetVNetRootExtension(pVNetRoot)      \
        (((pVNetRoot) == NULL) ? NULL :           \
        (PNFS41_V_NET_ROOT_EXTENSION)((pVNetRoot)->Context))

typedef struct _NFS41_FCB {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    FILE_BASIC_INFORMATION  BasicInfo;
    FILE_STANDARD_INFORMATION StandardInfo;
    ULONGLONG               fileid;
    ULONGLONG               fsid_major, fsid_minor;
    BOOLEAN                 Renamed;
    BOOLEAN                 DeletePending;
    DWORD                   mode;
#ifdef NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES
    DWORD                   owner_local_uid;       /* owner mapped into local uid */
    DWORD                   owner_group_local_gid; /* owner group mapped into local gid */
#endif /* NFS41_DRIVER_FEATURE_LOCAL_UIDGID_IN_NFSV3ATTRIBUTES */
    ULONGLONG               changeattr;
} NFS41_FCB, *PNFS41_FCB;
#define NFS41GetFcbExtension(pFcb)      \
        (((pFcb) == NULL) ? NULL : (PNFS41_FCB)((pFcb)->Context))

typedef struct _NFS41_FOBX {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;

    HANDLE nfs41_open_state;
    SECURITY_CLIENT_CONTEXT sec_ctx;
    PVOID acl;
    DWORD acl_len;
    LARGE_INTEGER time;
    DWORD deleg_type;
    BOOLEAN write_thru;
    BOOLEAN nocache;
    BOOLEAN timebasedcoherency;
} NFS41_FOBX, *PNFS41_FOBX;
#define NFS41GetFobxExtension(pFobx)  \
        (((pFobx) == NULL) ? NULL : (PNFS41_FOBX)((pFobx)->Context))

typedef struct _NFS41_SERVER_ENTRY {
    PMRX_SRV_CALL                 pRdbssSrvCall;
    WCHAR                         NameBuffer[SERVER_NAME_BUFFER_SIZE];
    UNICODE_STRING                Name;             // the server name.
} NFS41_SERVER_ENTRY, *PNFS41_SERVER_ENTRY;

typedef struct _NFS41_DEVICE_EXTENSION {
    NODE_TYPE_CODE          NodeTypeCode;
    NODE_BYTE_SIZE          NodeByteSize;
    PRDBSS_DEVICE_OBJECT    DeviceObject;
    ULONG                   ActiveNodes;
    HANDLE                  SharedMemorySection;
    DWORD                   nfs41d_version;
    HANDLE                  openlistHandle;
} NFS41_DEVICE_EXTENSION, *PNFS41_DEVICE_EXTENSION;

#define NFS41GetDeviceExtension(DeviceObject)        \
    ((PNFS41_DEVICE_EXTENSION) \
        (((PBYTE)(DeviceObject)) + sizeof(RDBSS_DEVICE_OBJECT)))

typedef struct _nfs41_fcb_list_entry {
    LIST_ENTRY next;
    PMRX_FCB fcb;
    HANDLE session;
    PNFS41_FOBX nfs41_fobx;
    ULONGLONG ChangeTime;
    BOOLEAN skip;
} nfs41_fcb_list_entry;

typedef struct _nfs41_fcb_list {
    LIST_ENTRY head;
} nfs41_fcb_list;
nfs41_fcb_list openlist;

typedef enum _NULMRX_STORAGE_TYPE_CODES {
    NTC_NFS41_DEVICE_EXTENSION      =   (NODE_TYPE_CODE)0xFC00,
} NFS41_STORAGE_TYPE_CODES;
#define RxDefineNode( node, type )          \
        (node)->NodeTypeCode = NTC_##type;  \
        (node)->NodeByteSize = sizeof(type);

#define RDR_NULL_STATE  0
#define RDR_UNLOADED    1
#define RDR_UNLOADING   2
#define RDR_LOADING     3
#define RDR_LOADED      4
#define RDR_STOPPED     5
#define RDR_STOPPING    6
#define RDR_STARTING    7
#define RDR_STARTED     8

/*
 * Assume network speed is 10MB/s (100base-T ethernet, lowest common
 * denominator which we support) plus disk speed is 10MB/s so add
 * time to transfer requested bytes over the network and read from
 * disk.
 * FIXME: What about ssh-tunneled NFSv4 mounts - should this be a
 * tuneable/mount option ?
 */
#define EXTRA_TIMEOUT_PER_BYTE(size) ((2LL * (size)) / (10*1024*1024LL))

/* Globals */
extern KEVENT upcallEvent;
extern FAST_MUTEX upcallLock;
extern FAST_MUTEX downcallLock;
extern FAST_MUTEX fcblistLock;
extern FAST_MUTEX openOwnerLock;

extern LONGLONG xid;
extern LONG open_owner_id;

#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
extern const LUID SystemLuid;
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */

/* |unix_time_diff| - needed to convert windows time to unix */
extern LARGE_INTEGER unix_time_diff;


/* Prototypes */
NTSTATUS map_mount_errors(
    DWORD status);
NTSTATUS map_sec_flavor(
    IN PUNICODE_STRING sec_flavor_name,
    OUT PDWORD sec_flavor);
NTSTATUS map_open_errors(
    DWORD status,
    USHORT len);
NTSTATUS map_close_errors(
    DWORD status);
NTSTATUS map_querydir_errors(
    DWORD status);
NTSTATUS map_volume_errors(
    DWORD status);
NTSTATUS map_setea_error(
    DWORD error);
NTSTATUS map_query_acl_error(
    DWORD error);
NTSTATUS map_queryfile_error(
    DWORD error);
NTSTATUS map_setfile_error(
    DWORD error);
NTSTATUS map_readwrite_errors(DWORD status);
NTSTATUS map_lock_errors(
    DWORD status);
NTSTATUS map_symlink_errors(
    NTSTATUS status);

VOID nfs41_remove_fcb_entry(
    PMRX_FCB fcb);

/* nfs41sys_acl.c */
NTSTATUS marshal_nfs41_getacl(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS marshal_nfs41_setacl(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_getacl(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_QuerySecurityInformation(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_SetSecurityInformation(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_dir.c */
NTSTATUS marshal_nfs41_dirquery(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_dirquery(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
void print_debug_filedirquery_header(
    PRX_CONTEXT RxContext);
NTSTATUS check_nfs41_dirquery_args(
    IN PRX_CONTEXT RxContext);
NTSTATUS nfs41_QueryDirectory(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_driver.c */
nfs41_fcb_list_entry *nfs41_allocate_nfs41_fcb_list_entry(void);
void nfs41_free_nfs41_fcb_list_entry(nfs41_fcb_list_entry *entry);
NTSTATUS marshall_unicode_as_utf8(
    IN OUT unsigned char **pos,
    IN PCUNICODE_STRING str);
NTSTATUS marshal_nfs41_shutdown(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void enable_caching(
    PMRX_SRV_OPEN SrvOpen,
    PNFS41_FOBX nfs41_fobx,
    ULONGLONG ChangeTime,
    HANDLE session);
VOID nfs41_update_fcb_list(
    PMRX_FCB fcb,
    ULONGLONG ChangeTime);

/* nfs41sys_ea.c */
NTSTATUS marshal_nfs41_easet(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS marshal_nfs41_eaget(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void unmarshal_nfs41_eaget(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_SetEaInformation(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_QueryEaInformation(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_fsctl.c */
NTSTATUS nfs41_FsCtl(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS marshal_nfs41_queryallocatedranges(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_queryallocatedranges(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS marshal_nfs41_setzerodata(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_setzerodata(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS marshal_nfs41_duplicatedata(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_duplicatedata(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);

/* nfs41sys_ioctl.c */
NTSTATUS nfs41_IoCtl(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_lock.c */
NTSTATUS marshal_nfs41_lock(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS marshal_nfs41_unlock(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS nfs41_IsLockRealizable(
    IN OUT PMRX_FCB pFcb,
    IN PLARGE_INTEGER  ByteOffset,
    IN PLARGE_INTEGER  Length,
    IN ULONG  LowIoLockFlags);
NTSTATUS nfs41_Lock(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_Unlock(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_mount.c */
void copy_nfs41_mount_config(NFS41_MOUNT_CONFIG *dest,
    NFS41_MOUNT_CONFIG *src);
NTSTATUS marshal_nfs41_mount(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS marshal_nfs41_unmount(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void unmarshal_nfs41_mount(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_unmount(
    HANDLE session,
    DWORD version,
    DWORD timeout);
NTSTATUS nfs41_mount(
    PNFS41_MOUNT_CONFIG config,
    DWORD sec_flavor,
    PHANDLE session,
    DWORD *version,
    NFS41_FILE_FS_ATTRIBUTE_INFORMATION *FsAttrs);
void nfs41_MountConfig_InitDefaults(
    OUT PNFS41_MOUNT_CONFIG Config);
NTSTATUS nfs41_MountConfig_ParseOptions(
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaLength,
    IN OUT PNFS41_MOUNT_CONFIG Config);
NTSTATUS nfs41_CreateVNetRoot(
    IN OUT PMRX_CREATENETROOT_CONTEXT pCreateNetRootContext);
VOID nfs41_ExtractNetRootName(
    IN PUNICODE_STRING FilePathName,
    IN PMRX_SRV_CALL SrvCall,
    OUT PUNICODE_STRING NetRootName,
    OUT PUNICODE_STRING RestOfName OPTIONAL);
NTSTATUS nfs41_FinalizeSrvCall(
    PMRX_SRV_CALL pSrvCall,
    BOOLEAN Force);
NTSTATUS nfs41_FinalizeSrvCall(
    PMRX_SRV_CALL pSrvCall,
    BOOLEAN Force);
NTSTATUS nfs41_FinalizeNetRoot(
    IN OUT PMRX_NET_ROOT pNetRoot,
    IN PBOOLEAN ForceDisconnect);
NTSTATUS nfs41_FinalizeVNetRoot(
    IN OUT PMRX_V_NET_ROOT pVNetRoot,
    IN PBOOLEAN ForceDisconnect);
NTSTATUS GetConnectionHandle(
    IN PUNICODE_STRING ConnectionName,
    IN PVOID EaBuffer,
    IN ULONG EaLength,
    OUT PHANDLE Handle);
NTSTATUS nfs41_CreateConnection(
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp);
NTSTATUS nfs41_DeleteConnection(
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp);

/* nfs41sys_openclose.c */
NTSTATUS marshal_nfs41_open(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS marshal_nfs41_close(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_open(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_Create(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_CollapseOpen(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_ShouldTryToCollapseThisOpen(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_CloseSrvOpen(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_readwrite.c */
NTSTATUS marshal_nfs41_rw(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS unmarshal_nfs41_rw(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_Read(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_Write(
    IN OUT PRX_CONTEXT RxContext);
ULONG nfs41_ExtendForCache(
    IN OUT PRX_CONTEXT RxContext,
    IN PLARGE_INTEGER pNewFileSize,
    OUT PLARGE_INTEGER pNewAllocationSize);

/* nfs41sys_symlink.c */
NTSTATUS marshal_nfs41_symlink(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void unmarshal_nfs41_symlink(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_SetSymlinkReparsePoint(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_GetSymlinkReparsePoint(
    IN OUT PRX_CONTEXT RxContext);
void print_reparse_buffer(
    PREPARSE_DATA_BUFFER r);

/* nfs41sys_reparse.c */
NTSTATUS nfs41_SetReparsePoint(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_GetReparsePoint(
    IN OUT PRX_CONTEXT RxContext);

/* nfs41_updowncall.c */
NTSTATUS marshal_nfs41_header(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void unmarshal_nfs41_attrget(
    nfs41_updowncall_entry *cur,
    PVOID attr_value,
    ULONG *attr_len,
    unsigned char **buf,
    BOOL copy_partial);
NTSTATUS nfs41_UpcallCreate(
    IN DWORD opcode,
    IN PSECURITY_CLIENT_CONTEXT clnt_sec_ctx,
    IN HANDLE session,
    IN HANDLE open_state,
    IN DWORD version,
    IN PUNICODE_STRING filename,
    OUT nfs41_updowncall_entry **entry_out);
void nfs41_UpcallDestroy(nfs41_updowncall_entry *entry);
NTSTATUS nfs41_UpcallWaitForReply(
    IN nfs41_updowncall_entry *entry,
    IN LONGLONG secs);
NTSTATUS nfs41_upcall(
    IN PRX_CONTEXT RxContext);
NTSTATUS nfs41_downcall(
    IN PRX_CONTEXT RxContext);

/* nfs41sys_fileinfo.c */
NTSTATUS marshal_nfs41_filequery(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
NTSTATUS marshal_nfs41_fileset(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void unmarshal_nfs41_setattr(
    nfs41_updowncall_entry *cur,
    PULONGLONG dest_buf,
    unsigned char **buf);
void unmarshal_nfs41_getattr(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_QueryFileInformation(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_SetFileInformation(
    IN OUT PRX_CONTEXT RxContext);
NTSTATUS nfs41_SetFileInformationAtCleanup(
      IN OUT PRX_CONTEXT RxContext);

/* nfs41sys_volinfo.c */
NTSTATUS marshal_nfs41_volume(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len);
void unmarshal_nfs41_volume(
    nfs41_updowncall_entry *cur,
    unsigned char **buf);
NTSTATUS nfs41_QueryVolumeInformation(
    IN OUT PRX_CONTEXT RxContext);

#endif /* !_NFS41SYS_DRIVER_H_ */
