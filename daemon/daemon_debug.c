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

#include <windows.h>
#include <stdio.h>
#include <sddl.h>

#include "daemon_debug.h"
#include "from_kernel.h"
#include "nfs41_driver.h"
#include "nfs41_ops.h"
#include "service.h"
#include "rpc/rpc.h"
#include "rpc/auth_sspi.h"

extern int g_debug_level = DEFAULT_DEBUG_LEVEL;

void set_debug_level(int level) { g_debug_level = level; }

static FILE *dlog_file;
static FILE *elog_file;

#ifndef STANDALONE_NFSD
void open_log_files()
{
    const char dfile[] = "nfsddbg.log";
    const char efile[] = "nfsderr.log";
    const char mode[] = "w";
    if (g_debug_level > 0) {
        dlog_file = fopen(dfile, mode);
        if (dlog_file == NULL) {
            ReportStatusToSCMgr(SERVICE_STOPPED, GetLastError(), 0);
            exit (GetLastError());
        }
    }
    elog_file = fopen(efile, mode);
    if (elog_file == NULL) {
        ReportStatusToSCMgr(SERVICE_STOPPED, GetLastError(), 0);
        exit (GetLastError());
    }
}

void close_log_files()
{
    if (dlog_file) fclose(dlog_file);
    if (elog_file) fclose(elog_file);
}
#else
void open_log_files()
{
    dlog_file = stdout;
    elog_file = stderr;
}
#endif


void dprintf_out(LPCSTR format, ...)
{
    va_list args;
    va_start(args, format);
    (void)fprintf(dlog_file, "%04x: ", (int)GetCurrentThreadId());
    (void)vfprintf(dlog_file, format, args);
    (void)fflush(dlog_file);
    va_end(args);
}

/* log events (mount, umount, auth, ...) */
void logprintf(LPCSTR format, ...)
{
    SYSTEMTIME stime;

    GetLocalTime(&stime);
    va_list args;
    va_start(args, format);
    (void)fprintf(dlog_file,
        "# LOG: ts=%04d-%02d-%02d_%02d:%02d:%02d:%04d"
        " thr=%04x msg=",
        (int)stime.wYear, (int)stime.wMonth, (int)stime.wDay,
        (int)stime.wHour, (int)stime.wMinute, (int)stime.wSecond,
        (int)stime.wMilliseconds,
        (int)GetCurrentThreadId());
    (void)vfprintf(dlog_file, format, args);
    (void)fflush(dlog_file);
    va_end(args);
}

void eprintf(LPCSTR format, ...)
{
    va_list args;
    va_start(args, format);
    (void)fprintf(elog_file, "%04x: ", (int)GetCurrentThreadId());
    (void)vfprintf(elog_file, format, args);
    (void)fflush(elog_file);
    va_end(args);
}

void print_hexbuf(int level, unsigned char *title, unsigned char *buf, int len) 
{
    int j, k;
    if (level > g_debug_level) return;
    fprintf(dlog_file, "%s", title);
    for(j = 0, k = 0; j < len; j++, k++) {
        fprintf(dlog_file, "%02x '%c' ", buf[j], isascii(buf[j])? buf[j]:' ');
        if (((k+1) % 10 == 0 && k > 0)) {
            fprintf(dlog_file, "\n");
        }
    }
    fprintf(dlog_file, "\n");
}

void print_hexbuf_no_asci(int level, unsigned char *title, unsigned char *buf, int len) 
{
    int j, k;
    if (level > g_debug_level) return;
    fprintf(dlog_file, "%s", title);
    for(j = 0, k = 0; j < len; j++, k++) {
        fprintf(dlog_file, "%02x ", buf[j]);
        if (((k+1) % 10 == 0 && k > 0)) {
            fprintf(dlog_file, "\n");
        }
    }
    fprintf(dlog_file, "\n");
}

void print_create_attributes(int level, DWORD create_opts) {
    if (level > g_debug_level) return;
    fprintf(dlog_file, "create attributes: ");
    if (create_opts & FILE_DIRECTORY_FILE)
        fprintf(dlog_file, "DIRECTORY_FILE ");
    if (create_opts & FILE_NON_DIRECTORY_FILE)
        fprintf(dlog_file, "NON_DIRECTORY_FILE ");
    if (create_opts & FILE_WRITE_THROUGH)
        fprintf(dlog_file, "WRITE_THROUGH ");
    if (create_opts & FILE_SEQUENTIAL_ONLY)
        fprintf(dlog_file, "SEQUENTIAL_ONLY ");
    if (create_opts & FILE_RANDOM_ACCESS)
        fprintf(dlog_file, "RANDOM_ACCESS ");
    if (create_opts & FILE_NO_INTERMEDIATE_BUFFERING)
        fprintf(dlog_file, "NO_INTERMEDIATE_BUFFERING ");
    if (create_opts & FILE_SYNCHRONOUS_IO_ALERT)
        fprintf(dlog_file, "SYNCHRONOUS_IO_ALERT ");
    if (create_opts & FILE_SYNCHRONOUS_IO_NONALERT)
        fprintf(dlog_file, "SYNCHRONOUS_IO_NONALERT ");
    if (create_opts & FILE_CREATE_TREE_CONNECTION)
        fprintf(dlog_file, "CREATE_TREE_CONNECTION ");
    if (create_opts & FILE_COMPLETE_IF_OPLOCKED)
        fprintf(dlog_file, "COMPLETE_IF_OPLOCKED ");
    if (create_opts & FILE_NO_EA_KNOWLEDGE)
        fprintf(dlog_file, "NO_EA_KNOWLEDGE ");
    if (create_opts & FILE_OPEN_REPARSE_POINT)
        fprintf(dlog_file, "OPEN_REPARSE_POINT ");
    if (create_opts & FILE_DELETE_ON_CLOSE)
        fprintf(dlog_file, "DELETE_ON_CLOSE ");
    if (create_opts & FILE_OPEN_BY_FILE_ID)
        fprintf(dlog_file, "OPEN_BY_FILE_ID ");
    if (create_opts & FILE_OPEN_FOR_BACKUP_INTENT)
        fprintf(dlog_file, "OPEN_FOR_BACKUP_INTENT ");
    if (create_opts & FILE_RESERVE_OPFILTER)
        fprintf(dlog_file, "RESERVE_OPFILTER");
    fprintf(dlog_file, "\n");
}

void print_disposition(int level, DWORD disposition) {
    if (level > g_debug_level) return;
    fprintf(dlog_file, "userland disposition = ");
    if (disposition == FILE_SUPERSEDE)
        fprintf(dlog_file, "FILE_SUPERSEDE\n");
    else if (disposition == FILE_CREATE)
        fprintf(dlog_file, "FILE_CREATE\n");
    else if (disposition == FILE_OPEN)
        fprintf(dlog_file, "FILE_OPEN\n");
    else if (disposition == FILE_OPEN_IF)
        fprintf(dlog_file, "FILE_OPEN_IF\n");
    else if (disposition == FILE_OVERWRITE)
        fprintf(dlog_file, "FILE_OVERWRITE\n");
    else if (disposition == FILE_OVERWRITE_IF)
        fprintf(dlog_file, "FILE_OVERWRITE_IF\n");
}

void print_access_mask(int level, DWORD access_mask) {
    if (level > g_debug_level) return;
    fprintf(dlog_file, "access mask: ");
    if (access_mask & FILE_READ_DATA)
        fprintf(dlog_file, "READ ");
    if (access_mask & STANDARD_RIGHTS_READ)
        fprintf(dlog_file, "READ_ACL ");
    if (access_mask & FILE_READ_ATTRIBUTES)
        fprintf(dlog_file, "READ_ATTR ");
    if (access_mask & FILE_READ_EA)
        fprintf(dlog_file, "READ_EA ");
    if (access_mask & FILE_WRITE_DATA)
        fprintf(dlog_file, "WRITE ");
    if (access_mask & STANDARD_RIGHTS_WRITE)
        fprintf(dlog_file, "WRITE_ACL ");
    if (access_mask & FILE_WRITE_ATTRIBUTES)
        fprintf(dlog_file, "WRITE_ATTR ");
    if (access_mask & FILE_WRITE_EA)
        fprintf(dlog_file, "WRITE_EA ");
    if (access_mask & FILE_APPEND_DATA)
        fprintf(dlog_file, "APPEND ");
    if (access_mask & FILE_EXECUTE)
        fprintf(dlog_file, "EXECUTE ");
    if (access_mask & FILE_LIST_DIRECTORY)
        fprintf(dlog_file, "LIST ");
    if (access_mask & FILE_TRAVERSE)
        fprintf(dlog_file, "TRAVERSE ");
    if (access_mask & SYNCHRONIZE)
        fprintf(dlog_file, "SYNC ");
    if (access_mask & FILE_DELETE_CHILD)
        fprintf(dlog_file, "DELETE_CHILD");
    fprintf(dlog_file, "\n");
}

void print_share_mode(int level, DWORD mode)
{
    if (level > g_debug_level) return;
    fprintf(dlog_file, "share mode: ");
    if (mode & FILE_SHARE_READ)
        fprintf(dlog_file, "READ ");
    if (mode & FILE_SHARE_WRITE)
        fprintf(dlog_file, "WRITE ");
    if (mode & FILE_SHARE_DELETE)
        fprintf(dlog_file, "DELETE");
    fprintf(dlog_file, "\n");
}

void print_file_id_both_dir_info(int level, FILE_ID_BOTH_DIR_INFO *pboth_dir_info)
{
    /* printf %zd is for |size_t| */

    if (level > g_debug_level)
        return;
    (void)fprintf(dlog_file, "FILE_ID_BOTH_DIR_INFO 0x%p %zd\n",
       pboth_dir_info, sizeof(unsigned char *));
    (void)fprintf(dlog_file, "\tNextEntryOffset=%ld %zd %zd\n",
        pboth_dir_info->NextEntryOffset,
        sizeof(pboth_dir_info->NextEntryOffset), sizeof(DWORD));
    (void)fprintf(dlog_file, "\tFileIndex=%ld %zd\n",
        pboth_dir_info->FileIndex,
        sizeof(pboth_dir_info->FileIndex));
    (void)fprintf(dlog_file, "\tCreationTime=0x%llx %zd\n",
        (long long)pboth_dir_info->CreationTime.QuadPart,
        sizeof(pboth_dir_info->CreationTime));
    (void)fprintf(dlog_file, "\tLastAccessTime=0x%llx %zd\n",
        (long long)pboth_dir_info->LastAccessTime.QuadPart,
        sizeof(pboth_dir_info->LastAccessTime));
    (void)fprintf(dlog_file, "\tLastWriteTime=0x%llx %zd\n",
        (long long)pboth_dir_info->LastWriteTime.QuadPart,
        sizeof(pboth_dir_info->LastWriteTime));
    (void)fprintf(dlog_file, "\tChangeTime=0x%llx %zd\n",
        (long long)pboth_dir_info->ChangeTime.QuadPart,
        sizeof(pboth_dir_info->ChangeTime));
    (void)fprintf(dlog_file, "\tEndOfFile=0x%llx %zd\n",
        (long long)pboth_dir_info->EndOfFile.QuadPart,
        sizeof(pboth_dir_info->EndOfFile));
    (void)fprintf(dlog_file, "\tAllocationSize=0x%llx %zd\n",
        (long long)pboth_dir_info->AllocationSize.QuadPart,
        sizeof(pboth_dir_info->AllocationSize));
    (void)fprintf(dlog_file, "\tFileAttributes=%ld %zd\n",
        pboth_dir_info->FileAttributes,
        sizeof(pboth_dir_info->FileAttributes));
    (void)fprintf(dlog_file, "\tFileNameLength=%ld %zd\n",
        pboth_dir_info->FileNameLength,
        sizeof(pboth_dir_info->FileNameLength));
    (void)fprintf(dlog_file, "\tEaSize=%ld %zd\n",
        pboth_dir_info->EaSize,
        sizeof(pboth_dir_info->EaSize));
    (void)fprintf(dlog_file, "\tShortNameLength=%d %zd\n",
        pboth_dir_info->ShortNameLength,
        sizeof(pboth_dir_info->ShortNameLength));
    (void)fprintf(dlog_file, "\tShortName='%S' %zd\n",
        pboth_dir_info->ShortName,
        sizeof(pboth_dir_info->ShortName));
    (void)fprintf(dlog_file, "\tFileId=0x%llx %zd\n",
        (long long)pboth_dir_info->FileId.QuadPart,
        sizeof(pboth_dir_info->FileId));
    (void)fprintf(dlog_file, "\tFileName='%S' 0x%p\n",
        pboth_dir_info->FileName,
        pboth_dir_info->FileName);
}

void print_sid(const char *label, PSID sid)
{
    PSTR sidstr = NULL;

    if (ConvertSidToStringSidA(sid, &sidstr)) {
        dprintf_out("%s=SID('%s')\n", label, sidstr);
        LocalFree(sidstr);
    }
    else {
        int status;

        status = GetLastError();
        dprintf_out("%s=<ConvertSidToStringSidA() failed error=%d>\n",
            label, status);
    }
}

const char* opcode2string(DWORD opcode)
{
    switch(opcode) {
    case NFS41_SHUTDOWN:    return "NFS41_SHUTDOWN";
    case NFS41_MOUNT:       return "NFS41_MOUNT";
    case NFS41_UNMOUNT:     return "NFS41_UNMOUNT";
    case NFS41_OPEN:        return "NFS41_OPEN";
    case NFS41_CLOSE:       return "NFS41_CLOSE";
    case NFS41_READ:        return "NFS41_READ";
    case NFS41_WRITE:       return "NFS41_WRITE";
    case NFS41_LOCK:        return "NFS41_LOCK";
    case NFS41_UNLOCK:      return "NFS41_UNLOCK";
    case NFS41_DIR_QUERY:   return "NFS41_DIR_QUERY";
    case NFS41_FILE_QUERY:  return "NFS41_FILE_QUERY";
    case NFS41_FILE_SET:    return "NFS41_FILE_SET";
    case NFS41_EA_SET:      return "NFS41_EA_SET";
    case NFS41_EA_GET:      return "NFS41_EA_GET";
    case NFS41_SYMLINK:     return "NFS41_SYMLINK";
    case NFS41_VOLUME_QUERY: return "NFS41_VOLUME_QUERY";
    case NFS41_ACL_QUERY:   return "NFS41_ACL_QUERY";
    case NFS41_ACL_SET:     return "NFS41_ACL_SET";
    default:                return "UNKNOWN";
    }
}

const char* nfs_opnum_to_string(int opnum)
{
    switch (opnum)
    {
    case OP_ACCESS: return "ACCESS";
    case OP_CLOSE: return "CLOSE";
    case OP_COMMIT: return "COMMIT";
    case OP_CREATE: return "CREATE";
    case OP_DELEGPURGE: return "DELEGPURGE";
    case OP_DELEGRETURN: return "DELEGRETURN";
    case OP_GETATTR: return "GETATTR";
    case OP_GETFH: return "GETFH";
    case OP_LINK: return "LINK";
    case OP_LOCK: return "LOCK";
    case OP_LOCKT: return "LOCKT";
    case OP_LOCKU: return "LOCKU";
    case OP_LOOKUP: return "LOOKUP";
    case OP_LOOKUPP: return "LOOKUPP";
    case OP_NVERIFY: return "NVERIFY";
    case OP_OPEN: return "OPEN";
    case OP_OPENATTR: return "OPENATTR";
    case OP_OPEN_CONFIRM: return "OPEN_CONFIRM";
    case OP_OPEN_DOWNGRADE: return "OPEN_DOWNGRADE";
    case OP_PUTFH: return "PUTFH";
    case OP_PUTPUBFH: return "PUTPUBFH";
    case OP_PUTROOTFH: return "PUTROOTFH";
    case OP_READ: return "READ";
    case OP_READDIR: return "READDIR";
    case OP_READLINK: return "READLINK";
    case OP_REMOVE: return "REMOVE";
    case OP_RENAME: return "RENAME";
    case OP_RENEW: return "RENEW";
    case OP_RESTOREFH: return "RESTOREFH";
    case OP_SAVEFH: return "SAVEFH";
    case OP_SECINFO: return "SECINFO";
    case OP_SETATTR: return "SETATTR";
    case OP_SETCLIENTID: return "SETCLIENTID";
    case OP_SETCLIENTID_CONFIRM: return "SETCLIENTID_CONFIRM";
    case OP_VERIFY: return "VERIFY";
    case OP_WRITE: return "WRITE";
    case OP_RELEASE_LOCKOWNER: return "RELEASE_LOCKOWNER";
    case OP_BACKCHANNEL_CTL: return "BACKCHANNEL_CTL";
    case OP_BIND_CONN_TO_SESSION: return "BIND_CONN_TO_SESSION";
    case OP_EXCHANGE_ID: return "EXCHANGE_ID";
    case OP_CREATE_SESSION: return "CREATE_SESSION";
    case OP_DESTROY_SESSION: return "DESTROY_SESSION";
    case OP_FREE_STATEID: return "FREE_STATEID";
    case OP_GET_DIR_DELEGATION: return "GET_DIR_DELEGATION";
    case OP_GETDEVICEINFO: return "GETDEVICEINFO";
    case OP_GETDEVICELIST: return "GETDEVICELIST";
    case OP_LAYOUTCOMMIT: return "LAYOUTCOMMIT";
    case OP_LAYOUTGET: return "LAYOUTGET";
    case OP_LAYOUTRETURN: return "LAYOUTRETURN";
    case OP_SECINFO_NO_NAME: return "SECINFO_NO_NAME";
    case OP_SEQUENCE: return "SEQUENCE";
    case OP_SET_SSV: return "SET_SSV";
    case OP_TEST_STATEID: return "TEST_STATEID";
    case OP_WANT_DELEGATION: return "WANT_DELEGATION";
    case OP_DESTROY_CLIENTID: return "DESTROY_CLIENTID";
    case OP_RECLAIM_COMPLETE: return "RECLAIM_COMPLETE";
    case OP_ILLEGAL: return "ILLEGAL";
    default: return "invalid nfs opnum";
    }
}

const char* nfs_error_string(int status)
{
    switch (status)
    {
#define NFSERR_TO_STRLITERAL(e) case e: return #e;
    NFSERR_TO_STRLITERAL(NFS4_OK)
    NFSERR_TO_STRLITERAL(NFS4ERR_PERM)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOENT)
    NFSERR_TO_STRLITERAL(NFS4ERR_IO)
    NFSERR_TO_STRLITERAL(NFS4ERR_NXIO)
    NFSERR_TO_STRLITERAL(NFS4ERR_ACCESS)
    NFSERR_TO_STRLITERAL(NFS4ERR_EXIST)
    NFSERR_TO_STRLITERAL(NFS4ERR_XDEV)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOTDIR)
    NFSERR_TO_STRLITERAL(NFS4ERR_ISDIR)
    NFSERR_TO_STRLITERAL(NFS4ERR_INVAL)
    NFSERR_TO_STRLITERAL(NFS4ERR_FBIG)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOSPC)
    NFSERR_TO_STRLITERAL(NFS4ERR_ROFS)
    NFSERR_TO_STRLITERAL(NFS4ERR_MLINK)
    NFSERR_TO_STRLITERAL(NFS4ERR_NAMETOOLONG)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOTEMPTY)
    NFSERR_TO_STRLITERAL(NFS4ERR_DQUOT)
    NFSERR_TO_STRLITERAL(NFS4ERR_STALE)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADHANDLE)
    NFSERR_TO_STRLITERAL(NFS4ERR_BAD_COOKIE)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOTSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_TOOSMALL)
    NFSERR_TO_STRLITERAL(NFS4ERR_SERVERFAULT)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADTYPE)
    NFSERR_TO_STRLITERAL(NFS4ERR_DELAY)
    NFSERR_TO_STRLITERAL(NFS4ERR_SAME)
    NFSERR_TO_STRLITERAL(NFS4ERR_DENIED)
    NFSERR_TO_STRLITERAL(NFS4ERR_EXPIRED)
    NFSERR_TO_STRLITERAL(NFS4ERR_LOCKED)
    NFSERR_TO_STRLITERAL(NFS4ERR_GRACE)
    NFSERR_TO_STRLITERAL(NFS4ERR_FHEXPIRED)
    NFSERR_TO_STRLITERAL(NFS4ERR_SHARE_DENIED)
    NFSERR_TO_STRLITERAL(NFS4ERR_WRONGSEC)
    NFSERR_TO_STRLITERAL(NFS4ERR_CLID_INUSE)
    NFSERR_TO_STRLITERAL(NFS4ERR_RESOURCE)
    NFSERR_TO_STRLITERAL(NFS4ERR_MOVED)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOFILEHANDLE)
    NFSERR_TO_STRLITERAL(NFS4ERR_MINOR_VERS_MISMATCH)
    NFSERR_TO_STRLITERAL(NFS4ERR_STALE_CLIENTID)
    NFSERR_TO_STRLITERAL(NFS4ERR_STALE_STATEID)
    NFSERR_TO_STRLITERAL(NFS4ERR_OLD_STATEID)
    NFSERR_TO_STRLITERAL(NFS4ERR_BAD_STATEID)
    NFSERR_TO_STRLITERAL(NFS4ERR_BAD_SEQID)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOT_SAME)
    NFSERR_TO_STRLITERAL(NFS4ERR_LOCK_RANGE)
    NFSERR_TO_STRLITERAL(NFS4ERR_SYMLINK)
    NFSERR_TO_STRLITERAL(NFS4ERR_RESTOREFH)
    NFSERR_TO_STRLITERAL(NFS4ERR_LEASE_MOVED)
    NFSERR_TO_STRLITERAL(NFS4ERR_ATTRNOTSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_NO_GRACE)
    NFSERR_TO_STRLITERAL(NFS4ERR_RECLAIM_BAD)
    NFSERR_TO_STRLITERAL(NFS4ERR_RECLAIM_CONFLICT)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADXDR)
    NFSERR_TO_STRLITERAL(NFS4ERR_LOCKS_HELD)
    NFSERR_TO_STRLITERAL(NFS4ERR_OPENMODE)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADOWNER)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADCHAR)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADNAME)
    NFSERR_TO_STRLITERAL(NFS4ERR_BAD_RANGE)
    NFSERR_TO_STRLITERAL(NFS4ERR_LOCK_NOTSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_OP_ILLEGAL)
    NFSERR_TO_STRLITERAL(NFS4ERR_DEADLOCK)
    NFSERR_TO_STRLITERAL(NFS4ERR_FILE_OPEN)
    NFSERR_TO_STRLITERAL(NFS4ERR_ADMIN_REVOKED)
    NFSERR_TO_STRLITERAL(NFS4ERR_CB_PATH_DOWN)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADIOMODE)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADLAYOUT)
    NFSERR_TO_STRLITERAL(NFS4ERR_BAD_SESSION_DIGEST)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADSESSION)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADSLOT)
    NFSERR_TO_STRLITERAL(NFS4ERR_COMPLETE_ALREADY)
    NFSERR_TO_STRLITERAL(NFS4ERR_CONN_NOT_BOUND_TO_SESSION)
    NFSERR_TO_STRLITERAL(NFS4ERR_DELEG_ALREADY_WANTED)
    NFSERR_TO_STRLITERAL(NFS4ERR_BACK_CHAN_BUSY)
    NFSERR_TO_STRLITERAL(NFS4ERR_LAYOUTTRYLATER)
    NFSERR_TO_STRLITERAL(NFS4ERR_LAYOUTUNAVAILABLE)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOMATCHING_LAYOUT)
    NFSERR_TO_STRLITERAL(NFS4ERR_RECALLCONFLICT)
    NFSERR_TO_STRLITERAL(NFS4ERR_UNKNOWN_LAYOUTTYPE)
    NFSERR_TO_STRLITERAL(NFS4ERR_SEQ_MISORDERED)
    NFSERR_TO_STRLITERAL(NFS4ERR_SEQUENCE_POS)
    NFSERR_TO_STRLITERAL(NFS4ERR_REQ_TOO_BIG)
    NFSERR_TO_STRLITERAL(NFS4ERR_REP_TOO_BIG)
    NFSERR_TO_STRLITERAL(NFS4ERR_REP_TOO_BIG_TO_CACHE)
    NFSERR_TO_STRLITERAL(NFS4ERR_RETRY_UNCACHED_REP)
    NFSERR_TO_STRLITERAL(NFS4ERR_UNSAFE_COMPOUND)
    NFSERR_TO_STRLITERAL(NFS4ERR_TOO_MANY_OPS)
    NFSERR_TO_STRLITERAL(NFS4ERR_OP_NOT_IN_SESSION)
    NFSERR_TO_STRLITERAL(NFS4ERR_HASH_ALG_UNSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_CLIENTID_BUSY)
    NFSERR_TO_STRLITERAL(NFS4ERR_PNFS_IO_HOLE)
    NFSERR_TO_STRLITERAL(NFS4ERR_SEQ_FALSE_RETRY)
    NFSERR_TO_STRLITERAL(NFS4ERR_BAD_HIGH_SLOT)
    NFSERR_TO_STRLITERAL(NFS4ERR_DEADSESSION)
    NFSERR_TO_STRLITERAL(NFS4ERR_ENCR_ALG_UNSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_PNFS_NO_LAYOUT)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOT_ONLY_OP)
    NFSERR_TO_STRLITERAL(NFS4ERR_WRONG_CRED)
    NFSERR_TO_STRLITERAL(NFS4ERR_WRONG_TYPE)
    NFSERR_TO_STRLITERAL(NFS4ERR_DIRDELEG_UNAVAIL)
    NFSERR_TO_STRLITERAL(NFS4ERR_REJECT_DELEG)
    NFSERR_TO_STRLITERAL(NFS4ERR_RETURNCONFLICT)
    NFSERR_TO_STRLITERAL(NFS4ERR_DELEG_REVOKED)
    NFSERR_TO_STRLITERAL(NFS4ERR_PARTNER_NOTSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_PARTNER_NO_AUTH)
    NFSERR_TO_STRLITERAL(NFS4ERR_UNION_NOTSUPP)
    NFSERR_TO_STRLITERAL(NFS4ERR_OFFLOAD_DENIED)
    NFSERR_TO_STRLITERAL(NFS4ERR_WRONG_LFS)
    NFSERR_TO_STRLITERAL(NFS4ERR_BADLABEL)
    NFSERR_TO_STRLITERAL(NFS4ERR_OFFLOAD_NO_REQS)
    NFSERR_TO_STRLITERAL(NFS4ERR_NOXATTR)
    NFSERR_TO_STRLITERAL(NFS4ERR_XATTR2BIG)
    default: return "invalid nfs error code";
    }
}

const char* rpc_error_string(int status)
{
    switch (status)
    {
    case RPC_CANTENCODEARGS: return "RPC_CANTENCODEARGS";
    case RPC_CANTDECODERES: return "RPC_CANTDECODERES";
    case RPC_CANTSEND: return "RPC_CANTSEND";
    case RPC_CANTRECV: return "RPC_CANTRECV";
    case RPC_TIMEDOUT: return "RPC_TIMEDOUT";
    case RPC_INTR: return "RPC_INTR";
    case RPC_UDERROR: return "RPC_UDERROR";
    case RPC_VERSMISMATCH: return "RPC_VERSMISMATCH";
    case RPC_AUTHERROR: return "RPC_AUTHERROR";
    case RPC_PROGUNAVAIL: return "RPC_PROGUNAVAIL";
    case RPC_PROGVERSMISMATCH: return "RPC_PROGVERSMISMATCH";
    case RPC_PROCUNAVAIL: return "RPC_PROCUNAVAIL";
    case RPC_CANTDECODEARGS: return "RPC_CANTDECODEARGS";
    case RPC_SYSTEMERROR: return "RPC_SYSTEMERROR";
    default: return "invalid rpc error code";
    }
}

const char* gssauth_string(int type) {
    switch(type) {
    case RPCSEC_SSPI_SVC_NONE: return "RPCSEC_SSPI_SVC_NONE";
    case RPCSEC_SSPI_SVC_INTEGRITY: return "RPCSEC_SSPI_SVC_INTEGRITY";
    case RPCSEC_SSPI_SVC_PRIVACY: return "RPCSEC_SSPI_SVC_PRIVACY";
    default: return "invalid gss auth type";
    }
}

void print_condwait_status(int level, int status)
{
    if (level > g_debug_level) return;
    switch(status) {
        case WAIT_ABANDONED: fprintf(dlog_file, "WAIT_ABANDONED\n"); break;
        case WAIT_OBJECT_0: fprintf(dlog_file, "WAIT_OBJECT_0\n"); break;
        case WAIT_TIMEOUT: fprintf(dlog_file, "WAIT_TIMEOUT\n"); break;
        case WAIT_FAILED: fprintf(dlog_file, "WAIT_FAILED %d\n", GetLastError());
        default: fprintf(dlog_file, "unknown status =%d\n", status);
    }
}

void print_sr_status_flags(int level, int flags)
{
    if (level > g_debug_level) return;
    fprintf(dlog_file, "%04x: sr_status_flags: ", GetCurrentThreadId());
    if (flags & SEQ4_STATUS_CB_PATH_DOWN) 
        fprintf(dlog_file, "SEQ4_STATUS_CB_PATH_DOWN ");
    if (flags & SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING) 
        fprintf(dlog_file, "SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING ");
    if (flags & SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED) 
        fprintf(dlog_file, "SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED ");
    if (flags & SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED) 
        fprintf(dlog_file, "SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED) 
        fprintf(dlog_file, "SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_ADMIN_STATE_REVOKED) 
        fprintf(dlog_file, "SEQ4_STATUS_ADMIN_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_RECALLABLE_STATE_REVOKED) 
        fprintf(dlog_file, "SEQ4_STATUS_RECALLABLE_STATE_REVOKED ");
    if (flags & SEQ4_STATUS_LEASE_MOVED) 
        fprintf(dlog_file, "SEQ4_STATUS_LEASE_MOVED ");
    if (flags & SEQ4_STATUS_RESTART_RECLAIM_NEEDED) 
        fprintf(dlog_file, "SEQ4_STATUS_RESTART_RECLAIM_NEEDED ");
    if (flags & SEQ4_STATUS_CB_PATH_DOWN_SESSION) 
        fprintf(dlog_file, "SEQ4_STATUS_CB_PATH_DOWN_SESSION ");
    if (flags & SEQ4_STATUS_BACKCHANNEL_FAULT) 
        fprintf(dlog_file, "SEQ4_STATUS_BACKCHANNEL_FAULT ");
    if (flags & SEQ4_STATUS_DEVID_CHANGED) 
        fprintf(dlog_file, "SEQ4_STATUS_DEVID_CHANGED ");
    if (flags & SEQ4_STATUS_DEVID_DELETED) 
        fprintf(dlog_file, "SEQ4_STATUS_DEVID_DELETED ");
    fprintf(dlog_file, "\n");
}

const char* secflavorop2name(DWORD sec_flavor)
{
    switch(sec_flavor) {
    case RPCSEC_AUTH_SYS:      return "AUTH_SYS";
    case RPCSEC_AUTHGSS_KRB5:  return "AUTHGSS_KRB5";
    case RPCSEC_AUTHGSS_KRB5I: return "AUTHGSS_KRB5I";
    case RPCSEC_AUTHGSS_KRB5P: return "AUTHGSS_KRB5P";
    }

    return "UNKNOWN FLAVOR";
}

void print_windows_access_mask(int on, ACCESS_MASK m)
{
    if (!on)
        return;
    if (!DPRINTF_LEVEL_ENABLED(1))
        return;

    dprintf_out("--> print_windows_access_mask: %x\n", m);
    if (m & GENERIC_READ)
        dprintf_out("\tGENERIC_READ\n");
    if (m & GENERIC_WRITE)
        dprintf_out("\tGENERIC_WRITE\n");
    if (m & GENERIC_EXECUTE)
        dprintf_out("\tGENERIC_EXECUTE\n");
    if (m & GENERIC_ALL)
        dprintf_out("\tGENERIC_ALL\n");
    if (m & MAXIMUM_ALLOWED)
        dprintf_out("\tMAXIMUM_ALLOWED\n");
    if (m & ACCESS_SYSTEM_SECURITY)
        dprintf_out("\tACCESS_SYSTEM_SECURITY\n");
    if ((m & SPECIFIC_RIGHTS_ALL) == SPECIFIC_RIGHTS_ALL)
        dprintf_out("\tSPECIFIC_RIGHTS_ALL\n");
    if ((m & STANDARD_RIGHTS_ALL) == STANDARD_RIGHTS_ALL)
        dprintf_out("\tSTANDARD_RIGHTS_ALL\n");
    if ((m & STANDARD_RIGHTS_REQUIRED) == STANDARD_RIGHTS_REQUIRED)
        dprintf_out("\tSTANDARD_RIGHTS_REQUIRED\n");
    if (m & SYNCHRONIZE)
        dprintf_out("\tSYNCHRONIZE\n");
    if (m & WRITE_OWNER)
        dprintf_out("\tWRITE_OWNER\n");
    if (m & WRITE_DAC)
        dprintf_out("\tWRITE_DAC\n");
    if (m & READ_CONTROL)
        dprintf_out("\tREAD_CONTROL\n");
    if (m & DELETE)
        dprintf_out("\tDELETE\n");
    if (m & FILE_READ_DATA)
        dprintf_out("\tFILE_READ_DATA\n");
    if (m & FILE_LIST_DIRECTORY)
        dprintf_out("\tFILE_LIST_DIRECTORY\n");
    if (m & FILE_WRITE_DATA)
        dprintf_out("\tFILE_WRITE_DATA\n");
    if (m & FILE_ADD_FILE)
        dprintf_out("\tFILE_ADD_FILE\n");
    if (m & FILE_APPEND_DATA)
        dprintf_out("\tFILE_APPEND_DATA\n");
    if (m & FILE_ADD_SUBDIRECTORY)
        dprintf_out("\tFILE_ADD_SUBDIRECTORY\n");
    if (m & FILE_CREATE_PIPE_INSTANCE)
        dprintf_out("\tFILE_CREATE_PIPE_INSTANCE\n");
    if (m & FILE_READ_EA)
        dprintf_out("\tFILE_READ_EA\n");
    if (m & FILE_WRITE_EA)
        dprintf_out("\tFILE_WRITE_EA\n");
    if (m & FILE_EXECUTE)
        dprintf_out("\tFILE_EXECUTE\n");
    if (m & FILE_TRAVERSE)
        dprintf_out("\tFILE_TRAVERSE\n");
    if (m & FILE_DELETE_CHILD)
        dprintf_out("\tFILE_DELETE_CHILD\n");
    if (m & FILE_READ_ATTRIBUTES)
        dprintf_out("\tFILE_READ_ATTRIBUTES\n");
    if (m & FILE_WRITE_ATTRIBUTES)
        dprintf_out("\tFILE_WRITE_ATTRIBUTES\n");
    if ((m & FILE_ALL_ACCESS) == FILE_ALL_ACCESS)
        dprintf_out("\tFILE_ALL_ACCESS\n");
    if ((m & FILE_GENERIC_READ) == FILE_GENERIC_READ)
        dprintf_out("\tFILE_GENERIC_READ\n");
    if ((m & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE)
        dprintf_out("\tFILE_GENERIC_WRITE\n");
    if ((m & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE)
        dprintf_out("\tFILE_GENERIC_EXECUTE\n");
}

void print_nfs_access_mask(int on, int m)
{
    if (!on) return;
    if (!DPRINTF_LEVEL_ENABLED(1))
        return;

    dprintf_out("--> print_nfs_access_mask: %x\n", m);
    if (m & ACE4_READ_DATA)
        dprintf_out("\tACE4_READ_DATA\n");
    if (m & ACE4_LIST_DIRECTORY)
        dprintf_out("\tACE4_LIST_DIRECTORY\n");
    if (m & ACE4_WRITE_DATA)
        dprintf_out("\tACE4_WRITE_DATA\n");
    if (m & ACE4_ADD_FILE)
        dprintf_out("\tACE4_ADD_FILE\n");
    if (m & ACE4_APPEND_DATA)
        dprintf_out("\tACE4_APPEND_DATA\n");
    if (m & ACE4_ADD_SUBDIRECTORY)
        dprintf_out("\tACE4_ADD_SUBDIRECTORY\n");
    if (m & ACE4_READ_NAMED_ATTRS)
        dprintf_out("\tACE4_READ_NAMED_ATTRS\n");
    if (m & ACE4_WRITE_NAMED_ATTRS)
        dprintf_out("\tACE4_WRITE_NAMED_ATTRS\n");
    if (m & ACE4_EXECUTE)
        dprintf_out("\tACE4_EXECUTE\n");
    if (m & ACE4_DELETE_CHILD)
        dprintf_out("\tACE4_DELETE_CHILD\n");
    if (m & ACE4_READ_ATTRIBUTES)
        dprintf_out("\tACE4_READ_ATTRIBUTES\n");
    if (m & ACE4_WRITE_ATTRIBUTES)
        dprintf_out("\tACE4_WRITE_ATTRIBUTES\n");
    if (m & ACE4_DELETE)
        dprintf_out("\tACE4_DELETE\n");
    if (m & ACE4_READ_ACL)
        dprintf_out("\tACE4_READ_ACL\n");
    if (m & ACE4_WRITE_ACL)
        dprintf_out("\tACE4_WRITE_ACL\n");
    if (m & ACE4_WRITE_OWNER)
        dprintf_out("\tACE4_WRITE_OWNER\n");
    if (m & ACE4_SYNCHRONIZE)
        dprintf_out("\tACE4_SYNCHRONIZE\n");
}
