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

#include <Windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>
#include <wincrypt.h> /* for Crypt*() functions */
#include <Lmcons.h>

#include "daemon_debug.h"
#include "util.h"
#include "nfs41_ops.h"


int safe_read(unsigned char **pos, uint32_t *remaining, void *dest, uint32_t dest_len) 
{
    if (*remaining < dest_len)
        return ERROR_BUFFER_OVERFLOW;

    CopyMemory(dest, *pos, dest_len);
    *pos += dest_len;
    *remaining -= dest_len;
    return 0;
}

int safe_write(unsigned char **pos, uint32_t *remaining, void *src, uint32_t src_len)
{
    if (*remaining < src_len)
        return ERROR_BUFFER_OVERFLOW;

    CopyMemory(*pos, src, src_len);
    *pos += src_len;
    *remaining -= src_len;
    return 0;
}

int get_name(unsigned char **pos, uint32_t *remaining, const char **out_name)
{
    int status;
    USHORT len;
    
    status = safe_read(pos, remaining, &len, sizeof(USHORT));
    if (status) goto out;
    if (*remaining < len) {
        status = ERROR_BUFFER_OVERFLOW;
        goto out;
    }
    *out_name = (const char*)*pos;
    *pos += len;
    *remaining -= len;
out:
    return status;
}

const char* strip_path(
    IN const char *path,
    OUT uint32_t *len_out)
{
    const char *name = strrchr(path, '\\');
    name = name ? name + 1 : path;
    if (len_out)
        *len_out = (uint32_t)strlen(name);
    return name;
}

uint32_t max_read_size(
    IN const nfs41_session *session,
    IN const nfs41_fh *fh)
{
    const uint32_t maxresponse = session->fore_chan_attrs.ca_maxresponsesize;
    return (uint32_t)min(fh->superblock->maxread, maxresponse - READ_OVERHEAD);
}

uint32_t max_write_size(
    IN const nfs41_session *session,
    IN const nfs41_fh *fh)
{
    const uint32_t maxrequest = session->fore_chan_attrs.ca_maxrequestsize;
    return (uint32_t)min(fh->superblock->maxwrite, maxrequest - WRITE_OVERHEAD);
}

bool_t verify_write(
    IN nfs41_write_verf *verf,
    IN OUT enum stable_how4 *stable)
{
    if (verf->committed != UNSTABLE4) {
        *stable = verf->committed;
        DPRINTF(3, ("verify_write: committed to stable storage\n"));
        return 1;
    }

    if (*stable != UNSTABLE4) {
        memcpy(verf->expected, verf->verf, NFS4_VERIFIER_SIZE);
        *stable = UNSTABLE4;
        DPRINTF(3, ("verify_write: first unstable write, saving verifier\n"));
        return 1;
    }

    if (memcmp(verf->expected, verf->verf, NFS4_VERIFIER_SIZE) == 0) {
        DPRINTF(3, ("verify_write: verifier matches expected\n"));
        return 1;
    }

    DPRINTF(2, ("verify_write: verifier changed; writes have been lost!\n"));
    return 0;
}

bool_t verify_commit(
    IN nfs41_write_verf *verf)
{
    if (memcmp(verf->expected, verf->verf, NFS4_VERIFIER_SIZE) == 0) {
        DPRINTF(3, ("verify_commit: verifier matches expected\n"));
        return 1;
    }
    DPRINTF(2, ("verify_commit: verifier changed; writes have been lost!\n"));
    return 0;
}

ULONG nfs_file_info_to_attributes(
    IN const nfs41_file_info *info)
{
    ULONG attrs = 0;
    if (info->type == NF4DIR)
        attrs |= FILE_ATTRIBUTE_DIRECTORY;
    else if (info->type == NF4LNK) {
        attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
        if (info->symlink_dir)
            attrs |= FILE_ATTRIBUTE_DIRECTORY;
    }
    else if (info->type != NF4REG) {
        DPRINTF(1, ("unhandled file type %d, defaulting to NF4REG\n",
            info->type));
    }

    if (info->mode == 0444) /* XXX: 0444 for READONLY */
        attrs |= FILE_ATTRIBUTE_READONLY;

    if (info->hidden) attrs |= FILE_ATTRIBUTE_HIDDEN;
    if (info->system) attrs |= FILE_ATTRIBUTE_SYSTEM;
    if (info->archive) attrs |= FILE_ATTRIBUTE_ARCHIVE;

    // FILE_ATTRIBUTE_NORMAL attribute is only set if no other attributes are present.
    // all other override this value.
    return attrs ? attrs : FILE_ATTRIBUTE_NORMAL;
}

void nfs_to_basic_info(
    IN const char *name,
    IN const nfs41_file_info *info,
    OUT PFILE_BASIC_INFO basic_out)
{
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&info->time_create, &basic_out->CreationTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_create not set\n", name));
        basic_out->CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&info->time_access, &basic_out->LastAccessTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_access not set\n", name));
        basic_out->LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &basic_out->LastWriteTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_modify not set\n", name));
        basic_out->LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &basic_out->ChangeTime);
    }
    else {
        DPRINTF(1, ("nfs_to_basic_info(name='%s'): "
            "time_modify2 not set\n", name));
        basic_out->ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    basic_out->FileAttributes = nfs_file_info_to_attributes(info);
}

void nfs_to_standard_info(
    IN const nfs41_file_info *info,
    OUT PFILE_STANDARD_INFO std_out)
{
    const ULONG FileAttributes = nfs_file_info_to_attributes(info);

    std_out->AllocationSize.QuadPart =
        std_out->EndOfFile.QuadPart = (LONGLONG)info->size;
    std_out->NumberOfLinks = info->numlinks;
    std_out->DeletePending = FALSE;
    std_out->Directory = FileAttributes & FILE_ATTRIBUTE_DIRECTORY ?
        TRUE : FALSE;
}

void nfs_to_network_openinfo(
    IN const char *name,
    IN const nfs41_file_info *info,
    OUT PFILE_NETWORK_OPEN_INFORMATION net_out)
{
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&info->time_create, &net_out->CreationTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_create not set\n", name));
        net_out->CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&info->time_access, &net_out->LastAccessTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_access not set\n", name));
        net_out->LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &net_out->LastWriteTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_modify not set\n", name));
        net_out->LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&info->time_modify, &net_out->ChangeTime);
    }
    else {
        DPRINTF(1, ("nfs_to_network_openinfo(name='%s'): "
            "time_modify2 not set\n", name));
        net_out->ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    net_out->AllocationSize.QuadPart =
        net_out->EndOfFile.QuadPart = (LONGLONG)info->size;
    net_out->FileAttributes = nfs_file_info_to_attributes(info);
}

/* copy |nfs41_file_info| */
void nfs41_file_info_cpy(
    OUT nfs41_file_info *dest,
    IN const nfs41_file_info *src)
{
    (void)memcpy(dest, src, sizeof(nfs41_file_info));
    if (src->owner != NULL)
        dest->owner = dest->owner_buf;
    if (src->owner_group != NULL)
        dest->owner_group = dest->owner_group_buf;
}

void get_file_time(
    OUT PLARGE_INTEGER file_time)
{
    GetSystemTimeAsFileTime((LPFILETIME)file_time);
}

void get_nfs_time(
    OUT nfstime4 *nfs_time)
{
    LARGE_INTEGER file_time;
    get_file_time(&file_time);
    file_time_to_nfs_time(&file_time, nfs_time);
}

bool_t multi_addr_find(
    IN const multi_addr4 *addrs,
    IN const netaddr4 *addr,
    OUT OPTIONAL uint32_t *index_out)
{
    uint32_t i;
    for (i = 0; i < addrs->count; i++) {
        const netaddr4 *saddr = &addrs->arr[i];
        if (!strncmp(saddr->netid, addr->netid, NFS41_NETWORK_ID_LEN) &&
            !strncmp(saddr->uaddr, addr->uaddr, NFS41_UNIVERSAL_ADDR_LEN)) {
            if (index_out) *index_out = i;
            return 1;
        }
    }
    return 0;
}

int nfs_to_windows_error(int status, int default_error)
{
    /* make sure this is actually an nfs error */
    if (status < 0 || (status > 70 && status < 10001) || status > 10087) {
        eprintf("nfs_to_windows_error called with non-nfs "
            "error code %d; returning the error as is\n", status);
        return status;
    }

    switch (status) {
    case NFS4_OK:               return NO_ERROR;
    case NFS4ERR_PERM:          return ERROR_ACCESS_DENIED;
    case NFS4ERR_NOENT:         return ERROR_FILE_NOT_FOUND;
    case NFS4ERR_IO:            return ERROR_NET_WRITE_FAULT;
    case NFS4ERR_ACCESS:        return ERROR_ACCESS_DENIED;
    case NFS4ERR_EXIST:         return ERROR_FILE_EXISTS;
    case NFS4ERR_XDEV:          return ERROR_NOT_SAME_DEVICE;
    case NFS4ERR_INVAL:         return ERROR_INVALID_PARAMETER;
    case NFS4ERR_FBIG:          return ERROR_FILE_TOO_LARGE;
    case NFS4ERR_NOSPC:         return ERROR_DISK_FULL;
    case NFS4ERR_ROFS:          return ERROR_NETWORK_ACCESS_DENIED;
    case NFS4ERR_MLINK:         return ERROR_TOO_MANY_LINKS;
    case NFS4ERR_NAMETOOLONG:   return ERROR_FILENAME_EXCED_RANGE;
    case NFS4ERR_STALE:         return ERROR_NETNAME_DELETED;
    case NFS4ERR_NOTEMPTY:      return ERROR_NOT_EMPTY;
    case NFS4ERR_DENIED:        return ERROR_LOCK_FAILED;
    case NFS4ERR_TOOSMALL:      return ERROR_BUFFER_OVERFLOW;
    case NFS4ERR_LOCKED:        return ERROR_LOCK_VIOLATION;
    case NFS4ERR_SHARE_DENIED:  return ERROR_SHARING_VIOLATION;
    case NFS4ERR_LOCK_RANGE:    return ERROR_NOT_LOCKED;
    case NFS4ERR_ATTRNOTSUPP:   return ERROR_NOT_SUPPORTED;
    case NFS4ERR_OPENMODE:      return ERROR_ACCESS_DENIED;
    case NFS4ERR_LOCK_NOTSUPP:  return ERROR_ATOMIC_LOCKS_NOT_SUPPORTED;

    case NFS4ERR_BADOWNER:      return ERROR_ACCESS_DENIED;
    case NFS4ERR_BADCHAR:
    case NFS4ERR_BADNAME:       return ERROR_INVALID_NAME;

    case NFS4ERR_NOTDIR:
    case NFS4ERR_ISDIR:
    case NFS4ERR_SYMLINK:
    case NFS4ERR_WRONG_TYPE:    return ERROR_INVALID_PARAMETER;

    case NFS4ERR_EXPIRED:
    case NFS4ERR_NOFILEHANDLE:
    case NFS4ERR_OLD_STATEID:
    case NFS4ERR_BAD_STATEID:
    case NFS4ERR_ADMIN_REVOKED: return ERROR_FILE_INVALID;

    case NFS4ERR_WRONGSEC:      return ERROR_ACCESS_DENIED;

    default:
        DPRINTF(1, ("nfs error '%s' not mapped to windows error; "
            "returning default error %d\n",
            nfs_error_string(status), default_error));
        return default_error;
    }
}

int map_symlink_errors(int status)
{
    switch (status) {
    case NFS4ERR_BADCHAR:
    case NFS4ERR_BADNAME:       return ERROR_INVALID_REPARSE_DATA;
    case NFS4ERR_WRONG_TYPE:    return ERROR_NOT_A_REPARSE_POINT;
    case NFS4ERR_ACCESS:        return ERROR_ACCESS_DENIED;
    case NFS4ERR_NOTEMPTY:      return ERROR_NOT_EMPTY;
    default: return nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
    }
}

bool_t next_component(
    IN const char *path,
    IN const char *path_end,
    OUT nfs41_component *component)
{
    const char *component_end;
    component->name = next_non_delimiter(path, path_end);
    component_end = next_delimiter(component->name, path_end);
    component->len = (unsigned short)(component_end - component->name);
    return component->len > 0;
}

bool_t last_component(
    IN const char *path,
    IN const char *path_end,
    OUT nfs41_component *component)
{
    const char *component_end = prev_delimiter(path_end, path);
    component->name = prev_non_delimiter(component_end, path);
    component->name = prev_delimiter(component->name, path);
    component->name = next_non_delimiter(component->name, component_end);
    component->len = (unsigned short)(component_end - component->name);
    return component->len > 0;
}

bool_t is_last_component(
    IN const char *path,
    IN const char *path_end)
{
    path = next_delimiter(path, path_end);
    return next_non_delimiter(path, path_end) == path_end;
}

void abs_path_copy(
    OUT nfs41_abs_path *dst,
    IN const nfs41_abs_path *src)
{
    dst->len = src->len;
    StringCchCopyNA(dst->path, NFS41_MAX_PATH_LEN, src->path, dst->len);
}

void path_fh_init(
    OUT nfs41_path_fh *file,
    IN nfs41_abs_path *path)
{
    file->path = path;
    last_component(path->path, path->path + path->len, &file->name);
}

void fh_copy(
    OUT nfs41_fh *dst,
    IN const nfs41_fh *src)
{
    dst->fileid = src->fileid;
    dst->superblock = src->superblock;
    dst->len = src->len;
    memcpy(dst->fh, src->fh, dst->len);
}

void path_fh_copy(
    OUT nfs41_path_fh *dst,
    IN const nfs41_path_fh *src)
{
    dst->path = src->path;
    if (dst->path) {
        const size_t name_start = src->name.name - src->path->path;
        dst->name.name = dst->path->path + name_start;
        dst->name.len = src->name.len;
    } else {
        dst->name.name = NULL;
        dst->name.len = 0;
    }
    fh_copy(&dst->fh, &src->fh);
}

int create_silly_rename(
    IN nfs41_abs_path *path,
    IN const nfs41_fh *fh,
    OUT nfs41_component *silly)
{
    HCRYPTPROV context;
    HCRYPTHASH hash;
    PBYTE buffer;
    DWORD length;
    const char *end = path->path + NFS41_MAX_PATH_LEN;
    const unsigned short extra_len = 2 + 16; //md5 is 16
    char name[NFS41_MAX_COMPONENT_LEN+1];
    unsigned char fhmd5[17] = { 0 };
    char *tmp;
    int status = NO_ERROR, i;

    if (path->len + extra_len >= NFS41_MAX_PATH_LEN) {
        status = ERROR_FILENAME_EXCED_RANGE;
        goto out;
    }

    /* set up the md5 hash generator */
    if (!CryptAcquireContext(&context, NULL, NULL,
        PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        status = GetLastError();
        eprintf("CryptAcquireContext() failed with %d\n", status);
        goto out;
    }
    if (!CryptCreateHash(context, CALG_MD5, 0, 0, &hash)) {
        status = GetLastError();
        eprintf("CryptCreateHash() failed with %d\n", status);
        goto out_context;
    }

    if (!CryptHashData(hash, (const BYTE*)fh->fh, (DWORD)fh->len, 0)) {
        status = GetLastError();
        eprintf("CryptHashData() failed with %d\n", status);
        goto out_hash;
    }

    /* extract the hash buffer */
    buffer = (PBYTE)fhmd5;
    length = 16;
    if (!CryptGetHashParam(hash, HP_HASHVAL, buffer, &length, 0)) {
        status = GetLastError();
        eprintf("CryptGetHashParam(val) failed with %d\n", status);
        goto out_hash;
    }    

    last_component(path->path, path->path + path->len, silly);
    StringCchCopyNA(name, NFS41_MAX_COMPONENT_LEN+1, silly->name, silly->len);

    tmp = (char*)silly->name;
    StringCchPrintfA(tmp, end - tmp, ".%s.", name);
    tmp += (size_t)silly->len + 2L;

    for (i = 0; i < 16; i++, tmp++)
        StringCchPrintfA(tmp, end - tmp, "%x", fhmd5[i]);

    path->len = path->len + extra_len;
    silly->len = silly->len + extra_len;

out_hash:
    CryptDestroyHash(hash);
out_context:
    CryptReleaseContext(context, 0);
out:
    return status;
}


/*
 * Like Win32 |popen()| but doesn't randomly fail or genrates EINVAL
 * for unknown reasons
 */
subcmd_popen_context *subcmd_popen(const char *command)
{
    subcmd_popen_context *pinfo;
    STARTUPINFOA si;
    SECURITY_ATTRIBUTES sa = { 0 };

    if (!command) {
        return NULL;
    }

    pinfo = malloc(sizeof(subcmd_popen_context));
    if (!pinfo)
        return NULL;

    pinfo->hReadPipe = pinfo->hWritePipe = NULL;

#ifdef NOT_WORKING_YET
    /*
     * gisburn: fixme: Currently |CreatePipe()| can fail with
     * |ERROR_BAD_IMPERSONATION_LEVEL|/|1346| for user
     * "SYSTEM" if nfsd(|debug).exe tries to impersonate
     * user "SYSTEM" while running as normal user.
     */
    SECURITY_DESCRIPTOR sd;
    (void)memset(&sd, 0, sizeof(SECURITY_DESCRIPTOR));
    (void)InitializeSecurityDescriptor(&sd, 1);
    sd.Revision = 1;
    sd.Control |= SE_DACL_PRESENT;
    sd.Dacl = NULL;
#endif /* NOT_WORKING_YET */

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
#ifdef NOT_WORKING_YET
    sa.lpSecurityDescriptor = &sd;
#else
    sa.lpSecurityDescriptor = NULL;
#endif /* NOT_WORKING_YET */

    /*
     * Create a pipe for communication between the parent and child
     * processes
     */
    if (!CreatePipe(&pinfo->hReadPipe, &pinfo->hWritePipe, &sa, 0)) {
        DPRINTF(0, ("subcmd_popen: CreatePipe error, status=%d\n",
            (int)GetLastError()));
        goto fail;
    }

    /* Set the pipe handles to non-inheritable */
    if (!SetHandleInformation(pinfo->hReadPipe, HANDLE_FLAG_INHERIT, FALSE)) {
        DPRINTF(0, ("subcmd_popen: SetHandleInformation error\n"));
        goto fail;
    }

    (void)memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = NULL;
    si.hStdOutput = pinfo->hWritePipe;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    if (!CreateProcessA(NULL,
        (LPSTR)command, NULL, NULL, TRUE, 0, NULL, NULL, &si,
        &pinfo->pi)) {
        DPRINTF(0, ("subcmd_popen: cannot create process\n"));
        goto fail;
    }

    CloseHandle(pinfo->hWritePipe);

    return pinfo;
fail:
    if (pinfo) {
        if (pinfo->hReadPipe)
            CloseHandle(pinfo->hReadPipe);
        if (pinfo->hWritePipe)
            CloseHandle(pinfo->hWritePipe);

        free(pinfo);
    }
    return NULL;
}

int subcmd_pclose(subcmd_popen_context *pinfo)
{
    DWORD status;

    /* Close the read handle to the pipe from the child process */
    CloseHandle(pinfo->hReadPipe);

    status = WaitForSingleObjectEx(pinfo->pi.hProcess, INFINITE, FALSE);
    EASSERT(status == WAIT_OBJECT_0);

    if (!GetExitCodeProcess(pinfo->pi.hProcess, &status)) {
        status = -1;
    }

    CloseHandle(pinfo->pi.hProcess);
    CloseHandle(pinfo->pi.hThread);

    if (status != 0) {
        DPRINTF(0, ("subcmd_pclose(): exit code=%d\n", (int)status));
    }
    free(pinfo);

    return status;
}

BOOL subcmd_readcmdoutput(subcmd_popen_context *pinfo, char *buff, size_t buff_size, DWORD *num_buff_read_ptr)
{
    return ReadFile(pinfo->hReadPipe, buff, (DWORD)buff_size, num_buff_read_ptr, NULL);
}

/*
 * |waitSRWlock()| - Wait for outstanding locks (usually used
 * before disposing (e.g. |free()| the memory of the structure
 * of the lock) a SRW lock.
 * Returns |TRUE| if we didn't had to wait for another thread
 * to release the lock first.
 */
bool_t waitSRWlock(PSRWLOCK srwlock)
{
    bool_t srw_locked;

    /* Check whether something is still using the lock */
    srw_locked = TryAcquireSRWLockExclusive(srwlock);
    if (srw_locked) {
        ReleaseSRWLockExclusive(srwlock);
    }
    else {
        AcquireSRWLockExclusive(srwlock);
        ReleaseSRWLockExclusive(srwlock);
    }
    return srw_locked;
}

/*
 * |waitcriticalsection()| - Wait for other threads using the
 * CRITICAL_SECTION (usually used before disposing (e.g.
 * |free()| the memory of the structure of the CRITICAL_SECTION)
 * a CRITICAL_SECTION.
 * Returns |TRUE| if we didn't had to wait for another thread
 * to release the lock first.
 */
bool_t waitcriticalsection(LPCRITICAL_SECTION cs)
{
    bool_t cs_locked;

    /* Check whether something is still using the critical section */
    cs_locked = TryEnterCriticalSection(cs);
    if (cs_locked) {
        LeaveCriticalSection(cs);
    }
    else {
        EnterCriticalSection(cs);
        LeaveCriticalSection(cs);
    }
    return cs_locked;
}

/*
 * Get WinNT version numbers
 *
 * We use this wrapper function because |RtlGetNtVersionNumbers()|
 * is a private API, but it should be safe to use as Cygwin and
 * other software relies on it
 */
bool getwinntversionnnumbers(
    DWORD *MajorVersionPtr,
    DWORD *MinorVersionPtr,
    DWORD *BuildNumberPtr)
{
    NTSTATUS RtlGetNtVersionNumbers(LPDWORD, LPDWORD, LPDWORD);

    /*
     * Reference:
     * https://cygwin.com/git/?p=newlib-cygwin.git;a=blob;f=winsup/cygwin/wincap.cc
     */
    (void)RtlGetNtVersionNumbers(MajorVersionPtr, MinorVersionPtr, BuildNumberPtr);
    *BuildNumberPtr &= 0xffff;

    return true;
}

/*
 * Performance hack:
 * GETTOKINFO_EXTRA_BUFFER - extra space for more data
 * |GetTokenInformation()| for |TOKEN_USER| and |TOKEN_PRIMARY_GROUP|
 * always fails in Win10 with |ERROR_INSUFFICIENT_BUFFER| if you
 * just pass the |sizeof(TOKEN_*)| value. Instead of calling
 * |GetTokenInformation()| with |NULL| arg to obtain the size to
 * allocate we just provide 2048 bytes of extra space after the
 * |TOKEN_*| size, and pray it is enough
 */
#define GETTOKINFO_EXTRA_BUFFER (2048)

bool get_token_user_name(HANDLE tok, char *out_buffer)
{
    DWORD tokdatalen;
    PTOKEN_USER ptuser;
    PSID pusid;
    DWORD namesize = UNLEN+1;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_USER)+GETTOKINFO_EXTRA_BUFFER;
    ptuser = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenUser, ptuser,
        tokdatalen, &tokdatalen)) {
        eprintf("get_token_username: "
            "GetTokenInformation(tok=0x%p, TokenUser) failed, "
            "status=%d\n",
            (void *)tok, (int)GetLastError());
        return false;
    }

    pusid = ptuser->User.Sid;

    if (!LookupAccountSidA(NULL, pusid, out_buffer, &namesize,
        domainbuffer, &domainbuffer_size, &name_use)) {
        eprintf("get_token_user_name: "
            "LookupAccountSidA() failed, status=%d\n",
            (int)GetLastError());
        return false;
    }

    return true;
}

bool get_token_primarygroup_name(HANDLE tok, char *out_buffer)
{
    DWORD tokdatalen;
    PTOKEN_PRIMARY_GROUP ptpgroup;
    PSID pgsid;
    DWORD namesize = GNLEN+1;
    char domainbuffer[UNLEN+1];
    DWORD domainbuffer_size = sizeof(domainbuffer);
    SID_NAME_USE name_use;

    tokdatalen = sizeof(TOKEN_PRIMARY_GROUP)+GETTOKINFO_EXTRA_BUFFER;
    ptpgroup = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenPrimaryGroup, ptpgroup,
        tokdatalen, &tokdatalen)) {
        eprintf("get_token_primarygroup_name: "
            "GetTokenInformation(tok=0x%p, TokenPrimaryGroup) failed, "
            "status=%d\n",
            (void *)tok, (int)GetLastError());
        return false;
    }

    pgsid = ptpgroup->PrimaryGroup;

    if (!LookupAccountSidA(NULL, pgsid, out_buffer, &namesize,
        domainbuffer, &domainbuffer_size, &name_use)) {
        eprintf("get_token_username: "
            "LookupAccountSidA() failed, status=%d\n",
            (int)GetLastError());
        return false;
    }

    return true;
}
