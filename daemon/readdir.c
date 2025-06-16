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

#include <Windows.h>
#include <strsafe.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include "nfs41_build_features.h"
#include "nfs41_driver.h" /* for |FILE_INFO_TIME_NOT_SET| */
#include "from_kernel.h"
#include "nfs41_ops.h"
#include "daemon_debug.h"
#include "upcall.h"
#include "fileinfoutil.h"
#include "util.h"


/*
 * Handle filename pattern for NtQueryDirectoryFile()
 */

/*
 * See
 * https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-_fsrtl_advanced_fcb_header-fsrtlisdbcsinexpression
 * for a description of the pattern syntax
 */
#define FILTER_STAR ('<')
#define FILTER_QM   ('>')
#define FILTER_DOT  ('"')

static
bool
readdir_filter(const char *filter, const char *name)
{
#define MAX_NUM_BACKTRACKING (256L)
    const size_t filter_len = strlen(filter);
    const size_t name_len = strlen(name);
    size_t foff;
    size_t pos;
    size_t bt_buf[MAX_NUM_BACKTRACKING], old_bt_buf[MAX_NUM_BACKTRACKING] = { 0 };
    size_t *bt = bt_buf, *old_bt = old_bt_buf;
    size_t bt_pos, old_bt_pos;
    size_t filter_pos, name_pos = 0, matching_chars = 1;
    int n_ch = 0, f_ch;
    bool endofnamebuf = false;
    bool res;
    bool donotskipdot;

    if ((filter_len == 0) || (name_len == 0))
    {
        if ((name_len == 0) && (filter_len == 0))
            return true;

        return false;
    }

    if ((filter_len == 1) && (filter[0] == '*'))
        return true;

    for (; !endofnamebuf; matching_chars = bt_pos)
    {
        old_bt_pos = bt_pos = 0;

        if (name_pos >= name_len)
        {
            endofnamebuf = true;
            if (matching_chars && (old_bt[matching_chars - 1] == (filter_len * 2)))
                break;
        }
        else
        {
            n_ch = name[name_pos];
            name_pos++;
        }

        while (matching_chars > old_bt_pos)
        {
            filter_pos = (old_bt[old_bt_pos++] + 1) / 2;

            for (foff = 0; filter_pos < filter_len; )
            {
                filter_pos += foff;

                if (filter_pos == filter_len)
                {
                    bt[bt_pos++] = filter_len * 2;
                    break;
                }

                /* backtracking buffer too small ? */
                if (bt_pos > (MAX_NUM_BACKTRACKING - 3L))
                {
                    eprintf("readdir_filter(filter='%s',name='%s'): "
                        "bt buffer too small: "
                        "bt_pos=%d, MAX_NUM_BACKTRACKING=0x%x\n",
                        filter,
                        name,
                        (int)bt_pos,
                        (int)MAX_NUM_BACKTRACKING);
                    res = false;
                    goto done;
                }

                f_ch = filter[filter_pos];
                foff = 1;

                if ((f_ch == n_ch) && !endofnamebuf)
                {
                    bt[bt_pos++] = (filter_pos + foff) * 2;
                }
                else if ((f_ch == '?') && !endofnamebuf)
                {
                    bt[bt_pos++] = (filter_pos + foff) * 2;
                }
                else if (f_ch == '*')
                {
                    bt[bt_pos++] = filter_pos * 2;
                    bt[bt_pos++] = (filter_pos * 2) + 1;
                    continue;
                }
                else if (f_ch == FILTER_STAR)
                {
                    donotskipdot = true;
                    if (!endofnamebuf && (n_ch == '.'))
                    {
                        for (pos = name_pos; pos < name_len; pos++)
                        {
                            if (name[pos] == '.')
                            {
                                donotskipdot = false;
                                break;
                            }
                         }
                    }

                    if (endofnamebuf || (n_ch != '.') || !donotskipdot)
                        bt[bt_pos++] = filter_pos * 2;

                    bt[bt_pos++] = (filter_pos * 2) + 1;
                    continue;
                }
                else if (f_ch == FILTER_QM)
                {
                    if (endofnamebuf || (n_ch == '.'))
                        continue;

                    bt[bt_pos++] = (filter_pos + foff) * 2;
                }
                else if (f_ch == FILTER_DOT)
                {
                    if (endofnamebuf)
                        continue;

                    if (n_ch == '.')
                        bt[bt_pos++] = (filter_pos + foff) * 2;
                }

                break;
            }

            for (pos = 0; (matching_chars > old_bt_pos) && (pos < bt_pos); pos++)
            {
                while ((matching_chars > old_bt_pos) && (bt[pos] > old_bt[old_bt_pos]))
                {
                    old_bt_pos++;
                }
            }
        }

        size_t *bt_swap;
        bt_swap = bt;
        bt = old_bt;
        old_bt = bt_swap;
    }

    res = matching_chars && (old_bt[matching_chars - 1] == (filter_len * 2));

done:
    return res;
}

#ifdef TEST_FILTER
static
void test_filter(const char *filter, const char *name, int expected_res)
{
    int res;
    res = filter_name(filter, name);

    (void)printf("filter_name(filter='%s',\tname='%s')\t = %s - \t%s\n",
        filter, name, res?"true":"false", ((expected_res==res)?"OK":"FAIL"));
}

int main(int ac, char *av[])
{
    test_filter("foo",              "foo",  1);
    test_filter("foo",              "",     0);
    test_filter("",                 "foo",  0);
    test_filter("",                 "",     1);
    test_filter("f*?",              "foo",  1);
    test_filter("f??",              "foo",  1);
    test_filter("f?x",              "foo",  0);
    test_filter("f*",               "foo",  1);
    test_filter("f<",               "foo",  1);
    test_filter("x*",               "foo",  0);
    test_filter("x<",               "foo",  0);
    test_filter("*o",               "foo",  1);
    test_filter("<o",               "foo",  1);
    test_filter("f*oo",             "foo",  1);
    test_filter("f\"o",             "f.o",  1);
    test_filter("f***********oo",   "foo",  1);
    test_filter("f<<<<<<<<<<<oo",   "foo",  1);
    test_filter("f<*<*<*<?<*<o",    "foo",  1);
    test_filter("f<*<*<*<?<*<",     "foo",  1);
    test_filter("<*<*<*<?<*<",      "foo",  1);
    test_filter("CL.write\"<.tlog", "CL.write.foo.bar.tlog", 1);
    test_filter("CL.write\"foo<.tlog", "CL.write.foo.bar.tlog", 1);
    test_filter("CL.write\">>><.tlog", "CL.write.foo.bar.tlog", 1);
    test_filter("<.tlog",           "bar.tlog", 1);
    test_filter(">.tlog",           "a.tlog", 1);
    test_filter(">.tlog",           "ab.tlog", 0);
    test_filter(">>.tlog",          "ab.tlog", 1);
    test_filter(">*.tlog",          "ab.tlog", 1);
    test_filter("*>*.tlog",         "ab.tlog", 1);
    test_filter(">?.tlog",          "ab.tlog", 1);
    return 0;
}
#endif /* TEST_FILTER */


typedef union _FILE_DIR_INFO_UNION {
    ULONG NextEntryOffset;
    FILE_NAMES_INFORMATION fni;
    FILE_DIRECTORY_INFORMATION fdi;
    FILE_FULL_DIR_INFORMATION ffdi;
    FILE_ID_FULL_DIR_INFORMATION fifdi;
    FILE_BOTH_DIR_INFORMATION fbdi;
    FILE_ID_BOTH_DIR_INFORMATION fibdi;
    FILE_ID_EXTD_DIR_INFORMATION fiedi;
    FILE_ID_EXTD_BOTH_DIR_INFORMATION fiebdi;
} FILE_DIR_INFO_UNION, *PFILE_DIR_INFO_UNION;


/* NFS41_SYSOP_DIR_QUERY */
static int parse_readdir(unsigned char *buffer, uint32_t length, nfs41_upcall *upcall)
{
    int status;
    readdir_upcall_args *args = &upcall->args.readdir;

    status = safe_read(&buffer, &length, &args->query_class, sizeof(args->query_class));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->buf_len, sizeof(args->buf_len));
    if (status) goto out;
    status = get_name(&buffer, &length, &args->filter);
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->initial, sizeof(args->initial));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->restart, sizeof(args->restart));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->single, sizeof(args->single));
    if (status) goto out;
    status = safe_read(&buffer, &length, &args->kbuf, sizeof(args->kbuf));
    if (status) goto out;
    args->root = upcall->root_ref;
    args->state = upcall->state_ref;

    DPRINTF(1, ("parsing NFS41_SYSOP_DIR_QUERY: info_class=%d buf_len=%d "
        "filter='%s'\n\tInitial\\Restart\\Single %d\\%d\\%d buf=0x%p\n",
        args->query_class, args->buf_len, args->filter,
        args->initial, args->restart, args->single, args->kbuf));
out:
    return status;
}


static uint32_t readdir_size_for_entry(
    IN int query_class,
    IN uint32_t wname_size)
{
    uint32_t needed = wname_size;
    switch (query_class)
    {
    case FileDirectoryInformation:
        needed += FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
        break;
    case FileIdFullDirectoryInformation:
        needed += FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName);
        break;
    case FileIdExtdDirectoryInformation:
        needed += FIELD_OFFSET(FILE_ID_EXTD_DIR_INFORMATION, FileName);
        break;
    case FileIdExtdBothDirectoryInformation:
        needed += FIELD_OFFSET(FILE_ID_EXTD_BOTH_DIR_INFORMATION,
            FileName);
        break;
    case FileFullDirectoryInformation:
        needed += FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
        break;
    case FileIdBothDirectoryInformation:
        needed += FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);
        break;
    case FileBothDirectoryInformation:
        needed += FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
        break;
    case FileNamesInformation:
        needed += FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
        break;
    default:
        eprintf("unhandled dir query class %d\n", query_class);
        return 0;
    }
    return needed;
}

static void readdir_copy_dir_info(
    IN nfs41_readdir_entry *entry,
    IN const nfs41_superblock *restrict superblock,
    IN PFILE_DIR_INFO_UNION info)
{
    info->fdi.FileIndex = (ULONG)entry->attr_info.fileid;

    uint32_t attrmask_arr1 = entry->attr_info.attrmask.arr[1];

    if (attrmask_arr1 & FATTR4_WORD1_TIME_CREATE) {
        nfs_time_to_file_time(&entry->attr_info.time_create,
            &info->fdi.CreationTime);
    }
    else {
        DPRINTF(1, ("readdir_copy_dir_info(entry->name='%s'): "
            "time_create not set\n", entry->name));
        info->fdi.CreationTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (attrmask_arr1 & FATTR4_WORD1_TIME_ACCESS) {
        nfs_time_to_file_time(&entry->attr_info.time_access,
            &info->fdi.LastAccessTime);
    }
    else {
        DPRINTF(1, ("readdir_copy_dir_info(entry->name='%s'): "
            "time_access not set\n", entry->name));
        info->fdi.LastAccessTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    if (attrmask_arr1 & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&entry->attr_info.time_modify,
            &info->fdi.LastWriteTime);
    }
    else {
        DPRINTF(1, ("readdir_copy_dir_info(entry->name='%s'): "
            "time_modify not set\n", entry->name));
        info->fdi.LastWriteTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    /* XXX: was using 'change' attr, but that wasn't giving a time */
    if (attrmask_arr1 & FATTR4_WORD1_TIME_MODIFY) {
        nfs_time_to_file_time(&entry->attr_info.time_modify,
            &info->fdi.ChangeTime);
    }
    else {
        DPRINTF(1, ("readdir_copy_dir_info(entry->name='%s'): "
            "time_modify2 not set\n", entry->name));
        info->fdi.ChangeTime.QuadPart = FILE_INFO_TIME_NOT_SET;
    }

    info->fdi.EndOfFile.QuadPart = entry->attr_info.size;
    info->fdi.AllocationSize.QuadPart = entry->attr_info.space_used;

    info->fdi.FileAttributes =
        nfs_file_info_to_attributes(superblock, &entry->attr_info);
}

#ifndef NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION
static void readdir_copy_shortname(
    IN LPCWSTR name,
    OUT LPWSTR name_out,
    OUT CCHAR *name_size_out)
{
    /* GetShortPathName returns number of characters, not including \0 */
    *name_size_out = (CCHAR)GetShortPathNameW(name, name_out, 12);
    if (*name_size_out) {
        (*name_size_out)++;
        *name_size_out *= sizeof(WCHAR);
    }
}
#endif /* !NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION */

static
ULONG get_ea_size(void)
{
    /*
     * Always return the maximum EA size (64k), so
     + applications will look for EAs (a value of |0| would
     * mean "no EAs here")
     */
    return (64*1024UL)-1;
}

static void readdir_copy_full_dir_info(
    IN nfs41_readdir_entry *entry,
    IN const nfs41_superblock *restrict superblock,
    IN PFILE_DIR_INFO_UNION info)
{
    readdir_copy_dir_info(entry, superblock, info);
    if (entry->attr_info.type == NF4LNK) {
        /*
         * For files with the |FILE_ATTRIBUTE_REPARSE_POINT|
         * attribute, |EaSize| is used instead to specify its
         * reparse tag. This makes the cmd.exe 'dir' command to
         * show files as <SYMLINK>/<SYMLINKD>, and triggers a
         * |FSCTL_GET_REPARSE_POINT| to query the symlink target
         */
        info->fifdi.EaSize = IO_REPARSE_TAG_SYMLINK;
    }
    else {
        info->fifdi.EaSize = get_ea_size();
    }
}

static void readdir_copy_both_dir_info(
    IN nfs41_readdir_entry *entry,
    IN LPWSTR wname,
    IN const nfs41_superblock *restrict superblock,
    IN PFILE_DIR_INFO_UNION info)
{
    readdir_copy_full_dir_info(entry, superblock, info);
#ifdef NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION
    info->fbdi.ShortName[0] = L'\0';
    info->fbdi.ShortNameLength = 0;
#else
    readdir_copy_shortname(wname, info->fbdi.ShortName,
        &info->fbdi.ShortNameLength);
#endif /* NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION */
}

static void readdir_copy_filename(
    IN LPCWSTR name,
    IN uint32_t name_size,
    OUT LPWSTR name_out,
    OUT ULONG *name_size_out)
{
    *name_size_out = name_size;
    memcpy(name_out, name, name_size);
}

static int format_abs_path(
    IN const nfs41_abs_path *path,
    IN const nfs41_component *name,
    OUT nfs41_abs_path *path_out)
{
    /* format an absolute path 'parent\name' */
    int status = NO_ERROR;

    InitializeSRWLock(&path_out->lock);
    abs_path_copy(path_out, path);
    if (FAILED(StringCchPrintfA(path_out->path + path_out->len,
        NFS41_MAX_PATH_LEN - path_out->len, "\\%s", name->name))) {
        status = ERROR_FILENAME_EXCED_RANGE;
        goto out;
    }
    path_out->len += name->len + 1;
out:
    return status;
}

static int lookup_entry(
    IN nfs41_root *root,
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    OUT nfs41_readdir_entry *entry)
{
    nfs41_abs_path path;
    nfs41_component name;
    int status;

    name.name = entry->name;
    name.len = (unsigned short)entry->name_len - 1;

    status = format_abs_path(parent->path, &name, &path);
    if (status) goto out;

    status = nfs41_lookup(root, session, &path,
        NULL, NULL, &entry->attr_info, NULL);
    if (status) goto out;
out:
    return status;
}

static int lookup_symlink(
    IN nfs41_root *root,
    IN nfs41_session *session,
    IN nfs41_path_fh *parent,
    IN const nfs41_component *name,
    OUT nfs41_file_info *info_out)
{
    nfs41_abs_path path;
    nfs41_path_fh file;
    nfs41_file_info info;
    int status;

    status = format_abs_path(parent->path, name, &path);
    if (status) goto out;

    file.path = &path;
    status = nfs41_lookup(root, session, &path, NULL, &file, &info, &session);
    if (status) goto out;

    last_component(path.path, path.path + path.len, &file.name);

    status = nfs41_symlink_follow(root, session, &file, &info);
    if (status) {
#ifdef NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS
        info_out->symlink_dir = TRUE;
#else
        info_out->symlink_dir = FALSE;
#endif /* NFS41_DRIVER_TREAT_UNRESOLVEABLE_SYMLINKS_AS_DIRS */
        goto out;
    }

    info_out->symlink_dir = info.type == NF4DIR;
out:
    return status;
}

static int readdir_copy_entry(
    IN readdir_upcall_args *args,
    IN nfs41_readdir_entry *entry,
    IN OUT unsigned char **dst_pos,
    IN OUT uint32_t *dst_len)
{
    int status = 0;
    WCHAR wname[NFS4_OPAQUE_LIMIT];
    uint32_t wname_len, wname_size, needed;
    PFILE_DIR_INFO_UNION info;
    const nfs41_superblock *superblock = args->state->file.fh.superblock;

    wname_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        entry->name, entry->name_len, wname, NFS4_OPAQUE_LIMIT);
    EASSERT(wname_len > 0);
    wname_size = (wname_len - 1) * sizeof(WCHAR);

    needed = readdir_size_for_entry(args->query_class, wname_size);
    if (!needed || needed > *dst_len) {
        status = -1;
        goto out;
    }

    info = (PFILE_DIR_INFO_UNION)*dst_pos;
    info->NextEntryOffset = align8(needed);
    *dst_pos += info->NextEntryOffset;
    *dst_len -= info->NextEntryOffset;

    if (entry->attr_info.rdattr_error == NFS4ERR_MOVED) {
        entry->attr_info.type = NF4DIR; /* default to dir */
        /* look up attributes for referral entries, but ignore return value;
         * it's okay if lookup fails, we'll just write garbage attributes */
        lookup_entry(args->root, args->state->session,
            &args->state->file, entry);
    } else if (entry->attr_info.type == NF4LNK) {
        nfs41_component name;
        name.name = entry->name;
        name.len = (unsigned short)entry->name_len - 1;
        /* look up the symlink target to see whether it's a directory */
        lookup_symlink(args->root, args->state->session,
            &args->state->file, &name, &entry->attr_info);
    }

    switch (args->query_class)
    {
    case FileNamesInformation:
        info->fni.FileIndex = 0;
        readdir_copy_filename(wname, wname_size,
            info->fni.FileName, &info->fni.FileNameLength);
        break;
    case FileDirectoryInformation:
        readdir_copy_dir_info(entry, superblock, info);
        readdir_copy_filename(wname, wname_size,
            info->fdi.FileName, &info->fdi.FileNameLength);
        break;
    case FileFullDirectoryInformation:
        readdir_copy_full_dir_info(entry, superblock, info);
        readdir_copy_filename(wname, wname_size,
            info->ffdi.FileName, &info->ffdi.FileNameLength);
        break;
    case FileIdFullDirectoryInformation:
        readdir_copy_full_dir_info(entry, superblock, info);
        info->fibdi.FileId.QuadPart = (LONGLONG)entry->attr_info.fileid;
        readdir_copy_filename(wname, wname_size,
            info->fifdi.FileName, &info->fifdi.FileNameLength);
        break;
    case FileIdExtdDirectoryInformation:
        readdir_copy_dir_info(entry, superblock, info);
        info->fiedi.EaSize = get_ea_size();
        info->fiedi.ReparsePointTag =
            (entry->attr_info.type == NF4LNK)?
                IO_REPARSE_TAG_SYMLINK : 0;
        nfs41_file_info_to_FILE_ID_128(&entry->attr_info, &info->fiedi.FileId);
        readdir_copy_filename(wname, wname_size,
            info->fiedi.FileName, &info->fiedi.FileNameLength);
        break;
    case FileIdExtdBothDirectoryInformation:
        readdir_copy_dir_info(entry, superblock, info);
        info->fiebdi.EaSize = get_ea_size();
        info->fiebdi.ReparsePointTag =
            (entry->attr_info.type == NF4LNK)?
                IO_REPARSE_TAG_SYMLINK : 0;
        nfs41_file_info_to_FILE_ID_128(&entry->attr_info, &info->fiebdi.FileId);
#ifdef NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION
        info->fiebdi.ShortName[0] = L'\0';
        info->fiebdi.ShortNameLength = 0;
#else
        readdir_copy_shortname(wname, info->fiebdi.ShortName,
            &info->fiebdi.ShortNameLength);
#endif /* NFS41_DRIVER_DISABLE_8DOT3_SHORTNAME_GENERATION */
        readdir_copy_filename(wname, wname_size,
            info->fiebdi.FileName, &info->fiebdi.FileNameLength);
        break;
    case FileBothDirectoryInformation:
        readdir_copy_both_dir_info(entry, wname, superblock, info);
        readdir_copy_filename(wname, wname_size,
            info->fbdi.FileName, &info->fbdi.FileNameLength);
        break;
    case FileIdBothDirectoryInformation:
        readdir_copy_both_dir_info(entry, wname, superblock, info);
        info->fibdi.FileId.QuadPart = (LONGLONG)entry->attr_info.fileid;
        readdir_copy_filename(wname, wname_size,
            info->fibdi.FileName, &info->fibdi.FileNameLength);
        break;
    default:
        eprintf("unhandled dir query class %d\n", args->query_class);
        status = -1;
        break;
    }
out:
    return status;
}

#define COOKIE_DOT      ((uint64_t)-2)
#define COOKIE_DOTDOT   ((uint64_t)-1)

static int readdir_add_dots(
    IN readdir_upcall_args *args,
    IN OUT unsigned char *entry_buf,
    IN uint32_t entry_buf_len,
    OUT uint32_t *len_out,
    OUT uint32_t **last_offset)
{
    int status = 0;
    const uint32_t entry_len = (uint32_t)FIELD_OFFSET(nfs41_readdir_entry, name);
    nfs41_readdir_entry *entry;
    nfs41_open_state *state = args->state;

    *len_out = 0;
    *last_offset = NULL;
    switch (state->cookie.cookie) {
    case 0:
        if (entry_buf_len < entry_len + 2) {
            status = ERROR_BUFFER_OVERFLOW;
            DPRINTF(0, ("readdir_add_dots: not enough room for '.' entry. received %d need %d\n",
                    entry_buf_len, entry_len + 2));
            args->query_reply_len = entry_len + 2;
            goto out;
        }

        entry = (nfs41_readdir_entry*)entry_buf;
        ZeroMemory(&entry->attr_info, sizeof(nfs41_file_info));

        status = nfs41_cached_getattr(state->session,
            &state->file, &entry->attr_info);
        if (status) {
            DPRINTF(0, ("readdir_add_dots: failed to add '.' entry.\n"));
            goto out;
        }
        entry->cookie = COOKIE_DOT;
        entry->name_len = 2;
        StringCbCopyA(entry->name, entry->name_len, ".");
        entry->next_entry_offset = entry_len + entry->name_len;

        entry_buf += entry->next_entry_offset;
        entry_buf_len -= entry->next_entry_offset;
        *len_out += entry->next_entry_offset;
        *last_offset = &entry->next_entry_offset;
        if (args->single)
            break;
        /* else no break! */
    case COOKIE_DOT:
        if (entry_buf_len < entry_len + 3) {
            status = ERROR_BUFFER_OVERFLOW;
            DPRINTF(0, ("readdir_add_dots: not enough room for '..' entry. received %d need %d\n",
                    entry_buf_len, entry_len));
            args->query_reply_len = entry_len + 2;
            goto out;
        }
        /* XXX: this skips '..' when listing root fh */
        if (state->file.name.len == 0)
            break;

        entry = (nfs41_readdir_entry*)entry_buf;
        ZeroMemory(&entry->attr_info, sizeof(nfs41_file_info));

        status = nfs41_cached_getattr(state->session,
            &state->parent, &entry->attr_info);
        if (status) {
            status = ERROR_FILE_NOT_FOUND;
            DPRINTF(0, ("readdir_add_dots: failed to add '..' entry.\n"));
            goto out;
        }
        entry->cookie = COOKIE_DOTDOT;
        entry->name_len = 3;
        StringCbCopyA(entry->name, entry->name_len, "..");
        entry->next_entry_offset = entry_len + entry->name_len;

        entry_buf += entry->next_entry_offset;
        entry_buf_len -= entry->next_entry_offset;
        *len_out += entry->next_entry_offset;
        *last_offset = &entry->next_entry_offset;
        break;
    }
    if (state->cookie.cookie == COOKIE_DOTDOT ||
        state->cookie.cookie == COOKIE_DOT)
        ZeroMemory(&state->cookie, sizeof(nfs41_readdir_cookie));
out:
    return status;
}

static int handle_readdir(void *deamon_context, nfs41_upcall *upcall)
{
    int status;
    readdir_upcall_args *args = &upcall->args.readdir;
    nfs41_open_state *state = upcall->state_ref;
    unsigned char *entry_buf = NULL;
    uint32_t entry_buf_len;
    bitmap4 attr_request;
    bool_t eof;
    /* make sure we allocate enough space for one nfs41_readdir_entry */
    const uint32_t max_buf_len = max(args->buf_len,
        sizeof(nfs41_readdir_entry) + NFS41_MAX_COMPONENT_LEN);

    DPRINTF(1, ("--> handle_nfs41_dirquery(filter='%s',initial=%d,restart=%d,single=%d)\n",
        args->filter, (int)args->initial, (int)args->restart, (int)args->single));

    args->query_reply_len = 0;

    if (args->initial || args->restart) {
        ZeroMemory(&state->cookie, sizeof(nfs41_readdir_cookie));
        if (!state->cookie.cookie) {
            DPRINTF(1, ("initializing the 1st readdir cookie\n"));
        }
        else if (args->restart) {
            DPRINTF(1, ("restarting; clearing previous cookie %llu\n",
                state->cookie.cookie));
        }
        else if (args->initial) {
            DPRINTF(1, ("*** initial; clearing previous cookie %llu!\n",
                state->cookie.cookie));
        }
    } else if (!state->cookie.cookie) {
        DPRINTF(1, ("handle_nfs41_readdir: EOF\n"));
        status = ERROR_NO_MORE_FILES;
        goto out;
    }

    entry_buf = calloc(max_buf_len, sizeof(unsigned char));
    if (entry_buf == NULL) {
        status = GetLastError();
        goto out_free_cookie;
    }
fetch_entries:
    entry_buf_len = max_buf_len;

    nfs41_superblock_getattr_mask(state->file.fh.superblock, &attr_request);
    attr_request.arr[0] |= FATTR4_WORD0_RDATTR_ERROR;

    if (strchr(args->filter, FILTER_STAR) ||
        strchr(args->filter, FILTER_QM) ||
        strchr(args->filter, FILTER_DOT) ||
        strchr(args->filter, '?') ||
        strchr(args->filter, '*')) {
        /* use READDIR for wildcards */

        uint32_t dots_len = 0;
        uint32_t *dots_next_offset = NULL;

        if (args->filter[0] == '*' && args->filter[1] == '\0') {
            status = readdir_add_dots(args, entry_buf,
                entry_buf_len, &dots_len, &dots_next_offset);
            if (status)
                goto out_free_cookie;
            entry_buf_len -= dots_len;
        }

        if (dots_len && args->single) {
            DPRINTF(2, ("skipping nfs41_readdir because the single query "
                "will use . or ..\n"));
            entry_buf_len = 0;
            eof = 0;
        } else {
            DPRINTF(2, ("calling nfs41_readdir with cookie %llu\n",
                state->cookie.cookie));
            status = nfs41_readdir(state->session, &state->file,
                &attr_request, &state->cookie, entry_buf + dots_len,
                &entry_buf_len, &eof);
            if (status) {
                DPRINTF(1, ("nfs41_readdir failed with '%s'\n",
                    nfs_error_string(status)));
                status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
                goto out_free_cookie;
            }
        }

        if (!entry_buf_len && dots_next_offset)
            *dots_next_offset = 0;
        entry_buf_len += dots_len;
    } else {
        /* use LOOKUP for single files */
        nfs41_readdir_entry *entry = (nfs41_readdir_entry*)entry_buf;
        entry->cookie = 0;
        entry->name_len = (uint32_t)strlen(args->filter) + 1;
        if (entry->name_len >= NFS41_MAX_COMPONENT_LEN) {
            DPRINTF(1,
                ("entry->name_len(=%d) >= NFS41_MAX_COMPONENT_LEN\n",
                (int)entry->name_len));
            status = ERROR_FILENAME_EXCED_RANGE;
            goto out_free_cookie;
        }
        StringCbCopyA(entry->name, entry->name_len, args->filter);
        entry->next_entry_offset = 0;

        status = lookup_entry(upcall->root_ref,
             state->session, &state->file, entry);
        if (status) {
            DPRINTF(1, ("single_lookup failed with %d\n", status));
            goto out_free_cookie;
        }
        entry_buf_len = entry->name_len +
                FIELD_OFFSET(nfs41_readdir_entry, name);

        eof = 1;
    }

    status = args->initial ? ERROR_FILE_NOT_FOUND : ERROR_NO_MORE_FILES;

    if (entry_buf_len) {
        unsigned char *entry_pos = entry_buf;
        unsigned char *dst_pos = args->kbuf;
        uint32_t dst_len = args->buf_len;
        nfs41_readdir_entry *entry;
        PULONG offset, last_offset = NULL;

        for (;;) {
            entry = (nfs41_readdir_entry*)entry_pos;
            offset = (PULONG)dst_pos; /* ULONG NextEntryOffset */

            DPRINTF(2, ("filter '%s' looking at '%s' with cookie %lld\n",
                args->filter, entry->name, (long long)entry->cookie));
            if (readdir_filter((const char*)args->filter, entry->name)) {
                if (readdir_copy_entry(args, entry, &dst_pos, &dst_len)) {
                    eof = 0;
                    DPRINTF(2,
                        ("not enough space to copy entry '%s' (cookie %lld)\n",
                        entry->name, (long long)entry->cookie));
                    break;
                }
                last_offset = offset;
                status = NO_ERROR;
            }
            state->cookie.cookie = entry->cookie;

            /* last entry we got from the server */
            if (!entry->next_entry_offset)
                break;

            /* we found our single entry, but the server has more */
            if (args->single && last_offset) {
                eof = 0;
                break;
            }
            entry_pos += entry->next_entry_offset;
        }
        args->query_reply_len = args->buf_len - dst_len;
        if (last_offset) {
            *last_offset = 0;
        } else if (!eof) {
            DPRINTF(1, ("no entries matched; fetch more\n"));
            goto fetch_entries;
        }
    }

    if (eof) {
        DPRINTF(1, ("we don't need to save a cookie\n"));
        goto out_free_cookie;
    } else {
        DPRINTF(1, ("saving cookie %llu\n", state->cookie.cookie));
    }

out_free_entry:
    free(entry_buf);
out:
    const char *debug_status_msg = "<NULL>";

    if (status) {
        switch (status) {
        case ERROR_FILE_NOT_FOUND:
            debug_status_msg = "ERROR_FILE_NOT_FOUND";
            break;
        case ERROR_NO_MORE_FILES:
            debug_status_msg = "ERROR_NO_MORE_FILES";
            break;
        case ERROR_BUFFER_OVERFLOW:
            upcall->last_error = status;
            status = ERROR_SUCCESS;
            debug_status_msg = "ERROR_BUFFER_OVERFLOW==SUCCESS";
            break;
        }
    }
    else {
        debug_status_msg = "SUCCESS";
    }

    DPRINTF(1, ("<-- handle_nfs41_dirquery("
        "filter='%s',initial=%d,restart=%d,single=%d) "
        "returning %d ('%s')\n",
        args->filter, (int)args->initial, (int)args->restart,
        (int)args->single, status, debug_status_msg));

    return status;
out_free_cookie:
    state->cookie.cookie = 0;
    goto out_free_entry;
}

static int marshall_readdir(unsigned char *buffer, uint32_t *length, nfs41_upcall *upcall)
{
    int status;
    readdir_upcall_args *args = &upcall->args.readdir;

    status = safe_write(&buffer, length, &args->query_reply_len, sizeof(args->query_reply_len));
    return status;
}


const nfs41_upcall_op nfs41_op_readdir = {
    .parse = parse_readdir,
    .handle = handle_readdir,
    .marshall = marshall_readdir,
    .arg_size = sizeof(readdir_upcall_args)
};
