/* NFSv4.1 client for Windows
 * Copyright (C) 2024-2026 Roland Mainz <roland.mainz@nrubsig.org>
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

#include <stdlib.h>
#include <stdbool.h>

#include "nfs41_build_features.h"
#include "winstreams.h"
#include "from_kernel.h"
#include "nfs41_ops.h"
#include "delegation.h"
#include "upcall.h"
#include "daemon_debug.h"
#include "util.h"

#ifdef NFS41_WINSTREAMS_SUPPORT

#define WINSTRLVL 1 /* |dprintf()| level for Windows streams logging */

/*
 * |WIN_NFS4_STREAMS_NAME_PREFIX| - Prefix for Windows streams in NFSv4
 * named attribute namespace
 *
 * We need such a prefix to avoid colliding with other users
 * in the NFSv4 named attribute namespace - for example SUN Microsystrems
 * (Solaris, Illumos, ...) uses "SUNWattr_" as prefix, and setting
 * such attributes can cause data corruption (or in case of
 * "SUNWattr_ro" will fail, because the attribute file is
 * read-only).
 */
#define WIN_NFS4_STREAMS_NAME_PREFIX "win32.stream."
#define WIN_NFS4_STREAMS_NAME_PREFIX_LEN (13)


static
int parse_stream_filename_streamname_streamtype(
    const char *restrict path,
    char *restrict filename,
    char *restrict streamname,
    char *restrict streamtype)
{
    const char *sep;
    const char *base;
    int colon_count;
    const char *c1;
    const char *c2;
    const char *p;
    size_t len_prefix;
    size_t len_sn;

    filename[0]   = '\0';
    streamname[0] = '\0';
    streamtype[0] = '\0';

    /* Take the last component after the last backslash */
    sep  = strrchr(path, '\\');
    base = sep ? (sep + 1) : path;

    /* Count colons and error out if >= 3 in the final component */
    colon_count = 0;
    for (p = base ; *p ; p++) {
        if (*p == ':') {
            colon_count++;
            if (colon_count >= 3)
                return ERROR_INVALID_NAME;
        }
    }

    /* Find first colon (if any) */
    c1 = strchr(base, ':');
    if (c1 == NULL) {
        /* No colon: filename is the entire path */
        (void)strcpy(filename, path);
        return NO_ERROR;
    }

    /*
     * First colon exists: filename before ':' can be empty in case if a
     * rename destination. |filename| should then be obtained from the
     * rename src filename
     */

    /*
     * One colon case
     */
    if (colon_count == 1) {
        if (*(c1 + 1) == '\0')
            return ERROR_INVALID_NAME; /* "filename:" => invalid */

        /* filename = full path up to first colon in base */
        len_prefix = (size_t)(c1 - path);
        (void)memcpy(filename, path, len_prefix);
        filename[len_prefix] = '\0';

        /* streamname after first colon */
        (void)strcpy(streamname, c1 + 1);
        /* streamtype stays empty */
        return NO_ERROR;
    }

    /*
     * Two colons case
     */
    c2 = strchr(c1 + 1, ':');
    if (c2 == NULL) {
        /* Should not happen when colon_count == 2 */
        return ERROR_INVALID_NAME;
    }

    if (*(c2 + 1) == '\0')
        return ERROR_INVALID_NAME; /* type must be non-empty */

    /* filename = full path up to first colon */
    len_prefix = (size_t)(c1 - path);
    (void)memcpy(filename, path, len_prefix);
    filename[len_prefix] = '\0';

    /* streamname = [c1+1, c2] (may be empty, e.g., "filename::$DATA") */
    len_sn = (size_t)(c2 - (c1 + 1));
    (void)memcpy(streamname, c1 + 1, len_sn);
    streamname[len_sn] = '\0';

    /* streamtype = (c2+1 .. end) */
    (void)strcpy(streamtype, c2 + 1);

    return NO_ERROR;
}

int parse_win32stream_name(
    IN const char *restrict path,
    IN bool allow_empty_base_name,
    OUT bool *restrict is_stream,
    OUT char *restrict base_name,
    OUT char *restrict stream_name)
{
    int status;
    char filenamebuff[NFS41_MAX_PATH_LEN+1];
    char streamnamebuff[NFS41_MAX_COMPONENT_LEN+1];
    /* |streamtypebuff| must include space for prefix+suffix */
    char streamtypebuff[NFS41_MAX_COMPONENT_LEN+1+128];
    char *p;

    status = parse_stream_filename_streamname_streamtype(path,
        filenamebuff, streamnamebuff, streamtypebuff);
    if (status) {
        eprintf("parse_win32stream_name: "
            "parsing for path='%s' failed, status=%d\n",
            path, status);
        return status;
    }

    if ((allow_empty_base_name == false) &&
        (filenamebuff[0] == '\0')) {
        return ERROR_INVALID_NAME;
    }

    DPRINTF(WINSTRLVL,
        ("parse_win32stream_name: "
        "parse_stream_filename_streamname_streamtype(path='%s') returned "
        "filenamebuff='%s', streamnamebuff='%s', streamtypebuff='%s'\n",
        path, filenamebuff, streamnamebuff, streamtypebuff));

    if ((streamnamebuff[0] == '\0') && (streamtypebuff[0] == '\0')) {
        return ERROR_INVALID_NAME;
    }

    /* We do not support any stream types except "$DATA" (yet) */
    if ((streamtypebuff[0] != '\0') &&
        ((_stricmp(streamtypebuff, "$DATA") != 0))) {
        eprintf("parse_win32stream_name: "
            "Unsupported stream type, path='%s', "
            "stream='%s', streamtype='%s'\n",
            path,
            streamnamebuff,
            streamtypebuff);
        return ERROR_INVALID_NAME;
    }

    /* "foo::$DATA" refers to "foo" */
    if (streamnamebuff[0] == '\0') {
        *is_stream = true;
        (void)strcpy(base_name, filenamebuff);
        stream_name[0] = '\0';
        return NO_ERROR;
    }

    /*
     * If we have a stream name, then add our NFS attr prefix for Windows
     * streams, and ":$DATA" as suffix
     */
    *is_stream = true;
    (void)strcpy(base_name, filenamebuff);
    p = stpcpy(stream_name, WIN_NFS4_STREAMS_NAME_PREFIX);
    p = stpcpy(p, streamnamebuff);
    (void)stpcpy(p, ":$DATA");

    return NO_ERROR;
}

#define ALIGNED_STREAMINFOSIZE(namebytelen) \
    (align8(sizeof(FILE_STREAM_INFORMATION) + (namebytelen)))

static
uint32_t calculate_stream_list_length(
    IN const nfs41_component *restrict basefile_name,
    IN const unsigned char *restrict position,
    IN uint32_t remaining)
{
    const nfs41_readdir_entry *entry;
    uint32_t length = 0;

    /*
     * We always have to add a dummy "::$DATA" entry for the default stream!
     *
     * (|FILE_STREAM_INFORMATION.StreamName| = L"::$DATA" == 8*sizeof(wchar_t))
     */
    length += ALIGNED_STREAMINFOSIZE(8*sizeof(wchar_t));

    /*
     * Enumerate streams
     */
    while (remaining) {
        entry = (const nfs41_readdir_entry *)position;

        if ((entry->name_len > WIN_NFS4_STREAMS_NAME_PREFIX_LEN) &&
            (memcmp(entry->name,
                WIN_NFS4_STREAMS_NAME_PREFIX,
                WIN_NFS4_STREAMS_NAME_PREFIX_LEN) == 0)) {
            char utf8streamname[NFS41_MAX_COMPONENT_LEN+1];
            int wcstreamname_len;

            (void)snprintf(utf8streamname, sizeof(utf8streamname),
                "%.*s:%.*s",
                (int)basefile_name->len,
                basefile_name->name,
                (int)(entry->name_len - WIN_NFS4_STREAMS_NAME_PREFIX_LEN),
                &entry->name[WIN_NFS4_STREAMS_NAME_PREFIX_LEN]);

            wcstreamname_len = MultiByteToWideChar(CP_UTF8,
                MB_ERR_INVALID_CHARS,
                utf8streamname,
                -1,
                NULL,
                0);
            if (wcstreamname_len <= 0) {
                eprintf("calculate_stream_list_length: "
                    "Cannot convert utf8streamname='%s' to widechar\n",
                    utf8streamname);
                goto next_readdir_entry;
            }

            length +=
                ALIGNED_STREAMINFOSIZE(wcstreamname_len*sizeof(WCHAR));
        }

next_readdir_entry:
        if (entry->next_entry_offset == 0)
            break;

        position += entry->next_entry_offset;
        remaining -= entry->next_entry_offset;
    }
    return length;
}

static
void populate_stream_list(
    IN const nfs41_component *restrict basefile_name,
    IN const nfs41_file_info *restrict basefile_info,
    IN const unsigned char *restrict position,
    OUT FILE_STREAM_INFORMATION *restrict stream_list)
{
    const nfs41_readdir_entry *entry;
    PFILE_STREAM_INFORMATION stream = stream_list;
    PFILE_STREAM_INFORMATION last_win_stream = NULL;
    bool is_win_stream;

    /*
     * We always have to add a dummy "::$DATA" entry for the default stream!
     */
    FILE_STREAM_INFORMATION base_stream = {
        .NextEntryOffset = 0,
        /* "::$DATA" == 8*sizeof(wchar_t) */
        .StreamNameLength = 8*sizeof(wchar_t),
        .StreamSize.QuadPart = basefile_info->size,
        .StreamAllocationSize.QuadPart = basefile_info->space_used
    };
    (void)memcpy(stream, &base_stream, sizeof(base_stream));
    (void)memcpy(stream->StreamName, L"::$DATA", 8*sizeof(wchar_t));
    stream->NextEntryOffset =
        ALIGNED_STREAMINFOSIZE(stream->StreamNameLength);
    last_win_stream = stream;
    stream = STREAMINFO_NEXT_ENTRY(stream);

    /*
     * Enumerate streams
     */
    for (;;) {
        entry = (const nfs41_readdir_entry *)position;

        if ((entry->name_len > WIN_NFS4_STREAMS_NAME_PREFIX_LEN) &&
            (memcmp(entry->name,
                WIN_NFS4_STREAMS_NAME_PREFIX,
                WIN_NFS4_STREAMS_NAME_PREFIX_LEN) == 0)) {
            is_win_stream = true;
        }
        else {
            is_win_stream = false;
        }

        if (is_win_stream) {
            char utf8streamname[NFS41_MAX_COMPONENT_LEN+1];
            int wcstreamname_len;

            (void)snprintf(utf8streamname, sizeof(utf8streamname),
                "%.*s:%.*s",
                (int)basefile_name->len,
                basefile_name->name,
                (int)(entry->name_len - WIN_NFS4_STREAMS_NAME_PREFIX_LEN),
                &entry->name[WIN_NFS4_STREAMS_NAME_PREFIX_LEN]);

            wcstreamname_len = MultiByteToWideChar(CP_UTF8,
                MB_ERR_INVALID_CHARS,
                utf8streamname,
                -1,
                stream->StreamName,
                NFS41_MAX_COMPONENT_LEN);
            if (wcstreamname_len <= 0) {
                eprintf("populate_stream_list: "
                    "Cannot convert utf8streamname='%s' to widechar\n",
                    utf8streamname);
                goto next_readdir_entry;
            }

            stream->StreamNameLength = wcstreamname_len*sizeof(WCHAR);

            EASSERT(bitmap_isset(&entry->attr_info.attrmask, 0,
                FATTR4_WORD0_SIZE));
            EASSERT(bitmap_isset(&entry->attr_info.attrmask, 1,
                FATTR4_WORD1_SPACE_USED));
            stream->StreamSize.QuadPart = entry->attr_info.size;
            stream->StreamAllocationSize.QuadPart = entry->attr_info.space_used;

            DPRINTF(WINSTRLVL,
                ("populate_streams_list: adding stream "
                    "entry->(name='%.*s' name_len=%d) "
                    "stream->(StreamName='%.*ls', StreamNameLength=%d, "
                    "StreamSize=%lld, StreamAllocationSize=%lld)\n",
                    (int)entry->name_len,
                    entry->name,
                    (int)entry->name_len,
                    (int)(stream->StreamNameLength/sizeof(WCHAR)),
                    stream->StreamName,
                    (int)stream->StreamNameLength,
                    (long long)stream->StreamSize.QuadPart,
                    (long long)stream->StreamAllocationSize.QuadPart));
            last_win_stream = stream;
        }

next_readdir_entry:
        if (entry->next_entry_offset == 0) {
            (last_win_stream?last_win_stream:stream)->NextEntryOffset = 0;
            break;
        }

        if (is_win_stream) {
            stream->NextEntryOffset =
                ALIGNED_STREAMINFOSIZE(stream->StreamNameLength);
            stream = STREAMINFO_NEXT_ENTRY(stream);
        }

        position += entry->next_entry_offset;
    }
}

static
int get_stream_list(
    IN OUT nfs41_open_state *state,
    IN nfs41_path_fh *streamfile,
    IN const nfs41_file_info *basefile_info,
    OUT FILE_STREAM_INFORMATION *restrict *restrict streamlist_out,
    OUT ULONG *streamlist_out_size)
{
    unsigned char *entry_list;
    PFILE_STREAM_INFORMATION stream_list;
    uint32_t entry_len, stream_list_size;
    int status = NO_ERROR;
    /* Attributes for stream */
    bitmap4 attr_request = {
        .count = 2,
        .arr = {
            [0] = FATTR4_WORD0_TYPE | FATTR4_WORD0_CHANGE |
                FATTR4_WORD0_SIZE | FATTR4_WORD0_FSID |
                FATTR4_WORD0_FILEID,
            [1] = FATTR4_WORD1_SPACE_USED,
            [2] = 0
        }
    };

    /* read the entire directory into a |nfs41_readdir_entry| buffer */
    status = read_entire_dir(state->session, streamfile,
        &attr_request,
        &entry_list, &entry_len);
    if (status)
        goto out;

    stream_list_size = calculate_stream_list_length(&streamfile->name,
        entry_list, entry_len);
    if (stream_list_size == 0) {
        *streamlist_out = NULL;
        *streamlist_out_size = 0UL;
        goto out_free;
    }
    stream_list = calloc(1, stream_list_size);
    if (stream_list == NULL) {
        status = GetLastError();
        goto out_free;
    }

    populate_stream_list(&streamfile->name, basefile_info,
        entry_list, stream_list);

    DPRINTF(WINSTRLVL,
        ("get_stream_list: stream_list=%p, stream_list_size=%ld\n",
        stream_list, (long)stream_list_size));
    *streamlist_out = stream_list;
    *streamlist_out_size = stream_list_size;
out_free:
    free_entire_dir(entry_list); /* allocated by |read_entire_dir()| */
out:
    return status;
}

int get_streaminformation(
    IN OUT nfs41_open_state *state,
    IN const nfs41_file_info *basefile_info,
    OUT FILE_STREAM_INFORMATION *restrict *restrict streamlist_out,
    OUT ULONG *streamlist_out_size)
{
    int status;
    nfs41_path_fh parent = { 0 };

    if (!state->file.fh.superblock->nfs_namedattr_support) {
        return ERROR_NOT_SUPPORTED;
    }

    EASSERT_MSG((basefile_info->type != NF4ATTRDIR),
        ("state->file.name='%.*s' is a NF4ATTRDIR\n",
            (int)state->file.name.len, state->file.name.name));

    /* |FileStreamInformation| for symlinks is not supported */
    if (basefile_info->type == NF4LNK) {
        return ERROR_NOT_SUPPORTED;
    }

    /*
     * FIXME: |FileStreamInformation| for streams is not supported
     * (yet), the expectation is that doing this for stream "abc:str1" will
     * return all streams for "abc"
     */
    if (is_stream_path_fh(&state->file)) {
        DPRINTF(0,
            ("get_streaminformation(name='%.*s'): "
            "stream info with stream name not implemented yet\n",
            (int)state->file.name.len, state->file.name.name));
        return ERROR_NOT_SUPPORTED;
    }

    EASSERT(basefile_info->type != NF4ATTRDIR);
    EASSERT(basefile_info->type != NF4NAMEDATTR);

    status = nfs41_rpc_openattr(state->session, &state->file, FALSE,
        &parent.fh);

    /*
     * No named attribute directory ?
     *
     * (Solaris+Illumos always have an NFSv4.1 attribute directory because
     * they store their SUNW_* attribute data there, but FreeBSD 15.0 does
     * not have an attribute directory by default)
     */
    if (status == NFS4ERR_NOENT) {
        FILE_STREAM_INFORMATION *stream;
        size_t streamsize;

        /* Return a default "file::$DATA" entry */
        DPRINTF(0,
            ("get_streaminformation(name='%.*s'): "
            "no named attribute directory\n",
            (int)state->file.name.len, state->file.name.name));

        FILE_STREAM_INFORMATION base_stream = {
            .NextEntryOffset = 0,
            /* "::$DATA" == 8*sizeof(wchar_t) */
            .StreamNameLength = 8*sizeof(wchar_t),
            .StreamSize.QuadPart = basefile_info->size,
            .StreamAllocationSize.QuadPart = basefile_info->space_used
        };

        streamsize = ALIGNED_STREAMINFOSIZE(base_stream.StreamNameLength);
        stream = calloc(1, streamsize);
        if (stream == NULL) {
            status = GetLastError();
            goto out;
        }
        (void)memcpy(stream, &base_stream, sizeof(base_stream));
        (void)memcpy(stream->StreamName, L"::$DATA", 8*sizeof(wchar_t));
        stream->NextEntryOffset = 0;

        *streamlist_out = stream;
        *streamlist_out_size = (ULONG)streamsize;

        status = NO_ERROR;
        goto out;
    } else if (status) {
        eprintf("get_streaminformation(name='%.*s'): "
            "nfs41_rpc_openattr() failed with '%s'\n",
            (int)state->file.name.len, state->file.name.name,
            nfs_error_string(status));
        status = nfs_to_windows_error(status, ERROR_BAD_NET_RESP);
        goto out;
    }

    status = get_stream_list(state,
        &parent,
        basefile_info,
        streamlist_out,
        streamlist_out_size);

out:
    return status;
}

void free_streaminformation(
    IN FILE_STREAM_INFORMATION *restrict streamlist)
{
    free(streamlist);
}

#endif /* NFS41_WINSTREAMS_SUPPORT */
