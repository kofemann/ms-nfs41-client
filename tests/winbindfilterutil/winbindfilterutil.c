
/*
 * MIT License
 *
 * Copyright (c) 2026 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * winbindfilterutil.c - utility for the (Win10+Win11) bind filter API
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Compile with:
 * $ clang -target x86_64-pc-windows-gnu -std=gnu17 -municode \
 *  -Wall -Wextra -DUNICODE=1 -D_UNICODE=1 -g \
 *  winbindfilterutil.c -lucrt -o winbindfilterutil.exe
 */

#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#include <sddl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <wchar.h>

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

/*
 * Bind filter API
 */
#define BINDFLT_FLAG_NONE                       0x00000000UL    /* No flags */
#define BINDFLT_FLAG_READ_ONLY_MAPPING          0x00000001UL    /* Expose the backing content read-only */
#define BINDFLT_FLAG_MERGED_BIND_MAPPING        0x00000002UL    /* Merge target entries into the virtualization root */
#define BINDFLT_FLAG_USE_CURRENT_SILO_MAPPING   0x00000004UL    /* Use the mapping attached to the current silo's job object */
#define BINDFLT_FLAG_REPARSE_ON_FILES           0x00000008UL    /* Enable reparsing on files */
#define BINDFLT_FLAG_SKIP_SHARING_CHECK         0x00000010UL    /* Skip create sharing checks; valid only with |BINDFLT_FLAG_READ_ONLY_MAPPING| */
#define BINDFLT_FLAG_CLOUD_FILES_ECPS           0x00000020UL    /* Enable Cloud Files ECP handling */
#define BINDFLT_FLAG_NO_MULTIPLE_TARGETS        0x00000040UL    /* Fail with |STATUS_INVALID_PARAMETER| if a mapping produces multiple targets */
#define BINDFLT_FLAG_IMMUTABLE_BACKING          0x00000080UL    /* Enable caching by asserting that the backing store is immutable */
#define BINDFLT_FLAG_PREVENT_CASE_SENSITIVE_BINDING 0x00000100UL /* Prevent binding to a case-sensitive directory */
#define BINDFLT_FLAG_EMPTY_VIRT_ROOT            0x00000200UL    /* Fail with |STATUS_OBJECT_PATH_NOT_FOUND| if parent mappings are absent */
#define BINDFLT_FLAG_NO_REPARSE_ON_ROOT         0x10000000UL    /* Do not reparse the virtualization root itself */
#define BINDFLT_FLAG_BATCHED_REMOVE_MAPPINGS    0x20000000UL    /* Remove mappings using the batched-removal behavior */

#define BINDFLT_GET_MAPPINGS_FLAG_VOLUME    0x00000001UL    /* Enumerate mappings for a volume */
#define BINDFLT_GET_MAPPINGS_FLAG_SILO      0x00000002UL    /* Enumerate mappings associated with a silo job object */
#define BINDFLT_GET_MAPPINGS_FLAG_USER      0x00000004UL    /* Enumerate mappings associated with a user SID */

/* |BINDFLT_GET_MAPPINGS_ENTRY_V1| - used in Windows 10 */
typedef struct _BINDFLT_GET_MAPPINGS_ENTRY_V1 {
    USHORT VirtRootLength;
    USHORT TargetRootLength;
    ULONG VirtRootOffset;
    ULONG TargetRootOffset;
} BINDFLT_GET_MAPPINGS_ENTRY_V1;

/* |BINDFLT_GET_MAPPINGS_ENTRY_V2| - used in Windows 11 */
typedef struct _BINDFLT_GET_MAPPINGS_ENTRY_V2 {
    ULONG VirtRootLength;
    ULONG VirtRootOffset;
    ULONG Flags;
    ULONG NumberOfTargets;
    ULONG TargetEntriesOffset;
} BINDFLT_GET_MAPPINGS_ENTRY_V2;

typedef struct _BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2 {
    ULONG TargetRootLength;
    ULONG TargetRootOffset;
} BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2;

typedef struct _BINDFLT_GET_MAPPINGS_INFO {
    ULONG Size;
    LONG Status;
    ULONG MappingCount;
    BYTE Entries[];
} BINDFLT_GET_MAPPINGS_INFO;

typedef HRESULT (WINAPI *BF_SETUP_FILTER_FN)(
    HANDLE JobHandle,
    ULONG Flags,
    LPCWSTR VirtualizationRootPath,
    LPCWSTR VirtualizationTargetPath,
    LPCWSTR *VirtualizationExceptionPaths,
    ULONG VirtualizationExceptionPathCount
);

typedef HRESULT (WINAPI *BF_SETUP_FILTER_EX_FN)(
    ULONG Flags,
    HANDLE JobHandle,
    PSID Sid,
    LPCWSTR VirtualizationRootPath,
    LPCWSTR VirtualizationTargetPath,
    LPCWSTR *VirtualizationExceptionPaths,
    ULONG VirtualizationExceptionPathCount
);
typedef HRESULT (WINAPI *BF_REMOVE_MAPPING_FN)(
    HANDLE JobHandle,
    LPCWSTR VirtualizationRootPath
);
typedef HRESULT (WINAPI *BF_REMOVE_MAPPING_EX_FN)(
    HANDLE JobHandle,
    PSID Sid,
    LPCWSTR VirtualizationRootPath
);

typedef HRESULT (WINAPI *BF_GET_MAPPINGS_FN)(
    ULONG Flags,
    HANDLE JobHandle,
    LPCWSTR VirtualizationRootPath,
    PSID Sid,
    PULONG BufferSize,
    LPVOID OutBuffer
);

typedef struct _BINDFLT_API {
    HMODULE Module;
    BF_SETUP_FILTER_FN SetupFilter;
    BF_SETUP_FILTER_EX_FN SetupFilterEx;
    BF_REMOVE_MAPPING_FN RemoveMapping;
    BF_REMOVE_MAPPING_EX_FN RemoveMappingEx;
    BF_GET_MAPPINGS_FN GetMappings;
} BINDFLT_API;

static
void usage()
{
    /* FIXME: We should use <tab> in output */
    (void)fwprintf(stderr, L"%ls",
        L"Usage: winbindfilterutil.exe SUBCOMMAND [ARGUMENTS] [OPTIONS]\n"
        L"Subcommands:\n"
        L"  CREATE [OPTIONS] virtual-path target-path\n"
        L"    /merge       Merge the virtual and backing directories\n"
        L"    /read-only   Make the backing content read-only through the mapping\n"
        L"    /prevent-case-sensitive-binding  Prevent a case-sensitive binding\n"
        L"    /empty-virt-root  Fail if parent mappings are absent\n"
        L"    /no-reparse-on-root  Do not reparse the virtualization root\n"
        L"    /virtualizationexceptionpath path\n"
        L"        Exclude path from virtualization;may be passed multiple times\n"
        L"  REMOVE [/sid sid-or-account-name] virtual-path\n"
        L"  LIST [/sid sid-or-account-name] [/volume volume-path] [/silo job-object-name]\n"
        L"    LIST selectors may be combined or omitted entirely\n"
        L"    sid-or-account-name may be a raw S-1-* SID, 'DOMAIN\\user',\n"
        L"    'COMPUTER\\user', or 'user'\n"
        L"    job-object-name is the name supplied when the job was created;\n"
        L"    unnamed job objects cannot be opened by another process\n"
        L"    Output format is 'CPV' (AST/ksh93 compound variable format)\n"
        L"\n"
        L"Examples (requires Adminstrator account):\n"
        L"- From admin cmd.exe: Map \"H:\\home\\gisburn\" to \"C:\\cygwin64\\home\\gisburn\"\n"
        L"> winbindfilterutil create C:\\cygwin64\\home\\gisburn H:\\home\\gisburn\n"
        L"- From Cygwin admin shell: Map 'freebsddir1' in the CWD to UNC path '\\\\10.49.0.242\\freebsddir1'\n"
        L"$ winbindfilterutil create \"$(cygpath -w \"$PWD/freebsddir1\")\" '\\\\10.49.0.242\\freebsddir1'\n"
        L"\n"
        L"Author:\n"
        L"Roland Mainz <roland.mainz@nrubsig.org>\n"
    );
}
static
void print_error_details(const wchar_t *operation, HRESULT hr)
{
    (void)fwprintf(stderr, L"%ls failed with HRESULT=0x%lx\n",
        operation, (long)(DWORD)hr);
}

/*
 * |load_bindflt_api()| - load symbols from bindfltapi.dll
 *
 * We cannot just link -lbindfltapi, because 64bit Windows 10 does
 * not have a 32bit bindfltapi.dll, so we cannot build both 32bit
 * and 64bit binaries on a 64bit machine.
 * Our "workaround" is to dynamically lookup all symbols, so we can
 * build both 32bit and 64bit binaries
 */
static
int load_bindflt_api(BINDFLT_API *api)
{
    FARPROC proc;
    DWORD lasterr;

    (void)memset(api, 0, sizeof(*api));

#define BINDFLTAPI_DLL_NAME L"bindfltapi.dll"
    api->Module = LoadLibraryExW(
        BINDFLTAPI_DLL_NAME, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (api->Module == NULL) {
        lasterr = GetLastError();
        (void)fwprintf(stderr,
            L"Cannot load '%ls', lasterr=%d\n",
            BINDFLTAPI_DLL_NAME,
            (int)lasterr);
        return EXIT_FAILURE;
    }

    proc = GetProcAddress(api->Module, "BfSetupFilter");
    if (proc == NULL) {
        (void)fwprintf(stderr, L"%ls has no BfSetupFilter() symbol\n",
            BINDFLTAPI_DLL_NAME);
        goto fail;
    }
    (void)memcpy(&api->SetupFilter, &proc, sizeof(api->SetupFilter));

    proc = GetProcAddress(api->Module, "BfRemoveMapping");
    if (proc == NULL) {
        (void)fwprintf(stderr, L"%ls has no BfRemoveMapping() symbol\n",
            BINDFLTAPI_DLL_NAME);
        goto fail;
    }
    (void)memcpy(&api->RemoveMapping, &proc, sizeof(api->RemoveMapping));

    proc = GetProcAddress(api->Module, "BfGetMappings");
    if (proc == NULL) {
        (void)fwprintf(stderr, L"%ls has no BfGetMappings() symbol\n",
            BINDFLTAPI_DLL_NAME);
        goto fail;
    }
    (void)memcpy(&api->GetMappings, &proc, sizeof(api->GetMappings));

    return EXIT_SUCCESS;

fail:
    (void)FreeLibrary(api->Module);
    (void)memset(api, 0, sizeof(*api));
    return EXIT_FAILURE;
}

static
void unload_bindflt_api(BINDFLT_API *api)
{
    if (api->Module != NULL) {
        (void)FreeLibrary(api->Module);
    }
}

static
int buffer_range_valid(ULONG buffer_size, ULONG offset, ULONG length)
{
    return (offset <= buffer_size) && (length <= buffer_size - offset);
}

static
int handle_create(const BINDFLT_API *api, int ac, wchar_t *av[])
{
    LPCWSTR positional[2] = { NULL, NULL };
    LPCWSTR *exception_paths;
    ULONG exception_count = 0;
    ULONG flags = BINDFLT_FLAG_NO_MULTIPLE_TARGETS; /* FIXME */
    HRESULT hr;
    int positional_count = 0;
    int index;

    exception_paths = (LPCWSTR *)calloc((size_t)ac, sizeof(*exception_paths));
    if (exception_paths == NULL) {
        (void)fwprintf(stderr, L"Out of memory\n");
        return EXIT_FAILURE;
    }
    for (index = 2; index < ac; index++) {
        if (_wcsicmp(av[index], L"/read-only") == 0) {
            flags |= BINDFLT_FLAG_READ_ONLY_MAPPING;
        } else if (_wcsicmp(av[index], L"/merge") == 0) {
            flags |= BINDFLT_FLAG_MERGED_BIND_MAPPING;
        } else if (_wcsicmp(av[index], L"/prevent-case-sensitive-binding") == 0) {
            flags |= BINDFLT_FLAG_PREVENT_CASE_SENSITIVE_BINDING;
        } else if (_wcsicmp(av[index], L"/empty-virt-root") == 0) {
            flags |= BINDFLT_FLAG_EMPTY_VIRT_ROOT;
        } else if (_wcsicmp(av[index], L"/no-reparse-on-root") == 0) {
            flags |= BINDFLT_FLAG_NO_REPARSE_ON_ROOT;
        } else if (_wcsicmp(av[index], L"/VirtualizationExceptionPath") == 0) {
            if (++index >= ac) {
                (void)fwprintf(stderr,
                    L"/VirtualizationExceptionPath requires a path\n");
                free(exception_paths);
                usage();
                return EXIT_USAGE;
            }
            exception_paths[exception_count++] = av[index];
        } else if (av[index][0] == L'/') {
            (void)fwprintf(stderr, L"Unknown option: '%ls'\n", av[index]);
            free(exception_paths);
            usage();
            return EXIT_USAGE;
        } else if (positional_count < 2) {
            positional[positional_count++] = av[index];
        } else {
            free(exception_paths);
            usage();
            return EXIT_USAGE;
        }
    }
    if (positional_count != 2) {
        free(exception_paths);
        usage();
        return EXIT_USAGE;
    }
    hr = api->SetupFilter(NULL, flags, positional[0], positional[1],
        exception_paths, exception_count);
    free(exception_paths);
    if (FAILED(hr)) {
        print_error_details(L"BfSetupFilter()", hr);
        return EXIT_FAILURE;
    }
    (void)wprintf(L"Bind mapping created\n"
        L"\"%ls\" draws content from \"%ls\"\n",
        positional[0], positional[1]);
    return EXIT_SUCCESS;
}

static PSID sid_name_to_sid(LPCWSTR sid_name);

static
int handle_remove(const BINDFLT_API *api, int ac, wchar_t *av[])
{
    LPCWSTR virtual_path = NULL;
    PSID sid = NULL;
    HRESULT hr;
    bool use_ex = false;
    int index;

    for (index = 2; index < ac; index++) {
        if (_wcsicmp(av[index], L"/sid") == 0) {
            PSID new_sid;
            if (++index >= ac) {
                (void)fwprintf(stderr, L"/sid requires an argument\n");
                free(sid);
                usage();
                return EXIT_USAGE;
            }
            new_sid = sid_name_to_sid(av[index]);
            if (new_sid == NULL) {
                free(sid);
                return EXIT_FAILURE;
            }
            free(sid);
            sid = new_sid;
        } else if (av[index][0] == L'/') {
            (void)fwprintf(stderr, L"Unknown option: '%ls'\n", av[index]);
            free(sid);
            usage();
            return EXIT_USAGE;
        } else if (virtual_path == NULL) {
            virtual_path = av[index];
        } else {
            free(sid);
            usage();
            return EXIT_USAGE;
        }
    }
    if (virtual_path == NULL) {
        free(sid);
        usage();
        return EXIT_USAGE;
    }
    use_ex = (sid != NULL);
    if (use_ex)
        hr = api->RemoveMappingEx(NULL, sid, virtual_path);
    else
        hr = api->RemoveMapping(NULL, virtual_path);
    free(sid);
    if (FAILED(hr)) {
        print_error_details(use_ex ?
            L"BfRemoveMappingEx()" : L"BfRemoveMapping()", hr);
        return EXIT_FAILURE;
    }
    (void)wprintf(L"Bind mapping for \"%ls\" removed\n", virtual_path);
    return EXIT_SUCCESS;
}

static
PSID account_name_to_sid(LPCWSTR account_name)
{
    DWORD sid_size = 0;
    DWORD domain_size = 0;
    SID_NAME_USE sid_type;
    PSID sid;
    wchar_t *domain;
    DWORD lasterr;
    BOOL success;

    success = LookupAccountNameW(NULL, account_name, NULL, &sid_size,
        NULL, &domain_size, &sid_type);
    lasterr = GetLastError();
    if ((!success && (lasterr != ERROR_INSUFFICIENT_BUFFER)) ||
        (sid_size == 0)) {
        (void)fwprintf(stderr, L"Cannot resolve account '%ls', lasterr=%d\n",
            account_name, (int)lasterr);
        return NULL;
    }

    sid = (PSID)malloc(sid_size);
    domain = (wchar_t *)malloc((size_t)domain_size * sizeof(*domain));
    if ((sid == NULL) || (domain == NULL)) {
        (void)fwprintf(stderr, L"Out of memory\n");
        free(domain);
        free(sid);
        return NULL;
    }

    if (!LookupAccountNameW(NULL, account_name, sid, &sid_size,
            domain, &domain_size, &sid_type)) {
        lasterr = GetLastError();
        (void)fwprintf(stderr, L"Cannot resolve account '%ls', lasterr=%d\n",
            account_name, (int)lasterr);
        free(domain);
        free(sid);
        return NULL;
    }

    free(domain);
    return sid;
}

static
PSID sid_name_to_sid(LPCWSTR sid_name)
{
    PSID converted_sid;
    PSID sid;
    DWORD sid_size;

    if ((_wcsnicmp(sid_name, L"S-1", 3) != 0))
        return account_name_to_sid(sid_name);
    if (!ConvertStringSidToSidW(sid_name, &converted_sid)) {
        (void)fwprintf(stderr, L"Invalid SID '%ls', lasterr=%d\n",
            sid_name, (int)GetLastError());
        return NULL;
    }
    if (!IsValidSid(converted_sid)) {
        (void)fwprintf(stderr, L"Invalid SID '%ls'\n", sid_name);
        (void)LocalFree(converted_sid);
        return NULL;
    }
    sid_size = GetLengthSid(converted_sid);
    sid = (PSID)malloc(sid_size);
    if ((sid == NULL) || !CopySid(sid_size, sid, converted_sid)) {
        (void)fwprintf(stderr, L"Cannot copy SID '%ls'\n", sid_name);
        free(sid);
        sid = NULL;
    }
    (void)LocalFree(converted_sid);
    return sid;
}

/*
 * Get WinNT version numbers
 *
 * We use this wrapper function because |RtlGetNtVersionNumbers()|
 * is a private API, but it should be safe to use as Cygwin and
 * other software relies on it
 */
#ifdef _WIN64
/*
 * Windows private API, so we add prototype here ourselves
 *
 * Note that this currently only works with 64bit Windows,
 * 32bit Windows generates this build error:
 * ---- snip ----
 * util.obj : error LNK2019: unresolved external symbol __RtlGetNtVersionNumbers referenced in function _getwinntversionnnumbers
 * ---- snip ----
 */
/*
 * Reference:
 * https://cygwin.com/git/?p=newlib-cygwin.git;a=blob;f=winsup/cygwin/wincap.cc
 */
typedef LONG NTSTATUS;
NTSTATUS RtlGetNtVersionNumbers(LPDWORD, LPDWORD, LPDWORD);
#endif /* _WIN64 */

bool getwinntversionnnumbers(
    DWORD *MajorVersionPtr,
    DWORD *MinorVersionPtr,
    DWORD *BuildNumberPtr)
{
#ifdef _WIN64
    (void)RtlGetNtVersionNumbers(MajorVersionPtr, MinorVersionPtr, BuildNumberPtr);
    *BuildNumberPtr &= 0xffff;

    return true;
#else
    (void)MajorVersionPtr;
    (void)MinorVersionPtr;
    (void)BuildNumberPtr;
    return false;
#endif /* _WIN64 */
}

static
bool is_windows_11_or_later(void)
{
    DWORD MajorVersion;
    DWORD MinorVersion;
    DWORD BuildNumber;

    /* We assume we are on Win10/32bit if this fails... */
    if (!getwinntversionnnumbers(&MajorVersion,
        &MinorVersion, &BuildNumber))
        return false;

    return (BuildNumber >= 22000)?true:false;
}

static
bool mappings_v1_valid(const BYTE *buffer, ULONG valid_size,
    const BINDFLT_GET_MAPPINGS_INFO *info)
{
    ULONG entries_offset = FIELD_OFFSET(BINDFLT_GET_MAPPINGS_INFO, Entries);
    ULONG entries_size;
    ULONG first_data_offset;
    ULONG i;

    if (info->MappingCount > (ULONG_MAX / (ULONG)sizeof(BINDFLT_GET_MAPPINGS_ENTRY_V1)))
        return false;
    entries_size = info->MappingCount *
        (ULONG)sizeof(BINDFLT_GET_MAPPINGS_ENTRY_V1);
    if (!buffer_range_valid(valid_size, entries_offset, entries_size))
        return false;
    first_data_offset = entries_offset + entries_size;

    for (i = 0; i < info->MappingCount; i++) {
        const BINDFLT_GET_MAPPINGS_ENTRY_V1 *entry =
            (const BINDFLT_GET_MAPPINGS_ENTRY_V1 *)(const void *)
            (buffer + entries_offset) + i;
        if (((entry->VirtRootLength % sizeof(wchar_t)) != 0) ||
            ((entry->TargetRootLength % sizeof(wchar_t)) != 0) ||
            (entry->VirtRootOffset < first_data_offset) ||
            (entry->TargetRootOffset < first_data_offset) ||
            !buffer_range_valid(valid_size, entry->VirtRootOffset,
                entry->VirtRootLength) ||
            !buffer_range_valid(valid_size, entry->TargetRootOffset,
                entry->TargetRootLength))
            return false;
    }

    return true;
}

static
bool mappings_v2_valid(const BYTE *buffer, ULONG valid_size,
    const BINDFLT_GET_MAPPINGS_INFO *info)
{
    ULONG entries_offset = FIELD_OFFSET(BINDFLT_GET_MAPPINGS_INFO, Entries);
    ULONG entries_size;
    ULONG first_data_offset;
    ULONG i;

    if (info->MappingCount > (ULONG_MAX / (ULONG)sizeof(BINDFLT_GET_MAPPINGS_ENTRY_V2)))
        return false;
    entries_size = info->MappingCount *
        (ULONG)sizeof(BINDFLT_GET_MAPPINGS_ENTRY_V2);
    if (!buffer_range_valid(valid_size, entries_offset, entries_size))
        return false;
    first_data_offset = entries_offset + entries_size;

    for (i = 0; i < info->MappingCount; i++) {
        const BINDFLT_GET_MAPPINGS_ENTRY_V2 *entry =
            (const BINDFLT_GET_MAPPINGS_ENTRY_V2 *)(const void *)
            (buffer + entries_offset) + i;
        ULONG targets_size;
        ULONG j;

        if (((entry->VirtRootLength % sizeof(wchar_t)) != 0) ||
            (entry->VirtRootOffset < first_data_offset) ||
            !buffer_range_valid(valid_size, entry->VirtRootOffset,
                entry->VirtRootLength) ||
            (entry->NumberOfTargets > (ULONG_MAX /
                (ULONG)sizeof(BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2))))
            return false;
        targets_size = entry->NumberOfTargets *
            (ULONG)sizeof(BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2);
        if ((entry->NumberOfTargets != 0) &&
            ((entry->TargetEntriesOffset < first_data_offset) ||
            !buffer_range_valid(valid_size, entry->TargetEntriesOffset,
                targets_size)))
            return false;

        for (j = 0; j < entry->NumberOfTargets; j++) {
            const BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2 *target =
                (const BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2 *)(const void *)
                (buffer + entry->TargetEntriesOffset) + j;
            if (((target->TargetRootLength % sizeof(wchar_t)) != 0) ||
                (target->TargetRootOffset < first_data_offset) ||
                !buffer_range_valid(valid_size, target->TargetRootOffset,
                    target->TargetRootLength))
                return false;
        }
    }

    return true;
}

static
int handle_list(const BINDFLT_API *api, int ac, wchar_t *av[])
{
    BYTE *buffer;
    ULONG get_mappings_flags = 0;
    LPCWSTR volume_path = NULL;
    HANDLE job_handle = NULL;
    PSID sid = NULL;
    ULONG valid_size;
    const ULONG allocation_size = 128UL * 1024UL;
    ULONG buffer_size;
    HRESULT hr;
    BINDFLT_GET_MAPPINGS_INFO *info;
    ULONG mapping_index;
    bool windows_11_or_later;
    DWORD lasterr;
    int index;

    for (index = 2; index < ac; index++) {
        if (_wcsicmp(av[index], L"/volume") == 0) {
            if ((volume_path != NULL) || (++index >= ac)) {
                (void)fwprintf(stderr, L"Invalid or duplicate /volume option\n");
                goto usage_fail;
            }
            volume_path = av[index];
            get_mappings_flags |= BINDFLT_GET_MAPPINGS_FLAG_VOLUME;
        } else if (_wcsicmp(av[index], L"/sid") == 0) {
            PSID new_sid;
            if (++index >= ac) {
                (void)fwprintf(stderr, L"/sid requires an argument\n");
                goto usage_fail;
            }
            new_sid = sid_name_to_sid(av[index]);
            if (new_sid == NULL)
                goto fail;
            free(sid);
            sid = new_sid;
            get_mappings_flags |= BINDFLT_GET_MAPPINGS_FLAG_USER;
        } else if (_wcsicmp(av[index], L"/silo") == 0) {
            if ((job_handle != NULL) || (++index >= ac)) {
                (void)fwprintf(stderr, L"Invalid or duplicate /silo option\n");
                goto usage_fail;
            }
            job_handle = OpenJobObjectW(JOB_OBJECT_QUERY, FALSE, av[index]);
            if (job_handle == NULL) {
                lasterr = GetLastError();
                (void)fwprintf(stderr,
                    L"Cannot open job object '%ls', lasterr=%d\n",
                    av[index], (int)lasterr);
                goto fail;
            }
            get_mappings_flags |= BINDFLT_GET_MAPPINGS_FLAG_SILO;
        } else {
            (void)fwprintf(stderr, L"Unknown LIST option: '%ls'\n", av[index]);
            goto usage_fail;
        }
    }

    buffer_size = allocation_size;
    buffer = (BYTE *)calloc(1, allocation_size);
    if (buffer == NULL) {
        (void)fwprintf(stderr, L"Out of memory\n");
        free(sid);
        if (job_handle != NULL)
            (void)CloseHandle(job_handle);
        return EXIT_FAILURE;
    }

    hr = api->GetMappings(get_mappings_flags, job_handle, volume_path,
        sid, &buffer_size, buffer);
    free(sid);
    if (job_handle != NULL)
        (void)CloseHandle(job_handle);
    if (FAILED(hr)) {
        print_error_details(L"BfGetMappings()", hr);
        free(buffer);
        return EXIT_FAILURE;
    }

    if ((buffer_size > allocation_size) ||
        (buffer_size < FIELD_OFFSET(BINDFLT_GET_MAPPINGS_INFO, Entries))) {
        (void)fwprintf(stderr, L"BfGetMappings() returned a truncated header\n");
        free(buffer);
        return EXIT_FAILURE;
    }

    info = (BINDFLT_GET_MAPPINGS_INFO *)buffer;
    if ((info->Size > buffer_size) ||
        (info->Size < FIELD_OFFSET(BINDFLT_GET_MAPPINGS_INFO, Entries))) {
        (void)fwprintf(stderr,
            L"BfGetMappings() returned an invalid size "
            L"(size=%lu, buffer=%lu)\n",
            (unsigned long)info->Size,
            (unsigned long)buffer_size);
        free(buffer);
        return EXIT_FAILURE;
    }
    valid_size = info->Size;
    if (info->Status < 0L) {
        (void)fwprintf(stderr, L"BfGetMappings() returned NTSTATUS=0x%lx\n",
            (long)(DWORD)info->Status);
        free(buffer);
        return EXIT_FAILURE;
    }

    windows_11_or_later = is_windows_11_or_later();

    if (windows_11_or_later) {
        if (!mappings_v2_valid(buffer, valid_size, info)) {
            (void)fwprintf(stderr,
                L"BfGetMappings() returned an invalid Windows 11 mapping "
                L"layout (count=%lu, buffer=%lu)\n",
                (unsigned long)info->MappingCount,
                (unsigned long)valid_size);
            free(buffer);
            return EXIT_FAILURE;
        }
    } else if (!mappings_v1_valid(buffer, valid_size, info)) {
        (void)fwprintf(stderr,
            L"BfGetMappings() returned an invalid Windows 10 mapping "
            L"layout (count=%lu, buffer=%lu)\n",
            (unsigned long)info->MappingCount,
            (unsigned long)valid_size);
        free(buffer);
        return EXIT_FAILURE;
    }

    /*
     * Write results as ksh93 compound variable
     * There are two format versions right now:
     * - V1 contains one target in each mapping entry
     * - V2 contains a target-entry array per mapping
     */
    (void)wprintf(L"(\n");
    (void)wprintf(L"\tcompound -a bindmappings=(\n");

    if (!windows_11_or_later) {
        const BINDFLT_GET_MAPPINGS_ENTRY_V1 *entries =
            (const BINDFLT_GET_MAPPINGS_ENTRY_V1 *)(const void *)
            (buffer + FIELD_OFFSET(BINDFLT_GET_MAPPINGS_INFO, Entries));

        for (mapping_index = 0 ;
            mapping_index < info->MappingCount ;
            mapping_index++) {
            const BINDFLT_GET_MAPPINGS_ENTRY_V1 *mapping =
                &entries[mapping_index];
            const wchar_t *virtual_root = (const wchar_t *)(const void *)
                (buffer + mapping->VirtRootOffset);
            const wchar_t *target_root = (const wchar_t *)(const void *)
                (buffer + mapping->TargetRootOffset);

            (void)wprintf(L"\t\t[%d]=(\n",
                (int)mapping_index);

            (void)wprintf(L"\t\t\tformat='APIv1'\n");
            (void)wprintf(L"\t\t\tvirtual_root='%.*ls'\n",
                (int)(mapping->VirtRootLength / sizeof(wchar_t)),
                virtual_root);
            (void)wprintf(L"\t\t\tcompound -a targets=(\n");
            (void)wprintf(L"\t\t\t\t[0]='%.*ls'\n",
                (int)(mapping->TargetRootLength / sizeof(wchar_t)),
                target_root);

            (void)wprintf(L"\t\t\t)\n");
            (void)wprintf(L"\t\t)\n");
        }
    } else {
        const BINDFLT_GET_MAPPINGS_ENTRY_V2 *entries =
            (const BINDFLT_GET_MAPPINGS_ENTRY_V2 *)(const void *)
            (buffer + FIELD_OFFSET(BINDFLT_GET_MAPPINGS_INFO, Entries));

        for (mapping_index = 0 ;
            mapping_index < info->MappingCount ;
            mapping_index++) {
            const BINDFLT_GET_MAPPINGS_ENTRY_V2 *mapping =
                &entries[mapping_index];
            const wchar_t *virtual_root = (const wchar_t *)(const void *)
                (buffer + mapping->VirtRootOffset);
            const BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2 *targets =
                (const BINDFLT_GET_MAPPINGS_TARGET_ENTRY_V2 *)(const void *)
                (buffer + mapping->TargetEntriesOffset);
            ULONG target_index;

            (void)wprintf(L"\t\t[%d]=(\n",
                (int)mapping_index);

            (void)wprintf(L"\t\t\tformat='APIv2'\n");
            (void)wprintf(L"\t\t\tvirtual_root='%.*ls'\n",
                (int)(mapping->VirtRootLength / sizeof(wchar_t)),
                virtual_root);
            (void)wprintf(L"\t\t\tflags=16#%lx\n",
                (unsigned long)mapping->Flags);
            (void)wprintf(L"\t\t\tcompound -a targets=(\n");
            for (target_index = 0;
                target_index < mapping->NumberOfTargets;
                target_index++) {
                const wchar_t *target_root =
                    (const wchar_t *)(const void *)
                    (buffer + targets[target_index].TargetRootOffset);
                (void)wprintf(L"\t\t\t\t[%d]='%.*ls'\n",
                    (int)target_index,
                    (int)(targets[target_index].TargetRootLength /
                        sizeof(wchar_t)),
                    target_root);
            }

            (void)wprintf(L"\t\t\t)\n");
            (void)wprintf(L"\t\t)\n");
        }
    }

    (void)wprintf(L"\t)\n");
    (void)wprintf(L")\n");

    free(buffer);
    return EXIT_SUCCESS;
usage_fail:
    usage();
    free(sid);
    if (job_handle != NULL)
        (void)CloseHandle(job_handle);
    return EXIT_USAGE;
fail:
    free(sid);
    if (job_handle != NULL)
        (void)CloseHandle(job_handle);
    return EXIT_FAILURE;
}

int wmain(int ac, wchar_t *av[])
{
    BINDFLT_API api;
    int result;

    if (ac < 2) {
        usage();
        return EXIT_USAGE;
    }

    if (load_bindflt_api(&api) != EXIT_SUCCESS)
        return EXIT_FAILURE;

    /*
     * Subcmd dispatcher
     */
    if (_wcsicmp(av[1], L"CREATE") == 0) {
        result = handle_create(&api, ac, av);
    }
    else if (_wcsicmp(av[1], L"REMOVE") == 0) {
        result = handle_remove(&api, ac, av);
    }
    else if (_wcsicmp(av[1], L"LIST") == 0) {
        result = handle_list(&api, ac, av);
    }
    else {
        (void)fwprintf(stderr, L"Unknown subcommand: '%ls'\n", av[1]);
        usage();
        result = EXIT_USAGE;
    }

    unload_bindflt_api(&api);
    return result;
}
