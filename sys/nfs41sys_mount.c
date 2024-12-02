/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2024 Roland Mainz <roland.mainz@nrubsig.org>
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

/* FIXME: Why does VS22 need this, but not VC19 ? */
#if _MSC_VER >= 1900
#if defined(_WIN64) && defined(_M_X64)
#ifndef _AMD64_
#define _AMD64_
#endif
#elif defined(_WIN32) && defined(_M_IX86)
#ifndef _X86_
#define _X86_
#endif
#elif defined(_WIN64) && defined(_M_ARM64)
#ifndef _ARM64_
#define _ARM64_
#endif
#elif defined(_WIN32) && defined(_M_ARM)
#ifndef _ARM_
#define _ARM_
#endif
#else
#error Unsupported arch
#endif
#endif /* _MSC_VER >= 1900 */

#define MINIRDR__NAME "Value is ignored, only fact of definition"
#include <rx.h>
#include <windef.h>
#include <winerror.h>

#include <Ntstrsafe.h>
#include <stdbool.h>

#include "nfs41sys_buildconfig.h"

#include "nfs41_driver.h"
#include "nfs41sys_debug.h"
#include "nfs41_build_features.h"

#include "nfs41sys_driver.h"
#include "nfs41sys_util.h"

void copy_nfs41_mount_config(NFS41_MOUNT_CONFIG *dest,
    NFS41_MOUNT_CONFIG *src)
{
    RtlCopyMemory(dest, src, sizeof(NFS41_MOUNT_CONFIG));
    dest->SrvName.Buffer = dest->srv_buffer;
    dest->MntPt.Buffer = dest->mntpt_buffer;
    dest->SecFlavor.Buffer = dest->sec_flavor_buffer;
}

static const char *secflavorop2name(
    DWORD sec_flavor)
{
    switch(sec_flavor) {
    case RPCSEC_AUTH_SYS:      return "AUTH_SYS";
    case RPCSEC_AUTHGSS_KRB5:  return "AUTHGSS_KRB5";
    case RPCSEC_AUTHGSS_KRB5I: return "AUTHGSS_KRB5I";
    case RPCSEC_AUTHGSS_KRB5P: return "AUTHGSS_KRB5P";
    }

    return "UNKNOWN FLAVOR";
}

NTSTATUS marshal_nfs41_mount(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG header_len = 0;
    unsigned char *tmp = buf;

    status = marshal_nfs41_header(entry, tmp, buf_len, len);
    if (status) goto out;
    else tmp += *len;

    /* 03/25/2011: Kernel crash to nfsd not running but mount upcall cued up */
    if (!MmIsAddressValid(entry->u.Mount.srv_name) ||
            !MmIsAddressValid(entry->u.Mount.root)) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }
    header_len = *len + length_as_utf8(entry->u.Mount.srv_name) +
        length_as_utf8(entry->u.Mount.root) + 4 * sizeof(DWORD);
    if (header_len > buf_len) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    status = marshall_unicode_as_utf8(&tmp, entry->u.Mount.srv_name);
    if (status) goto out;
    status = marshall_unicode_as_utf8(&tmp, entry->u.Mount.root);
    if (status) goto out;
    RtlCopyMemory(tmp, &entry->u.Mount.sec_flavor, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Mount.rsize, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Mount.wsize, sizeof(DWORD));
    tmp += sizeof(DWORD);
    RtlCopyMemory(tmp, &entry->u.Mount.use_nfspubfh, sizeof(DWORD));

    *len = header_len;

#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("marshal_nfs41_mount: server name='%wZ' mount point='%wZ' "
         "sec_flavor='%s' rsize=%d wsize=%d use_nfspubfh=%d\n",
	 entry->u.Mount.srv_name, entry->u.Mount.root,
         secflavorop2name(entry->u.Mount.sec_flavor),
         (int)entry->u.Mount.rsize, (int)entry->u.Mount.wsize,
         (int)entry->u.Mount.use_nfspubfh);
#endif
out:
    return status;
}

NTSTATUS marshal_nfs41_unmount(
    nfs41_updowncall_entry *entry,
    unsigned char *buf,
    ULONG buf_len,
    ULONG *len)
{
    return marshal_nfs41_header(entry, buf, buf_len, len);
}

void unmarshal_nfs41_mount(
    nfs41_updowncall_entry *cur,
    unsigned char **buf)
{
    RtlCopyMemory(&cur->session, *buf, sizeof(HANDLE));
    *buf += sizeof(HANDLE);
    RtlCopyMemory(&cur->version, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    RtlCopyMemory(&cur->u.Mount.lease_time, *buf, sizeof(DWORD));
    *buf += sizeof(DWORD);
    RtlCopyMemory(cur->u.Mount.FsAttrs, *buf, sizeof(FILE_FS_ATTRIBUTE_INFORMATION));
#ifdef DEBUG_MARSHAL_DETAIL
    DbgP("unmarshal_nfs41_mount: session=0x%p version=%d lease_time "
         "%d\n",
         cur->session, cur->version, cur->u.Mount.lease_time);
#endif
}

NTSTATUS nfs41_unmount(
    HANDLE session,
    DWORD version,
    DWORD timeout)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;

#ifdef DEBUG_MOUNT
    DbgEn();
#endif
    status = nfs41_UpcallCreate(NFS41_SYSOP_UNMOUNT, NULL, session,
        INVALID_HANDLE_VALUE, version, NULL, &entry);
    if (status) goto out;

    nfs41_UpcallWaitForReply(entry, timeout);

    if (entry->psec_ctx == &entry->sec_ctx) {
        SeDeleteClientSecurity(entry->psec_ctx);
    }
    entry->psec_ctx = NULL;
    nfs41_UpcallDestroy(entry);
out:
#ifdef ENABLE_TIMINGS
    print_op_stat("lookup", &lookup, 1);
    print_op_stat("open", &open, 1);
    print_op_stat("close", &close, 1);
    print_op_stat("volume", &volume, 1);
    print_op_stat("getattr", &getattr, 1);
    print_op_stat("setattr", &setattr, 1);
    print_op_stat("getexattr", &getexattr, 1);
    print_op_stat("setexattr", &setexattr, 1);
    print_op_stat("readdir", &readdir, 1);
    print_op_stat("getacl", &getacl, 1);
    print_op_stat("setacl", &setacl, 1);
    print_op_stat("read", &read, 1);
    print_op_stat("write", &write, 1);
    print_op_stat("lock", &lock, 1);
    print_op_stat("unlock", &unlock, 1);
#endif
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS map_mount_errors(
    DWORD status)
{
    switch (status) {
    case NO_ERROR:              return STATUS_SUCCESS;
    case ERROR_ACCESS_DENIED:   return STATUS_ACCESS_DENIED;
    case ERROR_NETWORK_UNREACHABLE: return STATUS_NETWORK_UNREACHABLE;
    case ERROR_BAD_NET_RESP:    return STATUS_UNEXPECTED_NETWORK_ERROR;
    case ERROR_BAD_NET_NAME:    return STATUS_BAD_NETWORK_NAME;
    case ERROR_BAD_NETPATH:     return STATUS_BAD_NETWORK_PATH;
    case ERROR_NOT_SUPPORTED:   return STATUS_NOT_SUPPORTED;
    case ERROR_INTERNAL_ERROR:  return STATUS_INTERNAL_ERROR;
    default:
        print_error("map_mount_errors: "
            "failed to map windows ERROR_0x%lx to NTSTATUS; "
            "defaulting to STATUS_INSUFFICIENT_RESOURCES\n",
            (long)status);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
}

NTSTATUS nfs41_mount(
    PNFS41_MOUNT_CONFIG config,
    DWORD sec_flavor,
    PHANDLE session,
    DWORD *version,
    PFILE_FS_ATTRIBUTE_INFORMATION FsAttrs)
{
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;
    nfs41_updowncall_entry *entry;

#ifdef DEBUG_MOUNT
    DbgEn();
    DbgP("Server Name '%wZ' Mount Point '%wZ' SecFlavor %d\n",
        &config->SrvName, &config->MntPt, sec_flavor);
#endif
    status = nfs41_UpcallCreate(NFS41_SYSOP_MOUNT, NULL, *session,
        INVALID_HANDLE_VALUE, *version, &config->MntPt, &entry);
    if (status) goto out;

    entry->u.Mount.srv_name = &config->SrvName;
    entry->u.Mount.root = &config->MntPt;
    entry->u.Mount.rsize = config->ReadSize;
    entry->u.Mount.wsize = config->WriteSize;
    entry->u.Mount.use_nfspubfh = config->use_nfspubfh;
    entry->u.Mount.sec_flavor = sec_flavor;
    entry->u.Mount.FsAttrs = FsAttrs;

    status = nfs41_UpcallWaitForReply(entry, config->timeout);
    if (entry->psec_ctx == &entry->sec_ctx) {
        SeDeleteClientSecurity(entry->psec_ctx);
    }
    entry->psec_ctx = NULL;
    if (status) goto out;
    *session = entry->session;
    if (entry->u.Mount.lease_time > config->timeout)
        config->timeout = entry->u.Mount.lease_time;

    /* map windows ERRORs to NTSTATUS */
    status = map_mount_errors(entry->status);
    if (status == STATUS_SUCCESS)
        *version = entry->version;
    nfs41_UpcallDestroy(entry);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}


void nfs41_MountConfig_InitDefaults(
    OUT PNFS41_MOUNT_CONFIG Config)
{
    RtlZeroMemory(Config, sizeof(NFS41_MOUNT_CONFIG));

    Config->ReadSize = MOUNT_CONFIG_RW_SIZE_DEFAULT;
    Config->WriteSize = MOUNT_CONFIG_RW_SIZE_DEFAULT;
    Config->use_nfspubfh = FALSE;
    Config->ReadOnly = FALSE;
    Config->write_thru = FALSE;
    Config->nocache = FALSE;
    Config->timebasedcoherency = FALSE; /* disabled by default because of bugs */
    Config->SrvName.Length = 0;
    Config->SrvName.MaximumLength = SERVER_NAME_BUFFER_SIZE;
    Config->SrvName.Buffer = Config->srv_buffer;
    Config->MntPt.Length = 0;
    Config->MntPt.MaximumLength = NFS41_SYS_MAX_PATH_LEN;
    Config->MntPt.Buffer = Config->mntpt_buffer;
    Config->SecFlavor.Length = 0;
    Config->SecFlavor.MaximumLength = MAX_SEC_FLAVOR_LEN;
    Config->SecFlavor.Buffer = Config->sec_flavor_buffer;
    RtlCopyUnicodeString(&Config->SecFlavor, &AUTH_SYS_NAME);
    Config->timeout = UPCALL_TIMEOUT_DEFAULT;
    Config->dir_createmode.use_nfsv3attrsea_mode = TRUE;
    Config->dir_createmode.mode =
        NFS41_DRIVER_DEFAULT_DIR_CREATE_MODE;
    Config->file_createmode.use_nfsv3attrsea_mode = TRUE;
    Config->file_createmode.mode =
        NFS41_DRIVER_DEFAULT_FILE_CREATE_MODE;
}

static
NTSTATUS nfs41_MountConfig_ParseBoolean(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    IN BOOLEAN negate_val,
    OUT PBOOLEAN Value)
{
    NTSTATUS status = STATUS_SUCCESS;

    /* if no value is specified, assume TRUE
     * if a value is specified, it must be a '1' */
    if (Option->EaValueLength == 0 || *usValue->Buffer == L'1')
        *Value = negate_val?FALSE:TRUE;
    else
        *Value = negate_val?TRUE:FALSE;

    DbgP("    '%ls' -> '%wZ' -> %u\n",
        (LPWSTR)Option->EaName, usValue, *Value);
    return status;
}


/* Parse |signed| integer value */
static
NTSTATUS nfs41_MountConfig_ParseINT64(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    OUT INT64 *outValue,
    IN INT64 Minimum,
    IN INT64 Maximum)
{
    NTSTATUS status;
    LONG64 Value = 0;
    LPWSTR Name = (LPWSTR)Option->EaName;

    if (!Option->EaValueLength)
        return STATUS_INVALID_PARAMETER;

    status = RtlUnicodeStringToInt64(usValue, 0, &Value, NULL);
    if (status == STATUS_SUCCESS) {
        if ((Value < Minimum) || (Value > Maximum))
            status = STATUS_INVALID_PARAMETER;

        if (status == STATUS_SUCCESS) {
            *outValue = Value;
        }
    }
    else {
        print_error("nfs41_MountConfig_ParseINT64: "
            "Failed to convert '%s'='%wZ' to unsigned long.\n",
            Name, usValue);
    }

    return status;
}

/* Parse |unsigned| integer value */
static
NTSTATUS nfs41_MountConfig_ParseDword(
    IN PFILE_FULL_EA_INFORMATION Option,
    IN PUNICODE_STRING usValue,
    OUT PDWORD outValue,
    IN DWORD Minimum,
    IN DWORD Maximum)
{
    INT64 tmpValue;
    NTSTATUS status;

    status = nfs41_MountConfig_ParseINT64(
        Option, usValue,
        &tmpValue, Minimum, Maximum);

    if (status == STATUS_SUCCESS) {
        *outValue = (DWORD)tmpValue;
    }

    return status;
}

NTSTATUS nfs41_MountConfig_ParseOptions(
    IN PFILE_FULL_EA_INFORMATION EaBuffer,
    IN ULONG EaLength,
    IN OUT PNFS41_MOUNT_CONFIG Config)
{
    DbgP("--> nfs41_MountConfig_ParseOptions(EaBuffer=0x%p,EaLength=%ld)\n",
        (void *)EaBuffer,
        (long)EaLength);
    NTSTATUS  status = STATUS_SUCCESS;
    PFILE_FULL_EA_INFORMATION Option;
    LPWSTR Name;
    size_t NameLen;
    UNICODE_STRING  usValue;
    ULONG error_offset;

    status = IoCheckEaBufferValidity(EaBuffer, EaLength, &error_offset);
    if (status) {
        DbgP("status(=0x%lx)=IoCheckEaBufferValidity"
            "(eainfo=0x%p, buflen=%lu, &(error_offset=%d)) failed\n",
            (long)status, (void *)EaBuffer, EaLength,
            (int)error_offset);
        goto out;
    }

    Option = EaBuffer;
    while (status == STATUS_SUCCESS) {
        DbgP("Option=0x%p\n", (void *)Option);
        Name = (LPWSTR)Option->EaName;
        NameLen = Option->EaNameLength/sizeof(WCHAR);

        DbgP("nfs41_MountConfig_ParseOptions: Name='%.*S'/NameLen=%d\n",
            (int)NameLen, Name, (int)NameLen);

        usValue.Length = usValue.MaximumLength = Option->EaValueLength;
        usValue.Buffer = (PWCH)(Option->EaName +
            Option->EaNameLength + sizeof(WCHAR));

        DbgP("nfs41_MountConfig_ParseOptions: option/usValue='%wZ'/%ld\n",
            &usValue, (long)usValue.Length);

        if (wcsncmp(L"ro", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                FALSE, &Config->ReadOnly);
        } else if (wcsncmp(L"rw", Name, NameLen) == 0) {
            /* opposite of "ro", so negate */
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                TRUE, &Config->ReadOnly);
        }
        else if (wcsncmp(L"writethru", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                FALSE, &Config->write_thru);
        }
        else if (wcsncmp(L"nowritethru", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                TRUE, &Config->write_thru);
        }
        else if (wcsncmp(L"cache", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                TRUE, &Config->nocache);
        }
        else if (wcsncmp(L"nocache", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                FALSE, &Config->nocache);
        }
        else if (wcsncmp(L"timebasedcoherency", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                FALSE, &Config->timebasedcoherency);
        }
        else if (wcsncmp(L"notimebasedcoherency", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                TRUE, &Config->timebasedcoherency);
        }
        else if (wcsncmp(L"timeout", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->timeout, UPCALL_TIMEOUT_DEFAULT,
                UPCALL_TIMEOUT_DEFAULT);
        }
        else if (wcsncmp(L"rsize", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->ReadSize, MOUNT_CONFIG_RW_SIZE_MIN,
                MOUNT_CONFIG_RW_SIZE_MAX);
        }
        else if (wcsncmp(L"wsize", Name, NameLen) == 0) {
            status = nfs41_MountConfig_ParseDword(Option, &usValue,
                &Config->WriteSize, MOUNT_CONFIG_RW_SIZE_MIN,
                MOUNT_CONFIG_RW_SIZE_MAX);
        }
        else if (wcsncmp(L"public", Name, NameLen) == 0) {
            /*
             + We ignore this value here, and instead rely on the
             * /pubnfs4 prefix
             */
            BOOLEAN dummy;
            status = nfs41_MountConfig_ParseBoolean(Option, &usValue,
                FALSE, &dummy);
        }
        else if (wcsncmp(L"srvname", Name, NameLen) == 0) {
            if (usValue.Length > Config->SrvName.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->SrvName, &usValue);
        }
        else if (wcsncmp(L"mntpt", Name, NameLen) == 0) {
            if (usValue.Length > Config->MntPt.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->MntPt, &usValue);
        }
        else if (wcsncmp(L"sec", Name, NameLen) == 0) {
            if (usValue.Length > Config->SecFlavor.MaximumLength)
                status = STATUS_NAME_TOO_LONG;
            else
                RtlCopyUnicodeString(&Config->SecFlavor, &usValue);
        }
        else if ((wcsncmp(L"createmode", Name, NameLen) == 0) ||
            (wcsncmp(L"dircreatemode", Name, NameLen) == 0) ||
            (wcsncmp(L"filecreatemode", Name, NameLen) == 0)) {
#define NFSV3ATTRMODE_WSTR L"nfsv3attrmode+"
#define NFSV3ATTRMODE_WCSLEN (14)
#define NFSV3ATTRMODE_BYTELEN (NFSV3ATTRMODE_WCSLEN*sizeof(WCHAR))
            bool set_dirmode = false;
            bool set_filemode = false;

            switch(Name[0]) {
                case L'c':
                    set_dirmode = true;
                    set_filemode = true;
                    break;
                case L'd':
                    set_dirmode = true;
                    break;
                case L'f':
                    set_filemode = true;
                    break;
                default:
                    print_error("nfs41_MountConfig_ParseOptions: "
                        "invalid createmode name\n");
                    status = STATUS_INVALID_PARAMETER;
                    break;
            }

#ifdef DEBUG_MOUNTCONFIG
            DbgP("nfs41_MountConfig_ParseOptions: "
                "set_dirmode=%d set_filemode=%d\n",
                (int)set_dirmode, (int)set_filemode);
#endif /* DEBUG_MOUNTCONFIG */

            if ((usValue.Length >= NFSV3ATTRMODE_BYTELEN) &&
                (!wcsncmp(NFSV3ATTRMODE_WSTR,
                    usValue.Buffer,
                    min(NFSV3ATTRMODE_WCSLEN,
                        usValue.Length/sizeof(WCHAR))))) {
                usValue.Buffer += NFSV3ATTRMODE_WCSLEN;
                usValue.Length = usValue.MaximumLength =
                    usValue.Length - NFSV3ATTRMODE_BYTELEN;
#ifdef DEBUG_MOUNTCONFIG
                DbgP("nfs41_MountConfig_ParseOptions: createmode "
                    "nfs4attr "
                    "leftover option/usValue='%wZ'/%ld\n",
                    &usValue, (long)usValue.Length);
#endif /* DEBUG_MOUNTCONFIG */
                if (set_dirmode)
                    Config->dir_createmode.use_nfsv3attrsea_mode = TRUE;
                if (set_filemode)
                    Config->file_createmode.use_nfsv3attrsea_mode = TRUE;
            }
            else {
#ifdef DEBUG_MOUNTCONFIG
                DbgP("nfs41_MountConfig_ParseOptions: createmode "
                    "leftover option/usValue='%wZ'/%ld\n",
                    &usValue, (long)usValue.Length);
#endif /* DEBUG_MOUNTCONFIG */
                if (set_dirmode)
                    Config->dir_createmode.use_nfsv3attrsea_mode  = FALSE;
                if (set_filemode)
                    Config->file_createmode.use_nfsv3attrsea_mode = FALSE;
            }

            if (usValue.Length >= (2*sizeof(WCHAR))) {
                ULONG parse_base = 0;
                ULONG cmode;

                if ((usValue.Buffer[0] == L'0') &&
                    iswdigit(usValue.Buffer[1])) {
                    /*
                     * Parse input as traditional POSIX/C octal number
                     * |RtlUnicodeStringToInteger()| only supports
                     * "0o" prefix for |parse_base==0|, so we skip
                     * the leading '0' and set |parse_base| to octal
                     * mode.
                     */
                    usValue.Buffer++;
                    usValue.Length-=sizeof(WCHAR);
                    parse_base = 8;
#ifdef DEBUG_MOUNTCONFIG
                    DbgP("nfs41_MountConfig_ParseOptions: "
                        "parsing POSIX/C octal number\n");
#endif /* DEBUG_MOUNTCONFIG */
                }

                status = RtlUnicodeStringToInteger(&usValue,
                    parse_base, &cmode);
                if (status == STATUS_SUCCESS) {
#ifdef DEBUG_MOUNTCONFIG
                    DbgP("nfs41_MountConfig_ParseOptions: createmode "
                        "parsed mode=0%o\n", (int)cmode);
#endif /* DEBUG_MOUNTCONFIG */
                    if (cmode > 0777) {
                        status = STATUS_INVALID_PARAMETER;
                        print_error("mode 0%o out of bounds\n",
                            (int)cmode);
                    }
                    else {
                        if (set_dirmode)
                            Config->dir_createmode.mode  = cmode;
                        if (set_filemode)
                            Config->file_createmode.mode = cmode;
                    }
                }
            }
            else {
                status = STATUS_INVALID_PARAMETER;
                print_error("Invalid createmode '%wZ'\n",
                    usValue);
            }

            DbgP("nfs41_MountConfig_ParseOptions: createmode: "
                "status=0x%lx, "
                "dir_createmode=(use_nfsv3attrsea_mode=%d mode=0%o) "
                "file_createmode=(use_nfsv3attrsea_mode=%d mode=0%o)\n",
                (long)status,
                (int)Config->dir_createmode.use_nfsv3attrsea_mode,
                (int)Config->dir_createmode.mode,
                (int)Config->file_createmode.use_nfsv3attrsea_mode,
                (int)Config->file_createmode.mode);
        }
        else {
            status = STATUS_INVALID_PARAMETER;
            print_error("Unrecognized option '%ls' -> '%wZ'\n",
                Name, usValue);
        }

        if (Option->NextEntryOffset == 0)
            break;

        Option = (PFILE_FULL_EA_INFORMATION)
            ((PBYTE)Option + Option->NextEntryOffset);
    }

out:
    DbgP("<-- nfs41_MountConfig_ParseOptions, status=0x%lx\n",
        (long)status);
    return status;
}

NTSTATUS map_sec_flavor(
    IN PUNICODE_STRING sec_flavor_name,
    OUT PDWORD sec_flavor)
{
    if (RtlCompareUnicodeString(sec_flavor_name, &AUTH_SYS_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTH_SYS;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5I_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5I;
    else if (RtlCompareUnicodeString(sec_flavor_name, &AUTHGSS_KRB5P_NAME, FALSE) == 0)
        *sec_flavor = RPCSEC_AUTHGSS_KRB5P;
    else return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static
NTSTATUS nfs41_GetLUID(
    PLUID id)
{
    NTSTATUS status = STATUS_SUCCESS;
    SECURITY_SUBJECT_CONTEXT sec_ctx;
    SECURITY_QUALITY_OF_SERVICE sec_qos;
    SECURITY_CLIENT_CONTEXT clnt_sec_ctx;

    SeCaptureSubjectContext(&sec_ctx);
    sec_qos.ContextTrackingMode = SECURITY_STATIC_TRACKING;
    sec_qos.ImpersonationLevel = SecurityIdentification;
    sec_qos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    sec_qos.EffectiveOnly = 0;
    /*
     * Arg |ServerIsRemote| must be |FALSE|, otherwise processes
     * like Cygwin setup-x86_64.exe can fail during "Activation
     * Context" creation in
     * |SeCreateClientSecurityFromSubjectContext()| with
     * |STATUS_BAD_IMPERSONATION_LEVEL|
     */
    status = SeCreateClientSecurityFromSubjectContext(&sec_ctx, &sec_qos,
        FALSE, &clnt_sec_ctx);
    if (status) {
        print_error("nfs41_GetLUID: SeCreateClientSecurityFromSubjectContext "
             "failed status=0x%lx\n", (long)status);
        goto release_sec_ctx;
    }
    status = SeQueryAuthenticationIdToken(clnt_sec_ctx.ClientToken, id);
    if (status) {
        print_error("nfs41_GetLUID: "
            "SeQueryAuthenticationIdToken() failed 0x%lx\n",
            (long)status);
        goto release_clnt_sec_ctx;
    }
release_clnt_sec_ctx:
    SeDeleteClientSecurity(&clnt_sec_ctx);
release_sec_ctx:
    SeReleaseSubjectContext(&sec_ctx);

    return status;
}

static
NTSTATUS has_nfs_prefix(
    IN PUNICODE_STRING SrvCallName,
    IN PUNICODE_STRING NetRootName,
    OUT BOOLEAN *pubfh_prefix)
{
    NTSTATUS status = STATUS_BAD_NETWORK_NAME;

#ifdef USE_ENTIRE_PATH_FOR_NETROOT
    if (NetRootName->Length >=
        (SrvCallName->Length + NfsPrefix.Length)) {
        size_t len = NetRootName->Length / 2;
        size_t i;
        int state = 0;

        /* Scan \hostname@port\nfs4 */
        for (i = 0 ; i < len ; i++) {
            wchar_t ch = NetRootName->Buffer[i];

            if ((ch == L'\\') && (state == 0)) {
                state = 1;
                continue;
            }
            else if ((ch == L'@') && (state == 1)) {
                state = 2;
                continue;
            }
            else if ((ch == L'\\') && (state == 2)) {
                state = 3;
                break;
            }
            else if (ch == L'\\') {
                /* Abort, '\\' with wrong state */
                break;
            }
        }

        if (state == 3) {
            if (!memcmp(&NetRootName->Buffer[i], L"\\nfs4",
                (4*sizeof(wchar_t))))) {
                *pubfh_prefix = FALSE;
                status = STATUS_SUCCESS;
            }
            if ((NetRootName->Length >=
                (SrvCallName->Length + PubNfsPrefix.Length)) &&
                (!memcmp(&NetRootName->Buffer[i], L"\\pubnfs4",
                    (4*sizeof(wchar_t))))) {
                *pubfh_prefix = TRUE;
                status = STATUS_SUCCESS;
            }
        }
    }
#else
    if (NetRootName->Length ==
        (SrvCallName->Length + NfsPrefix.Length)) {
        const UNICODE_STRING NetRootPrefix = {
            NfsPrefix.Length,
            NetRootName->MaximumLength - SrvCallName->Length,
            &NetRootName->Buffer[SrvCallName->Length/2]
        };
        if (!RtlCompareUnicodeString(&NetRootPrefix, &NfsPrefix, FALSE))
            *pubfh_prefix = FALSE;
            status = STATUS_SUCCESS;
    }
    else if (NetRootName->Length ==
        (SrvCallName->Length + PubNfsPrefix.Length)) {
        const UNICODE_STRING PubNetRootPrefix = {
            PubNfsPrefix.Length,
            NetRootName->MaximumLength - SrvCallName->Length,
            &NetRootName->Buffer[SrvCallName->Length/2]
        };
        if (!RtlCompareUnicodeString(&PubNetRootPrefix, &PubNfsPrefix, FALSE))
            *pubfh_prefix = TRUE;
            status = STATUS_SUCCESS;
    }
#endif /* USE_ENTIRE_PATH_FOR_NETROOT */
    return status;
}

NTSTATUS nfs41_CreateVNetRoot(
    IN OUT PMRX_CREATENETROOT_CONTEXT pCreateNetRootContext)
{
    NTSTATUS status = STATUS_SUCCESS;
    NFS41_MOUNT_CONFIG *Config;
    __notnull PMRX_V_NET_ROOT pVNetRoot = (PMRX_V_NET_ROOT)
        pCreateNetRootContext->pVNetRoot;
    __notnull PMRX_NET_ROOT pNetRoot = pVNetRoot->pNetRoot;
    __notnull PMRX_SRV_CALL pSrvCall = pNetRoot->pSrvCall;
    __notnull PNFS41_V_NET_ROOT_EXTENSION pVNetRootContext =
        NFS41GetVNetRootExtension(pVNetRoot);
    __notnull PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension(pNetRoot);
    NFS41GetDeviceExtension(pCreateNetRootContext->RxContext,DevExt);
    DWORD nfs41d_version = DevExt->nfs41d_version;
    nfs41_mount_entry *existing_mount = NULL;
    LUID luid;
    BOOLEAN found_existing_mount = FALSE, found_matching_flavor = FALSE;

    ASSERT((NodeType(pNetRoot) == RDBSS_NTC_NETROOT) &&
        (NodeType(pNetRoot->pSrvCall) == RDBSS_NTC_SRVCALL));

#ifdef DEBUG_MOUNT
    DbgEn();
    // print_srv_call(pSrvCall);
    // print_net_root(pNetRoot);
    // print_v_net_root(pVNetRoot);

    DbgP("pVNetRoot=0x%p pNetRoot=0x%p pSrvCall=0x%p\n", pVNetRoot, pNetRoot, pSrvCall);
    DbgP("pNetRoot='%wZ' Type=%d pSrvCallName='%wZ' VirtualNetRootStatus=0x%lx "
        "NetRootStatus=0x%x\n", pNetRoot->pNetRootName,
        pNetRoot->Type, pSrvCall->pSrvCallName,
        pCreateNetRootContext->VirtualNetRootStatus,
        (long)pCreateNetRootContext->NetRootStatus);
#endif

    if (pNetRoot->Type != NET_ROOT_DISK && pNetRoot->Type != NET_ROOT_WILD) {
        print_error("nfs41_CreateVNetRoot: Unsupported NetRoot Type %u\n",
            pNetRoot->Type);
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    pVNetRootContext->session = INVALID_HANDLE_VALUE;

    /*
     * In order to cooperate with other network providers, we
     * must only claim paths of the form '\\server\nfs4\path'
     * or '\\server\pubnfs4\path'
     */
    BOOLEAN pubfh_prefix = FALSE;
    status = has_nfs_prefix(pSrvCall->pSrvCallName, pNetRoot->pNetRootName, &pubfh_prefix);
    if (status) {
        print_error("nfs41_CreateVNetRoot: NetRootName '%wZ' doesn't match "
            "'\\nfs4' or '\\pubnfs4'!\n", pNetRoot->pNetRootName);
        goto out;
    }
    pNetRoot->MRxNetRootState = MRX_NET_ROOT_STATE_GOOD;
    pNetRoot->DeviceType = FILE_DEVICE_DISK;

    Config = RxAllocatePoolWithTag(NonPagedPoolNx,
            sizeof(NFS41_MOUNT_CONFIG), NFS41_MM_POOLTAG);
    if (Config == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto out;
    }
    nfs41_MountConfig_InitDefaults(Config);

    if (pCreateNetRootContext->RxContext->Create.EaLength) {
        /* Codepath for nfs_mount.exe */
        DbgP("Codepath for nfs_mount.exe, "
            "Create->{ EaBuffer=0x%p, EaLength=%ld }\n",
            pCreateNetRootContext->RxContext->Create.EaBuffer,
            (long)pCreateNetRootContext->RxContext->Create.EaLength);

        /* parse the extended attributes for mount options */
        status = nfs41_MountConfig_ParseOptions(
            pCreateNetRootContext->RxContext->Create.EaBuffer,
            pCreateNetRootContext->RxContext->Create.EaLength,
            Config);
        if (status != STATUS_SUCCESS) {
            DbgP("nfs41_MountConfig_ParseOptions() failed\n");
            goto out_free;
        }
        pVNetRootContext->read_only = Config->ReadOnly;
        pVNetRootContext->write_thru = Config->write_thru;
        pVNetRootContext->nocache = Config->nocache;
        pVNetRootContext->timebasedcoherency = Config->timebasedcoherency;
    } else {
        /*
         * Codepath for \\server@port\nfs4\path or
         * \\server@port\pubnfs4\path
         */
        DbgP("Codepath for \\\\server@port\\@(pubnfs4|nfs4)\\path\n");

        /*
         * STATUS_NFS_SHARE_NOT_MOUNTED - status code for the case
         * when a NFS filesystem is accessed via UNC path, but no
         * nfs_mount.exe was done for that filesystem
         */
#define STATUS_NFS_SHARE_NOT_MOUNTED STATUS_BAD_NETWORK_PATH
        if (!pNetRootContext->mounts_init) {
            /*
             * We can only support UNC paths when we got valid
             * mount options via nfs_mount.exe before this point.
             */
            DbgP("pNetRootContext(=0x%p) not initalised yet\n",
                pNetRootContext);
            status = STATUS_NFS_SHARE_NOT_MOUNTED;
            goto out_free;
        }

        /*
         * gisburn: Fixme: Originally the code was using the
         * SRV_CALL name (without leading \) as the hostname
         * like this:
         * ---- snip ----
         * Config->SrvName.Buffer = pSrvCall->pSrvCallName->Buffer+1;
         * Config->SrvName.Length =
         *     pSrvCall->pSrvCallName->Length - sizeof(WCHAR);
         * Config->SrvName.MaximumLength =
         *     pSrvCall->pSrvCallName->MaximumLength - sizeof(WCHAR);
         * ---- snip ----
         * IMHO we should validate that the hostname in
         * |existing_mount->Config| below matches
         * |pSrvCall->pSrvCallName->Buffer|
         */

        status = nfs41_GetLUID(&luid);
        if (status)
            goto out_free;

#ifdef DEBUG_MOUNT
        DbgP("UNC path LUID 0x%lx.0x%lx\n",
            (long)luid.HighPart, (long)luid.LowPart);
#endif

        PLIST_ENTRY pEntry;
        nfs41_mount_entry *found_mount_entry = NULL;
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
        nfs41_mount_entry *found_system_mount_entry = NULL;
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */

        status = STATUS_NFS_SHARE_NOT_MOUNTED;

        ExAcquireFastMutex(&pNetRootContext->mountLock);
        pEntry = &pNetRootContext->mounts.head;
        pEntry = pEntry->Flink;
        while (pEntry != NULL) {
            existing_mount = (nfs41_mount_entry *)CONTAINING_RECORD(pEntry,
                    nfs41_mount_entry, next);

#ifdef DEBUG_MOUNT
            DbgP("finding mount config: "
                "comparing luid=(0x%lx.0x%lx) with "
                "existing_mount->login_id=(0x%lx.0x%lx)\n",
                (long)luid.HighPart, (long)luid.LowPart,
                (long)existing_mount->login_id.HighPart,
                (long)existing_mount->login_id.LowPart);
#endif

            if (RtlEqualLuid(&luid, &existing_mount->login_id)) {
                /* found existing mount with exact LUID match */
                found_mount_entry = existing_mount;
                break;
            }
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
            else if (RtlEqualLuid(&SystemLuid,
                &existing_mount->login_id)) {
                /*
                 * found existing mount for user "SYSTEM"
                 * We continue searching the |pNetRootContext->mounts|
                 * list for an exact match ...
                 */
                found_system_mount_entry = existing_mount;
            }
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
            if (pEntry->Flink == &pNetRootContext->mounts.head)
                break;
            pEntry = pEntry->Flink;
        }

        if (found_mount_entry) {
            copy_nfs41_mount_config(Config, &found_mount_entry->Config);
            DbgP("Found existing mount: LUID=(0x%lx.0x%lx) Entry Config->MntPt='%wZ'\n",
                (long)found_mount_entry->login_id.HighPart,
                (long)found_mount_entry->login_id.LowPart,
                &Config->MntPt);
            status = STATUS_SUCCESS;
        }
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
        else if (found_system_mount_entry) {
            copy_nfs41_mount_config(Config, &found_system_mount_entry->Config);
            DbgP("Found existing SYSTEM mount: Entry Config->MntPt='%wZ'\n",
                &Config->MntPt);
            status = STATUS_SUCCESS;
        }
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
        ExReleaseFastMutex(&pNetRootContext->mountLock);

        if (status != STATUS_SUCCESS) {
            DbgP("No existing mount found, "
                "status==STATUS_NFS_SHARE_NOT_MOUNTED\n");
            goto out_free;
        }

        pVNetRootContext->read_only = Config->ReadOnly;
        pVNetRootContext->write_thru = Config->write_thru;
        pVNetRootContext->nocache = Config->nocache;
        pVNetRootContext->timebasedcoherency = Config->timebasedcoherency;
    }

    Config->use_nfspubfh = pubfh_prefix;

    DbgP("Config->{ "
        "MntPt='%wZ', "
        "SrvName='%wZ', "
        "usenfspubfh=%d, "
        "ro=%d, "
        "writethru=%d, "
        "nocache=%d "
        "timebasedcoherency=%d "
        "timeout=%d "
        "dir_cmode=(usenfsv3attrs=%d mode=0%o) "
        "file_cmode=(usenfsv3attrs=%d mode=0%o) "
        "}\n",
        &Config->MntPt,
        &Config->SrvName,
        Config->use_nfspubfh?1:0,
        Config->ReadOnly?1:0,
        Config->write_thru?1:0,
        Config->nocache?1:0,
        Config->timebasedcoherency?1:0,
        Config->timeout,
        Config->dir_createmode.use_nfsv3attrsea_mode?1:0,
        Config->dir_createmode.mode,
        Config->file_createmode.use_nfsv3attrsea_mode?1:0,
        Config->file_createmode.mode);

    pVNetRootContext->MountPathLen = Config->MntPt.Length;
    pVNetRootContext->timeout = Config->timeout;
    pVNetRootContext->dir_createmode.use_nfsv3attrsea_mode =
        Config->dir_createmode.use_nfsv3attrsea_mode;
    pVNetRootContext->dir_createmode.mode =
        Config->dir_createmode.mode;
    pVNetRootContext->file_createmode.use_nfsv3attrsea_mode =
        Config->file_createmode.use_nfsv3attrsea_mode;
    pVNetRootContext->file_createmode.mode =
        Config->file_createmode.mode;

    status = map_sec_flavor(&Config->SecFlavor, &pVNetRootContext->sec_flavor);
    if (status != STATUS_SUCCESS) {
        DbgP("Invalid rpcsec security flavor '%wZ'\n", &Config->SecFlavor);
        goto out_free;
    }

    status = nfs41_GetLUID(&luid);
    if (status)
        goto out_free;

    if (!pNetRootContext->mounts_init) {
#ifdef DEBUG_MOUNT
        DbgP("Initializing mount array\n");
#endif
        ExInitializeFastMutex(&pNetRootContext->mountLock);
        InitializeListHead(&pNetRootContext->mounts.head);
        pNetRootContext->mounts_init = TRUE;
    } else {
        PLIST_ENTRY pEntry;

        ExAcquireFastMutex(&pNetRootContext->mountLock);
        pEntry = &pNetRootContext->mounts.head;
        pEntry = pEntry->Flink;
        while (pEntry != NULL) {
            existing_mount = (nfs41_mount_entry *)CONTAINING_RECORD(pEntry,
                    nfs41_mount_entry, next);
#ifdef DEBUG_MOUNT
            DbgP("comparing 0x%lx.0x%lx with 0x%lx.0x%lx\n",
                (long)luid.HighPart, (long)luid.LowPart,
                (long)existing_mount->login_id.HighPart,
                (long)existing_mount->login_id.LowPart);
#endif
            if (RtlEqualLuid(&luid, &existing_mount->login_id)) {
#ifdef DEBUG_MOUNT
                DbgP("Found a matching LUID entry\n");
#endif
                found_existing_mount = TRUE;
                switch(pVNetRootContext->sec_flavor) {
                case RPCSEC_AUTH_SYS:
                    if (existing_mount->authsys_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session =
                            existing_mount->authsys_session;
                    break;
                case RPCSEC_AUTHGSS_KRB5:
                    if (existing_mount->gssi_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = existing_mount->gss_session;
                    break;
                case RPCSEC_AUTHGSS_KRB5I:
                    if (existing_mount->gss_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = existing_mount->gssi_session;
                    break;
                case RPCSEC_AUTHGSS_KRB5P:
                    if (existing_mount->gssp_session != INVALID_HANDLE_VALUE)
                        pVNetRootContext->session = existing_mount->gssp_session;
                    break;
                }
                if (pVNetRootContext->session &&
                        pVNetRootContext->session != INVALID_HANDLE_VALUE)
                    found_matching_flavor = 1;
                break;
            }
            if (pEntry->Flink == &pNetRootContext->mounts.head)
                break;
            pEntry = pEntry->Flink;
        }
        ExReleaseFastMutex(&pNetRootContext->mountLock);
#ifdef DEBUG_MOUNT
        if (!found_matching_flavor)
            DbgP("Didn't find matching security flavor\n");
#endif
    }

    /* send the mount upcall */
    status = nfs41_mount(Config, pVNetRootContext->sec_flavor,
        &pVNetRootContext->session, &nfs41d_version,
        &pVNetRootContext->FsAttrs);
    if (status != STATUS_SUCCESS) {
        BOOLEAN MountsEmpty;
        nfs41_IsListEmpty(pNetRootContext->mountLock,
            pNetRootContext->mounts, MountsEmpty);
        if (!found_existing_mount && MountsEmpty)
            pNetRootContext->mounts_init = FALSE;
        pVNetRootContext->session = INVALID_HANDLE_VALUE;
        goto out_free;
    }
    pVNetRootContext->timeout = Config->timeout;

    if (!found_existing_mount) {
        /* create a new mount entry and add it to the list */
        nfs41_mount_entry *entry;
        entry = RxAllocatePoolWithTag(NonPagedPoolNx, sizeof(nfs41_mount_entry),
            NFS41_MM_POOLTAG_MOUNT);
        if (entry == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto out_free;
        }
        entry->authsys_session = entry->gss_session =
            entry->gssi_session = entry->gssp_session = INVALID_HANDLE_VALUE;
        switch (pVNetRootContext->sec_flavor) {
        case RPCSEC_AUTH_SYS:
            entry->authsys_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5:
            entry->gss_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5I:
            entry->gssi_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5P:
            entry->gssp_session = pVNetRootContext->session; break;
        }
        RtlCopyLuid(&entry->login_id, &luid);
        /*
         * Save mount config so we can use it for
         * \\server@port\@(pubnfs4|nfs4)\path mounts later
         */
        copy_nfs41_mount_config(&entry->Config, Config);
        nfs41_AddEntry(pNetRootContext->mountLock,
            pNetRootContext->mounts, entry);
    } else if (!found_matching_flavor) {
        ASSERT(existing_mount != NULL);
        /* modify existing mount entry */
#ifdef DEBUG_MOUNT
        DbgP("Using existing %d flavor session 0x%x\n",
            (int)pVNetRootContext->sec_flavor);
#endif
        switch (pVNetRootContext->sec_flavor) {
        case RPCSEC_AUTH_SYS:
            existing_mount->authsys_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5:
            existing_mount->gss_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5I:
            existing_mount->gssi_session = pVNetRootContext->session; break;
        case RPCSEC_AUTHGSS_KRB5P:
            existing_mount->gssp_session = pVNetRootContext->session; break;
        }
    }
    pNetRootContext->nfs41d_version = nfs41d_version;
#ifdef DEBUG_MOUNT
    DbgP("Saving new session 0x%p\n", pVNetRootContext->session);
#endif

out_free:
    RxFreePool(Config);
out:
    pCreateNetRootContext->VirtualNetRootStatus = status;
    if (pNetRoot->Context == NULL)
        pCreateNetRootContext->NetRootStatus = status;
    pCreateNetRootContext->Callback(pCreateNetRootContext);

    /* RDBSS expects that MRxCreateVNetRoot returns STATUS_PENDING
     * on success or failure */
    status = STATUS_PENDING;
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

VOID nfs41_ExtractNetRootName(
    IN PUNICODE_STRING FilePathName,
    IN PMRX_SRV_CALL SrvCall,
    OUT PUNICODE_STRING NetRootName,
    OUT PUNICODE_STRING RestOfName OPTIONAL)
{
    ULONG length = FilePathName->Length;
    PWCH w = FilePathName->Buffer;
    PWCH wlimit = (PWCH)(((PCHAR)w)+length);
    PWCH wlow;

    w += (SrvCall->pSrvCallName->Length/sizeof(WCHAR));
    NetRootName->Buffer = wlow = w;
    /* parse the entire path into NetRootName */
#if USE_ENTIRE_PATH_FOR_NETROOT
    w = wlimit;
#else
    for (;;) {
        if (w >= wlimit)
            break;
        if ((*w == OBJ_NAME_PATH_SEPARATOR) && (w != wlow))
            break;
        w++;
    }
#endif
    NetRootName->Length = NetRootName->MaximumLength
                = (USHORT)((PCHAR)w - (PCHAR)wlow);
#ifdef DEBUG_MOUNT
    DbgP("nfs41_ExtractNetRootName: "
        "In: pSrvCall 0x%p PathName='%wZ' SrvCallName='%wZ' "
        "Out: NetRootName='%wZ'\n",
        SrvCall, FilePathName, SrvCall->pSrvCallName, NetRootName);
#endif
    return;

}

NTSTATUS nfs41_FinalizeSrvCall(
    PMRX_SRV_CALL pSrvCall,
    BOOLEAN Force)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_SERVER_ENTRY pServerEntry = (PNFS41_SERVER_ENTRY)(pSrvCall->Context);

#ifdef DEBUG_MOUNT
    DbgEn();
#endif
    // print_srv_call(pSrvCall);

    if (pSrvCall->Context == NULL)
        goto out;

    InterlockedCompareExchangePointer(&pServerEntry->pRdbssSrvCall,
        NULL, pSrvCall);
    RxFreePool(pServerEntry);

    pSrvCall->Context = NULL;
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_FinalizeNetRoot(
    IN OUT PMRX_NET_ROOT pNetRoot,
    IN PBOOLEAN ForceDisconnect)
{
    NTSTATUS status = STATUS_SUCCESS;
    PNFS41_NETROOT_EXTENSION pNetRootContext =
        NFS41GetNetRootExtension((PMRX_NET_ROOT)pNetRoot);
    nfs41_updowncall_entry *tmp;
    nfs41_mount_entry *mount_tmp;

#ifdef DEBUG_MOUNT
    DbgEn();
    print_net_root(pNetRoot);
#endif

    if (pNetRoot->Type != NET_ROOT_DISK && pNetRoot->Type != NET_ROOT_WILD) {
        status = STATUS_NOT_SUPPORTED;
        goto out;
    }

    if (pNetRootContext == NULL || !pNetRootContext->mounts_init) {
        print_error("nfs41_FinalizeNetRoot: No valid session established\n");
        goto out;
    }

    if (pNetRoot->NumberOfFcbs > 0 || pNetRoot->NumberOfSrvOpens > 0) {
        print_error("%d open Fcbs %d open SrvOpens\n", pNetRoot->NumberOfFcbs,
            pNetRoot->NumberOfSrvOpens);
        goto out;
    }

    do {
        nfs41_GetFirstMountEntry(pNetRootContext->mountLock,
            pNetRootContext->mounts, mount_tmp);
        if (mount_tmp == NULL)
            break;
#ifdef DEBUG_MOUNT
        DbgP("Removing entry luid 0x%lx.0x%lx from mount list\n",
            (long)mount_tmp->login_id.HighPart,
            (long)mount_tmp->login_id.LowPart);
#endif
        if (mount_tmp->authsys_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->authsys_session,
                pNetRootContext->nfs41d_version, UPCALL_TIMEOUT_DEFAULT);
            if (status)
                print_error("nfs41_unmount AUTH_SYS failed with %d\n", status);
        }
        if (mount_tmp->gss_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->gss_session,
                pNetRootContext->nfs41d_version, UPCALL_TIMEOUT_DEFAULT);
            if (status)
                print_error("nfs41_unmount RPCSEC_GSS_KRB5 failed with %d\n",
                            status);
        }
        if (mount_tmp->gssi_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->gssi_session,
                pNetRootContext->nfs41d_version, UPCALL_TIMEOUT_DEFAULT);
            if (status)
                print_error("nfs41_unmount RPCSEC_GSS_KRB5I failed with %d\n",
                            status);
        }
        if (mount_tmp->gssp_session != INVALID_HANDLE_VALUE) {
            status = nfs41_unmount(mount_tmp->gssp_session,
                pNetRootContext->nfs41d_version, UPCALL_TIMEOUT_DEFAULT);
            if (status)
                print_error("nfs41_unmount RPCSEC_GSS_KRB5P failed with %d\n",
                            status);
        }
        nfs41_RemoveEntry(pNetRootContext->mountLock, mount_tmp);
        RxFreePool(mount_tmp);
        mount_tmp = NULL;
    } while (1);
    /* ignore any errors from unmount */
    status = STATUS_SUCCESS;

    // check if there is anything waiting in the upcall or downcall queue
    do {
        nfs41_GetFirstEntry(upcallLock, upcall, tmp);
        if (tmp != NULL) {
            DbgP("Removing entry from upcall list\n");
            nfs41_RemoveEntry(upcallLock, tmp);
            tmp->status = STATUS_INSUFFICIENT_RESOURCES;
            KeSetEvent(&tmp->cond, 0, FALSE);
        } else
            break;
    } while (1);

    do {
        nfs41_GetFirstEntry(downcallLock, downcall, tmp);
        if (tmp != NULL) {
            DbgP("Removing entry from downcall list\n");
            nfs41_RemoveEntry(downcallLock, tmp);
            tmp->status = STATUS_INSUFFICIENT_RESOURCES;
            KeSetEvent(&tmp->cond, 0, FALSE);
        } else
            break;
    } while (1);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_FinalizeVNetRoot(
    IN OUT PMRX_V_NET_ROOT pVNetRoot,
    IN PBOOLEAN ForceDisconnect)
{
    NTSTATUS status = STATUS_SUCCESS;
#ifdef DEBUG_MOUNT
    DbgEn();
    print_v_net_root(pVNetRoot);
#endif
    if (pVNetRoot->pNetRoot->Type != NET_ROOT_DISK &&
            pVNetRoot->pNetRoot->Type != NET_ROOT_WILD)
        status = STATUS_NOT_SUPPORTED;
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS GetConnectionHandle(
    IN PUNICODE_STRING ConnectionName,
    IN PVOID EaBuffer,
    IN ULONG EaLength,
    OUT PHANDLE Handle)
{
    NTSTATUS status;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;

#ifdef DEBUG_MOUNT
    DbgEn();
#endif
    InitializeObjectAttributes(&ObjectAttributes, ConnectionName,
        OBJ_CASE_INSENSITIVE|OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(Handle, SYNCHRONIZE, &ObjectAttributes,
        &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN_IF,
        FILE_CREATE_TREE_CONNECTION | FILE_SYNCHRONOUS_IO_NONALERT,
        EaBuffer, EaLength);

#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_GetConnectionInfoFromBuffer(
    IN PVOID Buffer,
    IN ULONG BufferLen,
    OUT PUNICODE_STRING pConnectionName,
    OUT PVOID *ppEaBuffer,
    OUT PULONG pEaLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    USHORT NameLength, EaPadding;
    ULONG EaLength, BufferLenExpected;
    PBYTE ptr;

    /* make sure buffer is at least big enough for header */
    if (BufferLen < sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG)) {
        status = STATUS_BAD_NETWORK_NAME;
        print_error("Invalid input buffer.\n");
        pConnectionName->Length = pConnectionName->MaximumLength = 0;
        *ppEaBuffer = NULL;
        *pEaLength = 0;
        goto out;
    }

    ptr = Buffer;
    NameLength = *(PUSHORT)ptr;
    ptr += sizeof(USHORT);
    EaPadding = *(PUSHORT)ptr;
    ptr += sizeof(USHORT);
    EaLength = *(PULONG)ptr;
    ptr += sizeof(ULONG);

    /* validate buffer length */
    BufferLenExpected = sizeof(USHORT) + sizeof(USHORT) + sizeof(ULONG) +
        NameLength + EaPadding + EaLength;
    if (BufferLen != BufferLenExpected) {
        status = STATUS_BAD_NETWORK_NAME;
        print_error("Received buffer of length %lu, but expected %lu bytes.\n",
            BufferLen, BufferLenExpected);
        pConnectionName->Length = pConnectionName->MaximumLength = 0;
        *ppEaBuffer = NULL;
        *pEaLength = 0;
        goto out;
    }

    pConnectionName->Buffer = (PWCH)ptr;
    pConnectionName->Length = NameLength - sizeof(WCHAR);
    pConnectionName->MaximumLength = NameLength;

    if (EaLength)
        *ppEaBuffer = ptr + NameLength + EaPadding;
    else
        *ppEaBuffer = NULL;
    *pEaLength = EaLength;

out:
    return status;
}

NTSTATUS nfs41_CreateConnection(
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp)
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE Handle = INVALID_HANDLE_VALUE;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    PVOID Buffer = LowIoContext->ParamsFor.IoCtl.pInputBuffer, EaBuffer;
    ULONG BufferLen = LowIoContext->ParamsFor.IoCtl.InputBufferLength, EaLength;
    UNICODE_STRING FileName;
    BOOLEAN Wait = BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_WAIT);

#ifdef DEBUG_MOUNT
    DbgEn();
#endif

    if (!Wait) {
        //just post right now!
        DbgP("returning STATUS_PENDING\n");
        *PostToFsp = TRUE;
        status = STATUS_PENDING;
        goto out;
    }

    status = nfs41_GetConnectionInfoFromBuffer(Buffer, BufferLen,
        &FileName, &EaBuffer, &EaLength);
    if (status != STATUS_SUCCESS)
        goto out;

    status = GetConnectionHandle(&FileName, EaBuffer, EaLength, &Handle);
    if (!status && Handle != INVALID_HANDLE_VALUE)
        ZwClose(Handle);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}

NTSTATUS nfs41_DeleteConnection(
    IN PRX_CONTEXT RxContext,
    OUT PBOOLEAN PostToFsp)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PLOWIO_CONTEXT LowIoContext = &RxContext->LowIoContext;
    PWCHAR ConnectName = LowIoContext->ParamsFor.IoCtl.pInputBuffer;
    ULONG ConnectNameLen = LowIoContext->ParamsFor.IoCtl.InputBufferLength;
    HANDLE Handle;
    UNICODE_STRING FileName;
    PFILE_OBJECT pFileObject;
    BOOLEAN Wait = BooleanFlagOn(RxContext->Flags, RX_CONTEXT_FLAG_WAIT);

#ifdef DEBUG_MOUNT
    DbgEn();
#endif

    if (!Wait) {
        //just post right now!
        *PostToFsp = TRUE;
        DbgP("returning STATUS_PENDING\n");
        status = STATUS_PENDING;
        goto out;
    }

    FileName.Buffer = ConnectName;
    FileName.Length = (USHORT) ConnectNameLen - sizeof(WCHAR);
    FileName.MaximumLength = (USHORT) ConnectNameLen;

    status = GetConnectionHandle(&FileName, NULL, 0, &Handle);
    if (status != STATUS_SUCCESS)
        goto out;

    status = ObReferenceObjectByHandle(Handle, 0L, NULL, KernelMode,
                (PVOID *)&pFileObject, NULL);
    if (NT_SUCCESS(status)) {
        PV_NET_ROOT VNetRoot;

        // VNetRoot exists as FOBx in the FsContext2
        VNetRoot = (PV_NET_ROOT) pFileObject->FsContext2;
        // make sure the node looks right
        if (NodeType(VNetRoot) == RDBSS_NTC_V_NETROOT)
        {
#ifdef DEBUG_MOUNT
            DbgP("Calling RxFinalizeConnection for NetRoot 0x%p from VNetRoot 0x%p\n",
                VNetRoot->NetRoot, VNetRoot);
#endif
            status = RxFinalizeConnection(VNetRoot->NetRoot, VNetRoot, TRUE);
        }
        else
            status = STATUS_BAD_NETWORK_NAME;

        ObDereferenceObject(pFileObject);
    }
    ZwClose(Handle);
out:
#ifdef DEBUG_MOUNT
    DbgEx();
#endif
    return status;
}
