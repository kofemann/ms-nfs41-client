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

#if ((__STDC_VERSION__-0) < 201710L)
#error Code requires ISO C17
#endif

#include <windows.h>
#include <npapi.h>
#include <devioctl.h>
#include <strsafe.h>
#include <stdbool.h>

#include "nfs41_build_features.h"
#include "nfs41_driver.h"
#include "nfs41_np.h"
#include "options.h"

#define DBG 1

#ifdef DBG
#define DbgP(_x_) NFS41DbgPrint _x_
#else
#define DbgP(_x_)
#endif
#define TRACE_TAG   L"[NFS41_NP]"
#define WNNC_DRIVER(major, minor) (((major) * 0x00010000) + (minor))

#define PTR2PTRDIFF_T(p) (((char *)(p))-((char *)0))
#define HANDLE2INT(h) ((int)PTR2PTRDIFF_T(h))

#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
const LUID SystemLuid = SYSTEM_LUID;
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */

/* Internal marker for UNC entries in NFS41_USER_SHARED_MEMORY_NAME */
#define NFS41NP_LOCALNAME_UNC_MARKER L"_:"

/* Local prototypes */
static DWORD is_unc_path_mounted(__in LPWSTR lpRemoteName);


ULONG _cdecl NFS41DbgPrint(__in LPWSTR fmt, ...)
{
    DWORD saved_lasterr;
    ULONG rc = 0;
#define SZBUFFER_SIZE 1024
    wchar_t szbuffer[SZBUFFER_SIZE+1];
    wchar_t *szbp = szbuffer;

    saved_lasterr = GetLastError();

    va_list marker;
    va_start(marker, fmt);

    (void)StringCchPrintfW(szbp, SZBUFFER_SIZE-(szbp - szbuffer),
        TRACE_TAG L"[thr=%04x] ", (int)GetCurrentThreadId());
    szbp += wcslen(szbp);

    (void)StringCchVPrintfW(szbp, SZBUFFER_SIZE-(szbp - szbuffer),
        fmt, marker);
    szbuffer[SZBUFFER_SIZE-1] = L'\0';

    OutputDebugStringW(szbuffer);

    va_end(marker);

    SetLastError(saved_lasterr);

    return rc;
}

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
/*
 * |equal_luid()| - |LUID| might contain padding fields, so
 * we cannot use |memcpy()|!
 */
static
bool equal_luid(const LUID *restrict l1, const LUID *restrict l2)
{
    return((l1->LowPart == l2->LowPart) &&
        (l1->HighPart == l2->HighPart));
}

/*
 * Performance hack:
 * GETTOKINFO_EXTRA_BUFFER - extra space for more data
 * |GetTokenInformation()| for |TOKEN_USER|, |TOKEN_PRIMARY_GROUP|
 * and |TOKEN_GROUPS_AND_PRIVILEGES| always fails in Win10 with
 * |ERROR_INSUFFICIENT_BUFFER| if you just pass the |sizeof(TOKEN_*)|
 * value.
 * Instead of calling |GetTokenInformation()| with |NULL| arg to
 * obtain the size to allocate we just provide 8192 bytes of extra
 * space after the |TOKEN_*| size, and pray it is enough.
 */
#define GETTOKINFO_EXTRA_BUFFER (8192)

static
bool get_token_authenticationid(HANDLE tok, LUID *out_authenticationid)
{
    DWORD tokdatalen;
    PTOKEN_GROUPS_AND_PRIVILEGES ptgp;

    tokdatalen =
        sizeof(TOKEN_GROUPS_AND_PRIVILEGES)+GETTOKINFO_EXTRA_BUFFER;
    ptgp = _alloca(tokdatalen);
    if (!GetTokenInformation(tok, TokenGroupsAndPrivileges, ptgp,
        tokdatalen, &tokdatalen)) {
        DbgP((L"get_token_authenticationid: "
            L"GetTokenInformation(tok=0x%p, TokenGroupsAndPrivileges) "
            L"failed, "
            L"status=%d\n",
            (void *)tok, (int)GetLastError()));
        return false;
    }

    *out_authenticationid = ptgp->AuthenticationId;

    return true;
}
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

int filter(unsigned int code)
{
    DbgP((L"####Got exception %u\n", code));
    return EXCEPTION_CONTINUE_SEARCH;
}

static
DWORD OpenSharedMemory(
    PHANDLE phMutex,
    PHANDLE phMemory,
    PVOID   *pMemory)
/*++

Routine Description:

    This routine opens the shared memory for exclusive manipulation

Arguments:
    phMutex - the mutex handle
    phMemory - the memory handle
    pMemory - a ptr. to the shared memory which is set if successful

Return Value:
    WN_SUCCESS -- if successful

--*/
{
    DWORD dwStatus;

    *phMutex = 0;
    *phMemory = 0;
    *pMemory = NULL;

    DbgP((L"--> OpenSharedMemory()\n"));

    *phMutex = CreateMutexA(NULL, FALSE, NFS41NP_MUTEX_NAME);
    if (*phMutex == NULL) {
        dwStatus = GetLastError();
        DbgP((L"OpenSharedMemory: "
            "CreateMutexA() failed, lasterr=%d\n",
            dwStatus));
        goto OpenSharedMemoryAbort1;
    }

    (void)WaitForSingleObject(*phMutex, INFINITE);

    *phMemory = OpenFileMappingA(FILE_MAP_WRITE,
                                FALSE,
                                NFS41_USER_SHARED_MEMORY_NAME);
    if (*phMemory == NULL) {
        dwStatus = GetLastError();
        DbgP((L"OpenFileMappingA() failed, lasterr=%d\n", dwStatus));
        goto OpenSharedMemoryAbort2;
    }

    *pMemory = MapViewOfFile(*phMemory, FILE_MAP_WRITE, 0, 0, 0);
    if (*pMemory == NULL) {
        dwStatus = GetLastError();
        DbgP((L"MapViewOfFile failed, lasterr=%d\n", dwStatus));
        goto OpenSharedMemoryAbort3;
    }

    DbgP((L"<-- OpenSharedMemory() returns ERROR_SUCCESS\n"));
    return ERROR_SUCCESS;

OpenSharedMemoryAbort3:
    (void)CloseHandle(*phMemory);

OpenSharedMemoryAbort2:
    (void)ReleaseMutex(*phMutex);
    (void)CloseHandle(*phMutex);
    *phMutex = NULL;

OpenSharedMemoryAbort1:
    DbgP((L"<-- OpenSharedMemory: return dwStatus: %d\n", dwStatus));

    return dwStatus;
}

static
VOID CloseSharedMemory(
    PHANDLE hMutex,
    PHANDLE hMemory,
    PVOID   *pMemory)
/*++

Routine Description:
    This routine relinquishes control of the shared memory after
    exclusive manipulation

Arguments:
    hMutex - the mutex handle
    hMemory  - the memory handle
    pMemory - a ptr. to the shared memory which is set if successful

Return Value:

--*/
{
    DbgP((L"--> CloseSharedMemory\n"));
    if (*pMemory) {
        (void)UnmapViewOfFile(*pMemory);
        *pMemory = NULL;
    }
    if (*hMemory) {
        (void)CloseHandle(*hMemory);
        *hMemory = 0;
    }
    if (*hMutex) {
        if (ReleaseMutex(*hMutex) == FALSE) {
            DbgP((L"ReleaseMutex error: %d\n", (int)GetLastError()));
        }
        (void)CloseHandle(*hMutex);
        *hMutex = 0;
    }
    DbgP((L"<-- CloseSharedMemory\n"));
}

static DWORD StoreConnectionInfo(
    IN LPCWSTR LocalName,
    IN LPCWSTR ConnectionName,
    IN USHORT ConnectionNameLength,
    IN LPNETRESOURCEW lpNetResource)
{
    DWORD status;
    HANDLE hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY pSharedMemory;
    PNFS41NP_NETRESOURCE pNfs41NetResource;
    INT i;
    bool FreeEntryFound = false;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID authenticationid = { .LowPart = 0, .HighPart = 0L };
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    DbgP((L"--> StoreConnectionInfo\n"));

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    (void)get_token_authenticationid(GetCurrentThreadEffectiveToken(),
        &authenticationid);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    status = OpenSharedMemory(&hMutex, &hMemory,
        (PVOID *)&pSharedMemory);
    if (status)
        goto out;

    DbgP((L"StoreConnectionInfo: NextIndex %d, NumResources %d\n",
        pSharedMemory->NextAvailableIndex,
        pSharedMemory->NumberOfResourcesInUse));

    for (i = 0; i < pSharedMemory->NextAvailableIndex; i++)
    {
        if (!pSharedMemory->NetResources[i].InUse) {
            FreeEntryFound = true;
            DbgP((L"Reusing existing index %d\n", i));
            break;
        }
    }

    if (!FreeEntryFound) {
        if (pSharedMemory->NextAvailableIndex >= NFS41NP_MAX_DEVICES) {
            status = WN_NO_MORE_DEVICES;
            goto out_close;
        }
        i = pSharedMemory->NextAvailableIndex++;
        DbgP((L"Using new index %d\n", i));
    }

    pSharedMemory->NumberOfResourcesInUse += 1;

    pNfs41NetResource = &pSharedMemory->NetResources[i];

    pNfs41NetResource->InUse            = TRUE;
    pNfs41NetResource->dwScope          = lpNetResource->dwScope;
    pNfs41NetResource->dwType           = lpNetResource->dwType;
    pNfs41NetResource->dwDisplayType    =
        lpNetResource->dwDisplayType;
    pNfs41NetResource->dwUsage          = RESOURCEUSAGE_CONNECTABLE;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    pNfs41NetResource->MountAuthId      = authenticationid;
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
    pNfs41NetResource->LocalNameLength  =
        (USHORT)(wcslen(LocalName) + 1) * sizeof(WCHAR);
    pNfs41NetResource->RemoteNameLength =
        (USHORT)(wcslen(lpNetResource->lpRemoteName)+1)*sizeof(WCHAR);
    pNfs41NetResource->ConnectionNameLength = ConnectionNameLength;

    (void)StringCchCopyW(pNfs41NetResource->LocalName,
        pNfs41NetResource->LocalNameLength,
        LocalName);
    (void)StringCchCopyW(pNfs41NetResource->RemoteName,
        pNfs41NetResource->RemoteNameLength,
        lpNetResource->lpRemoteName);
    (void)StringCchCopyW(pNfs41NetResource->ConnectionName,
        pNfs41NetResource->ConnectionNameLength,
        ConnectionName);

    // TODO: copy mount options -cbodley

out_close:
    CloseSharedMemory(&hMutex, &hMemory, (PVOID *)&pSharedMemory);
out:
    DbgP((L"<-- StoreConnectionInfo returns %d\n", (int)status));

    return status;
}

static
ULONG SendTo_NFS41Driver(
    IN ULONG            IoctlCode,
    IN PVOID            InputDataBuf,
    IN ULONG            InputDataLen,
    IN PVOID            OutputDataBuf,
    IN PULONG           pOutputDataLen)
{
    HANDLE  DeviceHandle;       // The mini rdr device handle
    BOOL    rc = FALSE;
    ULONG   Status;

    DbgP((L"--> SendTo_NFS41Driver\n"));

    Status = WN_SUCCESS;
    DbgP((L"calling CreateFileW\n"));
    DeviceHandle = CreateFileW(
        NFS41_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        (LPSECURITY_ATTRIBUTES)NULL,
        OPEN_EXISTING,
        0,
        (HANDLE)NULL);
    DbgP((L"after CreateFileW() Device Handle\n"));

    if (DeviceHandle == INVALID_HANDLE_VALUE) {
        Status = GetLastError();
        DbgP((L"SendTo_NFS41Driver: error %08lx opening device\n",
            Status));
        goto out;
    }

    __try {
        DbgP((L"calling DeviceIoControl\n"));
        rc = DeviceIoControl(
            DeviceHandle,
            IoctlCode,
            InputDataBuf,
            InputDataLen,
            OutputDataBuf,
            *pOutputDataLen,
            pOutputDataLen,
            NULL);
    } __except(filter(GetExceptionCode())) {
        DbgP((L"#### DeviceIoControl() exception\n"));
    }
    Status = GetLastError();
    DbgP((L"DeviceIoControl returned rc=%08lx\n", rc));
    if (!rc) {
        DbgP((L"SendTo_NFS41Driver: "
            "returning error from DeviceIoctl\n"));
    }
    else {
        DbgP((L"SendTo_NFS41Driver: DeviceIoctl() success\n"));
        Status = WN_SUCCESS;
    }
    (void)CloseHandle(DeviceHandle);
out:
    DbgP((L"<-- SendTo_NFS41Driver returns %d\n", Status));
    return Status;
}

static
const char *netcaps2string(DWORD idx)
{
#define NETCAPS_TO_STRLITERAL(e) case e: return #e
    switch(idx) {
        NETCAPS_TO_STRLITERAL(WNNC_SPEC_VERSION);
        NETCAPS_TO_STRLITERAL(WNNC_NET_TYPE);
        NETCAPS_TO_STRLITERAL(WNNC_DRIVER_VERSION);
        NETCAPS_TO_STRLITERAL(WNNC_CONNECTION);
        NETCAPS_TO_STRLITERAL(WNNC_ENUMERATION);
        NETCAPS_TO_STRLITERAL(WNNC_START);
        NETCAPS_TO_STRLITERAL(WNNC_USER);
        NETCAPS_TO_STRLITERAL(WNNC_DIALOG);
        NETCAPS_TO_STRLITERAL(WNNC_ADMIN);
        NETCAPS_TO_STRLITERAL(WNNC_CONNECTION_FLAGS);
    }
    return "<unknown WNNC_* index>";
}

DWORD APIENTRY
NPGetCaps(
    DWORD nIndex )
{
    DWORD rc = 0;

    DbgP((L"--> GetNetCaps(nIndex='%S'(=%d)\n",
        netcaps2string(nIndex), nIndex));
    switch(nIndex) {
        case WNNC_SPEC_VERSION:
            rc = WNNC_SPEC_VERSION51;
            break;
        case WNNC_NET_TYPE:
            rc = WNNC_NET_RDR2SAMPLE;
            break;
        case WNNC_DRIVER_VERSION:
            rc = WNNC_DRIVER(1, 0);
            break;
        case WNNC_CONNECTION:
            rc = WNNC_CON_GETCONNECTIONS |
                 WNNC_CON_CANCELCONNECTION |
                 WNNC_CON_ADDCONNECTION |
                 WNNC_CON_ADDCONNECTION3;
            break;
        case WNNC_ENUMERATION:
            rc = WNNC_ENUM_LOCAL;
            break;
        case WNNC_START:
            rc = 1;
            break;
        case WNNC_USER:
        case WNNC_DIALOG:
        case WNNC_ADMIN:
        case WNNC_CONNECTION_FLAGS:
        default:
            rc = 0;
            break;
    }

    DbgP((L"<-- GetNetCaps returns %d\n", (int)rc));
    return rc;
}

DWORD APIENTRY
NPLogonNotify(
    __in PLUID   lpLogonId,
    __in PCWSTR lpAuthentInfoType,
    __in PVOID  lpAuthentInfo,
    __in PCWSTR lpPreviousAuthentInfoType,
    __in PVOID  lpPreviousAuthentInfo,
    __in PWSTR  lpStationName,
    __in PVOID  StationHandle,
    __out PWSTR  *lpLogonScript)
{
    *lpLogonScript = NULL;
    DbgP((L"NPLogonNotify: returning WN_SUCCESS\n"));
    return WN_SUCCESS;
}

DWORD APIENTRY
NPPasswordChangeNotify (
    __in LPCWSTR lpAuthentInfoType,
    __in LPVOID  lpAuthentInfo,
    __in LPCWSTR lpPreviousAuthentInfoType,
    __in LPVOID  lpPreviousAuthentInfo,
    __in LPWSTR  lpStationName,
    LPVOID  StationHandle,
    DWORD   dwChangeInfo )
{
    DbgP(( L"NPPasswordChangeNotify: WN_NOT_SUPPORTED\n"));
    SetLastError(WN_NOT_SUPPORTED);
    return WN_NOT_SUPPORTED;
}

DWORD APIENTRY
NPAddConnection(
    __in LPNETRESOURCEW  lpNetResource,
    __in_opt LPWSTR      lpPassword,
    __in_opt LPWSTR      lpUserName )
{
    return NPAddConnection3(NULL, lpNetResource, lpPassword,
        lpUserName, 0);
}

DWORD APIENTRY
NPAddConnection3(
    __in HWND           hwndOwner,
    __in LPNETRESOURCEW lpNetResource,
    __in_opt LPWSTR     lpPassword,
    __in_opt LPWSTR     lpUserName,
    __in DWORD          dwFlags)
{
    DWORD   Status;
    WCHAR   wszScratch[1024];
    WCHAR   LocalName[3];
    DWORD   CopyBytes = 0;
    CONNECTION_INFO Connection;
    LPWSTR  ConnectionName;
    WCHAR ServerName[NFS41_SYS_MAX_PATH_LEN];
    PWCHAR p;
    DWORD i;
    LPWSTR  lpLocalName = lpNetResource->lpLocalName;

    DbgP((L"-->  NPAddConnection3(lpNetResource->lpLocalName='%s', "
        L"lpNetResource->lpRemoteName='%s', "
        L"username='%s', passwd='%s')\n",
        lpLocalName,
        lpNetResource->lpRemoteName,lpUserName,
        lpPassword));

    if (lpLocalName == NULL) {
        lpLocalName = NFS41NP_LOCALNAME_UNC_MARKER;
        DbgP((L"lpLocalName==NULL, "
            "changed to " NFS41NP_LOCALNAME_UNC_MARKER L"\n"));
    }

    Status = InitializeConnectionInfo(&Connection,
        (PMOUNT_OPTION_BUFFER)lpNetResource->lpComment,
        &ConnectionName);
    if (Status)  {
        DbgP((L"InitializeConnectionInfo failed with %d\n", Status));
        goto out;
    }

    //  \device\miniredirector\;<DriveLetter>:\Server\Share

    // local name, must start with "X:"
    if (wcslen(lpLocalName) < 2 ||
        lpLocalName[1] != L':') {
        DbgP((L"lpLocalName(='%s') "
            "is not a device letter\n",
            lpLocalName));
        Status = WN_BAD_LOCALNAME;
        goto out;
    }

    LocalName[0] = towupper(lpLocalName[0]);
    LocalName[1] = L':';
    LocalName[2] = L'\0';
    (void)StringCchCopyW(ConnectionName,
        NFS41_SYS_MAX_PATH_LEN, NFS41_DEVICE_NAME);
    (void)StringCchCatW(ConnectionName,
        NFS41_SYS_MAX_PATH_LEN, L"\\;");
    (void)StringCchCatW(ConnectionName,
        NFS41_SYS_MAX_PATH_LEN, LocalName);

    // remote name, must start with "\\"
    if ((lpNetResource->lpRemoteName[0] == L'\0') ||
        (lpNetResource->lpRemoteName[0] != L'\\') ||
        (lpNetResource->lpRemoteName[1] != L'\\')) {
        Status = WN_BAD_NETNAME;
        goto out;
    }

    /*
     * Note: remotename comes as \\server but we need to
     * add \server thus +1 pointer
     */
    p = lpNetResource->lpRemoteName + 1;
    ServerName[0] = L'\\';
    i = 1;
    for(;;) {
        /* convert servername ending unix slash to windows slash */
        if (p[i] == L'/')
            p[i] = L'\\';
        /* deal with servername ending with any slash */
        if (p[i] == L'\0')
            p[i] = L'\\';
        ServerName[i] = p[i];
        if (p[i] == L'\\') break;
        i++;
    }
    ServerName[i] = L'\0';

    (void)StringCchCatW(ConnectionName,
        NFS41_SYS_MAX_PATH_LEN, ServerName);
#ifndef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
    /* insert the "nfs4" in between the server name and the path,
     * just to make sure all calls to our driver come thru this */
    (void)StringCchCatW(ConnectionName,
        NFS41_SYS_MAX_PATH_LEN, L"\\nfs4");
#endif /* NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX */

#ifdef CONVERT_2_UNIX_SLASHES
    /* convert all windows slashes to unix slashes */
    {
        PWCHAR q = p;
        DWORD j = 0;
        for(;;) {
            if(q[j] == L'\0') break;
            if (q[j] == L'\\') q[j] = L'/';
            j++;
        }
    }
#else
    /* convert all unix slashes to windows slashes */
    {
        PWCHAR q = p;
        DWORD j = 0;
        for(;;) {
            if(q[j] == L'\0') break;
            if (q[j] == L'/') q[j] = L'\\';
            j++;
        }
    }
#endif /* CONVERT_2_UNIX_SLASHES */

#if 1
    /*
     * Fold repeated backslash into a single backslash
     * This is a workaround for nfs://-URLs like
     * nfs://derfwnb4966_ipv4//////////net_tmpfs2//test2
     * where multiple slashes somehow prevent Windows
     * from looking up the path from the device letter
     * (e.g. device letter does not show up in /cygdrive/).
     * nfsd_daemon will still see the full path with all backslashes
     * (e.g. "msg=mount(hostport='derfwnb4966_ipv4@2049',
     * path='\\\\\\\\\net_tmpfs2\\test2')"
     */
    {
        wchar_t *q, *u;
        q = u = &p[i];

        while(*q != L'\0') {
            while((*q == '\\') && (*(q+1) == '\\'))
                q++;
            *u++ = *q++;
        }
        *u = L'\0';
    }
#endif

#ifdef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
    if (wcsncmp(&p[i], L"\\nfs4", 5) &&
        wcsncmp(&p[i], L"\\pubnfs4", 8)) {
        DbgP((L"Connection name '%s' not prefixed with "
            "'\\nfs41' or '\\pubnfs41'\n",
            &p[i]));
        Status = WN_BAD_NETNAME;
        goto out;
    }
#endif /* NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX */

    (void)StringCchCatW(ConnectionName,
        NFS41_SYS_MAX_PATH_LEN, &p[i]);
    DbgP((L"Full Connect Name: '%s'\n", ConnectionName));
    DbgP((L"Full Connect Name Length: %d %d\n",
        (wcslen(ConnectionName) + 1) * sizeof(WCHAR),
        (wcslen(ConnectionName) + 1) * sizeof(WCHAR)));

    if (lpNetResource->lpLocalName == NULL) {
        DWORD gc_status;

        gc_status = is_unc_path_mounted(lpNetResource->lpRemoteName);
        DbgP((L"lpNetResource->lpLocalName == NULL, "
            "is_unc_path_mounted(lpNetResource->lpRemoteName='%s') "
            "returned gc_status=%d\n",
            lpNetResource->lpRemoteName,
            (int)gc_status));

        if (gc_status == WN_SUCCESS) {
            /*
             * Do not return |WN_ALREADY_CONNECTED| here, as UNC
             * paths are reused
             * We explicitly use this to skip |StoreConnectionInfo()|
             * below, so we only have one stored UNC connection
             */
            Status = WN_SUCCESS;
            goto out;
        }
    }
    else {
        DWORD lasterr;

        wszScratch[0] = L'\0';
        Status = QueryDosDeviceW(LocalName, wszScratch, 1024);
        lasterr = GetLastError();
        DbgP((L"QueryDosDeviceW(lpDeviceName='%s',lpTargetPath='%s') "
            L"returned %d/GetLastError()=%d\n",
            LocalName, wszScratch, Status, (int)lasterr));

        if (Status || (lasterr != ERROR_FILE_NOT_FOUND)) {
            Status = WN_ALREADY_CONNECTED;
            goto out;
        }
    }

    MarshalConnectionInfo(&Connection);

    Status = SendTo_NFS41Driver(IOCTL_NFS41_ADDCONN,
        Connection.Buffer, Connection.BufferSize,
        NULL, &CopyBytes);
    DbgP(( L"SendTo_NFS41Driver() returned %d\n", Status));
    if (Status) {
        goto out;
    }

    if (lpNetResource->lpLocalName != NULL) {
        DbgP((L"DefineDosDeviceW(lpLocalName='%s', "
            L"ConnectionName='%s')\n",
            lpLocalName, ConnectionName));
        if (!DefineDosDeviceW(DDD_RAW_TARGET_PATH |
            DDD_NO_BROADCAST_SYSTEM,
            lpLocalName,
            ConnectionName)) {
            Status = GetLastError();
            DbgP((L"DefineDosDeviceW(lpLocalName='%s',"
                L"ConnectionName='%s') failed with %d\n",
                lpLocalName, ConnectionName, Status));
            goto out_delconn;
        }
    }

    // The connection was established and the local device mapping
    // added. Include this in the list of mapped devices.
    Status = StoreConnectionInfo(LocalName, ConnectionName,
        Connection.Buffer->NameLength, lpNetResource);
    if (Status) {
        DbgP((L"StoreConnectionInfo failed with %d\n", Status));
        goto out_undefine;
    }

out:
    FreeConnectionInfo(&Connection);
    DbgP((L"<-- NPAddConnection3 returns %d\n", (int)Status));
    return Status;
out_undefine:
    if (lpNetResource->lpLocalName != NULL) {
        (void)DefineDosDeviceW(DDD_REMOVE_DEFINITION |
            DDD_RAW_TARGET_PATH |
            DDD_EXACT_MATCH_ON_REMOVE,
            LocalName, ConnectionName);
    }
out_delconn:
    SendTo_NFS41Driver(IOCTL_NFS41_DELCONN, ConnectionName,
        Connection.Buffer->NameLength, NULL, &CopyBytes);
    goto out;
}

DWORD APIENTRY
NPCancelConnection(
    __in LPWSTR  lpName,
    __in BOOL    fForce )
{
    DWORD   Status = 0;

    HANDLE  hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY  pSharedMemory;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID authenticationid = { .LowPart = 0, .HighPart = 0L };
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
    bool is_unc_path;

    DbgP((L"--> NPCancelConnection(lpName='%s', fForce=%d)\n",
        lpName, (int)fForce));

    if (lpName && (lpName[0] == L'\\') && (lpName[1] == L'\\')) {
        is_unc_path = true;
    }
    else {
        is_unc_path = false;
    }

    DbgP((L"is_unc_path=%d\n", (int)is_unc_path));

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    (void)get_token_authenticationid(GetCurrentThreadEffectiveToken(),
        &authenticationid);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    Status = OpenSharedMemory(&hMutex,
        &hMemory,
        (PVOID)&pSharedMemory);

    if (Status != WN_SUCCESS)
        goto out;

    INT  Index;
    PNFS41NP_NETRESOURCE pNetResource;
    Status = WN_NOT_CONNECTED;

    DbgP((L"NPCancelConnection: NextIndex %d, NumResources %d\n",
                pSharedMemory->NextAvailableIndex,
                pSharedMemory->NumberOfResourcesInUse));

    for (Index = 0; Index < pSharedMemory->NextAvailableIndex; Index++) {
        pNetResource = &pSharedMemory->NetResources[Index];

        if (!pNetResource->InUse)
            continue;

        DbgP((L"Name '%s' EntryName '%s'\n",
            lpName, pNetResource->LocalName));

        if (is_unc_path) {
            LPWSTR unc_devname = NFS41NP_LOCALNAME_UNC_MARKER;

            if (
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
                /* Need exact match here, not |SYSTEM_LUID|! */
                equal_luid(&authenticationid,
                    &pNetResource->MountAuthId) &&
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
                (((wcslen(unc_devname)+1) * sizeof(WCHAR)) ==
                pNetResource->LocalNameLength) &&
                (!wcscmp(unc_devname, pNetResource->LocalName)) &&
                (((wcslen(lpName)+1) * sizeof(WCHAR)) ==
                pNetResource->RemoteNameLength) &&
                (!wcscmp(lpName, pNetResource->RemoteName))) {
                ULONG CopyBytes;

                DbgP((L"NPCancelConnection: UNC Connection Found:\n"));

                CopyBytes = 0;

                Status = SendTo_NFS41Driver(IOCTL_NFS41_DELCONN,
                            pNetResource->ConnectionName,
                            pNetResource->ConnectionNameLength,
                            NULL,
                            &CopyBytes);

                if (Status != WN_SUCCESS) {
                    DbgP((L"SendToMiniRdr returned Status %lx\n",
                        Status));
                    break;
                }

                pNetResource->InUse = FALSE;
                pSharedMemory->NumberOfResourcesInUse--;

                if (Index+1 == pSharedMemory->NextAvailableIndex)
                    pSharedMemory->NextAvailableIndex--;
                break;
            }
        }
        else {
            if (
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
                /* Need exact match here, not |SYSTEM_LUID|! */
                equal_luid(&authenticationid,
                    &pNetResource->MountAuthId) &&
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
                (((wcslen(lpName)+1) * sizeof(WCHAR)) ==
                pNetResource->LocalNameLength) &&
                (!wcscmp(lpName, pNetResource->LocalName))) {
                ULONG CopyBytes;

                DbgP((L"NPCancelConnection: Connection Found:\n"));

                CopyBytes = 0;

                Status = SendTo_NFS41Driver(IOCTL_NFS41_DELCONN,
                            pNetResource->ConnectionName,
                            pNetResource->ConnectionNameLength,
                            NULL,
                            &CopyBytes);

                if (Status != WN_SUCCESS) {
                    DbgP((L"SendToMiniRdr returned Status %lx\n",
                        Status));
                    break;
                }

                if (DefineDosDeviceW(DDD_REMOVE_DEFINITION |
                        DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE,
                    lpName,
                    pNetResource->ConnectionName) == FALSE) {
                    Status = GetLastError();
                    DbgP((L"DefineDosDeviceW error: %d\n",
                        (int)Status));
                }
                else {
                    pNetResource->InUse = FALSE;
                    pSharedMemory->NumberOfResourcesInUse--;

                    if (Index+1 == pSharedMemory->NextAvailableIndex)
                        pSharedMemory->NextAvailableIndex--;
                }
                break;
            }
        }
    }

    CloseSharedMemory(&hMutex,
        &hMemory,
        (PVOID)&pSharedMemory);
out:
    DbgP((L"<-- NPCancelConnection returns %d\n", (int)Status));
    return Status;
}

static
DWORD is_unc_path_mounted(
    __in LPWSTR lpRemoteName)
{
    DWORD   Status = 0;

    HANDLE  hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY  pSharedMemory;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID authenticationid = { .LowPart = 0, .HighPart = 0L };
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
    LPWSTR lpLocalName = NFS41NP_LOCALNAME_UNC_MARKER;

    DbgP((L"--> is_unc_path_mounted(lpRemoteName='%s')\n", lpRemoteName));

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    (void)get_token_authenticationid(GetCurrentThreadEffectiveToken(),
        &authenticationid);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    Status = OpenSharedMemory(&hMutex,
        &hMemory,
        (PVOID)&pSharedMemory);
    if (Status != WN_SUCCESS)
        goto out;

    INT  Index;
    PNFS41NP_NETRESOURCE pNetResource;
    PNFS41NP_NETRESOURCE foundNetResource = NULL;
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
    PNFS41NP_NETRESOURCE foundSystemLuidNetResource = NULL;
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
    Status = WN_NOT_CONNECTED;

    for (Index = 0; Index < pSharedMemory->NextAvailableIndex; Index++) {
        pNetResource = &pSharedMemory->NetResources[Index];

        if (!pNetResource->InUse)
            continue;

        if ((((wcslen(lpLocalName)+1)*sizeof(WCHAR)) ==
                pNetResource->LocalNameLength) &&
                (!wcscmp(lpLocalName, pNetResource->LocalName)) &&
                (((wcslen(lpRemoteName)+1)*sizeof(WCHAR)) ==
                pNetResource->RemoteNameLength) &&
                (!wcscmp(lpRemoteName, pNetResource->RemoteName))) {
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
                if (equal_luid(&authenticationid,
                    &pNetResource->MountAuthId)) {
                    foundNetResource = pNetResource;
                    break;
                }
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
            else if (equal_luid(&SystemLuid,
                &pNetResource->MountAuthId)) {
                /*
                 * Found netresource for user "SYSTEM", but
                 * continue searching |pSharedMemory->NetResources|
                 * for an exact match...
                 */
                foundSystemLuidNetResource = pNetResource;
            }
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
#else /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
            foundNetResource = pNetResource;
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
        }
    }

#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
    /*
     * No exact match found ? Then fall-back to any match we found for
     * user "SYSTEM"
     */
    if (foundNetResource == NULL) {
        foundNetResource = foundSystemLuidNetResource;
    }
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */

    if (foundNetResource) {
        Status = WN_SUCCESS;
    }

    CloseSharedMemory( &hMutex, &hMemory, (PVOID)&pSharedMemory);
out:
    DbgP((L"<-- is_unc_path_mounted returns %d\n", (int)Status));

    return Status;
}

DWORD APIENTRY
NPGetConnection(
    __in LPWSTR  lpLocalName,
    __out_bcount(*lpBufferSize) LPWSTR  lpRemoteName,
    __inout LPDWORD lpBufferSize )
{
    DWORD   Status = 0;

    HANDLE  hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY  pSharedMemory;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID authenticationid = { .LowPart = 0, .HighPart = 0L };
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    DbgP((L"--> NPGetConnection(lpLocalName='%s')\n", lpLocalName));

    if (lpLocalName == NULL) {
        lpLocalName = NFS41NP_LOCALNAME_UNC_MARKER;
        DbgP((L"lpLocalName==NULL, "
            "changed to " NFS41NP_LOCALNAME_UNC_MARKER L"\n"));
    }

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    (void)get_token_authenticationid(GetCurrentThreadEffectiveToken(),
        &authenticationid);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    Status = OpenSharedMemory(&hMutex,
        &hMemory,
        (PVOID)&pSharedMemory);
    if (Status != WN_SUCCESS)
        goto out;

    INT  Index;
    PNFS41NP_NETRESOURCE pNetResource;
    PNFS41NP_NETRESOURCE foundNetResource = NULL;
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
    PNFS41NP_NETRESOURCE foundSystemLuidNetResource = NULL;
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
    Status = WN_NOT_CONNECTED;

    for (Index = 0; Index < pSharedMemory->NextAvailableIndex; Index++) {
        pNetResource = &pSharedMemory->NetResources[Index];

        if (!pNetResource->InUse)
            break;

        if ((((wcslen(lpLocalName)+1)*sizeof(WCHAR)) ==
                pNetResource->LocalNameLength) &&
                (!wcscmp(lpLocalName, pNetResource->LocalName))) {
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
            if (equal_luid(&authenticationid,
                &pNetResource->MountAuthId)) {
                foundNetResource = pNetResource;
                break;
            }
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
            else if (equal_luid(&SystemLuid,
                &pNetResource->MountAuthId)) {
                /*
                 * Found netresource for user "SYSTEM", but
                 * continue searching |pSharedMemory->NetResources|
                 * for an exact match...
                 */
                foundSystemLuidNetResource = pNetResource;
            }
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
#else /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
            foundNetResource = pNetResource;
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
        }
    }

#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
    /*
     * No exact match found ? Then fall-back to any match we found for
     * user "SYSTEM"
     */
    if (foundNetResource == NULL) {
        foundNetResource = foundSystemLuidNetResource;
    }
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */

    if (foundNetResource) {
        if (*lpBufferSize < foundNetResource->RemoteNameLength) {
            *lpBufferSize = foundNetResource->RemoteNameLength;
            Status = WN_MORE_DATA;
        }
        else {
            *lpBufferSize = foundNetResource->RemoteNameLength;
            (void)memcpy(lpRemoteName,
                foundNetResource->RemoteName,
                foundNetResource->RemoteNameLength);
            Status = WN_SUCCESS;
        }
    }

    CloseSharedMemory( &hMutex, &hMemory, (PVOID)&pSharedMemory);
out:
    DbgP((L"<-- NPGetConnection returns %d\n", (int)Status));

    return Status;
}

DWORD APIENTRY
NPOpenEnum(
    DWORD           dwScope,
    DWORD           dwType,
    DWORD           dwUsage,
    LPNETRESOURCEW  lpNetResource,
    LPHANDLE        lphEnum)
{
    DWORD Status;

    DbgP((L" --> NPOpenEnum(dwScope=%d, dwType=%d, dwUsage=%d)\n",
        (int)dwScope, (int)dwType, (int)dwUsage));

    *lphEnum = NULL;

    switch(dwScope)
    {
        case RESOURCE_CONNECTED:
        {
            *lphEnum = HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY, sizeof(ULONG));

            if (*lphEnum ) {
                Status = WN_SUCCESS;
            }
            else {
                Status = WN_OUT_OF_MEMORY;
            }
            break;
        }
        break;

        case RESOURCE_CONTEXT:
        default:
            Status  = WN_NOT_SUPPORTED;
            break;
    }

    DbgP((L"<-- NPOpenEnum returns %d, *lphEnum=0x%x\n",
        (int)Status, HANDLE2INT(*lphEnum)));

    return(Status);
}

DWORD APIENTRY
NPEnumResource(
    HANDLE  hEnum,
    LPDWORD lpcCount,
    LPVOID  lpBuffer,
    LPDWORD lpBufferSize)
{
    DWORD           Status = WN_SUCCESS;
    ULONG           EntriesCopied;
    LPNETRESOURCEW  pNetResource;
    ULONG           SpaceNeeded = 0;
    ULONG           SpaceAvailable;
    PWCHAR          StringZone;
    HANDLE  hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY  pSharedMemory;
    PNFS41NP_NETRESOURCE pNfsNetResource;
    INT             Index = *(PULONG)hEnum;
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    LUID            authenticationid =
        { .LowPart = 0, .HighPart = 0L };
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    DbgP((L"--> NPEnumResource(hEnum=0x%x, *lpcCount=%d)\n",
        HANDLE2INT(hEnum), (int)*lpcCount));

#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
    (void)get_token_authenticationid(GetCurrentThreadEffectiveToken(),
        &authenticationid);
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */

    pNetResource = (LPNETRESOURCEW)lpBuffer;
    SpaceAvailable = *lpBufferSize;
    EntriesCopied = 0;
    StringZone = (PWCHAR) ((PBYTE)lpBuffer + *lpBufferSize);

    Status = OpenSharedMemory(&hMutex,
        &hMemory,
        (PVOID)&pSharedMemory);
    if (Status != WN_SUCCESS)
        goto out;

    Status = WN_NO_MORE_ENTRIES;
    for (Index = *(PULONG)hEnum; EntriesCopied < *lpcCount &&
            Index < pSharedMemory->NextAvailableIndex; Index++)
    {
        pNfsNetResource = &pSharedMemory->NetResources[Index];

        if (pNfsNetResource->InUse
#ifdef NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE
#ifdef NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL
            && (equal_luid(&authenticationid,
                &pNfsNetResource->MountAuthId) ||
                equal_luid(&SystemLuid,
                &pNfsNetResource->MountAuthId)
            )
#else /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
            && equal_luid(&authenticationid,
                &pNfsNetResource->MountAuthId)
#endif /* NFS41_DRIVER_SYSTEM_LUID_MOUNTS_ARE_GLOBAL */
#endif /* NFS41_DRIVER_USE_AUTHENTICATIONID_FOR_MOUNT_NAMESPACE */
                ) {
            SpaceNeeded  = sizeof(NETRESOURCE);
            SpaceNeeded += pNfsNetResource->LocalNameLength;
            SpaceNeeded += pNfsNetResource->RemoteNameLength;
            // comment
            SpaceNeeded += 5 * sizeof(WCHAR);
            // provider name
            SpaceNeeded += sizeof(NFS41_PROVIDER_NAME_U);
            if (SpaceNeeded > SpaceAvailable) {
                Status = WN_MORE_DATA;
                DbgP((L"NPEnumResource: "
                    "More Data Needed, SpaceNeeded=%d\n", SpaceNeeded));
                *lpBufferSize = SpaceNeeded;
                break;
            }
            else {
                SpaceAvailable -= SpaceNeeded;

                pNetResource->dwScope       = pNfsNetResource->dwScope;
                pNetResource->dwType        = pNfsNetResource->dwType;
                pNetResource->dwDisplayType = pNfsNetResource->dwDisplayType;
                pNetResource->dwUsage       = pNfsNetResource->dwUsage;

                // setup string area at opposite end of buffer
                SpaceNeeded -= sizeof(NETRESOURCE);
                StringZone = (PWCHAR)( (PBYTE) StringZone - SpaceNeeded);
                // copy local name
                (void)StringCchCopyW(StringZone,
                    pNfsNetResource->LocalNameLength,
                    pNfsNetResource->LocalName);
                pNetResource->lpLocalName = StringZone;
                StringZone += pNfsNetResource->LocalNameLength/sizeof(WCHAR);
                // copy remote name
                (void)StringCchCopyW(StringZone,
                    pNfsNetResource->RemoteNameLength,
                    pNfsNetResource->RemoteName);
                pNetResource->lpRemoteName = StringZone;
                StringZone += pNfsNetResource->RemoteNameLength/sizeof(WCHAR);
                // copy comment
                pNetResource->lpComment = StringZone;
                *StringZone++ = L'A';
                *StringZone++ = L'_';
                *StringZone++ = L'O';
                *StringZone++ = L'K';
                *StringZone++ = L'\0';
                // copy provider name
                pNetResource->lpProvider = StringZone;
                (void)StringCbCopyW(StringZone,
                    sizeof(NFS41_PROVIDER_NAME_U), NFS41_PROVIDER_NAME_U);
                StringZone += sizeof(NFS41_PROVIDER_NAME_U)/sizeof(WCHAR);
                EntriesCopied++;
                // set new bottom of string zone
                StringZone = (PWCHAR)((PBYTE)StringZone - SpaceNeeded);
                Status = WN_SUCCESS;
            }
            pNetResource++;
        }
    }

    CloseSharedMemory(&hMutex, &hMemory, (PVOID*)&pSharedMemory);
out:
    *lpcCount = EntriesCopied;
    *(PULONG) hEnum = Index;

    DbgP((L"<-- NPEnumResource returns: %d\n", (int)EntriesCopied));

    return Status;
}

DWORD APIENTRY
NPCloseEnum(
    HANDLE hEnum)
{
    DbgP((L"NPCloseEnum(handle=0x%x)\n", HANDLE2INT(hEnum)));
    HeapFree(GetProcessHeap(), 0, (PVOID)hEnum);
    return WN_SUCCESS;
}

DWORD APIENTRY
NPGetResourceParent(
    LPNETRESOURCEW  lpNetResource,
    LPVOID          lpBuffer,
    LPDWORD         lpBufferSize )
{
    DbgP((L"NPGetResourceParent: WN_NOT_SUPPORTED\n"));
    return WN_NOT_SUPPORTED;
}

DWORD APIENTRY
NPGetResourceInformation(
    __in LPNETRESOURCEW   lpNetResource,
    __out_bcount(*lpBufferSize) LPVOID  lpBuffer,
    __inout LPDWORD lpBufferSize,
    __deref_out LPWSTR *lplpSystem )
{
    DbgP((L"NPGetResourceInformation: WN_NOT_SUPPORTED\n"));
    return WN_NOT_SUPPORTED;
}

DWORD APIENTRY
NPGetUniversalName(
    LPCWSTR lpLocalPath,
    DWORD   dwInfoLevel,
    LPVOID  lpBuffer,
    LPDWORD lpBufferSize )
{
    DbgP((L"NPGetUniversalName(lpLocalPath='%s', dwInfoLevel=%d): "
        "WN_NOT_SUPPORTED\n",
        lpLocalPath, (int)dwInfoLevel));
    return WN_NOT_SUPPORTED;
}
