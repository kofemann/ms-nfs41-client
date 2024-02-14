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
#define TRACE_TAG   L"[NFS41_NP] "
#define WNNC_DRIVER(major, minor) ((major * 0x00010000) + (minor))


ULONG _cdecl NFS41DbgPrint(__in LPTSTR fmt, ...)
{
    ULONG rc = 0;
#define SZBUFFER_SIZE 1024
    wchar_t szbuffer[SZBUFFER_SIZE+1];
    wchar_t *szbp = szbuffer;

    va_list marker;
    va_start(marker, fmt);

#pragma warning( push )
    /*
     * Disable "'wcscpy': This function or variable may be unsafe",
     * in this context it is safe to use
     */
#pragma warning (disable : 4996)
    (void)wcscpy(szbp, TRACE_TAG);
#pragma warning( pop )
    szbp += wcslen(szbp);

    StringCchVPrintfW(szbp, SZBUFFER_SIZE-(szbp - szbuffer), fmt, marker);
    szbuffer[SZBUFFER_SIZE-1] = L'\0';

    OutputDebugString(szbuffer);

    va_end(marker);

    return rc;
}

int filter(unsigned int code)
{
    DbgP((L"####Got exception %u\n", code));
    return EXCEPTION_CONTINUE_SEARCH;
}

DWORD
OpenSharedMemory(
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

    *phMutex = CreateMutex(NULL, FALSE, TEXT(NFS41NP_MUTEX_NAME));
    if (*phMutex == NULL)
    {
        dwStatus = GetLastError();
        DbgP((TEXT("OpenSharedMemory:  OpenMutex failed\n")));
        goto OpenSharedMemoryAbort1;
    }

    WaitForSingleObject(*phMutex, INFINITE);

    *phMemory = OpenFileMapping(FILE_MAP_WRITE,
                                FALSE,
                                TEXT(NFS41_USER_SHARED_MEMORY_NAME));
    if (*phMemory == NULL)
    {
        dwStatus = GetLastError();
        DbgP((TEXT("OpenSharedMemory:  OpenFileMapping failed\n")));
        goto OpenSharedMemoryAbort2;
    }

    *pMemory = MapViewOfFile(*phMemory, FILE_MAP_WRITE, 0, 0, 0);
    if (*pMemory == NULL)
    {
        dwStatus = GetLastError();
        DbgP((TEXT("OpenSharedMemory:  MapViewOfFile failed\n")));
        goto OpenSharedMemoryAbort3;
    }

    return ERROR_SUCCESS;

OpenSharedMemoryAbort3:
    CloseHandle(*phMemory);

OpenSharedMemoryAbort2:
    ReleaseMutex(*phMutex);
    CloseHandle(*phMutex);
    *phMutex = NULL;

OpenSharedMemoryAbort1:
    DbgP((TEXT("OpenSharedMemory: return dwStatus: %d\n"), dwStatus));

    return dwStatus;
}

VOID
CloseSharedMemory(
    PHANDLE hMutex,
    PHANDLE hMemory,
    PVOID   *pMemory)
/*++

Routine Description:

    This routine relinquishes control of the shared memory after exclusive
    manipulation

Arguments:

    hMutex - the mutex handle

    hMemory  - the memory handle

    pMemory - a ptr. to the shared memory which is set if successful

Return Value:

--*/
{
    if (*pMemory)
    {
        UnmapViewOfFile(*pMemory);
        *pMemory = NULL;
    }
    if (*hMemory)
    {
        CloseHandle(*hMemory);
        *hMemory = 0;
    }
    if (*hMutex)
    {
        if (ReleaseMutex(*hMutex) == FALSE)
        {
            DbgP((TEXT("CloseSharedMemory: ReleaseMutex error: %d\n"), GetLastError()));
        }
        CloseHandle(*hMutex);
        *hMutex = 0;
    }
}

static DWORD StoreConnectionInfo(
    IN LPCWSTR LocalName,
    IN LPCWSTR ConnectionName,
    IN USHORT ConnectionNameLength,
    IN LPNETRESOURCE lpNetResource)
{
    DWORD status;
    HANDLE hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY pSharedMemory;
    PNFS41NP_NETRESOURCE pNfs41NetResource;
    INT Index;
    BOOLEAN FreeEntryFound = FALSE;

    DbgP((L"--> StoreConnectionInfo\n"));

    status = OpenSharedMemory(&hMutex, &hMemory, &(PVOID)pSharedMemory);
    if (status)
        goto out;

    DbgP((L"StoreConnectionInfo: NextIndex %d, NumResources %d\n",
        pSharedMemory->NextAvailableIndex,
        pSharedMemory->NumberOfResourcesInUse));

    for (Index = 0; Index < pSharedMemory->NextAvailableIndex; Index++)
    {
        if (!pSharedMemory->NetResources[Index].InUse)
        {
            FreeEntryFound = TRUE;
            DbgP((TEXT("Reusing existing index %d\n"), Index));
            break;
        }
    }

    if (!FreeEntryFound)
    {
        if (pSharedMemory->NextAvailableIndex >= NFS41NP_MAX_DEVICES) {
            status = WN_NO_MORE_DEVICES;
            goto out_close;
        }
        Index = pSharedMemory->NextAvailableIndex++;
        DbgP((TEXT("Using new index %d\n"), Index));
    }

    pSharedMemory->NumberOfResourcesInUse += 1;

    pNfs41NetResource = &pSharedMemory->NetResources[Index];

    pNfs41NetResource->InUse                = TRUE;
    pNfs41NetResource->dwScope              = lpNetResource->dwScope;
    pNfs41NetResource->dwType               = lpNetResource->dwType;
    pNfs41NetResource->dwDisplayType        = lpNetResource->dwDisplayType;
    pNfs41NetResource->dwUsage              = RESOURCEUSAGE_CONNECTABLE;
    pNfs41NetResource->LocalNameLength      = (USHORT)(wcslen(LocalName) + 1) * sizeof(WCHAR);
    pNfs41NetResource->RemoteNameLength     = (USHORT)(wcslen(lpNetResource->lpRemoteName) + 1) * sizeof(WCHAR);
    pNfs41NetResource->ConnectionNameLength = ConnectionNameLength;

    StringCchCopy(pNfs41NetResource->LocalName,
        pNfs41NetResource->LocalNameLength,
        LocalName);
    StringCchCopy(pNfs41NetResource->RemoteName,
        pNfs41NetResource->RemoteNameLength,
        lpNetResource->lpRemoteName);
    StringCchCopy(pNfs41NetResource->ConnectionName,
        pNfs41NetResource->ConnectionNameLength,
        ConnectionName);

    // TODO: copy mount options -cbodley

out_close:
    CloseSharedMemory(&hMutex, &hMemory, &(PVOID)pSharedMemory);
out:
    DbgP((TEXT("<-- StoreConnectionInfo returns %d\n"), (int)status));

    return status;
}

ULONG
SendTo_NFS41Driver(
    IN ULONG            IoctlCode,
    IN PVOID            InputDataBuf,
    IN ULONG            InputDataLen,
    IN PVOID            OutputDataBuf,
    IN PULONG           pOutputDataLen)
{
    HANDLE  DeviceHandle;       // The mini rdr device handle
    BOOL    rc = FALSE;
    ULONG   Status;

    DbgP((TEXT("--> SendTo_NFS41Driver\n")));

    Status = WN_SUCCESS;
    DbgP((L"calling CreateFile\n"));
    DeviceHandle = CreateFile(
        NFS41_USER_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        (LPSECURITY_ATTRIBUTES)NULL,
        OPEN_EXISTING,
        0,
        (HANDLE) NULL );

    DbgP((L"after CreateFile Device Handle\n"));
    if ( INVALID_HANDLE_VALUE != DeviceHandle )
    {
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
            NULL );
        } __except(filter(GetExceptionCode())) {
            DbgP((L"#### In except\n"));
        }
        DbgP((L"returned from DeviceIoControl %08lx\n", rc));
            if ( !rc )
            {
                DbgP((L"SendTo_NFS41Driver: returning error from DeviceIoctl\n"));
                Status = GetLastError( );
            }
            else
            {
                DbgP((L"SendTo_NFS41Driver: The DeviceIoctl call succeded\n"));
            }
            CloseHandle(DeviceHandle);
    }
    else
    {
        Status = GetLastError( );
        DbgP((L"SendTo_NFS41Driver: error %08lx opening device \n", Status));
    }
    DbgP((TEXT("<-- SendTo_NFS41Driver returns %d\n"), Status));
    return Status;
}

DWORD APIENTRY
NPGetCaps(
    DWORD nIndex )
{
   DWORD rc = 0;

    DbgP(( L"GetNetCaps %d\n", nIndex ));
    switch ( nIndex )
    {
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
        default:
            rc = 0;
            break;
    }

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
    DbgP(( L"NPLogonNotify: returning WN_SUCCESS\n" ));
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
    DbgP(( L"NPPasswordChangeNotify: WN_NOT_SUPPORTED\n" ));
    SetLastError( WN_NOT_SUPPORTED );
    return WN_NOT_SUPPORTED;
}

DWORD APIENTRY
NPAddConnection(
    __in LPNETRESOURCE   lpNetResource,
    __in_opt LPWSTR      lpPassword,
    __in_opt LPWSTR      lpUserName )
{
    return NPAddConnection3( NULL, lpNetResource, lpPassword, lpUserName, 0 );
}

DWORD APIENTRY
NPAddConnection3(
    __in HWND           hwndOwner,
    __in LPNETRESOURCE  lpNetResource,
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

    DbgP((L"-->  NPAddConnection3(lpNetResource->lpLocalName='%s', "
        L"lpNetResource->lpRemoteName='%s', "
        L"username='%s', passwd='%s')\n",
        lpNetResource->lpLocalName, lpNetResource->lpRemoteName, lpUserName, lpPassword));

    Status = InitializeConnectionInfo(&Connection,
        (PMOUNT_OPTION_BUFFER)lpNetResource->lpComment,
        &ConnectionName);
    if (Status)  {
        DbgP((L"InitializeConnectionInfo failed with %d\n", Status));
        goto out;
    }

    //  \device\miniredirector\;<DriveLetter>:\Server\Share

    // local name, must start with "X:"
    if (lstrlen(lpNetResource->lpLocalName) < 2 ||
        lpNetResource->lpLocalName[1] != L':') {
        DbgP((L"lpNetResource->lpLocalName(='%s') is not a device letter\n",
            lpNetResource->lpLocalName));
        Status = WN_BAD_LOCALNAME;
        goto out;
    }

    LocalName[0] = (WCHAR) toupper(lpNetResource->lpLocalName[0]);
    LocalName[1] = L':';
    LocalName[2] = L'\0';
    StringCchCopyW( ConnectionName, NFS41_SYS_MAX_PATH_LEN, NFS41_DEVICE_NAME );
    StringCchCatW( ConnectionName, NFS41_SYS_MAX_PATH_LEN, L"\\;" );
    StringCchCatW( ConnectionName, NFS41_SYS_MAX_PATH_LEN, LocalName );

    // remote name, must start with "\\"
    if (lpNetResource->lpRemoteName[0] == L'\0' ||
        lpNetResource->lpRemoteName[0] != L'\\' ||
        lpNetResource->lpRemoteName[1] != L'\\') {
        Status = WN_BAD_NETNAME;
        goto out;
    }

    /* note: remotename comes as \\server but we need to add \server thus +1 pointer */
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

    StringCchCatW( ConnectionName, NFS41_SYS_MAX_PATH_LEN, ServerName);
#ifndef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
    /* insert the "nfs4" in between the server name and the path,
     * just to make sure all calls to our driver come thru this */
    StringCchCatW( ConnectionName, NFS41_SYS_MAX_PATH_LEN, L"\\nfs4" );
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
#endif

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
    if (wcsncmp(&p[i], L"\\nfs4", 5) != 0) {
        DbgP(( L"Connection name '%s' not prefixed with '\\nfs41'\n", &p[i]));
        Status = WN_BAD_NETNAME;
        goto out;
    }
#endif /* NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX */

    StringCchCatW( ConnectionName, NFS41_SYS_MAX_PATH_LEN, &p[i]);
    DbgP(( L"Full Connect Name: '%s'\n", ConnectionName ));
    DbgP(( L"Full Connect Name Length: %d %d\n",
        (wcslen(ConnectionName) + 1) * sizeof(WCHAR),
        (lstrlen(ConnectionName) + 1) * sizeof(WCHAR)));

    wszScratch[0] = L'\0';
    Status = QueryDosDevice(LocalName, wszScratch, 1024);
    DbgP((L"QueryDosDevice(lpDeviceName='%s',lpTargetPath='%s') "
        L"returned %d/GetLastError()=%d\n",
        LocalName, wszScratch, Status, (int)GetLastError()));

    if (Status || (GetLastError() != ERROR_FILE_NOT_FOUND)) {
        Status = WN_ALREADY_CONNECTED;
        goto out;
    }

    MarshalConnectionInfo(&Connection);

    Status = SendTo_NFS41Driver( IOCTL_NFS41_ADDCONN,
        Connection.Buffer, Connection.BufferSize,
        NULL, &CopyBytes );
    DbgP(( L"SendTo_NFS41Driver() returned %d\n", Status));
    if (Status) {
        goto out;
    }

    DbgP((L"DefineDosDevice(lpNetResource->lpLocalName='%s',ConnectionName='%s')\n", lpNetResource->lpLocalName, ConnectionName));
    if ( !DefineDosDevice( DDD_RAW_TARGET_PATH |
                           DDD_NO_BROADCAST_SYSTEM,
                           lpNetResource->lpLocalName,
                           ConnectionName ) ) {
        Status = GetLastError();
        DbgP(( L"DefineDosDevice(lpNetResource->lpLocalName='%s',"
            L"ConnectionName='%s') failed with %d\n",
            lpNetResource->lpLocalName, ConnectionName, Status));
        goto out_delconn;
    }

    // The connection was established and the local device mapping
    // added. Include this in the list of mapped devices.
    Status = StoreConnectionInfo(LocalName, ConnectionName,
        Connection.Buffer->NameLength, lpNetResource);
    if (Status) {
        DbgP(( L"StoreConnectionInfo failed with %d\n", Status));
        goto out_undefine;
    }

out:
    FreeConnectionInfo(&Connection);
    DbgP((TEXT("<-- NPAddConnection3 returns %d\n"), (int)Status));
    return Status;
out_undefine:
    DefineDosDevice(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH |
        DDD_EXACT_MATCH_ON_REMOVE, LocalName, ConnectionName);
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

    DbgP((TEXT("--> NPCancelConnection(lpName='%s', fForce=%d)\n"),
        lpName, (int)fForce));

    Status = OpenSharedMemory( &hMutex,
                               &hMemory,
                               (PVOID)&pSharedMemory);

    if (Status == WN_SUCCESS)
    {
        INT  Index;
        PNFS41NP_NETRESOURCE pNetResource;
        Status = WN_NOT_CONNECTED;

        DbgP((TEXT("NPCancelConnection: NextIndex %d, NumResources %d\n"),
                    pSharedMemory->NextAvailableIndex,
                    pSharedMemory->NumberOfResourcesInUse));

        for (Index = 0; Index < pSharedMemory->NextAvailableIndex; Index++)
        {
            pNetResource = &pSharedMemory->NetResources[Index];

            if (pNetResource->InUse)
            {
                if ( ( (wcslen(lpName) + 1) * sizeof(WCHAR) ==
                        pNetResource->LocalNameLength)
                        && ( !wcscmp(lpName, pNetResource->LocalName) ))
                {
                    ULONG CopyBytes;

                    DbgP((TEXT("NPCancelConnection: Connection Found:\n")));

                    CopyBytes = 0;

                    Status = SendTo_NFS41Driver( IOCTL_NFS41_DELCONN,
                                pNetResource->ConnectionName,
                                pNetResource->ConnectionNameLength,
                                NULL,
                                &CopyBytes );

                    if (Status != WN_SUCCESS)
                    {
                        DbgP((TEXT("NPCancelConnection: SendToMiniRdr returned Status %lx\n"),Status));
                        break;
                    }

                    if (DefineDosDevice(DDD_REMOVE_DEFINITION | DDD_RAW_TARGET_PATH | DDD_EXACT_MATCH_ON_REMOVE,
                            lpName,
                            pNetResource->ConnectionName) == FALSE)
                    {
                        DbgP((TEXT("RemoveDosDevice:  DefineDosDevice error: %d\n"), GetLastError()));
                        Status = GetLastError();
                    }
                    else
                    {
                        pNetResource->InUse = FALSE;
                        pSharedMemory->NumberOfResourcesInUse--;

                        if (Index+1 == pSharedMemory->NextAvailableIndex)
                            pSharedMemory->NextAvailableIndex--;
                    }
                    break;
                }

                DbgP((TEXT("NPCancelConnection: Name '%s' EntryName '%s'\n"),
                            lpName,pNetResource->LocalName));
                DbgP((TEXT("NPCancelConnection: Name Length %d Entry Name Length %d\n"),
                           pNetResource->LocalNameLength,pNetResource->LocalName));

            }
        }

        CloseSharedMemory( &hMutex,
                           &hMemory,
                          (PVOID)&pSharedMemory);
    }

    DbgP((TEXT("<-- NPCancelConnection returns %d\n"), (int)Status));
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

    DbgP((TEXT("--> NPGetConnection(lpLocalName='%s')\n"), lpLocalName));

    Status = OpenSharedMemory( &hMutex,
                               &hMemory,
                               (PVOID)&pSharedMemory);

    if (Status == WN_SUCCESS)
    {
        INT  Index;
        PNFS41NP_NETRESOURCE pNetResource;
        Status = WN_NOT_CONNECTED;

        for (Index = 0; Index < pSharedMemory->NextAvailableIndex; Index++)
        {
            pNetResource = &pSharedMemory->NetResources[Index];

            if (pNetResource->InUse)
            {
                if ( ( (wcslen(lpLocalName) + 1) * sizeof(WCHAR) ==
                        pNetResource->LocalNameLength)
                        && ( !wcscmp(lpLocalName, pNetResource->LocalName) ))
                {
                    if (*lpBufferSize < pNetResource->RemoteNameLength)
                    {
                        *lpBufferSize = pNetResource->RemoteNameLength;
                        Status = WN_MORE_DATA;
                    }
                    else
                    {
                        *lpBufferSize = pNetResource->RemoteNameLength;
                        CopyMemory( lpRemoteName,
                                    pNetResource->RemoteName,
                                    pNetResource->RemoteNameLength);
                        Status = WN_SUCCESS;
                    }
                    break;
                }
            }
        }

        CloseSharedMemory( &hMutex, &hMemory, (PVOID)&pSharedMemory);
    }

    DbgP((TEXT("<-- NPGetConnection returns %d\n"), (int)Status));

    return Status;
}

DWORD APIENTRY
NPOpenEnum(
    DWORD          dwScope,
    DWORD          dwType,
    DWORD          dwUsage,
    LPNETRESOURCE  lpNetResource,
    LPHANDLE       lphEnum )
{
    DWORD   Status;

    DbgP((L" --> NPOpenEnum(dwScope=%d, dwType=%d, dwUsage=%d)\n",
        (int)dwScope, (int)dwType, (int)dwUsage));

    *lphEnum = NULL;

    switch ( dwScope )
    {
        case RESOURCE_CONNECTED:
        {
            *lphEnum = HeapAlloc( GetProcessHeap( ), HEAP_ZERO_MEMORY, sizeof( ULONG ) );

            if (*lphEnum )
            {
                Status = WN_SUCCESS;
            }
            else
            {
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


    DbgP((L"<-- NPOpenEnum returns %d\n", (int)Status));

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
    LPNETRESOURCE   pNetResource;
    ULONG           SpaceNeeded = 0;
    ULONG           SpaceAvailable;
    PWCHAR          StringZone;
    HANDLE  hMutex, hMemory;
    PNFS41NP_SHARED_MEMORY  pSharedMemory;
    PNFS41NP_NETRESOURCE pNfsNetResource;
    INT  Index = *(PULONG)hEnum;

    DbgP((L"--> NPEnumResource(*lpcCount=%d)\n", (int)*lpcCount));

    pNetResource = (LPNETRESOURCE) lpBuffer;
    SpaceAvailable = *lpBufferSize;
    EntriesCopied = 0;
    StringZone = (PWCHAR) ((PBYTE)lpBuffer + *lpBufferSize);

    Status = OpenSharedMemory( &hMutex,
                               &hMemory,
                               (PVOID)&pSharedMemory);

    if ( Status == WN_SUCCESS)
    {
        Status = WN_NO_MORE_ENTRIES;
        for (Index = *(PULONG)hEnum; EntriesCopied < *lpcCount &&
                Index < pSharedMemory->NextAvailableIndex; Index++)
        {
            pNfsNetResource = &pSharedMemory->NetResources[Index];

            if (pNfsNetResource->InUse)
            {
                SpaceNeeded  = sizeof( NETRESOURCE );
                SpaceNeeded += pNfsNetResource->LocalNameLength;
                SpaceNeeded += pNfsNetResource->RemoteNameLength;
                SpaceNeeded += 5 * sizeof(WCHAR);               // comment
                SpaceNeeded += sizeof(NFS41_PROVIDER_NAME_U);  // provider name
                if ( SpaceNeeded > SpaceAvailable )
                {
                    Status = WN_MORE_DATA;
                    DbgP((L"NPEnumResource More Data Needed - %d\n", SpaceNeeded));
                    *lpBufferSize = SpaceNeeded;
                    break;
                }
                else
                {
                    SpaceAvailable -= SpaceNeeded;

                    pNetResource->dwScope       = pNfsNetResource->dwScope;
                    pNetResource->dwType        = pNfsNetResource->dwType;
                    pNetResource->dwDisplayType = pNfsNetResource->dwDisplayType;
                    pNetResource->dwUsage       = pNfsNetResource->dwUsage;

                    // setup string area at opposite end of buffer
                    SpaceNeeded -= sizeof( NETRESOURCE );
                    StringZone = (PWCHAR)( (PBYTE) StringZone - SpaceNeeded );
                    // copy local name
                    StringCchCopy( StringZone,
                        pNfsNetResource->LocalNameLength,
                        pNfsNetResource->LocalName );
                    pNetResource->lpLocalName = StringZone;
                    StringZone += pNfsNetResource->LocalNameLength/sizeof(WCHAR);
                    // copy remote name
                    StringCchCopy( StringZone,
                        pNfsNetResource->RemoteNameLength,
                        pNfsNetResource->RemoteName );
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
                    StringCbCopyW( StringZone, sizeof(NFS41_PROVIDER_NAME_U), NFS41_PROVIDER_NAME_U );
                    StringZone += sizeof(NFS41_PROVIDER_NAME_U)/sizeof(WCHAR);
                    EntriesCopied++;
                    // set new bottom of string zone
                    StringZone = (PWCHAR)( (PBYTE) StringZone - SpaceNeeded );
                    Status = WN_SUCCESS;
                }
                pNetResource++;
            }
        }
        CloseSharedMemory( &hMutex, &hMemory, (PVOID*)&pSharedMemory);
    }

    *lpcCount = EntriesCopied;
    *(PULONG) hEnum = Index;

    DbgP((L"<-- NPEnumResource returns: %d\n", (int)EntriesCopied));

    return Status;
}

DWORD APIENTRY
NPCloseEnum(
    HANDLE hEnum )
{
    DbgP((L"NPCloseEnum\n"));
    HeapFree( GetProcessHeap( ), 0, (PVOID) hEnum );
    return WN_SUCCESS;
}

DWORD APIENTRY
NPGetResourceParent(
    LPNETRESOURCE   lpNetResource,
    LPVOID  lpBuffer,
    LPDWORD lpBufferSize )
{
    DbgP(( L"NPGetResourceParent: WN_NOT_SUPPORTED\n" ));
    return WN_NOT_SUPPORTED;
}

DWORD APIENTRY
NPGetResourceInformation(
    __in LPNETRESOURCE   lpNetResource,
    __out_bcount(*lpBufferSize) LPVOID  lpBuffer,
    __inout LPDWORD lpBufferSize,
    __deref_out LPWSTR *lplpSystem )
{
    DbgP(( L"NPGetResourceInformation: WN_NOT_SUPPORTED\n" ));
    return WN_NOT_SUPPORTED;
}

DWORD APIENTRY
NPGetUniversalName(
    LPCWSTR lpLocalPath,
    DWORD   dwInfoLevel,
    LPVOID  lpBuffer,
    LPDWORD lpBufferSize )
{
    DbgP(( L"NPGetUniversalName(lpLocalPath='%s', dwInfoLevel=%d): WN_NOT_SUPPORTED\n",
        lpLocalPath, (int)dwInfoLevel));
    return WN_NOT_SUPPORTED;
}
