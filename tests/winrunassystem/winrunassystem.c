
/*
 * MIT License
 *
 * Copyright (c) 2025 Roland Mainz <roland.mainz@nrubsig.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * allcopies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/*
 * runassystem.c - run Win32 program as Windows user "SYSTEM"
 *
 * Written by Roland Mainz <roland.mainz@nrubsig.org>
 */

/*
 * Compile with:
 * $ clang -target x86_64-pc-windows-gnu -Wall -municode runassystem.c \
 *      -lWtsapi32 -o runassystem.exe
 */

#define WIN32_LEAN_AND_MEAN 1

#include <windows.h>
#include <strsafe.h>
#include <stdbool.h>
#include <stdio.h>
#include <wchar.h>
#include <WtsApi32.h>
#include <sddl.h>
#include <fcntl.h>

#define EXIT_USAGE (2) /* Traditional UNIX exit code for usage */

/* Global variables */
/*
 * |service_name_buffer| - only valid after calling
 * |SetupTemporaryServiceName()|
 */
static wchar_t service_name_buffer[512];
static const wchar_t* SERVICE_DISPLAY_NAME = L"runassystem temporary service";

static SERVICE_STATUS g_ServiceStatus = {0};
static SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
static HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

/*
 * Store argument array passed to |wmain()| because the argument
 * array for |ServiceMain()| does not have these arguments
 *
 * service_argv[0] == *.exe name
 * service_argv[1] == "--service"
 * service_argv[2] == <Service name>
 * service_argv[3] == <command-to-run>
 * service_argv[4..n] == <command-args>
 */
static int service_argc = 0;
static wchar_t **service_argv = NULL;


/* Local prototypes */
static void ReportError(const char* context);
static void LaunchInteractiveProcess(void);
static void WINAPI ServiceCtrlHandler(DWORD CtrlCode);
static void WINAPI ServiceMain(DWORD argc, LPWSTR* argv);

// #define DBG 1

#ifdef DBG
#define D(x) x
#define DbgP(_x_) RASDbgPrint _x_
#else
#define DbgP(_x_)
#define D(x)
#endif
#define TRACE_TAG   L"[RAS]"

#define PTR2PTRDIFF_T(p) (((char *)(p))-((char *)0))
#define HANDLE2INT(h) ((int)PTR2PTRDIFF_T(h))

#ifdef DBG
static
ULONG _cdecl RASDbgPrint(__in LPWSTR fmt, ...)
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
#endif /* DBG */

static
void ReportError(const char* context)
{
    (void)fprintf(stderr,
        "ERROR in %s: %d\n",
        context,
        (int)GetLastError());
}

static
int remove_fmt(const char *fmt, ...)
{
    int retval;
    char buffer[16384];

    va_list args;
    va_start(args, fmt);

    (void)vsnprintf(buffer, sizeof(buffer), fmt, args);
    retval = remove(buffer);

    va_end(args);

    return retval;
}

static
void LaunchInteractiveProcess(void)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD child_retval = 120;

    const wchar_t *service_name = service_argv[2];
    char namebuff[256];

    char buffer[16384];
    char *s = buffer;

    HANDLE hFile_stdout = INVALID_HANDLE_VALUE;
    HANDLE hFile_stderr = INVALID_HANDLE_VALUE;
    HANDLE hFile_status = INVALID_HANDLE_VALUE;

    SECURITY_ATTRIBUTES sa = { 0 };

    (void)memset(&si, 0, sizeof(si));
    (void)memset(&pi, 0, sizeof(pi));

    si.cb = sizeof(si);

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;

    (void)snprintf(namebuff, sizeof(namebuff),
        "C:\\Windows\\Temp\\%ls_stdout", service_name);
    hFile_stdout = CreateFileA(namebuff,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        &sa,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (hFile_stdout == INVALID_HANDLE_VALUE) {
        DbgP((L"LaunchInteractiveProcess: cannot open stdout, lasterr=%d\n",
            (int)GetLastError()));
        goto done;
    }
    (void)snprintf(namebuff, sizeof(namebuff),
        "C:\\Windows\\Temp\\%ls_stderr", service_name);
    hFile_stderr = CreateFileA(namebuff,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        &sa,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (hFile_stderr == INVALID_HANDLE_VALUE) {
        DbgP((L"LaunchInteractiveProcess: cannot open stderr, lasterr=%d\n",
            (int)GetLastError()));
        goto done;
    }
    (void)snprintf(namebuff, sizeof(namebuff),
        "C:\\Windows\\Temp\\%ls_status_not_ready", service_name);
    hFile_status = CreateFileA(namebuff,
        GENERIC_READ|GENERIC_WRITE,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        &sa,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (hFile_status == INVALID_HANDLE_VALUE) {
        DbgP((L"LaunchInteractiveProcess: "
            L"cannot open status file, lasterr=%d\n",
            (int)GetLastError()));
        goto done;
    }
    (void)SetHandleInformation(hFile_stdout, HANDLE_FLAG_INHERIT, TRUE);
    (void)SetHandleInformation(hFile_stderr, HANDLE_FLAG_INHERIT, TRUE);

    /* Command name + <space> separator */
    s += sprintf(s, "%ls ", service_argv[3]);

    int i;
    for (i=4 ; i < service_argc ; i++) {
        s += sprintf(s, " \"%ls\"", service_argv[i]);
    }

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = hFile_stdout;
    si.hStdError = hFile_stderr;

    if (!CreateProcessA(NULL,
        buffer,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &si,
        &pi)) {
        (void)printf("CreateProcess failed (%d).\n", (int)GetLastError());
        return;
    }

    (void)WaitForSingleObject(pi.hProcess, INFINITE);

    (void)GetExitCodeProcess(pi.hProcess, &child_retval);

done:
    (void)CloseHandle(pi.hProcess);
    (void)CloseHandle(pi.hThread);

    (void)CloseHandle(hFile_stdout);
    (void)CloseHandle(hFile_stderr);

    if (hFile_status != INVALID_HANDLE_VALUE) {
        char statusbuff[16];

        (void)sprintf(statusbuff, "%d", (int)child_retval);
        (void)WriteFile(hFile_status,
            statusbuff, strlen(statusbuff), NULL, NULL);
        (void)CloseHandle(hFile_status);

        /*
         * Atomically rename file, parent will wait until the file
         * is available
         */
        char oldnamebuff[256];
        char newnamebuff[256];
        (void)snprintf(oldnamebuff, sizeof(oldnamebuff),
            "C:\\Windows\\Temp\\%ls_status_not_ready", service_name);
        (void)snprintf(newnamebuff, sizeof(newnamebuff),
            "C:\\Windows\\Temp\\%ls_status", service_name);
        (void)rename(oldnamebuff, newnamebuff);
    }
}

static
void WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
    switch (CtrlCode) {
        case SERVICE_CONTROL_STOP:
            if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
                break;

            g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
            SetEvent(g_ServiceStopEvent);
            break;
        default:
            break;
    }
}

static
void WINAPI ServiceMain(DWORD argc, wchar_t *argv[])
{
    (void)argc; /* unused */
    (void)argv; /* unused */

    g_StatusHandle = RegisterServiceCtrlHandlerW(service_argv[2],
        ServiceCtrlHandler);
    if (!g_StatusHandle) {
        ReportError("RegisterServiceCtrlHandlerW");
        return;
    }

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        return;
    }

    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    LaunchInteractiveProcess();

    (void)WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    (void)CloseHandle(g_ServiceStopEvent);
}

static
void SetupTemporaryServiceName(void)
{
    FILETIME ft;
    SYSTEMTIME st;

    /*
     * Create service name for our temporary service
     *
     * Naming requirements:
     * - unique name
     * - includes the word "temporary" to give Admins a hint
     * what we are doing
     */
    GetSystemTimePreciseAsFileTime(&ft);
    (void)FileTimeToSystemTime(&ft, &st);
    ULONGLONG ullTime =
        (ULONGLONG)(ft.dwHighDateTime) << 32 | ft.dwLowDateTime;
    ULONGLONG nanoseconds = (ullTime % 10000000ULL) * 100ULL;

    /* "RunAsSYSTEM_temporary_service0001_<yyyy-dd-mm_hhmmss.ns>" */
    (void)swprintf(service_name_buffer, sizeof(service_name_buffer),
        L"RunAsSYSTEM_%stemporary_service001_%04d%02d%02d_%02d%02d%02d.%09llu",
        "", /* site-prefix */
        (int)st.wYear, (int)st.wMonth, (int)st.wDay,
        (int)st.wHour, (int)st.wMinute, (int)st.wSecond,
        (unsigned long long)nanoseconds);
}

static
bool InstallService(int argc, wchar_t *argv[])
{
    bool retval = false;
    wchar_t szPath[MAX_PATH+1];
    wchar_t szPathWithArg[16384];
    wchar_t *s;
    SC_HANDLE hSCManager;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        ReportError("OpenSCManager");
        return false;
    }

    /* Get our *.exe name */
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0) {
        ReportError("GetModuleFileNameW");
        retval = false;
        goto done;
    }

    /* Manually construct the path with the argument for the service */
    s = szPathWithArg;
    s += swprintf(s, 1024, L"\"%ls\" --service %ls",
        szPath, service_name_buffer);
    int i;
    for (i=1 ; i < argc ; i++) {
        /* FIXME: Quoting */
        s += swprintf(s, 1024, L" \"%ls\"", argv[i]);
    }

    /* Print arguments */
    D((void)wprintf(L"szPathWithArg='%ls'\n", szPathWithArg));

    /*
     * FIXME: We should implement -u and -g to define username and primary
     * group name
     */
    SC_HANDLE hService = CreateServiceW(hSCManager,
        service_name_buffer, SERVICE_DISPLAY_NAME, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        szPathWithArg, NULL, NULL, NULL, L"NT AUTHORITY\\SYSTEM", NULL);
    if (!hService) {
        ReportError("CreateServiceW");
        retval = false;
        goto done;
    }

    D((void)wprintf(L"Service '%ls' created successfully.\n",
        service_name_buffer));
    if (!StartServiceW(hService, 0, NULL)) {
        ReportError("StartServiceW");
        retval = false;
        goto done;
    }

    D((void)wprintf(L"Service '%ls' started successfully.\n",
        service_name_buffer));

    /* Wait until *_status file appears  */
    char namebuff[256];
    (void)snprintf(namebuff, sizeof(namebuff),
        "C:\\Windows\\Temp\\%ls_status",
        service_name_buffer);
    while (_access(namebuff, 00) != 0) {
        /*
         * FIXME: We should have a timeout, test for <CTRL-C>, and decrease
         * the threads priority while polling (to avoid starving the child
         * process)
         */
        Sleep(200);
    }

    (void)CloseServiceHandle(hService);

    /* Success! */
    retval = true;

done:
    (void)CloseServiceHandle(hSCManager);
    return retval;
}

static
void UninstallService(void)
{
    SC_HANDLE hSCManager;
    SERVICE_STATUS status;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        ReportError("UninstallService: OpenSCManager");
        return;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager,
        service_name_buffer, SERVICE_ALL_ACCESS);
    if (!hService) {
        ReportError("UninstallService: OpenServiceW");
        goto done;
    }

    (void)ControlService(hService, SERVICE_CONTROL_STOP, &status);
    D((void)wprintf(L"Service stopped.\n"));

    if (!DeleteService(hService)) {
        ReportError("UninstallService: DeleteService");
    } else {
        D((void)wprintf(L"UninstallService: Service deleted.\n"));
    }

    (void)CloseServiceHandle(hService);

done:
    (void)CloseServiceHandle(hSCManager);
}

static
bool readfilecontentsintobuffer(const wchar_t *filename,
    char *buffer,
    size_t buffersize,
    size_t *numreadbytes)
{
    HANDLE hFile;
    bool retval = false;
    DWORD readfile_numbytesread = 0UL;

    hFile = CreateFileW(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_TEMPORARY,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        D((void)wprintf(L"readfilecontentsintobuffer: "
            L"cannot open status file, lasterr=%d\n",
            (int)GetLastError()));
        return false;
    }

    retval = ReadFile(hFile, buffer, (DWORD)buffersize,
        &readfile_numbytesread, NULL)?true:false;
    *numreadbytes = readfile_numbytesread;

    if (hFile != INVALID_HANDLE_VALUE) {
        (void)CloseHandle(hFile);
    }

    return retval;
}

static
bool CopyFileToHANDLE(wchar_t *filename, HANDLE hDest)
{
    HANDLE hSrc = INVALID_HANDLE_VALUE;
    BYTE buffer[4096];
    DWORD dwBytesRead = 0;
    DWORD dwBytesWritten = 0;
    BOOL bSuccess = FALSE;
    bool retval = false;

    hSrc = CreateFileW(filename,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hSrc == INVALID_HANDLE_VALUE) {
        (void)fwprintf(stderr,
            L"Unable to open source file '%ls', lasterr=%d\n",
            filename, (int)GetLastError());
        return false;
    }

    while (ReadFile(hSrc, buffer, sizeof(buffer), &dwBytesRead, NULL) &&
        (dwBytesRead > 0)) {
        bSuccess = WriteFile(hDest,
            buffer,
            dwBytesRead,
            &dwBytesWritten,
            NULL);

        if (!bSuccess || (dwBytesRead != dwBytesWritten)) {
            (void)fwprintf(stderr,
                L"Failed to write to the destination file, lasterr=%d\n",
                (int)GetLastError());
            retval = false;
            goto done;
        }
    }

    retval = true;

done:
    (void)CloseHandle(hSrc);

    return retval;
}

static
int winrunassystem_main(int argc, wchar_t *argv[])
{
    int retval = EXIT_FAILURE;

    /*
     * If started with "--service", run as a service
     */
    if ((argc > 2) && (wcscmp(argv[1], L"--service") == 0)) {
        service_argc = argc;
        service_argv = argv;

        SERVICE_TABLE_ENTRYW ServiceTable[] = {
            { .lpServiceName = argv[2], .lpServiceProc = ServiceMain },
            { .lpServiceName = NULL,    .lpServiceProc = NULL }
        };

        if (!StartServiceCtrlDispatcherW(ServiceTable)) {
            ReportError("StartServiceCtrlDispatcherW");
            return 1;
        }
        return 0;
    }

    /* Otherwise, run as the client to manage the service */
    D((void)wprintf(L"Running as client to install and start the service...\n"));

    SetupTemporaryServiceName();

    /* Remove old status file */
    (void)remove_fmt("C:\\Windows\\Temp\\%ls_status", service_name_buffer);

    /* Install and Start */
    if (InstallService(argc, argv)) {
        wchar_t filenamebuff[MAX_PATH+1];

        /* Stop and Uninstall */
        UninstallService();

        /* Get child stdout+stderr */
        (void)swprintf(filenamebuff, sizeof(filenamebuff),
            L"C:\\Windows\\Temp\\%ls_stderr",
            service_name_buffer);
        (void)CopyFileToHANDLE(filenamebuff, GetStdHandle(STD_ERROR_HANDLE));
        (void)swprintf(filenamebuff, sizeof(filenamebuff),
            L"C:\\Windows\\Temp\\%ls_stdout",
            service_name_buffer);
        (void)CopyFileToHANDLE(filenamebuff, GetStdHandle(STD_OUTPUT_HANDLE));

        /* Read child return value */
        char statusvalue[256];
        size_t numbytesread = 0UL;
        (void)swprintf(filenamebuff, sizeof(filenamebuff),
            L"C:\\Windows\\Temp\\%ls_status",
            service_name_buffer);
        if (readfilecontentsintobuffer(filenamebuff,
            statusvalue, sizeof(statusvalue), &numbytesread)) {
            statusvalue[numbytesread] = '\0';
            retval = atoi(statusvalue);
        }
        else {
            (void)fwprintf(stderr,
                L"%ls: Cannot read child status from file '%ls'\n",
                argv[0], filenamebuff);
            retval = EXIT_FAILURE;
        }

        /* Delete temporary files */
        (void)remove_fmt("C:\\Windows\\Temp\\%ls_stdout", service_name_buffer);
        (void)remove_fmt("C:\\Windows\\Temp\\%ls_stderr", service_name_buffer);
        (void)remove_fmt("C:\\Windows\\Temp\\%ls_status", service_name_buffer);
    }

    return retval;
}

#ifdef BUILD_WINRUNASSYSTEM
static
void usage(const wchar_t *av0)
{
    (void)fwprintf(stderr,
        L"%ls: Run command as user SYSTEM\n",
        av0);
}

int wmain(int argc, wchar_t *argv[])
{
    if ((argc == 1) ||
        ((argc == 2) &&
            ((wcscmp(argv[1], L"--help") == 0) ||
            (wcscmp(argv[1], L"-h") == 0) ||
            (wcscmp(argv[1], L"/?") == 0)))) {
        usage(argv[0]);
        return EXIT_USAGE;
    }

    return winrunassystem_main(argc, argv);
}
#elif BUILD_NFS_GLOBALMOUNT

/*
 * Implement /sbin/nfs_globalmount.exe as EXE instead of a script,
 * so it can be easily called from cmd.exe, powershell.exe, and
 * be whitelisted in MS Defender
 */

/* Paths to nfs_mount*.exe */
#ifdef _WIN64
#define NFS_MOUNT_PATH L"C:\\cygwin64\\sbin\\nfs_mount.exe"
#define NFS_MOUNT_PATH_X86 L"C:\\cygwin64\\sbin\\nfs_mount.i686.exe"
#define NFS_MOUNT_PATH_AMD64 L"C:\\cygwin64\\sbin\\nfs_mount.x86_64.exe"
#else
#define NFS_MOUNT_PATH L"C:\\cygwin\\sbin\\nfs_mount.exe"
#define NFS_MOUNT_PATH_X86 L"C:\\cygwin\\sbin\\nfs_mount.i686.exe"
#define NFS_MOUNT_PATH_AMD64 L"C:\\cygwin\\sbin\\nfs_mount.x86_64.exe"
#endif /* _WIN64 */
/* FIXME: What about ARM64 ? */

int wmain(int argc, wchar_t *argv[])
{
    int i;
    const wchar_t *nfs_mount_path;

    /*
     * Select nfs_mount.exe binary based on our argv[0] name, e.g.
     * "nfs_globalmount.i686.exe" ---> "/sbin/nfs_mount.i686.exe",
     * "nfs_globalmount.x86_64.exe" ---> "/sbin/nfs_mount.x86_64.exe",
     * etc
     *
     * FIXME: What about ARM64 ?
     */
    if (wcsstr(argv[0], L".i686") != NULL) {
        nfs_mount_path = NFS_MOUNT_PATH_X86;
    }
    else if (wcsstr(argv[0], L".x86_64") != NULL) {
        nfs_mount_path = NFS_MOUNT_PATH_AMD64;
    }
    else {
        nfs_mount_path = NFS_MOUNT_PATH;
    }

    if ((argc > 2) && (wcscmp(argv[1], L"--service") == 0)) {
        return winrunassystem_main(argc, argv);
    }
    else {
        wchar_t **new_argv = (wchar_t **)alloca(sizeof(wchar_t *)*(argc+3));
        new_argv[0] = argv[0];
        new_argv[1] = (wchar_t *)nfs_mount_path;
        for (i=1 ; i < argc ; i++)
            new_argv[i+1] = argv[i];
        return winrunassystem_main(argc+1, new_argv);
    }
}
#else
#error Unknown target, BUILD_WINRUNASSYSTEM+BUILD_NFS_GLOBALMOUNT not set
#endif
