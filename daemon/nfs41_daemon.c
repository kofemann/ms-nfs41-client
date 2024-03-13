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

#include <Windows.h>
#include <process.h>
#include <tchar.h>
#include <stdio.h>

#include <devioctl.h>
#include <lmcons.h> /* UNLEN for GetUserName() */
#include <iphlpapi.h> /* for GetNetworkParam() */
#include "nfs41_build_features.h"
#include "nfs41_driver.h" /* for NFS41_USER_DEVICE_NAME_A */
#include "nfs41_np.h" /* for NFS41NP_SHARED_MEMORY */

#include "nfs41_daemon.h"
#include "daemon_debug.h"
#include "upcall.h"
#include "sid.h"
#include "util.h"

/* nfs41_dg.num_worker_threads sets the actual number of worker threads */
#define MAX_NUM_THREADS 1024
#define DEFAULT_NUM_THREADS 32
DWORD NFS41D_VERSION = 0;

static const char FILE_NETCONFIG[] = "C:\\etc\\netconfig";

/* Globals */
nfs41_daemon_globals nfs41_dg = {
    .default_uid = NFS_USER_NOBODY_UID,
    .default_gid = NFS_GROUP_NOGROUP_GID,
    .num_worker_threads = DEFAULT_NUM_THREADS,
    .crtdbgmem_flags = NFS41D_GLOBALS_CRTDBGMEM_FLAGS_NOT_SET,
};


#ifndef STANDALONE_NFSD //make sure to define it in "sources" not here
#include "service.h"
HANDLE  stop_event = NULL;
#endif
typedef struct _nfs41_process_thread {
    HANDLE handle;
    uint32_t tid;
} nfs41_process_thread;

static int map_current_user_to_ids(nfs41_idmapper *idmapper, uid_t *uid, gid_t *gid)
{
    char username[UNLEN + 1];
    DWORD len = UNLEN + 1;
    int status = NO_ERROR;

    if (!GetUserNameA(username, &len)) {
        status = GetLastError();
        eprintf("map_current_user_to_ids: GetUserName() failed with %d\n", status);
        goto out;
    }
    DPRINTF(1, ("map_current_user_to_ids: mapping user '%s'\n", username));

    if (nfs41_idmap_name_to_ids(idmapper, username, uid, gid)) {
        /* instead of failing for auth_sys, fall back to 'nobody' uid/gid */
        *uid = nfs41_dg.default_uid;
        *gid = nfs41_dg.default_gid;
    }
out:
    return status;
}

static unsigned int nfsd_worker_thread_main(void *args)
{
    nfs41_daemon_globals *nfs41dg = (nfs41_daemon_globals *)args;
    DWORD status = 0;
    HANDLE pipe;
    // buffer used to process upcall, assumed to be fixed size.
    // if we ever need to handle non-cached IO, need to make it dynamic
    unsigned char outbuf[UPCALL_BUF_SIZE], inbuf[UPCALL_BUF_SIZE]; 
    DWORD inbuf_len = UPCALL_BUF_SIZE, outbuf_len;
    nfs41_upcall upcall;

    pipe = CreateFileA(NFS41_USER_DEVICE_NAME_A, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        eprintf("Unable to open upcall pipe %d\n", GetLastError());
        return GetLastError();
    }

    while(1) {
        status = DeviceIoControl(pipe, IOCTL_NFS41_READ, NULL, 0,
            outbuf, UPCALL_BUF_SIZE, (LPDWORD)&outbuf_len, NULL);
        if (!status) {
            eprintf("IOCTL_NFS41_READ failed %d\n", GetLastError());
            continue;
        }

        status = upcall_parse(outbuf, (uint32_t)outbuf_len, &upcall);
        if (status) {
            upcall.status = status;
            goto write_downcall;
        }

        /*
         * Map current username to uid/gid
         * Each thread can handle a different user
         */
        status = map_current_user_to_ids(nfs41dg->idmapper,
            &upcall.uid, &upcall.gid);
        if (status) {
            upcall.status = status;
            goto write_downcall;
        }

        if (upcall.opcode == NFS41_SHUTDOWN) {
            printf("Shutting down..\n");
            exit(0);
        }

        status = upcall_handle(&nfs41_dg, &upcall);

write_downcall:
        DPRINTF(1, ("writing downcall: xid=%lld opcode='%s' status=%d "
            "get_last_error=%d\n", upcall.xid, opcode2string(upcall.opcode),
            upcall.status, upcall.last_error));

        upcall_marshall(&upcall, inbuf, (uint32_t)inbuf_len, (uint32_t*)&outbuf_len);

        DPRINTF(2, ("making a downcall: outbuf_len %ld\n\n", outbuf_len));
        status = DeviceIoControl(pipe, IOCTL_NFS41_WRITE,
            inbuf, inbuf_len, NULL, 0, (LPDWORD)&outbuf_len, NULL);
        if (!status) {
            eprintf("IOCTL_NFS41_WRITE failed with %d xid=%lld opcode='%s'\n",
                GetLastError(), upcall.xid, opcode2string(upcall.opcode));
            upcall_cancel(&upcall);
        }
        if (upcall.status != NFSD_VERSION_MISMATCH)
            upcall_cleanup(&upcall);
    }
    CloseHandle(pipe);

    return GetLastError();
}

static unsigned int WINAPI nfsd_thread_main(void *args)
{
    unsigned int res = 120 /* fixme: semi-random value */;

    __try {
        res = nfsd_worker_thread_main(args);
    }
    __except(EXCEPTION_EXECUTE_HANDLER ) {
        eprintf("#### FATAL: Worker thread crashed with exception ####\n");
    }

    return res;
}


#ifndef STANDALONE_NFSD
VOID ServiceStop()
{
   if (stop_event)
      SetEvent(stop_event);
}
#endif

typedef struct _nfsd_args {
    bool_t ldap_enable;
    int debug_level;
} nfsd_args;

static bool_t check_for_files()
{
    FILE *fd;
     
    fd = fopen(FILE_NETCONFIG, "r");
    if (fd == NULL) {
        fprintf(stderr,"nfsd() failed to open file '%s'\n", FILE_NETCONFIG);
        return FALSE;
    }
    fclose(fd);
    return TRUE;
}

static void PrintUsage()
{
    (void)fprintf(stderr, "Usage: nfsd.exe -d <debug_level> "
        "--noldap "
        "--uid <non-zero value> "
        "--gid <non-zero value> "
        "--numworkerthreads <value-between 16 and %d> "
#ifdef _DEBUG
        "--crtdbgmem <'allocmem'|'leakcheck'|'delayfree', "
            "'all', 'none' or 'default'> "
#endif /* _DEBUG */
        "\n", MAX_NUM_THREADS);
}
static bool_t parse_cmdlineargs(int argc, TCHAR *argv[], nfsd_args *out)
{
    int i;

    /* set defaults. */
    out->debug_level = 1;
    out->ldap_enable = TRUE;

    /* parse command line */
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == TEXT('-')) {
            if (_tcscmp(argv[i], TEXT("-h")) == 0) { /* help */
                PrintUsage();
                return FALSE;
            }
            else if (_tcscmp(argv[i], TEXT("-d")) == 0) { /* debug level */
                ++i;
                if (i >= argc) {
                    fprintf(stderr, "Missing debug level value\n");
                    PrintUsage();
                    return FALSE;
                }
                out->debug_level = _ttoi(argv[i]);
            }
#ifdef _DEBUG
            else if (_tcscmp(argv[i], TEXT("--crtdbgmem")) == 0) {
                ++i;
                const TCHAR *memdbgoptions = argv[i];
                if (i >= argc) {
                    fprintf(stderr, "Missing options\n");
                    PrintUsage();
                    return FALSE;
                }

                if (nfs41_dg.crtdbgmem_flags ==
                    NFS41D_GLOBALS_CRTDBGMEM_FLAGS_NOT_SET)
                    nfs41_dg.crtdbgmem_flags = 0;

                nfs41_dg.crtdbgmem_flags |=
                    (_tcsstr(memdbgoptions, TEXT("allocmem")) != NULL)?
                    _CRTDBG_ALLOC_MEM_DF:0;
                nfs41_dg.crtdbgmem_flags |=
                    (_tcsstr(memdbgoptions, TEXT("leakcheck")) != NULL)?
                    _CRTDBG_LEAK_CHECK_DF:0;
                nfs41_dg.crtdbgmem_flags |=
                    (_tcsstr(memdbgoptions, TEXT("delayfree")) != NULL)?
                    _CRTDBG_DELAY_FREE_MEM_DF:0;
                nfs41_dg.crtdbgmem_flags |=
                    (_tcsstr(memdbgoptions, TEXT("all")) != NULL)?
                    (_CRTDBG_ALLOC_MEM_DF|_CRTDBG_LEAK_CHECK_DF|_CRTDBG_DELAY_FREE_MEM_DF):0;

                if (_tcsstr(memdbgoptions, TEXT("none")) != NULL) {
                    nfs41_dg.crtdbgmem_flags = 0;
                }

                if (_tcsstr(memdbgoptions, TEXT("default")) != NULL) {
                    nfs41_dg.crtdbgmem_flags =
                        NFS41D_GLOBALS_CRTDBGMEM_FLAGS_NOT_SET;
                }
            }
#endif /* _DEBUG */
            else if (_tcscmp(argv[i], TEXT("--noldap")) == 0) { /* no LDAP */
                out->ldap_enable = FALSE;
            }
            else if (_tcscmp(argv[i], TEXT("--uid")) == 0) { /* no LDAP, setting default uid */
                ++i;
                if (i >= argc) {
                    fprintf(stderr, "Missing uid value\n");
                    PrintUsage();
                    return FALSE;
                }
                nfs41_dg.default_uid = _ttoi(argv[i]);
                if (!nfs41_dg.default_uid) {
                    fprintf(stderr, "Invalid (or missing) anonymous uid value of %d\n",
                        nfs41_dg.default_uid);
                    return FALSE;
                }
            }
            else if (_tcscmp(argv[i], TEXT("--gid")) == 0) { /* no LDAP, setting default gid */
                ++i;
                if (i >= argc) {
                    fprintf(stderr, "Missing gid value\n");
                    PrintUsage();
                    return FALSE;
                }
                nfs41_dg.default_gid = _ttoi(argv[i]);
            }
            else if (_tcscmp(argv[i], TEXT("--numworkerthreads")) == 0) {
                ++i;
                if (i >= argc) {
                    fprintf(stderr, "Missing value for num_worker_threads\n");
                    PrintUsage();
                    return FALSE;
                }
                nfs41_dg.num_worker_threads = _ttoi(argv[i]);
                if (nfs41_dg.num_worker_threads < 16) {
                    fprintf(stderr, "--numworkerthreads requires at least 16 worker threads\n");
                    PrintUsage();
                    return FALSE;
                }
                if (nfs41_dg.num_worker_threads >= MAX_NUM_THREADS) {
                    fprintf(stderr,
                        "--numworkerthreads supports a maximum of "
                        "%d worker threads\n",
                        MAX_NUM_THREADS);
                    PrintUsage();
                    return FALSE;
                }
            }
            else
                fprintf(stderr, "Unrecognized option '%S', disregarding.\n", argv[i]);
        }
    }

    (void)fprintf(stdout, "parse_cmdlineargs: debug_level %d ldap is %d "
#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
        "idmap_cygwin is 1 "
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */
        "\n",
        out->debug_level, out->ldap_enable);
    return TRUE;
}

static void print_getaddrinfo(struct addrinfo *ptr)
{
    char ipstringbuffer[46];
    DWORD ipbufferlength = 46;

    DPRINTF(1, ("getaddrinfo response flags: 0x%x\n", ptr->ai_flags));
    switch (ptr->ai_family) {
    case AF_UNSPEC: DPRINTF(1, ("Family: Unspecified\n")); break;
    case AF_INET:
        DPRINTF(1, ("Family: AF_INET IPv4 address '%s'\n",
            inet_ntoa(((struct sockaddr_in *)ptr->ai_addr)->sin_addr)));
        break;
    case AF_INET6:
        if (WSAAddressToStringA((LPSOCKADDR)ptr->ai_addr, (DWORD)ptr->ai_addrlen,
                NULL, ipstringbuffer, &ipbufferlength)) {
            DPRINTF(1, ("WSAAddressToString failed with %u\n", WSAGetLastError()));
        }
        else {
            DPRINTF(1, ("Family: AF_INET6 IPv6 address '%s'\n", ipstringbuffer));
        }
        break;
    case AF_NETBIOS: DPRINTF(1, ("AF_NETBIOS (NetBIOS)\n")); break;
    default: DPRINTF(1, ("Other %ld\n", ptr->ai_family)); break;
    }
    DPRINTF(1, ("Canonical name: '%s'\n", ptr->ai_canonname));
}

static int getdomainname()
{
    int status = 0;
    PFIXED_INFO net_info = NULL;
    DWORD size = 0;
    BOOLEAN flag = FALSE;

    status = GetNetworkParams(net_info, &size);
    if (status != ERROR_BUFFER_OVERFLOW) {
        eprintf("getdomainname: GetNetworkParams returned %d\n", status);
        goto out;
    }
    net_info = calloc(1, size);
    if (net_info == NULL) {
        status = GetLastError();
        goto out;
    }
    status = GetNetworkParams(net_info, &size);
    if (status) {
        eprintf("getdomainname: GetNetworkParams returned %d\n", status);
        goto out_free;
    }

    if (net_info->DomainName[0] == '\0') {
        struct addrinfo *result = NULL, *ptr = NULL, hints = { 0 };
        char hostname[NI_MAXHOST], servInfo[NI_MAXSERV];

        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        status = getaddrinfo(net_info->HostName, NULL, &hints, &result);
        if (status) {
            status = WSAGetLastError();
            eprintf("getdomainname: getaddrinfo failed with %d\n", status);
            goto out_free;
        } 

        for (ptr=result; ptr != NULL; ptr=ptr->ai_next) {
            print_getaddrinfo(ptr);

            switch (ptr->ai_family) {
            case AF_INET6:
            case AF_INET:
                status = getnameinfo((struct sockaddr *)ptr->ai_addr,
                            (socklen_t)ptr->ai_addrlen, hostname, NI_MAXHOST,
                            servInfo, NI_MAXSERV, NI_NAMEREQD);
                if (status) {
                    DPRINTF(1, ("getnameinfo failed %d\n", WSAGetLastError()));
                }
                else {
                    size_t i, len = strlen(hostname);
                    char *p = hostname;
                    DPRINTF(1, ("getdomainname: hostname '%s' %d\n", hostname, len));
                    for (i = 0; i < len; i++)
                        if (p[i] == '.')
                            break;
                    if (i == len)
                        break;
                    flag = TRUE;
                    memcpy(nfs41_dg.localdomain_name, &hostname[i+1], len-i);
                    DPRINTF(1, ("getdomainname: domainname '%s' %d\n",
                            nfs41_dg.localdomain_name, strlen(nfs41_dg.localdomain_name)));
                    goto out_loop;
                }
                break;
            default:
                break;
            }
        }
out_loop:
        if (!flag) {
            status = ERROR_INTERNAL_ERROR;
            eprintf("getdomainname: unable to get a domain name. "
                "Set this machine's domain name:\n"
                "System > ComputerName > Change > More > mydomain\n");
        }
        freeaddrinfo(result);
    } else {
        DPRINTF(1, ("domain name is '%s'\n", net_info->DomainName));
        memcpy(nfs41_dg.localdomain_name, net_info->DomainName,
                strlen(net_info->DomainName));
        nfs41_dg.localdomain_name[strlen(net_info->DomainName)] = '\0';
    }
out_free:
    free(net_info);
out:
    return status;
}


static
void nfsd_crt_debug_init(void)
{
#ifdef _DEBUG
    /* dump memory leaks to stderr on exit; this requires the debug heap,
    /* available only when built in debug mode under visual studio -cbodley */

    int crtsetdbgflags = nfs41_dg.crtdbgmem_flags;

    if (crtsetdbgflags == NFS41D_GLOBALS_CRTDBGMEM_FLAGS_NOT_SET) {
        DPRINTF(1, ("crtsetdbgflags not set, using defaults\n"));
        crtsetdbgflags = 0;

        crtsetdbgflags |= _CRTDBG_ALLOC_MEM_DF;
        crtsetdbgflags |= _CRTDBG_LEAK_CHECK_DF;
        /*
         * _CRTDBG_DELAY_FREE_MEM_DF - Delay freeing of memory, but
         * fill memory blocks passed to |free()| with 0xdd. We rely
         * on that to see 0xdddddddddddddddd-pointers for
         * use-after-free and catch them in stress testing instead
         * of having to deal with a core dump.
         *
         * This is off by default, as it can lead to memory
         * exhaustion (e.g. 5GB for $ git clone -b
         * 'releases/gcc-13.2.0' git://gcc.gnu.org/git/gcc.git on a
         * NFS filesystem)
         * ---- snip ----
         * crtsetdbgflags |= _CRTDBG_DELAY_FREE_MEM_DF;
         * ---- snip ----
         */
    }

    DPRINTF(0, ("memory debug flags _CRTDBG_(=0x%x)"
        "{ ALLOC_MEM_DF=%d, LEAK_CHECK_DF=%d, DELAY_FREE_MEM_DF=%d }\n",
        crtsetdbgflags,
        ((crtsetdbgflags & _CRTDBG_ALLOC_MEM_DF)?1:0),
        ((crtsetdbgflags & _CRTDBG_LEAK_CHECK_DF)?1:0),
        ((crtsetdbgflags & _CRTDBG_DELAY_FREE_MEM_DF)?1:0)));

    (void)_CrtSetDbgFlag(crtsetdbgflags);

    /*
     * Do not fill memory with 0xFE for functions like |strcpy_s()|
     * etc, as it causes bad performance. We have drmemory to find
     * issues like that instead
     */
    (void)_CrtSetDebugFillThreshold(0);

    (void)_CrtSetReportMode(_CRT_WARN,      _CRTDBG_MODE_FILE);
    (void)_CrtSetReportMode(_CRT_ERROR,     _CRTDBG_MODE_FILE);
    (void)_CrtSetReportMode(_CRT_ASSERT,    _CRTDBG_MODE_FILE);

    (void)_CrtSetReportFile(_CRT_WARN,    _CRTDBG_FILE_STDERR);
    (void)_CrtSetReportFile(_CRT_ERROR,   _CRTDBG_FILE_STDERR);
    (void)_CrtSetReportFile(_CRT_ASSERT,  _CRTDBG_FILE_STDERR);

    if (crtsetdbgflags & _CRTDBG_LEAK_CHECK_DF) {
        DPRINTF(1, ("debug mode. dumping memory leaks to stderr on exit.\n"));
    }
#endif /* _DEBUG */
}

static
void init_version_string(void)
{
    char uname_buff[256];
    char *s;
    DWORD buff_read;

    /*
     * gisburn: fixme:
     * We should get the Windows version numbers from the
     * Windows registry, unfortunately this is going to be a
     * another variantion of vesion hell, as |GetVersionEx()|
     * is depreciated
     */
    subcmd_popen_context *scmd_uname = subcmd_popen("C:\\cygwin64\\bin\\uname.exe -a");
    if (scmd_uname) {
        buff_read = 0;
        if (subcmd_readcmdoutput(scmd_uname, uname_buff, sizeof(uname_buff), &buff_read)) {
            /* Remove trailing newline */
            if ((buff_read > 0) && (uname_buff[buff_read-1] == '\n'))
                uname_buff[buff_read-1] = '\0';
            else
                uname_buff[buff_read] = '\0';

            /* Stomp newline&co. */
            for (s = uname_buff ; *s != '\0' ; s++) {
                if ((*s == '\n') || (*s == '\r'))
                    *s = ' ';
            }
        }
        else {
            eprintf("init_version_string: subcmd_readcmdoutput() for 'uname -a' failed\n");
            uname_buff[0] = '\0';
        }
        subcmd_pclose(scmd_uname);
    }
    else {
        eprintf("init_version_string: subcmd_popen() for 'uname -a' failed\n");
        uname_buff[0] = '\0';
    }

    /*
     * gisburn: fixme:
     * 1. We should include cygwin uname output only in Cygwin mode
     * 2. We should determinate the Windows version numvber ourselves
     * 3. We should include our own version and git tag
     * 4. We should honor RFC5661: "... it is RECOMMENDED
     *   that the nii_name be used to distinguish machine architecture,
     *   machine platforms, revisions, versions, and patch levels. The
     *   nii_date field is the timestamp of when the software instance
     *   was published or built..."
     */
    (void)snprintf(nfs41_dg.nfs41_nii_name,
        sizeof(nfs41_dg.nfs41_nii_name),
        "msnfs41client 0.1 WinNT NFSv4.1 client, cygwin_vers='%s'",
        uname_buff);
    DPRINTF(1, ("init_version_string: versionstring='%s'\n",
        nfs41_dg.nfs41_nii_name));
}

#ifdef STANDALONE_NFSD
void __cdecl _tmain(int argc, TCHAR *argv[])
#else
VOID ServiceStart(DWORD argc, LPTSTR *argv)
#endif
{
    DWORD status = 0, len;
    // handle to our drivers
    HANDLE pipe;
    nfs41_process_thread tids[MAX_NUM_THREADS];
    int i;
    nfsd_args cmd_args;

    if (!check_for_files())
        exit(1);
    if (!parse_cmdlineargs(argc, argv, &cmd_args))
        exit(1);
    set_debug_level(cmd_args.debug_level);
    open_log_files();
    init_version_string();
    nfsd_crt_debug_init();
#ifdef NFS41_DRIVER_SID_CACHE
    sidcache_init();
#else
    DPRINTF(0, ("SID cache disabled\n"));
#endif /* NFS41_DRIVER_SID_CACHE */

    /* acquire and store in global memory current dns domain name.
     * needed for acls */
    if (getdomainname()) {
        eprintf("Could not get domain name\n");
        exit(1);
    }

    /*
     * Set high priority class to avoid that the daemon gets stomped
     * by other processes, which might lead to some kind of priority
     * inversion
     */
    if(SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS)) {
        DPRINTF(1, ("Running as HIGH_PRIORITY_CLASS\n"));
    }
    else {
        eprintf("Failed to enter HIGH_PRIORITY_CLASS mode\n");
    }

#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
    /* force enable for cygwin getent passwd/group testing */
    cmd_args.ldap_enable = TRUE;
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */

    nfs41_server_list_init();

    if (cmd_args.ldap_enable) {
        status = nfs41_idmap_create(&(nfs41_dg.idmapper));
        if (status) {
            eprintf("id mapping initialization failed with %d\n", status);
            goto out_logs;
        }
    }

    NFS41D_VERSION = GetTickCount();
    DPRINTF(1, ("NFS41 Daemon starting: version %d\n", NFS41D_VERSION));

    pipe = CreateFileA(NFS41_USER_DEVICE_NAME_A, GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
        0, NULL);
    if (pipe == INVALID_HANDLE_VALUE)
    {
        eprintf("Unable to open upcall pipe %d\n", GetLastError());
        goto out_idmap;
    }

    DPRINTF(1, ("starting nfs41 mini redirector\n"));
    status = DeviceIoControl(pipe, IOCTL_NFS41_START,
        &NFS41D_VERSION, sizeof(DWORD), NULL, 0, (LPDWORD)&len, NULL);
    if (!status) {
        eprintf("IOCTL_NFS41_START failed with %d\n", 
                GetLastError());
        goto out_pipe;
    }

#ifndef STANDALONE_NFSD
    stop_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (stop_event == NULL)
      goto out_pipe;
#endif

    DPRINTF(1, ("Starting %d worker threads...\n",
        (int)nfs41_dg.num_worker_threads));
    for (i = 0; i < nfs41_dg.num_worker_threads; i++) {
        tids[i].handle = (HANDLE)_beginthreadex(NULL, 0, nfsd_thread_main,
                &nfs41_dg, 0, &tids[i].tid);
        if (tids[i].handle == INVALID_HANDLE_VALUE) {
            status = GetLastError();
            eprintf("_beginthreadex failed %d\n", status);
            goto out_pipe;
        }
    }
#ifndef STANDALONE_NFSD
    // report the status to the service control manager.
    if (!ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0))
        goto out_pipe;
    WaitForSingleObject(stop_event, INFINITE);
#else
    //This can be changed to waiting on an array of handles and using waitformultipleobjects
    DPRINTF(1, ("Parent waiting for children threads\n"));
    for (i = 0; i < nfs41_dg.num_worker_threads; i++)
        WaitForSingleObject(tids[i].handle, INFINITE );
#endif
    DPRINTF(1, ("Parent woke up!!!!\n"));

out_pipe:
    CloseHandle(pipe);
out_idmap:
    if (nfs41_dg.idmapper)
        nfs41_idmap_free(nfs41_dg.idmapper);
out_logs:
#ifndef STANDALONE_NFSD
    close_log_files();
#endif
    return;
}
