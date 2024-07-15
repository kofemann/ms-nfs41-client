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

#include <crtdbg.h>
#include <Windows.h>
#include <tchar.h>
#include <strsafe.h>
#include <Winnetwk.h> /* for WNet*Connection */
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "nfs41_build_features.h"
#include "nfs41_driver.h" /* NFS41_PROVIDER_NAME_A */
#include "options.h"
#include "urlparser1.h"


/*
 * Disable "warning C4996: 'wcscpy': This function or variable may be
 * unsafe." because in this case the buffers are properly sized,
 * making this function safe
 */
#pragma warning (disable : 4996)

#define MOUNT_CONFIG_NFS_PORT_DEFAULT   2049

DWORD EnumMounts(
    IN LPNETRESOURCE pContainer);

static DWORD ParseRemoteName(
    IN bool use_nfspubfh,
    IN int override_portnum,
    IN LPTSTR pRemoteName,
    IN OUT PMOUNT_OPTION_LIST pOptions,
    OUT LPTSTR pParsedRemoteName,
    OUT LPTSTR pConnectionName,
    IN size_t cchConnectionLen);
static DWORD DoMount(
    IN LPTSTR pLocalName,
    IN LPTSTR pRemoteName,
    IN LPTSTR pParsedRemoteName,
    IN BOOL bPersistent,
    IN PMOUNT_OPTION_LIST pOptions);
static DWORD DoUnmount(
    IN LPTSTR pLocalName,
    IN BOOL bForce);
static BOOL ParseDriveLetter(
    IN LPTSTR pArg,
    OUT PTCH pDriveLetter);
void PrintErrorMessage(
    IN DWORD dwError);

static VOID PrintUsage(LPTSTR pProcess)
{
    (void)_tprintf(
        TEXT("Usage: %s [options] <drive letter|*> <hostname>:<path>\n")

        TEXT("* Options:\n")
        TEXT("\t-h\thelp\n")
        TEXT("\t/?\thelp\n")
        TEXT("\t-d\tunmount\n")
        TEXT("\t-f\tforce unmount if the drive is in use\n")
        TEXT("\t-F <type>\tFilesystem type to use (only 'nfs' supported)"
	    " (Solaris/Illumos compat)\n")
        TEXT("\t-t <type>\tFilesystem type to use (only 'nfs' supported)"
	    " (Linux compat)\n")
        TEXT("\t-p\tmake the mount persist over reboots\n")
        TEXT("\t-o <comma-separated mount options>\n")
        TEXT("\t-r\tAlias for -o ro (read-only mount)\n")
        TEXT("\t-w\tAlias for -o rw (read-write mount)\n")

        TEXT("* Mount options:\n")
        TEXT("\tpublic\tconnect to the server using the public file handle lookup protocol.\n")
        TEXT("\t\t(See WebNFS Client Specification, RFC 2054).\n")
        TEXT("\tro\tmount as read-only\n")
        TEXT("\trw\tmount as read-write (default)\n")
        TEXT("\tport=#\tTCP port to use (defaults to 2049)\n")
        TEXT("\trsize=#\tread buffer size in bytes\n")
        TEXT("\twsize=#\twrite buffer size in bytes\n")
        TEXT("\tsec=sys:krb5:krb5i:krb5p\tspecify (gss) security flavor\n")
        TEXT("\twritethru\tturns off rdbss caching for writes\n")
        TEXT("\tnowritethru\tturns on rdbss caching for writes (default)\n")
        TEXT("\tcache\tturns on rdbss caching (default)\n")
        TEXT("\tnocache\tturns off rdbss caching\n")
        TEXT("\twsize=#\twrite buffer size in bytes\n")
        TEXT("\tcreatemode=\tspecify default POSIX permission mode\n"
            "\t\tfor new files created on the NFS share.\n"
            "\t\tArgument is an octal value prefixed with '0o',\n"
            "\t\tif this value is prefixed with 'nfsv3attrmode+'\n"
            "\t\tthe mode value from a \"NfsV3Attributes\" EA will be used\n"
            "\t\t(defaults \"nfsv3attrmode+0o%o\").\n")

        TEXT("* URL parameters:\n")
        TEXT("\tro=1\tmount as read-only\n")
        TEXT("\trw=1\tmount as read-write (default)\n")

        TEXT("* Hostname:\n")
        TEXT("\tDNS name, or hostname in domain\n")
        TEXT("\tentry in C:\\Windows\\System32\\drivers\\etc\\hosts\n")
        TEXT("\tIPv4 address\n")
        TEXT("\tIPv6 address within '[', ']' "
            "(will be converted to *.ipv6-literal.net)\n")

        TEXT("* Examples:\n")
        TEXT("\tnfs_mount.exe -p -o rw 'H' derfwpc5131_ipv4:/export/home2/rmainz\n")
        TEXT("\tnfs_mount.exe -o rw '*' bigramhost:/tmp\n")
        TEXT("\tnfs_mount.exe -o ro '*' archive1:/tmp\n")
        TEXT("\tnfs_mount.exe '*' archive1:/tmp?ro=1\n")
        TEXT("\tnfs_mount.exe -o rw,sec=sys,port=30000 T grendel:/net_tmpfs2\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1//net_tmpfs2/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys S nfs://myhost1//net_tmpfs2/test2?rw=1\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1:1234//net_tmpfs2/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw,port=1234 S nfs://myhost1//net_tmpfs2/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw '*' [fe80::21b:1bff:fec3:7713]://net_tmpfs2/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw '*' nfs://[fe80::21b:1bff:fec3:7713]//net_tmpfs2/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1//dirwithspace/dir%%20space/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1//dirwithspace/dir+space/test2\n")
        TEXT("\tnfs_mount.exe -o sec=sys S nfs://myhost1//dirwithspace/dir+space/test2?rw=1\n"),
        pProcess, (int)NFS41_DRIVER_DEFAULT_CREATE_MODE);
}

DWORD __cdecl _tmain(DWORD argc, LPTSTR argv[])
{
    DWORD   i, result = NO_ERROR;
    TCHAR   szLocalName[] = TEXT("C:\0");
    LPTSTR  pLocalName = NULL;
    LPTSTR  pRemoteName = NULL;
    BOOL    bUnmount = FALSE;
    BOOL    bForceUnmount = FALSE;
    BOOL    bPersistent = FALSE;
    int     port_num = -1;
    MOUNT_OPTION_LIST Options;
#define MAX_MNTOPTS 128
    TCHAR   *mntopts[MAX_MNTOPTS] = { 0 };
    size_t  num_mntopts = 0;

    int crtsetdbgflags = 0;
    crtsetdbgflags |= _CRTDBG_ALLOC_MEM_DF;  /* use debug heap */
    crtsetdbgflags |= _CRTDBG_LEAK_CHECK_DF; /* report leaks on exit */
    crtsetdbgflags |= _CRTDBG_DELAY_FREE_MEM_DF;
    (void)_CrtSetDbgFlag(crtsetdbgflags);
    (void)_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);


    if (argc == 1) {
        /* list open nfs shares */
        result = EnumMounts(NULL);
        if (result)
            PrintErrorMessage(GetLastError());
        goto out;
    }

    result = InitializeMountOptions(&Options, MAX_OPTION_BUFFER_SIZE);
    if (result) {
        PrintErrorMessage(GetLastError());
        goto out;
    }

    bool use_nfspubfh = false;

    /* parse command line */
    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == TEXT('-'))
        {
            if (_tcscmp(argv[i], TEXT("-h")) == 0) /* help */
            {
                PrintUsage(argv[0]);
                goto out;
            }
            else if (_tcscmp(argv[i], TEXT("-d")) == 0) /* unmount */
            {
                bUnmount = TRUE;
            }
            else if (_tcscmp(argv[i], TEXT("-f")) == 0) /* force unmount */
            {
                bForceUnmount = TRUE;
            }
            else if (_tcscmp(argv[i], TEXT("-p")) == 0) /* persistent */
            {
                bPersistent = TRUE;
            }
            else if (_tcscmp(argv[i], TEXT("-o")) == 0) /* mount option */
            {
                ++i;
                if (i >= argc)
                {
                    result = ERROR_BAD_ARGUMENTS;
                    _ftprintf(stderr, TEXT("Mount options missing ")
                        TEXT("after '-o'.\n\n"));
                    PrintUsage(argv[0]);
                    goto out_free;
                }

                if (num_mntopts >= (MAX_MNTOPTS-1)) {
                    result = ERROR_BAD_ARGUMENTS;
                    _ftprintf(stderr, TEXT("Too many -o ")
                        TEXT("options.\n\n"));
                    goto out_free;
                }

                mntopts[num_mntopts++] = argv[i];

                wchar_t *argv_i = argv[i];
                bool found_opt;

opt_o_argv_i_again:
                /*
                 * Extract options here, which are needed by
                 * |ParseRemoteName()|. General parsing of -o options
                 * happens *AFTER* |ParseRemoteName()|, so any
                 * settings from a nfs://-URL can be overridden
                 * via -o options.
                 */
                found_opt = false;

                /*
                 * Extract "public" option
                 */
                if (wcsstr(argv_i, L"public=0")) {
                    use_nfspubfh = false;
                    argv_i += 8;
                    found_opt = true;
                }
                else if (wcsstr(argv_i, L"public")) {
                    use_nfspubfh = true;
                    argv_i += 6;
                    found_opt = true;
                }

                /*
                 * Extract port number
                 */
                wchar_t *pns; /* port number string */
                pns = wcsstr(argv_i, L"port=");
                if (pns) {
                    wchar_t *db;
                    wchar_t digit_buff[20];

                    pns += 5; /* skip "port=" */

                    /* Copy digits... */
                    for(db = digit_buff ;
                        iswdigit(*pns) &&
                        ((db-digit_buff) < sizeof(digit_buff)) ; )
                        *db++ = *pns++;
                    *db = L'\0';

                    /* ... and convert them to a port number */
                    port_num = wcstol(digit_buff, NULL, 0);
                    if ((port_num < 1) || (port_num > 65535)) {
                        (void)_ftprintf(stderr, TEXT("NFSv4 TCP port number out of range.\n"));
                        result = ERROR_BAD_ARGUMENTS;
                        goto out;
                    }

                    argv_i = pns-1;
                    found_opt = true;
                }

                /*
                 * Try again with the remainder of the |argv[i]| string,
                 * so "port=666,port=888" will result in the port number
                 * "888"
                 */
                if (found_opt) {
                    goto opt_o_argv_i_again;
                }
            }
            else if (_tcscmp(argv[i], TEXT("-r")) == 0) /* mount option */
            {
                if (num_mntopts >= (MAX_MNTOPTS-1)) {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)_ftprintf(stderr, TEXT("Too many options.\n\n"));
                    goto out_free;
                }

                mntopts[num_mntopts++] = TEXT("ro");
            }
            else if (_tcscmp(argv[i], TEXT("-w")) == 0) /* mount option */
            {
                if (num_mntopts >= (MAX_MNTOPTS-1)) {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)_ftprintf(stderr, TEXT("Too many options.\n\n"));
                    goto out_free;
                }

                mntopts[num_mntopts++] = TEXT("rw");
            }
	    /*
	     * Filesystem type, we use this for Solaris
	     * $ mount(1M) -F nfs ... # and Linux
	     * $ mount.nfs4 -t nfs ... # compatiblity
	     */
            else if ((_tcscmp(argv[i], TEXT("-F")) == 0) ||
	             (_tcscmp(argv[i], TEXT("-t")) == 0))
            {
                ++i;
                if (i >= argc)
                {
                    result = ERROR_BAD_ARGUMENTS;
                    _ftprintf(stderr, TEXT("Filesystem type missing ")
                        TEXT("after '-t'/'-F'.\n\n"));
                    PrintUsage(argv[0]);
                    goto out_free;
                }

                if (_tcscmp(argv[i], TEXT("nfs")) != 0)
                {
                    result = ERROR_BAD_ARGUMENTS;
                    _ftprintf(stderr, TEXT("Filesystem type '%s' ")
                        TEXT("not supported.\n\n"), argv[i]);
                    PrintUsage(argv[0]);
                    goto out_free;
                }
            }
            else
                _ftprintf(stderr, TEXT("Unrecognized option ")
                    TEXT("'%s', disregarding.\n"), argv[i]);
        }
        else if (_tcscmp(argv[i], TEXT("/?")) == 0)
	{
	    /* Windows-style "nfs_mount /?" help */
            PrintUsage(argv[0]);
            goto out;
	}
	else if (pLocalName == NULL) /* drive letter */
        {
            pLocalName = argv[i];
        }
        else if (pRemoteName == NULL) /* remote path */
        {
            pRemoteName = argv[i];
        }
        else
            _ftprintf(stderr, TEXT("Unrecognized argument ")
                TEXT("'%s', disregarding.\n"), argv[i]);
    }

    /* validate local drive letter */
    if (pLocalName == NULL)
    {
        result = ERROR_BAD_ARGUMENTS;
        _ftprintf(stderr, TEXT("Missing argument for drive letter.\n\n"));
        PrintUsage(argv[0]);
        goto out_free;
    }
    if (FALSE == ParseDriveLetter(pLocalName, szLocalName))
    {
        result = ERROR_BAD_ARGUMENTS;
        _ftprintf(stderr, TEXT("Invalid drive letter '%s'. ")
            TEXT("Expected 'C' or 'C:'.\n\n"), pLocalName);
        PrintUsage(argv[0]);
        goto out_free;
    }

    if (bUnmount == TRUE) /* unmount */
    {
        result = DoUnmount(szLocalName, bForceUnmount);
        if (result)
            PrintErrorMessage(result);
    }
    else /* mount */
    {
        TCHAR szRemoteName[NFS41_SYS_MAX_PATH_LEN];
        TCHAR szParsedRemoteName[NFS41_SYS_MAX_PATH_LEN];

        *szRemoteName = TEXT('\0');

        if (pRemoteName == NULL)
        {
            result = ERROR_BAD_NET_NAME;
            _ftprintf(stderr, TEXT("Missing argument for remote path.\n\n"));
            PrintUsage(argv[0]);
            goto out_free;
        }

        /*
         * First we need to parse the remote name, which might be a
         * nfs://-URL with URL parameters, which provide default
         * options for a NFS mount point, which can be overridden via
         * -o below.
         */
        result = ParseRemoteName(use_nfspubfh, port_num,
            pRemoteName, &Options,
            szParsedRemoteName, szRemoteName,
            NFS41_SYS_MAX_PATH_LEN);
        if (result)
            goto out;

        /*
         * Parse saved -o options (possibly overriding defaults
         * provided via (nfs://-)URL parameters above.
         */
        for (i = 0 ; i < num_mntopts ; i++) {
            if (!ParseMountOptions(mntopts[i], &Options)) {
                result = ERROR_BAD_ARGUMENTS;
                goto out_free;
            }
        }

        result = DoMount(szLocalName, szRemoteName, szParsedRemoteName, bPersistent, &Options);
        if (result)
            PrintErrorMessage(result);
    }

out_free:
    FreeMountOptions(&Options);
out:
    return result;
}

static void ConvertUnixSlashes(
    IN OUT LPTSTR pRemoteName)
{
    LPTSTR pos = pRemoteName;
    for (pos = pRemoteName; *pos; pos++)
        if (*pos == TEXT('/'))
            *pos = TEXT('\\');
}


char *wcs2utf8str(const wchar_t *wstr)
{
    char *utf8str;
    size_t wstr_len;
    size_t utf8_len;

    wstr_len = wcslen(wstr);
    utf8_len = WideCharToMultiByte(CP_UTF8, 0,
        wstr, (int)wstr_len, NULL, 0, NULL, NULL);

    utf8str = malloc(utf8_len+1);
    if (!utf8str)
        return NULL;
    (void)WideCharToMultiByte(CP_UTF8, 0,
        wstr, (int)wstr_len, utf8str, (int)utf8_len, NULL, NULL);
    utf8str[utf8_len] = '\0';
    return utf8str;
}

static
wchar_t *utf8str2wcs(const char *utf8str)
{
    wchar_t *wstr;
    size_t utf8len;
    size_t wstr_len;

    utf8len = strlen(utf8str);
    wstr_len = MultiByteToWideChar(CP_UTF8, 0,
        utf8str, (int)utf8len, NULL, 0);

    wstr = malloc((wstr_len+1)*sizeof(wchar_t));
    if (!wstr)
        return NULL;

    (void)MultiByteToWideChar(CP_UTF8, 0,
        utf8str, (int)utf8len, wstr, (int)wstr_len);
    wstr[wstr_len] = L'\0';
    return wstr;
}

static DWORD ParseRemoteName(
    IN bool use_nfspubfh,
    IN int override_portnum,
    IN LPTSTR pRemoteName,
    IN OUT PMOUNT_OPTION_LIST pOptions,
    OUT LPTSTR pParsedRemoteName,
    OUT LPTSTR pConnectionName,
    IN size_t cchConnectionLen)
{
    DWORD result = NO_ERROR;
    LPTSTR pEnd;
    wchar_t *mountstrmem = NULL;
    int port = MOUNT_CONFIG_NFS_PORT_DEFAULT;
    wchar_t remotename[NFS41_SYS_MAX_PATH_LEN];
    wchar_t *premotename = remotename;
/* sizeof(hostname+'@'+integer) */
#define SRVNAME_LEN (NFS41_SYS_MAX_PATH_LEN+1+32)
    wchar_t srvname[SRVNAME_LEN];
    url_parser_context *uctx = NULL;

    result = StringCchCopy(premotename, NFS41_SYS_MAX_PATH_LEN, pRemoteName);

    /*
     * Support nfs://-URLS per RFC 2224 ("NFS URL
     * SCHEME", see https://www.rfc-editor.org/rfc/rfc2224.html),
     * including port support (nfs://hostname@port/path/...)
     */
    if (!wcsncmp(premotename, TEXT("nfs://"), 6)) {
        char *premotename_utf8;
        wchar_t *hostname_wstr;

        /*
         * URLs do urlencoding and urldecoding in bytes (see
         * RFC3986 ("Uniform Resource Identifier (URI): Generic
         * Syntax"), e.g. Unicode Euro symbol U+20AC is encoded
         * as "%E2%82%AC".
         * So we have to convert from our |wchar_t| string to
         * a UTF-8 byte string, do the URL processing on byte
         * level, and convert that UTF-8 byte string back to a
         * |wchar_t| string.
         */
        premotename_utf8 = wcs2utf8str(premotename);
        if (!premotename_utf8) {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto out;
        }

        uctx = url_parser_create_context(premotename_utf8, 0);
        free(premotename_utf8);
        if (!uctx) {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto out;
        }

        if (url_parser_parse(uctx) < 0) {
            result = ERROR_BAD_ARGUMENTS;
            (void)_ftprintf(stderr, TEXT("Error parsing nfs://-URL.\n"));
            goto out;
        }

        if (uctx->login.username || uctx->login.passwd) {
            result = ERROR_BAD_ARGUMENTS;
            (void)_ftprintf(stderr, TEXT("Username/Password are not defined for nfs://-URL.\n"));
            goto out;
        }

        if (uctx->num_parameters > 0) {
            int pi;
            const char *pname;
            const char *pvalue;

            /*
             * FIXME: Values added here based on URL parameters
             * should be added at the front of the list of options,
             * so users can override the nfs://-URL given default.
             * Right now this does not work, e.g.
             * $ nfs_mount.exe -o rw nfs://foo//bar?ro=1 # will
             * result in a read-only mount, while the expectation
             * is that -o overrides URL settings.
             */
            for (pi = 0; pi < uctx->num_parameters ; pi++) {
                pname = uctx->parameters[pi].name;
                pvalue = uctx->parameters[pi].value;

                if (!strcmp(pname, "rw")) {
                    if ((pvalue == NULL) || (!strcmp(pvalue, "1"))) {
                        (void)InsertOption(TEXT("rw"), TEXT("1"), pOptions);
                    }
                    else if (!strcmp(pvalue, "0")) {
                        (void)InsertOption(TEXT("ro"), TEXT("1"), pOptions);
                    }
                    else {
                        result = ERROR_BAD_ARGUMENTS;
                        (void)_ftprintf(stderr,
                            TEXT("Unsupported nfs://-URL parameter ")
                            TEXT("'%S' value '%S'.\n"),
                            pname, pvalue);
                        goto out;
                    }
                }
                else if (!strcmp(pname, "ro")) {
                    if ((pvalue == NULL) || (!strcmp(pvalue, "1"))) {
                        (void)InsertOption(TEXT("ro"), TEXT("1"), pOptions);
                    }
                    else if (!strcmp(pvalue, "0")) {
                        (void)InsertOption(TEXT("rw"), TEXT("1"), pOptions);
                    }
                    else {
                        result = ERROR_BAD_ARGUMENTS;
                        (void)_ftprintf(stderr,
                            TEXT("Unsupported nfs://-URL parameter ")
                            TEXT("'%S' value '%S'.\n"),
                            pname, pvalue);
                        goto out;
                    }
                }
                else {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)_ftprintf(stderr,
                        TEXT("Unsupported nfs://-URL parameter '%S'.\n"), pname);
                    goto out;
                }
            }
        }

        if (uctx->hostport.port != -1)
            port = uctx->hostport.port;

        hostname_wstr = utf8str2wcs(uctx->hostport.hostname);
        if (!hostname_wstr) {
            result = ERROR_NOT_ENOUGH_MEMORY;
            goto out;
        }
        (void)wcscpy_s(premotename, NFS41_SYS_MAX_PATH_LEN, hostname_wstr);
        free(hostname_wstr);
        ConvertUnixSlashes(premotename);

        if (!uctx->path) {
            result = ERROR_BAD_ARGUMENTS;
            (void)_ftprintf(stderr, TEXT("Path missing in nfs://-URL\n"));
            goto out;
        }

        if (uctx->path[0] != '/') {
            result = ERROR_BAD_ARGUMENTS;
            (void)_ftprintf(stderr, TEXT("Relative nfs://-URLs are not supported\n"));
            goto out;
        }

        pEnd = mountstrmem = utf8str2wcs(uctx->path);
        ConvertUnixSlashes(pEnd);
    }
    else
    {
        ConvertUnixSlashes(premotename);

        /*
         * Remote hostname should not contain a '@' since we use this
         * to communicate the NFSv4 port number below
         * Use $ nfs_mount.exe -o port=portnumber ... # instead.
         *
         * We have this limitation to avoid confusion for Windows
         * users, but we explicitly allow the nfs://-URLs to have a
         * port number, and -o port=<num> to override that.
         */
        if (_tcsrchr(premotename, TEXT('@'))) {
            (void)_ftprintf(stderr,
                TEXT("Remote path should not contain '@', ")
                TEXT("use -o port=tcpportnum.\n"));
            result = ERROR_BAD_ARGUMENTS;
            goto out;
        }

        /* fail if the server name doesn't end with :\ */
        pEnd = _tcsrchr(premotename, TEXT(':'));
        if (pEnd == NULL || pEnd[1] != TEXT('\\')) {
            (void)_ftprintf(stderr, TEXT("Failed to parse the remote path. ")
                TEXT("Expected 'hostname:\\path'.\n"));
            result = ERROR_BAD_ARGUMENTS;
            goto out;
        }
        *pEnd++ = TEXT('\0');
    }

    /*
     * Override the NFSv4 TCP port with the -o port=<num> option,
     * inclding for nfs://-URLs with port numbers
     */
    if (override_portnum != -1) {
        port = override_portnum;
    }

    /*
     * Make sure that we do not pass raw IPv6 addresses to the kernel.
     *
     * UNC paths do not allow ':' characters, so passing a raw IPv6
     * address to the kernel is both illegal, and causes havoc.
     *
     * Microsoft solved this problem by providing a transcription
     * method to represent an IPv6 address in the form of a domain
     * name that can be used in UNC paths, e.g.
     * "[fe80::219:99ff:feae:73ce]" should be turned into
     * "fe80--219-99ff-feae-73ce.ipv6-literal.net"
     *
     * See https://en.wikipedia.org/wiki/IPv6_address#Literal_IPv6_addresses_in_UNC_path_names
     * for details
     */
    if (premotename[0] == TEXT('[')) {
        size_t len = wcslen(premotename);
        size_t i;
        wchar_t c;

        /* Check for minimum length and trailing ']' */
        if ((len < 4) || (premotename[len-1] != TEXT(']'))) {
            _ftprintf(stderr, TEXT("Failed to parse raw IPv6 address,")
	        TEXT(" trailing ']' is missing, ")
		TEXT("or address string too short.\n"));
            result = ERROR_BAD_ARGUMENTS;
            goto out;
	}

        /* Skip '[', stomp ']' */
        premotename[len-1] = TEXT('\0');
        premotename++;
        len -= 2;

        /* Check whether this is a valid IPv6 address */
        for (i=0 ; i < len ; i++) {
            c = premotename[i];
            if (!(iswxdigit(c) || (c == TEXT(':')))) {
                _ftprintf(stderr, TEXT("Failed to parse raw IPv6 ")
		    TEXT("address, illegal character '%c' found.\n"),
		    c);
                result = ERROR_BAD_ARGUMENTS;
                goto out;
            }
        }

	for (i = 0 ; i < len ; i++) {
	    /* IPv6 separator */
            if (premotename[i] == TEXT(':'))
                premotename[i] = TEXT('-');
	    /* zone index */
	    else if (premotename[i] == TEXT('%'))
                premotename[i] = TEXT('s');
        }

        /*
	 * 1. Append .ipv6-literal.net to hostname
	 * 2. ALWAYS add port number to hostname, so UNC paths use it
	 *   too
	 */
        (void)swprintf(srvname, SRVNAME_LEN,
	    TEXT("%s.ipv6-literal.net@%d"), premotename, port);
    }
    else {
        /* ALWAYS add port number to hostname, so UNC paths use it too */
        (void)swprintf(srvname, SRVNAME_LEN, TEXT("%s@%d"),
	    premotename, port);
    }

    /*
     * Safeguard against ':' in UNC paths, e.g if we pass raw IPv6
     * address without ':', or just random garbage
     */
    if (wcschr(srvname, TEXT(':'))) {
        _ftprintf(stderr,
	    TEXT("Illegal ':' character hostname '%s'.\n"), srvname);
        result = ERROR_BAD_ARGUMENTS;
        goto out;
    }

#ifdef DEBUG_MOUNT
    (void)_ftprintf(stderr,
        TEXT("srvname='%s', mntpt='%s'\n"),
        srvname,
        pEnd);
#endif

    if (!InsertOption(TEXT("srvname"), srvname, pOptions) ||
        !InsertOption(TEXT("mntpt"), *pEnd ? pEnd : TEXT("\\"), pOptions)) {
        result = ERROR_BAD_ARGUMENTS;
        goto out;
    }

    result = StringCchCopy(pConnectionName, cchConnectionLen, TEXT("\\\\"));
    if (FAILED(result))
        goto out;
    result = StringCbCat(pConnectionName, cchConnectionLen, srvname);
    if (FAILED(result))
        goto out;
#ifdef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
    result = StringCbCat(pConnectionName, cchConnectionLen,
        (use_nfspubfh?(TEXT("\\pubnfs4")):(TEXT("\\nfs4"))));
    if (FAILED(result))
        goto out;
#endif /* NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX */
    if (*pEnd)
        result = StringCchCat(pConnectionName, cchConnectionLen, pEnd);

    result = StringCchCopy(pParsedRemoteName, cchConnectionLen, srvname);

#ifdef DEBUG_MOUNT
    (void)_ftprintf(stderr,
        TEXT("pConnectionName='%s', pParsedRemoteName='%s', use_nfspubfh='%d'\n"),
        pConnectionName,
        pParsedRemoteName,
        (int)use_nfspubfh);
#endif

out:
    if (uctx) {
        url_parser_free_context(uctx);
    }
    if (mountstrmem) {
        free(mountstrmem);
    }
    return result;
}

static DWORD DoMount(
    IN LPTSTR pLocalName,
    IN LPTSTR pRemoteName,
    IN LPTSTR pParsedRemoteName,
    IN BOOL bPersistent,
    IN PMOUNT_OPTION_LIST pOptions)
{
    DWORD result = NO_ERROR;
    TCHAR szExisting[NFS41_SYS_MAX_PATH_LEN];
    DWORD dwLength;
    NETRESOURCE NetResource;

    if (pOptions->Buffer->Length) {
        if (pOptions->Current)
            pOptions->Current->NextEntryOffset = 0;
        NetResource.lpComment = (LPTSTR)&pOptions->Buffer[0];
    }

#ifdef DEBUG_MOUNT
    (void)_ftprintf(stderr,
        TEXT("DoMount(pLocalName='%s', pRemoteName='%s', pParsedRemoteName='%s')\n"),
        pLocalName,
        pRemoteName,
        pParsedRemoteName);
    RecursivePrintEaInformation((PFILE_FULL_EA_INFORMATION)pOptions->Buffer->Buffer);
#endif /* DEBUG_MOUNT */

    /* fail if the connection already exists */
    dwLength = NFS41_SYS_MAX_PATH_LEN;
    result = WNetGetConnection(pLocalName, (LPTSTR)szExisting, &dwLength);
    if (result == NO_ERROR)
    {
        result = ERROR_ALREADY_ASSIGNED;
        _ftprintf(stderr, TEXT("Mount failed, drive %s is ")
            TEXT("already assigned to '%s'.\n"),
            pLocalName, szExisting);
    }
    else
    {
        TCHAR szConnection[NFS41_SYS_MAX_PATH_LEN];
        DWORD ConnectSize = NFS41_SYS_MAX_PATH_LEN, ConnectResult, Flags = 0;

        ZeroMemory(&NetResource, sizeof(NETRESOURCE));
        NetResource.dwType = RESOURCETYPE_DISK;
        /* drive letter is chosen automatically if lpLocalName == NULL */
        NetResource.lpLocalName = *pLocalName == TEXT('*') ? NULL : pLocalName;
        NetResource.lpRemoteName = pRemoteName;
        /* ignore other network providers */
        NetResource.lpProvider = TEXT(NFS41_PROVIDER_NAME_A);
        /* pass mount options via lpComment */
        if (pOptions->Buffer->Length) {
            NetResource.lpComment = (LPTSTR)pOptions->Buffer;
        }

        if (bPersistent)
            Flags |= CONNECT_UPDATE_PROFILE;

        result = WNetUseConnection(NULL,
            &NetResource, NULL, NULL, Flags,
            szConnection, &ConnectSize, &ConnectResult);

        if (result == NO_ERROR)
            _tprintf(TEXT("Successfully mounted '%s' to drive '%s'\n"),
                pParsedRemoteName, szConnection);
        else
            _ftprintf(stderr, TEXT("WNetUseConnection(%s, %s) ")
                TEXT("failed with error code %u.\n"),
                pLocalName, pRemoteName, result);
    }

    return result;
}

static DWORD DoUnmount(
    IN LPTSTR pLocalName,
    IN BOOL bForce)
{
    DWORD result;

    /* disconnect the specified local drive */
    result = WNetCancelConnection2(pLocalName, CONNECT_UPDATE_PROFILE, bForce);
    /* TODO: verify that this connection uses the nfs41 provider -cbodley */
    switch (result)
    {
    case NO_ERROR:
        _tprintf(TEXT("Drive %s unmounted successfully.\n"), pLocalName);
        break;
    case ERROR_NOT_CONNECTED:
        _ftprintf(stderr, TEXT("Drive %s is not currently ")
            TEXT("connected.\n"), pLocalName);
        break;
    default:
        _ftprintf(stderr, TEXT("WNetCancelConnection2(%s) failed ")
            TEXT("with error code %u.\n"), pLocalName, result);
        break;
    }
    return result;
}

static BOOL ParseDriveLetter(
    IN LPTSTR pArg,
    OUT PTCH pDriveLetter)
{
    /* accept 'C' or 'C:' */
    switch (_tcslen(pArg))
    {
    case 2:
        if (pArg[1] != TEXT(':'))
            return FALSE;
        /* break intentionally missing */
    case 1:
        if (_istlower(*pArg))
            *pArg = (TCHAR)_totupper(*pArg);
        else if (!_istupper(*pArg) && *pArg != TEXT('*'))
            return FALSE;

        *pDriveLetter = *pArg;
        return TRUE;
    }
    return FALSE;
}

void PrintErrorMessage(
    IN DWORD dwError)
{
    LPTSTR lpMsgBuf = NULL;
    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);
    _fputts(lpMsgBuf, stderr);
    LocalFree(lpMsgBuf);
}
