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
#include <strsafe.h>
#include <Winnetwk.h> /* for WNet*Connection */
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <locale.h>
#include <io.h>
#include <fcntl.h>

#include "nfs41_build_features.h"
#include "nfs41_driver.h" /* |NFS41_PROVIDER_NAME_U| */
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
    IN LPNETRESOURCEW pContainer);

static DWORD ParseRemoteName(
    IN bool use_nfspubfh,
    IN int override_portnum,
    IN LPWSTR pRemoteName,
    IN OUT PMOUNT_OPTION_LIST pOptions,
    OUT LPWSTR pParsedRemoteName,
    OUT LPWSTR pConnectionName,
    IN size_t cchConnectionLen);
static DWORD DoMount(
    IN LPWSTR pLocalName,
    IN LPWSTR pRemoteName,
    IN LPWSTR pParsedRemoteName,
    IN BOOL bPersistent,
    IN PMOUNT_OPTION_LIST pOptions);
static DWORD DoUnmount(
    IN LPWSTR pLocalName,
    IN BOOL bForce);
static BOOL ParseDriveLetter(
    IN LPWSTR pArg,
    OUT PWCH pDriveLetter);
void PrintErrorMessage(
    IN DWORD dwError);

static
void PrintMountUsage(LPWSTR pProcess)
{
    (void)fwprintf(stderr,
        L"Usage: %s [options] <drive letter|*> <hostname>:<path>\n"
        "Usage: %s [options] <hostname>:<path>\n"
        "Usage: %s -d [options] <drive letter>\n"
        "Usage: %s\n"

        "* Options:\n"
        "\t-h, --help, /?\thelp\n"
        "\t-d, --unmount\tunmount\n"
        "\t-f, --force\tforce unmount if the drive is in use\n"
            "\t-F <type>\tFilesystem type to use (only 'nfs' supported)"
	    " (Solaris/Illumos compat)\n"
        "\t-t, --types <type>\tFilesystem type to use (only 'nfs' supported)"
	    " (Linux compat)\n"
        "\t-p, --persistent\tmake the mount persist over reboots\n"
        "\t-o. --options <comma-separated mount options>\n"
        "\t-r, --read-only\tAlias for -o ro (read-only mount)\n"
        "\t-w, --rw, --read-write\tAlias for -o rw (read-write mount)\n"

        "* Mount options:\n"
        "\tpublic\tconnect to the server using the public file handle lookup protocol.\n"
        "\t\t(See WebNFS Client Specification, RFC 2054).\n"
        "\tro\tmount as read-only\n"
        "\trw\tmount as read-write (default)\n"
        "\tport=#\tTCP port to use (defaults to 2049)\n"
        "\trsize=#\tread buffer size in bytes\n"
        "\twsize=#\twrite buffer size in bytes\n"
        "\tsec=sys:krb5:krb5i:krb5p\tspecify (gss) security flavor\n"
        "\twritethru\tturns off rdbss caching for writes\n"
        "\tnowritethru\tturns on rdbss caching for writes (default)\n"
        "\tcache\tturns on rdbss caching (default)\n"
        "\tnocache\tturns off rdbss caching\n"
        "\ttimebasedcoherency\tturns on time-based coherency\n"
        "\tnotimebasedcoherency\tturns off time-based coherency (default, due to bugs)\n"
        "\twsize=#\twrite buffer size in bytes\n"
        "\tcreatemode=\tspecify default POSIX permission mode\n"
            "\t\tfor new directories and files created on the NFS share.\n"
            "\t\tArgument is an octal value prefixed with '0' or '0o',\n"
            "\t\tif this value is prefixed with 'nfsv3attrmode+'\n"
            "\t\tthe mode value from a \"NfsV3Attributes\" EA will be used\n"
            "\t\t(defaults \"nfsv3attrmode+0%o\" for dirs and \n"
            "\t\t\"nfsv3attrmode+0%o\" for files).\n"
        "\tdircreatemode=\tspecify default POSIX permission mode\n"
            "\t\tfor new directories created on the NFS share.\n"
            "\t\tArgument is an octal value prefixed with '0' or '0o',\n"
            "\t\tif this value is prefixed with 'nfsv3attrmode+'\n"
            "\t\tthe mode value from a \"NfsV3Attributes\" EA will be used\n"
            "\t\t(defaults \"nfsv3attrmode+0%o\").\n"
        "\tfilecreatemode=\tspecify default POSIX permission mode\n"
            "\t\tfor new files created on the NFS share.\n"
            "\t\tArgument is an octal value prefixed with '0' or '0o',\n"
            "\t\tif this value is prefixed with 'nfsv3attrmode+'\n"
            "\t\tthe mode value from a \"NfsV3Attributes\" EA will be used\n"
            "\t\t(defaults \"nfsv3attrmode+0%o\").\n"

        "* URL parameters:\n"
        "\tro=1\tmount as read-only\n"
        "\trw=1\tmount as read-write (default)\n"

        "* Hostname:\n"
        "\tDNS name, or hostname in domain\n"
        "\tentry in C:\\Windows\\System32\\drivers\\etc\\hosts\n"
        "\tIPv4 address\n"
        "\tIPv6 address within '[', ']' "
            "(will be converted to *.ipv6-literal.net)\n"

        "* Examples:\n"
        "\tnfs_mount.exe -p -o rw 'H' derfwpc5131_ipv4:/export/home2/rmainz\n"
        "\tnfs_mount.exe -o rw '*' bigramhost:/tmp\n"
        "\tnfs_mount.exe -o ro '*' archive1:/tmp\n"
        "\tnfs_mount.exe '*' archive1:/tmp?ro=1\n"
        "\tnfs_mount.exe -o rw,sec=sys,port=30000 T grendel:/net_tmpfs2\n"
        "\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1//net_tmpfs2/test2\n"
        "\tnfs_mount.exe -o sec=sys S nfs://myhost1//net_tmpfs2/test2?rw=1\n"
        "\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1:1234//net_tmpfs2/test2\n"
        "\tnfs_mount.exe -o sec=sys,rw,port=1234 S nfs://myhost1//net_tmpfs2/test2\n"
        "\tnfs_mount.exe -o sec=sys,rw '*' [fe80::21b:1bff:fec3:7713]://net_tmpfs2/test2\n"
        "\tnfs_mount.exe -o sec=sys,rw '*' nfs://[fe80::21b:1bff:fec3:7713]//net_tmpfs2/test2\n"
        "\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1//dirwithspace/dir%%20space/test2\n"
        "\tnfs_mount.exe -o sec=sys,rw nfs://myhost1//dirwithspace/dir%%20space/test2\n"
        "\tnfs_mount.exe -o sec=sys,rw S nfs://myhost1//dirwithspace/dir+space/test2\n"
        "\tnfs_mount.exe -o sec=sys S nfs://myhost1//dirwithspace/dir+space/test2?rw=1\n"
        "\tnfs_mount.exe -o sec=sys nfs://myhost1//dirwithspace/dir+space/test2?rw=1\n",
        pProcess, pProcess, pProcess, pProcess,
        (int)NFS41_DRIVER_DEFAULT_DIR_CREATE_MODE,
        (int)NFS41_DRIVER_DEFAULT_FILE_CREATE_MODE,
        (int)NFS41_DRIVER_DEFAULT_DIR_CREATE_MODE,
        (int)NFS41_DRIVER_DEFAULT_FILE_CREATE_MODE);
}


static
void PrintUmountUsage(LPWSTR pProcess)
{
    (void)fwprintf(stderr,
        L"Usage: %s [options] <drive letter>\n"

        "* Options:\n"
        "\t-h, --help, /?\thelp\n"
        "\t-f, --force\tforce unmount if the drive is in use\n",
        pProcess);
}


static
int mount_main(int argc, wchar_t *argv[])
{
    int     i;
    DWORD   result = NO_ERROR;
    wchar_t szLocalName[NFS41_SYS_MAX_PATH_LEN];
    LPWSTR  pLocalName = NULL;
    LPWSTR  pRemoteName = NULL;
    BOOL    bUnmount = FALSE;
    BOOL    bForceUnmount = FALSE;
    BOOL    bPersistent = FALSE;
    int     port_num = -1;
    MOUNT_OPTION_LIST Options;
#define MAX_MNTOPTS 128
    wchar_t *mntopts[MAX_MNTOPTS] = { 0 };
    int     num_mntopts = 0;

    result = InitializeMountOptions(&Options, MAX_OPTION_BUFFER_SIZE);
    if (result) {
        PrintErrorMessage(GetLastError());
        goto out;
    }

    bool use_nfspubfh = false;

    /* parse command line */
    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == L'-')
        {
            /* help */
            if ((!wcscmp(argv[i], L"-h")) ||
                (!wcscmp(argv[i], L"--help"))) {
                PrintMountUsage(argv[0]);
                result = 1;
                goto out;
            }
            /* unmount */
            else if ((!wcscmp(argv[i], L"-d")) ||
                    (!wcscmp(argv[i], L"--unmount"))) {
                bUnmount = TRUE;
            }
            /* force unmount */
            else if ((!wcscmp(argv[i], L"-f")) ||
                (!wcscmp(argv[i], L"--force"))) {
                bForceUnmount = TRUE;
            }
            /* persistent */
            else if ((!wcscmp(argv[i], L"-p")) ||
                    (!wcscmp(argv[i], L"--persistent"))) {
                bPersistent = TRUE;
            }
            /* mount option */
            else if ((!wcscmp(argv[i], L"-o")) ||
                    (!wcscmp(argv[i], L"--options"))) {
                ++i;
                if (i >= argc)
                {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr,
                        L"Mount options missing after '-o'.\n\n");
                    PrintMountUsage(argv[0]);
                    goto out_free;
                }

                if (num_mntopts >= (MAX_MNTOPTS-1)) {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr,
                        L"Too many -o options.\n\n");
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
                        (void)fwprintf(stderr,
                            L"NFSv4 TCP port number out of range.\n");
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
            /* mount option */
            else if ((!wcscmp(argv[i], L"-r")) ||
                    (!wcscmp(argv[i], L"--read-only"))) {
                if (num_mntopts >= (MAX_MNTOPTS-1)) {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr, L"Too many options.\n\n");
                    goto out_free;
                }

                mntopts[num_mntopts++] = L"ro";
            }
            /* mount option */
            else if ((!wcscmp(argv[i], L"-w")) ||
                    (!wcscmp(argv[i], L"--rw")) ||
                    (!wcscmp(argv[i], L"--read-write"))) {
                if (num_mntopts >= (MAX_MNTOPTS-1)) {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr, L"Too many options.\n\n");
                    goto out_free;
                }

                mntopts[num_mntopts++] = L"rw";
            }
	    /*
	     * Filesystem type, we use this for Solaris
	     * $ mount(1M) -F nfs ... # and Linux
	     * $ mount.nfs4 -t nfs ... # compatiblity
	     */
            else if ((!wcscmp(argv[i], L"-F")) ||
                    (!wcscmp(argv[i], L"-t")) ||
                    (!wcscmp(argv[i], L"--types"))) {
                ++i;
                if (i >= argc)
                {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr, L"Filesystem type missing "
                        L"after '-t'/'-F'.\n\n");
                    PrintMountUsage(argv[0]);
                    goto out_free;
                }

                if (!wcscmp(argv[i], L"nfs")) {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr, L"Filesystem type '%s' "
                        L"not supported.\n\n./build.vc19/x64/Debug/nfs_mount.exe", argv[i]);
                    PrintMountUsage(argv[0]);
                    goto out_free;
                }
            }
            else {
                (void)fwprintf(stderr,
                    L"Unrecognized option '%s'\n",
                    argv[i]);
                result = 1;
                goto out;
            }
        }
        /* Windows-style "nfs_mount /?" help */
        else if (!wcscmp(argv[i], L"/?")) {
            PrintMountUsage(argv[0]);
            result = 1;
            goto out;
	}
        /* drive letter */
	else if ((!bUnmount) && (pLocalName == NULL) &&
            (i == (argc-2)) && (wcslen(argv[i]) <= 2)) {
            pLocalName = argv[i];
        }
        /* remote path */
        else if ((pRemoteName == NULL) && (i == (argc-1))) {
            pRemoteName = argv[i];
        }
        else {
            (void)fwprintf(stderr,
                L"Unrecognized argument '%s'.\n",
                argv[i]);
            result = 1;
            goto out;
        }
    }

    /* validate local drive letter */
    if (pLocalName) {
        if (!ParseDriveLetter(pLocalName, szLocalName)) {
            result = ERROR_BAD_ARGUMENTS;
            (void)fwprintf(stderr, L"Invalid drive letter '%s'. "
                L"Expected 'C' or 'C:'.\n\n",
                pLocalName);
            PrintMountUsage(argv[0]);
            goto out_free;
        }
    }

    if (bUnmount == TRUE) /* unmount */
    {
        result = DoUnmount(pLocalName?szLocalName:pRemoteName,
            bForceUnmount);
        if (result)
            PrintErrorMessage(result);
    }
    else /* mount */
    {
        wchar_t szRemoteName[NFS41_SYS_MAX_PATH_LEN];
        wchar_t szParsedRemoteName[NFS41_SYS_MAX_PATH_LEN];

        *szRemoteName = L'\0';

        if (pRemoteName == NULL)
        {
            result = ERROR_BAD_NET_NAME;
            (void)fwprintf(stderr, L"Missing argument for remote path.\n\n");
            PrintMountUsage(argv[0]);
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

        result = DoMount(pLocalName?szLocalName:NULL,
            szRemoteName, szParsedRemoteName, bPersistent,
            &Options);
        if (result)
            PrintErrorMessage(result);
    }

out_free:
    FreeMountOptions(&Options);
out:
    return result;
}


static
int umount_main(int argc, wchar_t *argv[])
{
    int     i;
    DWORD   result = NO_ERROR;
    LPWSTR  pLocalName = NULL;
    wchar_t szLocalName[] = L"C:\0";
    BOOL    bForceUnmount = FALSE;

    /* parse command line */
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == L'-') {
            /* help */
            if ((!wcscmp(argv[i], L"-h")) ||
                (!wcscmp(argv[i], L"--help"))) {
                PrintUmountUsage(argv[0]);
                result = 1;
                goto out;
            }
            /* force unmount */
            else if ((!wcscmp(argv[i], L"-f")) ||
                (!wcscmp(argv[i], L"--force"))) {
                bForceUnmount = TRUE;
            }
            else {
                (void)fwprintf(stderr, L"Unrecognized option "
                    L"'%s', disregarding.\n",
                    argv[i]);
                result = ERROR_BAD_ARGUMENTS;
            }
        }
        /* Windows-style "nfs_umount /?" help */
        else if (!wcscmp(argv[i], L"/?")) {
            PrintUmountUsage(argv[0]);
            result = 1;
            goto out;
	}
        /* drive letter */
	else if (pLocalName == NULL) {
            pLocalName = argv[i];
        }
        else {
            (void)fwprintf(stderr, L"Unrecognized argument "
                L"'%s', disregarding.\n",
                argv[i]);
        }
    }

    if (pLocalName == NULL) {
        result = ERROR_BAD_ARGUMENTS;
        (void)fwprintf(stderr, L"Drive letter expected.\n");
        PrintUmountUsage(argv[0]);
        goto out;
    }

    if (!ParseDriveLetter(pLocalName, szLocalName)) {
        result = ERROR_BAD_ARGUMENTS;
        (void)fwprintf(stderr, L"Invalid drive letter '%s'. "
            L"Expected 'C' or 'C:'.\n\n",
            pLocalName);
        PrintUmountUsage(argv[0]);
        goto out;
    }

    result = DoUnmount(szLocalName, bForceUnmount);
    if (result)
        PrintErrorMessage(result);
out:
    return result;
}


static
int list_nfs_mounts_main(int argc, wchar_t *argv[])
{
    DWORD result;

    /* Unused for now */
    (void)argc;
    (void)argv;

    /* list open nfs shares */
    result = EnumMounts(NULL);
    if (result)
        PrintErrorMessage(GetLastError());

    return result;
}


int __cdecl wmain(int argc, wchar_t *argv[])
{
    DWORD result = NO_ERROR;
    int crtsetdbgflags = 0;

    (void)setlocale(LC_ALL, "");
    /*
     * |_O_WTEXT| - set streams to wide-char mode so we print
     * non-ASCII characters like Japanese or Chinese/GB18030
     * correctly.
     * Note that in CRT/UCRT any attempt to use single-byte
     * functions like |printf()| will trigger an exception
     */
    (void)_setmode(_fileno(stdout), _O_WTEXT);
    (void)_setmode(_fileno(stderr), _O_WTEXT);

    crtsetdbgflags |= _CRTDBG_ALLOC_MEM_DF;  /* use debug heap */
    crtsetdbgflags |= _CRTDBG_LEAK_CHECK_DF; /* report leaks on exit */
    crtsetdbgflags |= _CRTDBG_DELAY_FREE_MEM_DF;
    (void)_CrtSetDbgFlag(crtsetdbgflags);
    (void)_CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    (void)_CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);

    if (argc == 1) {
        result = list_nfs_mounts_main(argc, argv);
        goto out;
    }
    else if (wcsstr(argv[0], L"nfs_mount")) {
        result = mount_main(argc, argv);
        goto out;
    }
    else if (wcsstr(argv[0], L"nfs_umount")) {
        result = umount_main(argc, argv);
        goto out;
    }
    else {
        (void)fwprintf(stderr, L"%s: Unknown mode\n", argv[0]);
        result = 1;
        goto out;
    }

out:
    /*
     * POSIX return value of a command can only in the range from
     * |0|...|SCHAR_MAX|, so map the |ERROR_*| to |1|,|0|.
     */
    return (result != NO_ERROR)?1:0;
}


static void ConvertUnixSlashes(
    IN OUT LPWSTR pRemoteName)
{
    LPWSTR pos = pRemoteName;
    for (pos = pRemoteName; *pos; pos++)
        if (*pos == L'/')
            *pos = L'\\';
}


char *wcs2utf8str(const wchar_t *wstr)
{
    char *utf8str;
    size_t wstr_len;
    size_t utf8_len;

    wstr_len = wcslen(wstr);
    utf8_len = WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS|WC_NO_BEST_FIT_CHARS,
        wstr, (int)wstr_len, NULL, 0, NULL, NULL);
    if (utf8_len == 0)
        return NULL;

    utf8str = malloc(utf8_len+1);
    if (!utf8str) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    (void)WideCharToMultiByte(CP_UTF8,
        WC_ERR_INVALID_CHARS|WC_NO_BEST_FIT_CHARS,
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
    wstr_len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        utf8str, (int)utf8len, NULL, 0);
    if (wstr_len == 0)
        return NULL;

    wstr = malloc((wstr_len+1)*sizeof(wchar_t));
    if (!wstr) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    (void)MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        utf8str, (int)utf8len, wstr, (int)wstr_len);
    wstr[wstr_len] = L'\0';
    return wstr;
}

static DWORD ParseRemoteName(
    IN bool use_nfspubfh,
    IN int override_portnum,
    IN LPWSTR pRemoteName,
    IN OUT PMOUNT_OPTION_LIST pOptions,
    OUT LPWSTR pParsedRemoteName,
    OUT LPWSTR pConnectionName,
    IN size_t cchConnectionLen)
{
    DWORD result = NO_ERROR;
    LPWSTR pEnd;
    wchar_t *mountstrmem = NULL;
    int port = MOUNT_CONFIG_NFS_PORT_DEFAULT;
    wchar_t remotename[NFS41_SYS_MAX_PATH_LEN];
    wchar_t *premotename = remotename;
/* sizeof(hostname+'@'+integer) */
#define SRVNAME_LEN (NFS41_SYS_MAX_PATH_LEN+1+32)
    wchar_t srvname[SRVNAME_LEN];
    url_parser_context *uctx = NULL;

    result = StringCchCopyW(premotename, NFS41_SYS_MAX_PATH_LEN, pRemoteName);

    /*
     * Support nfs://-URLS per RFC 2224 ("NFS URL
     * SCHEME", see https://www.rfc-editor.org/rfc/rfc2224.html),
     * including port support (nfs://hostname@port/path/...)
     */
    if (!wcsncmp(premotename, L"nfs://", 6)) {
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
            result = GetLastError();
            (void)fwprintf(stderr,
                L"wcs2utf8str() failed, lasterr=%d\n.",
                (int)result);
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
            (void)fwprintf(stderr, L"Error parsing nfs://-URL '%S'.\n", premotename_utf8);
            goto out;
        }

        if (uctx->login.username || uctx->login.passwd) {
            result = ERROR_BAD_ARGUMENTS;
            (void)fwprintf(stderr,
                L"Username/Password are not defined for nfs://-URL.\n");
            goto out;
        }

        if (uctx->num_parameters > 0) {
            int pi;
            const char *pname;
            const char *pvalue;

            /*
             * Values added here based on URL parameters
             * are added at the front of the list of options,
             * so users can override the nfs://-URL given default.
             */
            for (pi = 0; pi < uctx->num_parameters ; pi++) {
                pname = uctx->parameters[pi].name;
                pvalue = uctx->parameters[pi].value;

                if (!strcmp(pname, "rw")) {
                    if ((pvalue == NULL) || (!strcmp(pvalue, "1"))) {
                        (void)InsertOption(L"rw", L"1", pOptions);
                    }
                    else if (!strcmp(pvalue, "0")) {
                        (void)InsertOption(L"ro", L"1", pOptions);
                    }
                    else {
                        result = ERROR_BAD_ARGUMENTS;
                        (void)fwprintf(stderr,
                            L"Unsupported nfs://-URL parameter "
                            L"'%S' value '%S'.\n",
                            pname, pvalue);
                        goto out;
                    }
                }
                else if (!strcmp(pname, "ro")) {
                    if ((pvalue == NULL) || (!strcmp(pvalue, "1"))) {
                        (void)InsertOption(L"ro", L"1", pOptions);
                    }
                    else if (!strcmp(pvalue, "0")) {
                        (void)InsertOption(L"rw", L"1", pOptions);
                    }
                    else {
                        result = ERROR_BAD_ARGUMENTS;
                        (void)fwprintf(stderr,
                            L"Unsupported nfs://-URL parameter "
                            L"'%S' value '%S'.\n",
                            pname, pvalue);
                        goto out;
                    }
                }
                else {
                    result = ERROR_BAD_ARGUMENTS;
                    (void)fwprintf(stderr,
                        L"Unsupported nfs://-URL parameter '%S'.\n",
                        pname);
                    goto out;
                }
            }
        }

        if (uctx->hostport.port != -1)
            port = uctx->hostport.port;

        hostname_wstr = utf8str2wcs(uctx->hostport.hostname);
        if (!hostname_wstr) {
            result = GetLastError();
            (void)fwprintf(stderr, L"Cannot convert URL host '%S', lasterr=%d\n",
                uctx->hostport.hostname, result);
            goto out;
        }

        (void)wcscpy_s(premotename, NFS41_SYS_MAX_PATH_LEN, hostname_wstr);
        free(hostname_wstr);
        ConvertUnixSlashes(premotename);

        if (!uctx->path) {
            result = ERROR_BAD_ARGUMENTS;
            (void)fwprintf(stderr, L"Path missing in nfs://-URL\n");
            goto out;
        }

        if (uctx->path[0] != '/') {
            result = ERROR_BAD_ARGUMENTS;
            (void)fwprintf(stderr, L"Relative nfs://-URLs are not supported\n");
            goto out;
        }

        pEnd = mountstrmem = utf8str2wcs(uctx->path);
        if (!mountstrmem) {
            result = GetLastError();
            (void)fwprintf(stderr, L"Cannot convert URL path '%S', lasterr=%d\n",
                uctx->path, result);
            goto out;
        }
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
        if (wcsrchr(premotename, L'@')) {
            (void)fwprintf(stderr,
                L"Remote path should not contain '@', "
                L"use -o port=tcpportnum.\n");
            result = ERROR_BAD_ARGUMENTS;
            goto out;
        }

        /* fail if the server name doesn't end with :\ */
        pEnd = wcsrchr(premotename, L':');
        if (pEnd == NULL || pEnd[1] != L'\\') {
            (void)fwprintf(stderr, L"Failed to parse the remote path. "
                L"Expected 'hostname:\\path'.\n");
            result = ERROR_BAD_ARGUMENTS;
            goto out;
        }
        *pEnd++ = L'\0';
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
    if (premotename[0] == L'[') {
        size_t len = wcslen(premotename);
        size_t i;
        wchar_t c;

        /* Check for minimum length and trailing ']' */
        if ((len < 4) || (premotename[len-1] != L']')) {
            fwprintf(stderr, L"Failed to parse raw IPv6 address,"
	        L" trailing ']' is missing, "
		L"or address string too short.\n");
            result = ERROR_BAD_ARGUMENTS;
            goto out;
	}

        /* Skip '[', stomp ']' */
        premotename[len-1] = L'\0';
        premotename++;
        len -= 2;

        /* Check whether this is a valid IPv6 address */
        for (i=0 ; i < len ; i++) {
            c = premotename[i];
            if (!(iswxdigit(c) || (c == L':'))) {
                fwprintf(stderr, L"Failed to parse raw IPv6 "
		    L"address, illegal character '%c' found.\n",
		    c);
                result = ERROR_BAD_ARGUMENTS;
                goto out;
            }
        }

	for (i = 0 ; i < len ; i++) {
	    /* IPv6 separator */
            if (premotename[i] == L':')
                premotename[i] = L'-';
	    /* zone index */
	    else if (premotename[i] == L'%')
                premotename[i] = L's';
        }

        /*
	 * 1. Append .ipv6-literal.net to hostname
	 * 2. ALWAYS add port number to hostname, so UNC paths use it
	 *   too
	 */
        (void)swprintf(srvname, SRVNAME_LEN,
	    L"%s.ipv6-literal.net@%d", premotename, port);
    }
    else {
        /* ALWAYS add port number to hostname, so UNC paths use it too */
        (void)swprintf(srvname, SRVNAME_LEN, L"%s@%d",
	    premotename, port);
    }

    /*
     * Safeguard against ':' in UNC paths, e.g if we pass raw IPv6
     * address without ':', or just random garbage
     */
    if (wcschr(srvname, L':')) {
        fwprintf(stderr,
	    L"Illegal ':' character hostname '%s'.\n", srvname);
        result = ERROR_BAD_ARGUMENTS;
        goto out;
    }

#ifdef DEBUG_MOUNT
    (void)fwprintf(stderr,
        L"srvname='%s', mntpt='%s'\n",
        srvname,
        pEnd);
#endif

    if (!InsertOption(L"srvname", srvname, pOptions) ||
        !InsertOption(L"mntpt", (*pEnd ? pEnd : L"\\"), pOptions)) {
        result = ERROR_BAD_ARGUMENTS;
        goto out;
    }

    result = StringCchCopyW(pConnectionName, cchConnectionLen, L"\\\\");
    if (FAILED(result))
        goto out;
    result = StringCbCatW(pConnectionName, cchConnectionLen, srvname);
    if (FAILED(result))
        goto out;
#ifdef NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX
    result = StringCbCatW(pConnectionName, cchConnectionLen,
        (use_nfspubfh?(L"\\pubnfs4"):(L"\\nfs4")));
    if (FAILED(result))
        goto out;
#endif /* NFS41_DRIVER_MOUNT_DOES_NFS4_PREFIX */
    if (*pEnd)
        result = StringCchCatW(pConnectionName, cchConnectionLen, pEnd);

    result = StringCchCopyW(pParsedRemoteName, cchConnectionLen, srvname);

#ifdef DEBUG_MOUNT
    (void)fwprintf(stderr,
        L"pConnectionName='%s', pParsedRemoteName='%s', use_nfspubfh='%d'\n",
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
    IN LPWSTR pLocalName,
    IN LPWSTR pRemoteName,
    IN LPWSTR pParsedRemoteName,
    IN BOOL bPersistent,
    IN PMOUNT_OPTION_LIST pOptions)
{
    DWORD result = NO_ERROR;
    wchar_t szExisting[NFS41_SYS_MAX_PATH_LEN];
    DWORD dwLength;
    NETRESOURCEW NetResource;

    if (pOptions->Buffer->Length) {
        if (pOptions->Current)
            pOptions->Current->NextEntryOffset = 0;
        NetResource.lpComment = (LPWSTR)&pOptions->Buffer[0];
    }

#ifdef DEBUG_MOUNT
    (void)fwprintf(stderr,
        L"DoMount(pLocalName='%s', pRemoteName='%s', pParsedRemoteName='%s')\n",
        pLocalName,
        pRemoteName,
        pParsedRemoteName);
    RecursivePrintEaInformation((PFILE_FULL_EA_INFORMATION)pOptions->Buffer->Buffer);
#endif /* DEBUG_MOUNT */

    if (pLocalName) {
        /* fail if the connection already exists */
        dwLength = NFS41_SYS_MAX_PATH_LEN;
        result = WNetGetConnectionW(pLocalName, (LPWSTR)szExisting, &dwLength);
        if (result == NO_ERROR) {
            result = ERROR_ALREADY_ASSIGNED;
            (void)fwprintf(stderr, L"Mount failed, drive '%s' is "
                L"already assigned to '%s'.\n",
                pLocalName, szExisting);
            return result;
        }
    }

    wchar_t szConnection[NFS41_SYS_MAX_PATH_LEN];
    DWORD ConnectSize = NFS41_SYS_MAX_PATH_LEN;
    DWORD ConnectResult;
    DWORD Flags = 0;

    (void)memset(&NetResource, 0, sizeof(NETRESOURCEW));
    NetResource.dwType = RESOURCETYPE_DISK;
    if (pLocalName) {
        /* drive letter is chosen automatically if lpLocalName == "*" */
        if (*pLocalName == L'*') {
            NetResource.lpLocalName = NULL;
            Flags |= CONNECT_REDIRECT;
        }
        else {
            NetResource.lpLocalName = pLocalName;
        }
    }
    else {
        NetResource.lpLocalName = NULL;
    }
    NetResource.lpRemoteName = pRemoteName;
    /* ignore other network providers */
    NetResource.lpProvider = NFS41_PROVIDER_NAME_U;
    /* pass mount options via lpComment */
    if (pOptions->Buffer->Length) {
        NetResource.lpComment = (LPWSTR)pOptions->Buffer;
    }

    if (bPersistent)
        Flags |= CONNECT_UPDATE_PROFILE;

    result = WNetUseConnectionW(NULL,
        &NetResource, NULL, NULL, Flags,
        szConnection, &ConnectSize, &ConnectResult);

    if (result == NO_ERROR) {
        (void)wprintf(L"Successfully mounted '%s' to drive '%s'\n",
            pParsedRemoteName, szConnection);
    }
    else {
        (void)fwprintf(stderr, L"WNetUseConnectionW('%s', '%s') "
            L"failed with error code %u.\n",
            pLocalName, pRemoteName, result);
    }

    return result;
}

static DWORD DoUnmount(
    IN LPWSTR pLocalName,
    IN BOOL bForce)
{
    DWORD result;

    /* disconnect the specified local drive */
    result = WNetCancelConnection2W(pLocalName, CONNECT_UPDATE_PROFILE, bForce);
    /* TODO: verify that this connection uses the nfs41 provider -cbodley */
    switch (result)
    {
    case NO_ERROR:
        (void)wprintf(L"Drive '%s' unmounted successfully.\n",
            pLocalName);
        break;
    case ERROR_NOT_CONNECTED:
        (void)fwprintf(stderr, L"Drive '%s' is not currently "
            L"connected.\n", pLocalName);
        break;
    default:
        (void)fwprintf(stderr, L"WNetCancelConnection2W('%s') failed "
            L"with error code %u.\n", pLocalName, result);
        break;
    }
    return result;
}

#define ISWDOSLETTER(c) \
    ( \
        (((c) >= L'a') && ((c) <= L'z')) || \
        (((c) >= L'A') && ((c) <= L'Z')) \
    )

static BOOL ParseDriveLetter(
    IN LPWSTR pArg,
    OUT PWCH pDriveLetter)
{
    /* accept 'C' or 'C:' */
    switch (wcslen(pArg)) {
        case 2:
            if (pArg[1] != L':')
                return FALSE;
            /* fall-through */
        case 1:
            if (!ISWDOSLETTER(*pArg) && (*pArg != L'*'))
                return FALSE;

            pDriveLetter[0] = towupper(*pArg);
            pDriveLetter[1] = L':';
            pDriveLetter[2] = L'\0';
            return TRUE;
    }

    return FALSE;
}

void PrintErrorMessage(
    IN DWORD dwError)
{
    LPWSTR lpMsgBuf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf, 0, NULL);
    (void)fputws(lpMsgBuf, stderr);
    LocalFree(lpMsgBuf);
}
