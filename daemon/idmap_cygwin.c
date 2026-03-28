/* NFSv4.1 client for Windows
 * Copyright (C) 2023-2026 Roland Mainz <roland.mainz@nrubsig.org>
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

#include <Windows.h>
#include <strsafe.h>
#include <Winldap.h>
#include <stdlib.h> /* for strtoul() */
#include <time.h>

#include "nfs41_build_features.h"
#include "idmap.h"
#include "util.h"
#include "nfs41_const.h"
#include "list.h"
#include "daemon_debug.h"
#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
#include "cpvparser1.h"
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */

#define CYGWINIDLVL 2   /* dprintf level for idmap logging */

#define VAL_LEN 257

#ifdef _WIN64
#define CYGWIN_IDMAPPER_SCRIPT \
    ("C:\\cygwin64\\bin\\ksh93.exe " \
    "/cygdrive/c/cygwin64/lib/msnfs41client/cygwin_idmapper.ksh")
#else
#define CYGWIN_IDMAPPER_SCRIPT \
    ("C:\\cygwin\\bin\\ksh93.exe " \
    "/cygdrive/c/cygwin/lib/msnfs41client/cygwin_idmapper.ksh")
#endif /* _WIN64 */

#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
int cygwin_getent_passwd(
    const char *restrict name,
    char *restrict res_localaccountname,
    uid_t *restrict res_localuid,
    char *restrict res_nfsowner,
    uid_t *restrict res_nfsuid)
{
    char cmdbuff[1024];
    char buff[2048];
    DWORD num_buff_read;
    subcmd_popen_context *script_pipe = NULL;
    int res = 1;
    unsigned long localuid = ~0UL;
    unsigned long nfsuid = ~0UL;
    void *cpvp = NULL;
    int numcnv = 0;
    int i = 0;
    cpv_name_val cnv[64] = { 0 };
    cpv_name_val *cnv_cur = NULL;
    const char *localaccountname = NULL;
    const char *nfsowner = NULL;

    DPRINTF(CYGWINIDLVL,
        ("--> cygwin_getent_passwd(name='%s')\n",
        name));

    if (name[0] == '\0') {
        DPRINTF(0,
            ("cygwin_getent_passwd(name='%s'): "
            "ERROR: Empty user name.\n",
            name));
        goto fail;
    }

    EASSERT_MSG(IS_PRINCIPAL_NAME(name),
        ("name='%s' is not a principal\n", name));

    /* fixme: better quoting for |name| needed */
    (void)snprintf(cmdbuff, sizeof(cmdbuff),
        "%s nfsserver_owner2localaccount \"%s\"",
        CYGWIN_IDMAPPER_SCRIPT,
        name);
    if ((script_pipe = subcmd_popen(cmdbuff)) == NULL) {
        int last_error = GetLastError();
        DPRINTF(0,
            ("cygwin_getent_passwd(name='%s'): "
            "'%s' failed, GetLastError()='%d'\n",
            name,
            cmdbuff,
            last_error));
        goto fail;
    }

    if (!subcmd_readcmdoutput(script_pipe,
        buff, sizeof(buff), &num_buff_read)) {
        DPRINTF(0,
            ("cygwin_getent_passwd(name='%s'): "
            "subcmd_readcmdoutput() failed\n",
            name));
        goto fail;
    }

    buff[num_buff_read] = '\0';

    if (num_buff_read < 10) {
        DPRINTF(0,
            ("cygwin_getent_passwd(name='%s'): "
            "Could not read enough data, returned %d\n",
            name, (int)num_buff_read));
        goto fail;
    }

    cpvp = cpv_create_parser(buff, 0/*CPVFLAG_DEBUG_OUTPUT*/);
    if (!cpvp) {
        DPRINTF(0,
            ("cygwin_getent_passwd(name='%s'): "
            "Could not create parser\n",
            name));
        goto fail;
    }

    if (cpv_read_cpv_header(cpvp)) {
        DPRINTF(0,
            ("cygwin_getent_passwd(name='%s'): "
            "cpv_read_cpv_header failed\n",
            name));
        goto fail;
    }

    /* Loop parsing compound variable elements */
    for (numcnv=0 ;
        (cpv_parse_name_val(cpvp, &cnv[numcnv]) == 0) && (numcnv < 64) ;
        numcnv++) {
    }

    for (i=0 ; i < numcnv ; i++) {
        cnv_cur = &cnv[i];
        if (!strcmp("localaccountname", cnv_cur->cpv_name)) {
            localaccountname = cnv_cur->cpv_value;

            EASSERT_MSG(IS_PRINCIPAL_NAME(localaccountname),
                ("localaccountname='%s' is not a principal\n", localaccountname));
        }
        else if (!strcmp("nfsowner", cnv_cur->cpv_name)) {
            nfsowner = cnv_cur->cpv_value;

            EASSERT_MSG(IS_PRINCIPAL_NAME(nfsowner),
                ("nfsowner='%s' is not a principal\n", nfsowner));
        }
        else if (!strcmp("localuid", cnv_cur->cpv_name)) {
            errno = 0;
            localuid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
        else if (!strcmp("nfsuid", cnv_cur->cpv_name)) {
            errno = 0;
            nfsuid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
    }

    if (localaccountname == NULL)
        goto fail;
    if (nfsowner == NULL)
        goto fail;

    /*
     * Cygwin /usr/bin/getent passwd can return "Unknown+User"
     * in cases when an SID is valid but does not match an account.
     * The idmapper script must never return this!
     */
    if (!strcmp(localaccountname, "Unknown+User")) {
        eprintf("cygwin_getent_passwd(name='%s'): "
            "idmapper returned illegal value '%s'\n",
            name, localaccountname);
        goto fail;
    }

    if (res_localaccountname)
        (void)strcpy_s(res_localaccountname, VAL_LEN, localaccountname);
    if (res_nfsowner)
        (void)strcpy_s(res_nfsowner, VAL_LEN, nfsowner);
    if (res_localuid)
        *res_localuid = localuid;
    if (res_nfsuid)
        *res_nfsuid = nfsuid;
    res = 0;

fail:
    if (script_pipe)
        (void)subcmd_pclose(script_pipe);

    for (i=0 ; i < numcnv ; i++) {
        cpv_free_name_val_data(&cnv[i]);
    }

    cpv_free_parser(cpvp);

    if (res == 0) {
        DPRINTF(CYGWINIDLVL,
            ("<-- cygwin_getent_passwd(name='%s'): "
            "returning res_localuid=%u, res_localaccountname='%s', "
            "res_nfsowner='%s' res_nfsuid=%u\n",
            name,
            (unsigned int)(res_localuid?(*res_localuid):~0),
            res_localaccountname?res_localaccountname:"<NULL>",
            res_nfsowner?res_nfsowner:"<NULL>",
            (unsigned int)(res_nfsuid?*res_nfsuid:~0)));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- cygwin_getent_passwd(name='%s'): no match found\n",
            name));
    }

    return res;
}

int cygwin_getent_group(
    const char *restrict name,
    char *restrict res_localgroupname,
    gid_t *restrict res_localgid,
    char *restrict res_nfsownergroup,
    gid_t *restrict res_nfsgid)
{
    char cmdbuff[1024];
    char buff[2048];
    DWORD num_buff_read;
    subcmd_popen_context *script_pipe = NULL;
    int res = 1;
    unsigned long localgid = ~0UL;
    unsigned long nfsgid = ~0UL;
    void *cpvp = NULL;
    int numcnv = 0;
    int i = 0;
    cpv_name_val cnv[64] = { 0 };
    cpv_name_val *cnv_cur = NULL;

    const char *localgroupname = NULL;
    const char *nfsownergroup = NULL;

    DPRINTF(CYGWINIDLVL,
        ("--> cygwin_getent_group(name='%s')\n",
        name));

    if (name[0] == '\0') {
        DPRINTF(0,
            ("cygwin_getent_group(name='%s'): "
            "ERROR: Empty group name.\n",
            name));
        goto fail;
    }

    EASSERT_MSG(IS_PRINCIPAL_NAME(name),
        ("name='%s' is not a principal\n", name));

    /* fixme: better quoting for |name| needed */
    (void)snprintf(cmdbuff, sizeof(cmdbuff),
        "%s nfsserver_owner_group2localgroup \"%s\"",
        CYGWIN_IDMAPPER_SCRIPT,
        name);
    if ((script_pipe = subcmd_popen(cmdbuff)) == NULL) {
        int last_error = GetLastError();
        DPRINTF(0,
            ("cygwin_getent_group(name='%s'): "
            "'%s' failed, GetLastError()='%d'\n",
            name,
            cmdbuff,
            last_error));
        goto fail;
    }

    if (!subcmd_readcmdoutput(script_pipe,
        buff, sizeof(buff), &num_buff_read)) {
        DPRINTF(0,
            ("cygwin_getent_group(name='%s'): "
            "subcmd_readcmdoutput() failed\n",
            name));
        goto fail;
    }

    buff[num_buff_read] = '\0';

    if (num_buff_read < 10) {
        DPRINTF(0,
            ("cygwin_getent_group(name='%s'): "
            "Could not read enough data, returned %d\n",
            name, (int)num_buff_read));
        goto fail;
    }

    cpvp = cpv_create_parser(buff, 0/*CPVFLAG_DEBUG_OUTPUT*/);
    if (!cpvp) {
        DPRINTF(0,
            ("cygwin_getent_group(name='%s'): "
            "Could not create parser\n",
            name));
        goto fail;
    }

    if (cpv_read_cpv_header(cpvp)) {
        DPRINTF(0,
            ("cygwin_getent_group(name='%s'): "
            "cpv_read_cpv_header failed\n",
            name));
        goto fail;
    }

    /* Loop parsing compound variable elements */
    for (numcnv=0 ;
        (cpv_parse_name_val(cpvp, &cnv[numcnv]) == 0) && (numcnv < 64) ;
        numcnv++) {
    }

    for (i=0 ; i < numcnv ; i++) {
        cnv_cur = &cnv[i];
        if (!strcmp("localgroupname", cnv_cur->cpv_name)) {
            localgroupname = cnv_cur->cpv_value;

            EASSERT_MSG(IS_PRINCIPAL_NAME(localgroupname),
                ("localgroupname='%s' is not a principal\n", localgroupname));
        }
        else if (!strcmp("nfsownergroup", cnv_cur->cpv_name)) {
            nfsownergroup = cnv_cur->cpv_value;

            EASSERT_MSG(IS_PRINCIPAL_NAME(nfsownergroup),
                ("nfsownergroup='%s' is not a principal\n", nfsownergroup));
        }
        else if (!strcmp("localgid", cnv_cur->cpv_name)) {
            errno = 0;
            localgid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
        else if (!strcmp("nfsgid", cnv_cur->cpv_name)) {
            errno = 0;
            nfsgid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
    }

    if (localgroupname == NULL)
        goto fail;
    if (nfsownergroup == NULL)
        goto fail;

    /*
     * Cygwin /usr/bin/getent group can return "Unknown+Group"
     * in cases when an SID is valid but does not match an account.
     * The idmapper script must never return this!
     */
    if (!strcmp(localgroupname, "Unknown+Group")) {
        eprintf("cygwin_getent_group(name='%s'): "
            "idmapper returned illegal value '%s'\n",
            name, localgroupname);
        goto fail;
    }

    if (res_localgroupname)
        (void)strcpy_s(res_localgroupname, VAL_LEN, localgroupname);
    if (res_nfsownergroup)
        (void)strcpy_s(res_nfsownergroup, VAL_LEN, nfsownergroup);
    if (res_localgid)
        *res_localgid = localgid;
    if (res_nfsgid)
        *res_nfsgid = nfsgid;
    res = 0;

fail:
    if (script_pipe)
        (void)subcmd_pclose(script_pipe);

    for (i=0 ; i < numcnv ; i++) {
        cpv_free_name_val_data(&cnv[i]);
    }

    cpv_free_parser(cpvp);

    if (res == 0) {
        DPRINTF(CYGWINIDLVL,
            ("<-- cygwin_getent_group(name='%s'): "
            "returning res_localgid=%u, res_localgroupname='%s', res_nfsownergroup='%s', res_localgid=%u\n",
            name,
            (unsigned int)(res_localgid?*res_localgid:~0),
            res_localgroupname?res_localgroupname:"<NULL>",
            res_nfsownergroup?res_nfsownergroup:"<NULL>",
            (unsigned int)(res_nfsgid?*res_nfsgid:~0)));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- cygwin_getent_group(name='%s'): no match found\n",
            name));
    }

    return res;
}
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */
