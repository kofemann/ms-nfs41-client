/* NFSv4.1 client for Windows
 * Copyright © 2023 Roland Mainz <roland.mainz@nrubsig.org>
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

#define CYGWIN_IDMAPPER_SCRIPT \
    ("C:\\cygwin64\\bin\\ksh93.exe " \
    "/cygdrive/c/cygwin64/lib/msnfs41client/cygwin_idmapper.ksh")


#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
int cygwin_getent_passwd(const char *name, char *res_loginname, uid_t *res_uid, gid_t *res_gid)
{
    char cmdbuff[1024];
    char buff[2048];
    DWORD num_buff_read;
    subcmd_popen_context *script_pipe = NULL;
    int res = 1;
    unsigned long uid = -1;
    unsigned long gid = -1;
    void *cpvp = NULL;
    int numcnv = 0;
    int i = 0;
    cpv_name_val cnv[64] = { 0 };
    cpv_name_val *cnv_cur = NULL;
    const char *localaccoutname = NULL;

    dprintf(CYGWINIDLVL, "--> cygwin_getent_passwd('%s')\n", name);

    /* fixme: better quoting for |name| needed */
    (void)snprintf(cmdbuff, sizeof(cmdbuff),
        "%s nfsserver_owner2localaccount \"%s\"",
        CYGWIN_IDMAPPER_SCRIPT,
        name);
    if ((script_pipe = subcmd_popen(cmdbuff)) == NULL) {
        int last_error = GetLastError();
        dprintf(0, "cygwin_getent_passwd: '%s' failed, GetLastError()='%d'\n",
            cmdbuff,
            last_error);
        goto fail;
    }

    if (!subcmd_readcmdoutput(script_pipe,
        buff, sizeof(buff), &num_buff_read)) {
        dprintf(0, "cygwin_getent_passwd: subcmd_readcmdoutput() failed\n");
        goto fail;
    }

    buff[num_buff_read] = '\0';

    if (num_buff_read < 10) {
        dprintf(0, "cygwin_getent_passwd: Could not read enough data, returned %d\n", (int)num_buff_read);
        goto fail;
    }

    cpvp = cpv_create_parser(buff, 0/*CPVFLAG_DEBUG_OUTPUT*/);
    if (!cpvp) {
        dprintf(0, "cygwin_getent_passwd: Could not create parser\n");
        goto fail;
    }

    if (cpv_read_cpv_header(cpvp)) {
        dprintf(0, "cygwin_getent_passwd: cpv_read_cpv_header failed\n");
        goto fail;
    }

    /* Loop parsing compound variable elements */
    for (numcnv=0 ;
        (cpv_parse_name_val(cpvp, &cnv[numcnv]) == 0) && (numcnv < 64) ;
        numcnv++) {
    }

    for (i=0 ; i < numcnv ; i++) {
        cnv_cur = &cnv[i];
        if (!strcmp("localaccoutname", cnv_cur->cpv_name)) {
            localaccoutname = cnv_cur->cpv_value;
        }
        else if (!strcmp("localuid", cnv_cur->cpv_name)) {
            errno = 0;
            uid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
        else if (!strcmp("localgid", cnv_cur->cpv_name)) {
            errno = 0;
            gid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
    }

    if (res_loginname)
        (void)strcpy_s(res_loginname, VAL_LEN, localaccoutname);
    *res_uid = uid;
    *res_gid = gid;
    res = 0;

fail:
    if (script_pipe)
        (void)subcmd_pclose(script_pipe);

    for (i=0 ; i < numcnv ; i++) {
        cpv_free_name_val_data(&cnv[i]);
    }

    cpv_free_parser(cpvp);

    if (res == 0) {
        dprintf(CYGWINIDLVL, "<-- cygwin_getent_passwd('%s'): "
            "returning res_uid=%lu, res_gid=%lu, res_loginname='%s'\n",
            name,
            (unsigned long)(*res_uid),
            (unsigned long)(*res_gid),
            res_loginname?res_loginname:"<NULL>");
    }
    else {
        dprintf(CYGWINIDLVL, "<-- cygwin_getent_passwd('%s'): no match found\n",
            name);
    }

    return res;
}

int cygwin_getent_group(const char* name, char* res_group_name, gid_t* res_gid)
{
    char cmdbuff[1024];
    char buff[2048];
    DWORD num_buff_read;
    subcmd_popen_context *script_pipe = NULL;
    int res = 1;
    unsigned long gid = -1;
    void *cpvp = NULL;
    int numcnv = 0;
    int i = 0;
    cpv_name_val cnv[64] = { 0 };
    cpv_name_val *cnv_cur = NULL;

    const char *localgroupname = NULL;

    dprintf(CYGWINIDLVL, "--> cygwin_getent_group('%s')\n", name);

    /* fixme: better quoting for |name| needed */
    (void)snprintf(cmdbuff, sizeof(cmdbuff),
        "%s nfsserver_owner_group2localgroup \"%s\"",
        CYGWIN_IDMAPPER_SCRIPT,
        name);
    if ((script_pipe = subcmd_popen(cmdbuff)) == NULL) {
        int last_error = GetLastError();
        dprintf(0, "cygwin_getent_group: '%s' failed, GetLastError()='%d'\n",
            cmdbuff,
            last_error);
        goto fail;
    }

    if (!subcmd_readcmdoutput(script_pipe,
        buff, sizeof(buff), &num_buff_read)) {
        dprintf(0, "cygwin_getent_group: subcmd_readcmdoutput() failed\n");
        goto fail;
    }

    buff[num_buff_read] = '\0';

    if (num_buff_read < 10) {
        dprintf(0, "cygwin_getent_group: Could not read enough data, returned %d\n", (int)num_buff_read);
        goto fail;
    }

    cpvp = cpv_create_parser(buff, 0/*CPVFLAG_DEBUG_OUTPUT*/);
    if (!cpvp) {
        dprintf(0, "cygwin_getent_group: Could not create parser\n");
        goto fail;
    }

    if (cpv_read_cpv_header(cpvp)) {
        dprintf(0, "cygwin_getent_group: cpv_read_cpv_header failed\n");
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
        }
        else if (!strcmp("localgid", cnv_cur->cpv_name)) {
            errno = 0;
            gid = strtol(cnv_cur->cpv_value, NULL, 10);
            if (errno != 0)
                goto fail;
        }
    }

    if (res_group_name)
        (void)strcpy_s(res_group_name, VAL_LEN, localgroupname);
    *res_gid = gid;
    res = 0;

fail:
    if (script_pipe)
        (void)subcmd_pclose(script_pipe);

    for (i=0 ; i < numcnv ; i++) {
        cpv_free_name_val_data(&cnv[i]);
    }

    cpv_free_parser(cpvp);

    if (res == 0) {
        dprintf(CYGWINIDLVL, "<-- cygwin_getent_group('%s'): "
            "returning res_gid=%lu, res_group_name='%s'\n",
            name,
            (unsigned long)(*res_gid),
            res_group_name?res_group_name:"<NULL>");
    }
    else {
        dprintf(CYGWINIDLVL, "<-- cygwin_getent_group('%s'): no match found\n",
            name);
    }

    return res;
}
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */
