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
#include <stdlib.h> /* for strtoul() */
#include <stdbool.h>
//#include <stdio.h>
#include <string.h>
#include <time.h>
#include "queue.h"

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
static
int cygwin_getent_passwd(
    const char *restrict mode,
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
        ("--> cygwin_getent_passwd(mode='%s',name='%s')\n",
        mode, name));

    if (name[0] == '\0') {
        DPRINTF(0,
            ("cygwin_getent_passwd(mode='%s',name='%s'): "
            "ERROR: Empty user name.\n",
            mode, name));
        goto fail;
    }

    if (!isdigit(name[0])) {
        EASSERT_MSG(IS_PRINCIPAL_NAME(name),
            ("name='%s' is not a principal\n", name));
    }

    /* fixme: better quoting for |name| needed */
    (void)snprintf(cmdbuff, sizeof(cmdbuff),
        "%s %s \"%s\"",
        CYGWIN_IDMAPPER_SCRIPT,
        mode,
        name);
    if ((script_pipe = subcmd_popen(cmdbuff)) == NULL) {
        int last_error = GetLastError();
        DPRINTF(0,
            ("cygwin_getent_passwd(mode='%s',name='%s'): "
            "'%s' failed, GetLastError()='%d'\n",
            mode,
            name,
            cmdbuff,
            last_error));
        goto fail;
    }

    if (!subcmd_readcmdoutput(script_pipe,
        buff, sizeof(buff), &num_buff_read)) {
        DPRINTF(0,
            ("cygwin_getent_passwd(mode='%s',name='%s'): "
            "subcmd_readcmdoutput() failed\n",
            mode, name));
        goto fail;
    }

    buff[num_buff_read] = '\0';

    if (num_buff_read < 10) {
        DPRINTF(0,
            ("cygwin_getent_passwd(mode='%s',name='%s'): "
            "Could not read enough data, returned %d\n",
            mode, name, (int)num_buff_read));
        goto fail;
    }

    cpvp = cpv_create_parser(buff, 0/*CPVFLAG_DEBUG_OUTPUT*/);
    if (!cpvp) {
        DPRINTF(0,
            ("cygwin_getent_passwd(mode='%s',name='%s'): "
            "Could not create parser\n",
            mode, name));
        goto fail;
    }

    if (cpv_read_cpv_header(cpvp)) {
        DPRINTF(0,
            ("cygwin_getent_passwd(mode='%s',name='%s'): "
            "cpv_read_cpv_header failed\n",
            mode, name));
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
        eprintf("cygwin_getent_passwd(mode='%s',name='%s'): "
            "idmapper returned illegal value '%s'\n",
            mode, name, localaccountname);
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
            ("<-- cygwin_getent_passwd(mode='%s',name='%s'): "
            "returning res_localuid=%u, res_localaccountname='%s', "
            "res_nfsowner='%s' res_nfsuid=%u\n",
            mode,
            name,
            (unsigned int)(res_localuid?(*res_localuid):~0),
            res_localaccountname?res_localaccountname:"<NULL>",
            res_nfsowner?res_nfsowner:"<NULL>",
            (unsigned int)(res_nfsuid?*res_nfsuid:~0)));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- cygwin_getent_passwd(mode='%s',name='%s'): no match found\n",
            mode, name));
    }

    return res;
}

int cygwin_local_getent_passwd(
    const char *restrict name,
    char *restrict res_localaccountname,
    uid_t *restrict res_localuid,
    char *restrict res_nfsowner,
    uid_t *restrict res_nfsuid)
{
    return cygwin_getent_passwd(
        "lookup_user_by_localname",
        name,
        res_localaccountname,
        res_localuid,
        res_nfsowner,
        res_nfsuid);
}

int cygwin_nfsserver_getent_passwd(
    const char *restrict name,
    char *restrict res_localaccountname,
    uid_t *restrict res_localuid,
    char *restrict res_nfsowner,
    uid_t *restrict res_nfsuid)
{
    return cygwin_getent_passwd(
        "lookup_user_by_nfsserver_owner",
        name,
        res_localaccountname,
        res_localuid,
        res_nfsowner,
        res_nfsuid);
}

static
int cygwin_getent_group(
    const char *restrict mode,
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
        ("--> cygwin_getent_group(mode='%s',name='%s')\n",
        mode, name));

    if (name[0] == '\0') {
        DPRINTF(0,
            ("cygwin_getent_group(mode='%s',name='%s'): "
            "ERROR: Empty group name.\n",
            mode, name));
        goto fail;
    }

    if (!isdigit(name[0])) {
        EASSERT_MSG(IS_PRINCIPAL_NAME(name),
            ("name='%s' is not a principal\n", name));
    }

    /* fixme: better quoting for |name| needed */
    (void)snprintf(cmdbuff, sizeof(cmdbuff),
        "%s %s \"%s\"",
        CYGWIN_IDMAPPER_SCRIPT,
        mode,
        name);
    if ((script_pipe = subcmd_popen(cmdbuff)) == NULL) {
        int last_error = GetLastError();
        DPRINTF(0,
            ("cygwin_getent_group(mode='%s',name='%s'): "
            "'%s' failed, GetLastError()='%d'\n",
            mode,
            name,
            cmdbuff,
            last_error));
        goto fail;
    }

    if (!subcmd_readcmdoutput(script_pipe,
        buff, sizeof(buff), &num_buff_read)) {
        DPRINTF(0,
            ("cygwin_getent_group(mode='%s',name='%s'): "
            "subcmd_readcmdoutput() failed\n",
            mode, name));
        goto fail;
    }

    buff[num_buff_read] = '\0';

    if (num_buff_read < 10) {
        DPRINTF(0,
            ("cygwin_getent_group(mode='%s',name='%s'): "
            "Could not read enough data, returned %d\n",
            mode, name, (int)num_buff_read));
        goto fail;
    }

    cpvp = cpv_create_parser(buff, 0/*CPVFLAG_DEBUG_OUTPUT*/);
    if (!cpvp) {
        DPRINTF(0,
            ("cygwin_getent_group(mode='%s',name='%s'): "
            "Could not create parser\n",
            mode, name));
        goto fail;
    }

    if (cpv_read_cpv_header(cpvp)) {
        DPRINTF(0,
            ("cygwin_getent_group(mode='%s',name='%s'): "
            "cpv_read_cpv_header failed\n",
            mode, name));
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
        eprintf("cygwin_getent_group(mode='%s',name='%s'): "
            "idmapper returned illegal value '%s'\n",
            mode, name, localgroupname);
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
            ("<-- cygwin_getent_group(mode='%s',name='%s'): "
            "returning res_localgid=%u, res_localgroupname='%s', res_nfsownergroup='%s', res_localgid=%u\n",
            mode,
            name,
            (unsigned int)(res_localgid?*res_localgid:~0),
            res_localgroupname?res_localgroupname:"<NULL>",
            res_nfsownergroup?res_nfsownergroup:"<NULL>",
            (unsigned int)(res_nfsgid?*res_nfsgid:~0)));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- cygwin_getent_group(mode='%s',name='%s'): no match found\n",
            mode, name));
    }

    return res;
}

int cygwin_local_getent_group(
    const char *restrict name,
    char *restrict res_localgroupname,
    gid_t *restrict res_localgid,
    char *restrict res_nfsownergroup,
    gid_t *restrict res_nfsgid)
{
    return cygwin_getent_group(
        "lookup_group_by_localgroup",
        name,
        res_localgroupname,
        res_localgid,
        res_nfsownergroup,
        res_nfsgid);
}

int cygwin_nfsserver_getent_group(
    const char *restrict name,
    char *restrict res_localgroupname,
    gid_t *restrict res_localgid,
    char *restrict res_nfsownergroup,
    gid_t *restrict res_nfsgid)
{
    return cygwin_getent_group(
        "lookup_group_by_nfsserver_owner_group",
        name,
        res_localgroupname,
        res_localgid,
        res_nfsownergroup,
        res_nfsgid);
}
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */


/*
 * New idmapper cache
 */
struct idmapcache_node {
    struct _idmapcache_entry entry;

    LIST_ENTRY(idmapcache_node) list_node;
    volatile LONG refcounter;
};

LIST_HEAD(idmapcache_head, idmapcache_node);

typedef struct _idmapcache_context {
    struct idmapcache_head head;
    SRWLOCK lock;
} idmapcache_context;

typedef bool (*idmapcache_cmp_fn)(const struct idmapcache_node *restrict entry, const void *restrict search_val);

void idmapcache_entry_refcount_inc(idmapcache_entry *restrict e)
{
    struct idmapcache_node *en = (struct idmapcache_node *)e;
    (void)InterlockedIncrement(&en->refcounter);
}

void idmapcache_entry_refcount_dec(idmapcache_entry *restrict e)
{
    struct idmapcache_node *en = (struct idmapcache_node *)e;
    if (InterlockedDecrement(&en->refcounter) == 0) {
        free(e);
    }
}

static
bool cmp_by_win32name(const struct idmapcache_node *restrict node, const void *restrict search_val)
{
    const idmap_namestr *search_str = (const idmap_namestr *)search_val;

    if (search_str->len != node->entry.win32name.len) {
        return false;
    }
    return memcmp(node->entry.win32name.buf, search_str->buf, search_str->len) == 0;
}

static
bool cmp_by_nfsname(const struct idmapcache_node *restrict node, const void *restrict search_val)
{
    const idmap_namestr *search_str = (const idmap_namestr *)search_val;

    if (search_str->len != node->entry.nfsname.len) {
        return false;
    }
    return memcmp(node->entry.nfsname.buf, search_str->buf, search_str->len) == 0;
}

static
bool cmp_by_localid(const struct idmapcache_node *restrict node, const void *restrict search_val)
{
    return node->entry.localid == *(const idmapcache_idnumber *)search_val;
}

static
bool cmp_by_nfsid(const struct idmapcache_node *restrict node, const void *restrict search_val)
{
    return node->entry.nfsid == *(const idmapcache_idnumber *)search_val;
}

static
idmapcache_entry *idmapcache_lookup(idmapcache_context *restrict ctx,
    idmapcache_cmp_fn cmp,
    const void *restrict search_val)
{
    struct idmapcache_node *found_node = NULL;
    time_t current_time;
    struct idmapcache_node *node;

    AcquireSRWLockShared(&ctx->lock);

    current_time = time(NULL);

    LIST_FOREACH(node, &ctx->head, list_node) {
        if ((current_time - node->entry.last_updated) > IDMAPCACHE_TTL_SECONDS)
            continue;

        if (cmp(node, search_val)) {
            found_node = node;
            idmapcache_entry_refcount_inc(&found_node->entry);
            break;
        }
    }

    ReleaseSRWLockShared(&ctx->lock);

    return (found_node != NULL)?(&found_node->entry):(NULL);
}

static
void cleanup_expired_entries(idmapcache_context *restrict ctx, time_t current_time)
{
    struct idmapcache_node *node;
    struct idmapcache_node *tmpnode;

    for (node = LIST_FIRST(&ctx->head) ; node != NULL ; node = tmpnode) {
        tmpnode = LIST_NEXT(node, list_node);

        if ((current_time - node->entry.last_updated) > IDMAPCACHE_TTL_SECONDS) {
            LIST_REMOVE(node, list_node);
            idmapcache_entry_refcount_dec(&node->entry);
        }
    }
}

idmapcache_context *idmapcache_context_create(void)
{
    idmapcache_context *ctx = malloc(sizeof(struct _idmapcache_context));
    if (ctx == NULL)
        return NULL;

    (void)memset(ctx, 0, sizeof(*ctx));
    InitializeSRWLock(&ctx->lock);
    LIST_INIT(&ctx->head);

    return ctx;
}

void idmapcache_context_destroy(idmapcache_context *restrict ctx)
{
    AcquireSRWLockExclusive(&ctx->lock);

    struct idmapcache_node *node = LIST_FIRST(&ctx->head);
    struct idmapcache_node *tmp;

    while (node != NULL) {
        tmp = LIST_NEXT(node, list_node);
        LIST_REMOVE(node, list_node);
        idmapcache_entry_refcount_dec(&node->entry);

        node = tmp;
    }

    ReleaseSRWLockExclusive(&ctx->lock);
    free(ctx);
}

idmapcache_entry *idmapcache_add(idmapcache_context *restrict ctx,
    const char *restrict win32name,
    idmapcache_idnumber localid,
    const char *restrict nfsname,
    idmapcache_idnumber nfsid)
{
    size_t win32name_len = strlen(win32name);
    if (win32name_len >= IDMAPCACHE_MAXNAME_LEN)
        return false;

    size_t nfsname_len = strlen(nfsname);
    if (nfsname_len >= IDMAPCACHE_MAXNAME_LEN)
        return false;

    struct idmapcache_node *new_node = malloc(sizeof(struct idmapcache_node));
    if (new_node == NULL)
        return false;

    (void)memset(new_node, 0, sizeof(*new_node)); /* only debug */
    /*
     * Refcounter: One count to stay valid in the list,
     * and one count for the return cod
     */
    new_node->refcounter = 1L + 1L;

    (void)memcpy(new_node->entry.win32name.buf, win32name, win32name_len);
    new_node->entry.win32name.buf[win32name_len] = '\0';
    new_node->entry.win32name.len = win32name_len;

    new_node->entry.localid = localid;

    (void)memcpy(new_node->entry.nfsname.buf, nfsname, nfsname_len);
    new_node->entry.nfsname.buf[nfsname_len] = '\0';
    new_node->entry.nfsname.len = nfsname_len;

    new_node->entry.nfsid = nfsid;

    AcquireSRWLockExclusive(&ctx->lock);

    time_t current_time = time(NULL);
    new_node->entry.last_updated = current_time;

    cleanup_expired_entries(ctx, current_time);
    LIST_INSERT_HEAD(&ctx->head, new_node, list_node);

    ReleaseSRWLockExclusive(&ctx->lock);

    return &new_node->entry;
}

idmapcache_entry *idmapcache_lookup_by_win32name(idmapcache_context *restrict ctx,
    const char *restrict win32name)
{
    idmap_namestr search_term;
    search_term.len = strlen(win32name);
    if (search_term.len >= IDMAPCACHE_MAXNAME_LEN)
        return NULL;
    (void)memcpy(search_term.buf, win32name, search_term.len);

    return idmapcache_lookup(ctx, cmp_by_win32name, &search_term);
}

idmapcache_entry *idmapcache_lookup_by_localid(idmapcache_context *restrict ctx,
    idmapcache_idnumber search_localid)
{
    return idmapcache_lookup(ctx, cmp_by_localid, &search_localid);
}

idmapcache_entry *idmapcache_lookup_by_nfsname(idmapcache_context *restrict ctx,
    const char *restrict nfsname)
{
    idmap_namestr search_term;
    search_term.len = strlen(nfsname);
    if (search_term.len >= IDMAPCACHE_MAXNAME_LEN)
        return NULL;
    (void)memcpy(search_term.buf, nfsname, search_term.len);

    return idmapcache_lookup(ctx, cmp_by_nfsname, &search_term);
}

idmapcache_entry *idmapcache_lookup_by_nfsid(idmapcache_context *restrict ctx,
    idmapcache_idnumber search_nfsid)
{
    return idmapcache_lookup(ctx, cmp_by_nfsid, &search_nfsid);
}

/*
 * Public idmapper API
 */

idmapcache_entry *nfs41_idmap_user_lookup_by_win32name(struct idmap_context *context,
    const char *restrict name)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_user_lookup_by_win32name(name='%s')\n",
        name));

    ie = idmapcache_lookup_by_win32name(context->usercache, name);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    uid_t localuid;
    char nfsowner[IDMAPCACHE_MAXNAME_LEN];
    uid_t nfsuid;

    if (!cygwin_local_getent_passwd(name,
        localname,
        &localuid,
        nfsowner,
        &nfsuid)) {
        DPRINTF(0,
            ("nfs41_idmap_user_lookup_by_win32name(name='%s'): "
            "Adding new user entry localname='%s', localuid=%ld, nfsowner='%s', nfsuid=%ld\n",
            name,
            localname,
            (long)localuid,
            nfsowner,
            (long)nfsuid));

        ie = idmapcache_add(context->usercache,
            localname,
            localuid,
            nfsowner,
            nfsuid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_user_lookup_by_win32name(name='%s'): idmapcache_add() failed\n",
                name));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_win32name(name='%s'): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localuid=%ld, nfsname='%s', nfsid=%ld\n",
            name,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_win32name(name='%s'): "
            "returning status=%d / ie=NULL\n",
            name,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_user_lookup_by_localid(struct idmap_context *context,
    idmapcache_idnumber search_localid)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_user_lookup_by_localid(search_localid=%ld)\n",
        (long)search_localid));

    ie = idmapcache_lookup_by_localid(context->usercache, search_localid);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    uid_t localuid;
    char nfsowner[IDMAPCACHE_MAXNAME_LEN];
    uid_t nfsuid;
    char name[64];
    (void)sprintf(name, "%ld", (long)search_localid);

    if (!cygwin_local_getent_passwd(name,
        localname,
        &localuid,
        nfsowner,
        &nfsuid)) {
        DPRINTF(0,
            ("nfs41_idmap_user_lookup_by_localid(search_localid=%ld): "
            "Adding new user entry localname='%s', localuid=%ld, nfsowner='%s', nfsuid=%ld\n",
            (long)search_localid,
            localname,
            (long)localuid,
            nfsowner,
            (long)nfsuid));

        ie = idmapcache_add(context->usercache,
            localname,
            localuid,
            nfsowner,
            nfsuid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_user_lookup_by_localid(search_localid=%ld): idmapcache_add() failed\n",
                (long)search_localid));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_localid(search_localid=%ld): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localuid=%ld, nfsname='%s', nfsid=%ld\n",
            (long)search_localid,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_localid(search_localid=%ld): "
            "returning status=%d / ie=NULL\n",
            (long)search_localid,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_user_lookup_by_nfsname(struct idmap_context *context,
    const char *restrict name)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_user_lookup_by_nfsname(name='%s')\n",
        name));

    ie = idmapcache_lookup_by_nfsname(context->usercache, name);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    uid_t localuid;
    char nfsowner[IDMAPCACHE_MAXNAME_LEN];
    uid_t nfsuid;

    if (!cygwin_nfsserver_getent_passwd(name,
        localname,
        &localuid,
        nfsowner,
        &nfsuid)) {
        DPRINTF(0,
            ("nfs41_idmap_user_lookup_by_nfsname(name='%s'): "
            "Adding new user entry localname='%s', localuid=%ld, nfsowner='%s', nfsuid=%ld\n",
            name,
            localname,
            (long)localuid,
            nfsowner,
            (long)nfsuid));

        ie = idmapcache_add(context->usercache,
            localname,
            localuid,
            nfsowner,
            nfsuid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_user_lookup_by_nfsname(name='%s'): idmapcache_add() failed\n",
                name));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_nfsname(name='%s'): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localuid=%ld, nfsname='%s', nfsid=%ld\n",
            name,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_nfsname(name='%s'): "
            "returning status=%d / ie=NULL\n",
            name,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_user_lookup_by_nfsid(struct idmap_context *context,
    idmapcache_idnumber search_nfsid)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_user_lookup_by_nfsid(search_nfsid=%ld)\n",
        (long)search_nfsid));

    ie = idmapcache_lookup_by_nfsid(context->usercache, search_nfsid);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    uid_t localuid;
    char nfsowner[IDMAPCACHE_MAXNAME_LEN];
    uid_t nfsuid;
    char name[64];
    (void)sprintf(name, "%ld", (long)search_nfsid);

    if (!cygwin_nfsserver_getent_passwd(name,
        localname,
        &localuid,
        nfsowner,
        &nfsuid)) {
        DPRINTF(0,
            ("nfs41_idmap_user_lookup_by_nfsid(search_nfsid=%ld): "
            "Adding new user entry localname='%s', localuid=%ld, nfsowner='%s', nfsuid=%ld\n",
            (long)search_nfsid,
            localname,
            (long)localuid,
            nfsowner,
            (long)nfsuid));

        ie = idmapcache_add(context->usercache,
            localname,
            localuid,
            nfsowner,
            nfsuid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_user_lookup_by_nfsid(search_nfsid=%ld): idmapcache_add() failed\n",
                (long)search_nfsid));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_nfsid(search_nfsid=%ld): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localuid=%ld, nfsname='%s', nfsid=%ld\n",
            (long)search_nfsid,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_user_lookup_by_nfsid(search_nfsid=%ld): "
            "returning status=%d / ie=NULL\n",
            (long)search_nfsid,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_group_lookup_by_win32name(struct idmap_context *context,
    const char *restrict name)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_group_lookup_by_win32name(name='%s')\n", name));

    ie = idmapcache_lookup_by_win32name(context->groupcache, name);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    gid_t localgid;
    char nfsownergroup[IDMAPCACHE_MAXNAME_LEN];
    gid_t nfsgid;

    if (!cygwin_local_getent_group(name,
        localname,
        &localgid,
        nfsownergroup,
        &nfsgid)) {
        DPRINTF(0,
            ("nfs41_idmap_group_lookup_by_win32name(name='%s'): "
            "Adding new group entry localname='%s', localgid=%ld, nfsownergroup='%s', nfsgid=%ld\n",
            name,
            localname,
            (long)localgid,
            nfsownergroup,
            (long)nfsgid));

        ie = idmapcache_add(context->groupcache,
            localname,
            localgid,
            nfsownergroup,
            nfsgid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_group_lookup_by_win32name(name='%s'): idmapcache_add() failed\n", name));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_win32name(name='%s'): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localgid=%ld, nfsname='%s', nfsid=%ld\n",
            name,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_win32name(name='%s'): "
            "returning status=%d / ie=NULL\n",
            name,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_group_lookup_by_localid(struct idmap_context *context,
    idmapcache_idnumber search_localid)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_group_lookup_by_localid(search_localid=%ld)\n",
        (long)search_localid));

    ie = idmapcache_lookup_by_localid(context->groupcache, search_localid);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    gid_t localgid;
    char nfsownergroup[IDMAPCACHE_MAXNAME_LEN];
    gid_t nfsgid;
    char name[64];
    (void)sprintf(name, "%ld", (long)search_localid);

    if (!cygwin_local_getent_group(name,
        localname,
        &localgid,
        nfsownergroup,
        &nfsgid)) {
        DPRINTF(0,
            ("nfs41_idmap_group_lookup_by_localid(search_localid=%ld): "
            "Adding new group entry localname='%s', localgid=%ld, nfsownergroup='%s', nfsgid=%ld\n",
            (long)search_localid,
            localname,
            (long)localgid,
            nfsownergroup,
            (long)nfsgid));

        ie = idmapcache_add(context->groupcache,
            localname,
            localgid,
            nfsownergroup,
            nfsgid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_group_lookup_by_localid(search_localid=%ld): idmapcache_add() failed\n",
                (long)search_localid));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_localid(search_localid=%ld): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localgid=%ld, nfsname='%s', nfsid=%ld\n",
            (long)search_localid,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_localid(search_localid=%ld): "
            "returning status=%d / ie=NULL\n",
            (long)search_localid,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_group_lookup_by_nfsname(struct idmap_context *context,
    const char *restrict name)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_group_lookup_by_nfsname(name='%s')\n",
        name));

    ie = idmapcache_lookup_by_nfsname(context->groupcache, name);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    gid_t localgid;
    char nfsownergroup[IDMAPCACHE_MAXNAME_LEN];
    gid_t nfsgid;

    if (!cygwin_nfsserver_getent_group(name,
        localname,
        &localgid,
        nfsownergroup,
        &nfsgid)) {
        DPRINTF(0,
            ("nfs41_idmap_group_lookup_by_nfsname(name='%s'): "
            "Adding new group entry localname='%s', localgid=%ld, nfsownergroup='%s', nfsgid=%ld\n",
            name,
            localname,
            (long)localgid,
            nfsownergroup,
            (long)nfsgid));

        ie = idmapcache_add(context->groupcache,
            localname,
            localgid,
            nfsownergroup,
            nfsgid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_group_lookup_by_nfsname(name='%s'): idmapcache_add() failed\n",
                name));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_nfsname(name='%s'): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localgid=%ld, nfsname='%s', nfsid=%ld\n",
            name,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_nfsname(name='%s'): "
            "returning status=%d / ie=NULL\n",
            name,
            status));
    }

    return ie;
}

idmapcache_entry *nfs41_idmap_group_lookup_by_nfsid(struct idmap_context *context,
    idmapcache_idnumber search_nfsid)
{
    int status = ERROR_NOT_FOUND;
    idmapcache_entry *ie;

    DPRINTF(CYGWINIDLVL,
        ("--> nfs41_idmap_group_lookup_by_nfsid(search_nfsid=%ld)\n",
        (long)search_nfsid));

    ie = idmapcache_lookup_by_nfsid(context->groupcache, search_nfsid);
    if (ie != NULL) {
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[IDMAPCACHE_MAXNAME_LEN];
    gid_t localgid;
    char nfsownergroup[IDMAPCACHE_MAXNAME_LEN];
    gid_t nfsgid;
    char name[64];
    (void)sprintf(name, "%ld", (long)search_nfsid);

    if (!cygwin_nfsserver_getent_group(name,
        localname,
        &localgid,
        nfsownergroup,
        &nfsgid)) {
        DPRINTF(0,
            ("nfs41_idmap_group_lookup_by_nfsid(search_nfsid=%ld): "
            "Adding new group entry localname='%s', localgid=%ld, nfsownergroup='%s', nfsgid=%ld\n",
            (long)search_nfsid,
            localname,
            (long)localgid,
            nfsownergroup,
            (long)nfsgid));

        ie = idmapcache_add(context->groupcache,
            localname,
            localgid,
            nfsownergroup,
            nfsgid);
        if (ie == NULL) {
            DPRINTF(0,
                ("nfs41_idmap_group_lookup_by_nfsid(search_nfsid=%ld): idmapcache_add() failed\n",
                (long)search_nfsid));
        }
        else {
            status = ERROR_SUCCESS;
        }
    }

out:
    if (ie != NULL) {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_nfsid(search_nfsid=%ld): "
            "returning status=%d / user ie(=0x%p)={ win32name='%s', localgid=%ld, nfsname='%s', nfsid=%ld\n",
            (long)search_nfsid,
            status,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
    }
    else {
        DPRINTF(CYGWINIDLVL,
            ("<-- nfs41_idmap_group_lookup_by_nfsid(search_nfsid=%ld): "
            "returning status=%d / ie=NULL\n",
            (long)search_nfsid,
            status));
    }

    return ie;
}
