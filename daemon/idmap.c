/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2023-2026 Roland Mainz <roland.mainz@nrubsig.org>
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

#include <Windows.h>
#include <strsafe.h>
#include <Winldap.h>
#include <stdlib.h> /* for strtoul() */
#include <errno.h>

#include "nfs41_build_features.h"
#include "idmap.h"
#include "nfs41_const.h"
#include "list.h"
#include "daemon_debug.h"
#include "util.h"

#define PTR2UID_T(p) ((uid_t)PTR2PTRDIFF_T(p))
#define PTR2GID_T(p) ((gid_t)PTR2PTRDIFF_T(p))
#define PTR2UINT(p)  ((UINT)PTR2PTRDIFF_T(p))
#define UID_T2PTR(u) (PTRDIFF_T2PTR((ptrdiff_t)u))
#define GID_T2PTR(g) (PTRDIFF_T2PTR((ptrdiff_t)g))

#define IDLVL 2         /* dprintf level for idmap logging */
#define CYGWINIDLVL 2   /* dprintf level for idmap logging */

#define FILTER_LEN 1024
#define NAME_LEN 32
#define VAL_LEN 257


enum ldap_class {
    CLASS_USER,
    CLASS_GROUP,

    NUM_CLASSES
};

enum ldap_attr {
    ATTR_USER_NAME,
    ATTR_GROUP_NAME,
    ATTR_PRINCIPAL,
    ATTR_UID,
    ATTR_GID,

    NUM_ATTRIBUTES
};

#define ATTR_FLAG(attr) (1 << (attr))
#define ATTR_ISSET(mask, attr) (((mask) & ATTR_FLAG(attr)) != 0)


/* ldap/cache lookups */
struct idmap_lookup {
    enum ldap_attr attr;
    enum ldap_class klass;
    enum config_type type;
    list_compare_fn compare;
    const void *value;
};


/* configuration */
static const char CONFIG_FILENAME[] = "C:\\etc\\ms-nfs41-idmap.conf";

struct idmap_config {
    /* ldap server information */
    char hostname[NFS41_HOSTNAME_LEN+1];
    char localdomain_name[NFS41_HOSTNAME_LEN+1];
    UINT port;
    UINT version;
    UINT timeout;

    /* ldap schema information */
    char classes[NUM_CLASSES][NAME_LEN];
    char attributes[NUM_ATTRIBUTES][NAME_LEN];
    char base[VAL_LEN];

    /* caching configuration */
    INT cache_ttl;
};


enum config_type {
    TYPE_STR,
    TYPE_INT
};

struct config_option {
    const char *key;
    const char *def;
    enum config_type type;
    size_t offset;
    size_t max_len;
};

/* helper macros for declaring config_options */
#define OPT_INT(key,def,field) \
    { key, def, TYPE_INT, FIELD_OFFSET(struct idmap_config, field), 0 }
#define OPT_STR(key,def,field,len) \
    { key, def, TYPE_STR, FIELD_OFFSET(struct idmap_config, field), len }
#define OPT_CLASS(key,def,index) \
    { key, def, TYPE_STR, FIELD_OFFSET(struct idmap_config, classes[index]), NAME_LEN }
#define OPT_ATTR(key,def,index) \
    { key, def, TYPE_STR, FIELD_OFFSET(struct idmap_config, attributes[index]), NAME_LEN }

/* table of recognized config options, including type and default value */
static const struct config_option g_options[] = {
    /* server information */
    OPT_STR("ldap_hostname", "localhost", hostname, NFS41_HOSTNAME_LEN+1),
    OPT_INT("ldap_port", "389", port),
    OPT_INT("ldap_version", "3", version),
    OPT_INT("ldap_timeout", "0", timeout),

    /* schema information */
    OPT_STR("ldap_base", "cn=localhost", base, VAL_LEN),
    OPT_CLASS("ldap_class_users", "user", CLASS_USER),
    OPT_CLASS("ldap_class_groups", "group", CLASS_GROUP),
    OPT_ATTR("ldap_attr_username", "cn", ATTR_USER_NAME),
    OPT_ATTR("ldap_attr_groupname", "cn", ATTR_GROUP_NAME),
    OPT_ATTR("ldap_attr_gssAuthName", "gssAuthName", ATTR_PRINCIPAL),
    OPT_ATTR("ldap_attr_uidNumber", "uidNumber", ATTR_UID),
    OPT_ATTR("ldap_attr_gidNumber", "gidNumber", ATTR_GID),

    /* caching configuration */
    OPT_INT("cache_ttl", "6000", cache_ttl),
};


/* parse each line into key-value pairs
 * accepts 'key = value' or 'key = "value"',
 * ignores whitespace anywhere outside the ""s */
struct config_pair {
    const char *key, *value;
    size_t key_len, value_len;
};

static int config_parse_pair(
    char *line,
    struct config_pair *pair)
{
    char *pos = line;
    int status = NO_ERROR;

    /* terminate at comment */
    pos = strchr(line, '#');
    if (pos) *pos = 0;

    /* skip whitespace before key */
    pos = line;
    while (isspace(*pos)) pos++;
    pair->key = pos;

    pos = strchr(pos, '=');
    if (pos == NULL) {
        eprintf("missing '='\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    /* skip whitespace after key */
    pair->key_len = pos - pair->key;
    while (pair->key_len && isspace(pair->key[pair->key_len-1]))
        pair->key_len--;

    if (pair->key_len <= 0) {
        eprintf("empty key\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    /* skip whitespace after = */
    pos++;
    while (isspace(*pos)) pos++;

    if (*pos == 0) {
        eprintf("end of line looking for value\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    if (*pos == '\"') {
        /* value is between the "s */
        pair->value = pos + 1;
        pos = strchr(pair->value, '\"');
        if (pos == NULL) {
            eprintf("no matching '\"'\n");
            status = ERROR_INVALID_PARAMETER;
            goto out;
        }
        pair->value_len = pos - pair->value;
    } else {
        pair->value = pos;
        pair->value_len = strlen(pair->value);

        /* skip whitespace after value */
        while (pair->value_len && isspace(pair->value[pair->value_len-1]))
            pair->value_len--;
    }

    /* on success, null terminate the key and value */
    ((char*)pair->key)[pair->key_len] = 0;
    ((char*)pair->value)[pair->value_len] = 0;
out:
    return status;
}

static BOOL parse_uint(
    const char *str,
    UINT *id_out)
{
    PCHAR endp;
    const UINT id = strtoul(str, &endp, 10);

    /* must convert the whole string */
    if ((endp - str) < (ptrdiff_t)strlen(str))
        return FALSE;

    /* result must fit in 32 bits */
    if (id == ULONG_MAX && errno == ERANGE)
        return FALSE;

    *id_out = id;
    return TRUE;
}

/* parse default values from g_options[] into idmap_config */
static int config_defaults(
    struct idmap_config *config)
{
    const struct config_option *option;
    const int count = ARRAYSIZE(g_options);
    char *dst;
    int i, status = NO_ERROR;

    for (i = 0; i < count; i++) {
        option = &g_options[i];
        dst = (char*)config + option->offset;

        if (option->type == TYPE_INT) {
            if (!parse_uint(option->def, (UINT*)dst)) {
                status = ERROR_INVALID_PARAMETER;
                eprintf("failed to parse default value of '%s'=\"%s\": "
                    "expected a number\n", option->key, option->def);
                break;
            }
        } else {
            if (FAILED(StringCchCopyA(dst, option->max_len, option->def))) {
                status = ERROR_BUFFER_OVERFLOW;
                eprintf("failed to parse default value of '%s'=\"%s\": "
                    "buffer overflow > %lu\n", option->key, option->def,
                    (unsigned long)option->max_len);
                break;
            }
        }
    }
    return status;
}

static int config_find_option(
    const struct config_pair *pair,
    const struct config_option **option)
{
    int i, count = ARRAYSIZE(g_options);
    int status = ERROR_NOT_FOUND;

    /* find the config_option by key */
    for (i = 0; i < count; i++) {
        if (_stricmp(pair->key, g_options[i].key) == 0) {
            *option = &g_options[i];
            status = NO_ERROR;
            break;
        }
    }
    return status;
}

static int config_load(
    struct idmap_config *config,
    const char *filename)
{
    char buffer[1024], *pos;
    FILE *file;
    struct config_pair pair;
    const struct config_option *option;
    int line = 0;
    int status = NO_ERROR;

    /* open the file */
    file = fopen(filename, "r");
    if (file == NULL) {
        eprintf("config_load() failed to open file '%s'\n", filename);
        goto out;
    }

    /* read each line */
    while (fgets(buffer, sizeof(buffer), file)) {
        line++;

        /* skip whitespace */
        pos = buffer;
        while (isspace(*pos)) pos++;

        /* skip comments and empty lines */
        if (*pos == '#' || *pos == 0)
            continue;

        /* parse line into a key=value pair */
        status = config_parse_pair(buffer, &pair);
        if (status) {
            eprintf("error on line %d: '%s'\n", line, buffer);
            break;
        }

        /* find the config_option by key */
        status = config_find_option(&pair, &option);
        if (status) {
            eprintf("unrecognized option '%s' on line %d: '%s'\n",
                pair.key, line, buffer);
            status = ERROR_INVALID_PARAMETER;
            break;
        }

        if (option->type == TYPE_INT) {
            if (!parse_uint(pair.value, (UINT*)((char*)config + option->offset))) {
                status = ERROR_INVALID_PARAMETER;
                eprintf("expected a number on line %d: '%s'=\"%s\"\n",
                    line, pair.key, pair.value);
                break;
            }
        } else {
            if (FAILED(StringCchCopyNA((char*)config + option->offset,
                    option->max_len, pair.value, pair.value_len))) {
                status = ERROR_BUFFER_OVERFLOW;
                eprintf("overflow on line %d: '%s'=\"%s\"\n",
                    line, pair.key, pair.value);
                break;
            }
        }
    }

    fclose(file);
out:
    return status;
}

static int config_init(
    struct idmap_config *config)
{
    int status;

    /* load default values */
    status = config_defaults(config);
    if (status) {
        eprintf("config_defaults() failed with %d\n", status);
        goto out;
    }

    /* load configuration from file */
    status = config_load(config, CONFIG_FILENAME);
    if (status) {
        eprintf("config_load('%s') failed with %d\n", CONFIG_FILENAME, status);
        goto out;
    }
out:
    return status;
}


/* generic cache */


/* ldap context */
struct idmap_context {
    struct idmap_config config;

    idmapcache_context *usercache;
    idmapcache_context *groupcache;

    LDAP *ldap;
};


/* public idmap interface */
int nfs41_idmap_create(
    struct idmap_context **context_out, const char *localdomain_name)
{
    struct idmap_context *context;
    int status = NO_ERROR;

    context = calloc(1, sizeof(struct idmap_context));
    if (context == NULL) {
        status = GetLastError();
        goto out;
    }

    (void)strcpy_s(context->config.localdomain_name,
        sizeof(context->config.localdomain_name),
        localdomain_name);
    if (context == NULL) {
        status = GetLastError();
        goto out;
    }

    /* initialize the caches */
    context->usercache = idmapcache_context_create();
    context->groupcache = idmapcache_context_create();

    if ((context->usercache == NULL) || (context->groupcache == NULL)) {
        eprintf("nfs41_idmap_create: Cannot create idmapcache\n");
        goto out;
    }

    /* load ldap configuration from file */
    status = config_init(&context->config);
    if (status) {
        eprintf("config_init() failed with %d\n", status);
        goto out_err_free;
    }

#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
    DPRINTF(CYGWINIDLVL, ("nfs41_idmap_create: Force context->config.timeout = 6000;\n"));
    context->config.timeout = 6000;
#endif /* NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN */

    *context_out = context;

out:
    return status;

out_err_free:
    nfs41_idmap_free(context);
    goto out;
}

void nfs41_idmap_free(
    struct idmap_context *context)
{
    /* clean up the connection */
    if (context->ldap)
        ldap_unbind(context->ldap);

    idmapcache_context_destroy(context->usercache);
    idmapcache_context_destroy(context->groupcache);

    free(context);
}

int nfs41_idmap_name_to_uid(
    struct idmap_context *context,
    const char *name,
    uid_t *uid_out)
{
    int status = ERROR_NOT_FOUND;

    DPRINTF(IDLVL, ("--> nfs41_idmap_name_to_uid(name='%s')\n", name));

    idmapcache_entry *ie = NULL;

    ie = idmapcache_lookup_by_nfsname(context->usercache, name);
    if (ie != NULL) {
        *uid_out = ie->nfsid;
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[256];
    uid_t localuid;
    char nfsowner[256];
    uid_t nfsuid;

    if (!cygwin_getent_passwd(name,
        localname,
        &localuid,
        nfsowner,
        &nfsuid)) {
        DPRINTF(0, ("nfs41_idmap_name_to_uid(name='%s'): "
            "Adding new user entry localname='%s', localuid=%ld, nfsowner='%s', nfsuid=%ld\n",
            name,
            localname,
            (long)localuid,
            nfsowner,
            (long)nfsuid));

        ie = idmapcache_add(context->usercache,
            name/*localname*/,
            localuid,
            name/*nfsowner*/,
            localuid/*nfsuid*/);
        if (ie == NULL) {
            DPRINTF(0, ("nfs41_idmap_name_to_uid(name='%s'): idmapcache_add() failed\n", name));
        }
        else {
            *uid_out = ie->nfsid;
            status = ERROR_SUCCESS;
        }
    }

out:
    DPRINTF(IDLVL, ("<-- nfs41_idmap_name_to_uid(name='%s') "
        "returning status=%d, uid=%u\n",
        name,
        status,
        (unsigned int)*uid_out));

    if (ie != NULL) {
        DPRINTF(3, ("nfs41_idmap_name_to_uid(name='%s'): "
            "returning *uid_out=%u / user ie(=0x%p)={ win32name='%s', localuid=%ld, nfsname='%s', nfsid=%ld\n",
            name,
            (unsigned int)*uid_out,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
        idmapcache_entry_refcount_dec(ie);
    }

    return status;
}

int nfs41_idmap_uid_to_name(
    struct idmap_context *context,
    uid_t uid,
    char *name,
    size_t len)
{
    int status = ERROR_NOT_FOUND;

    DPRINTF(IDLVL, ("--> nfs41_idmap_uid_to_name(uid=%u)\n", (unsigned int)uid));

    idmapcache_entry *ie = NULL;

    ie = idmapcache_lookup_by_nfsid(context->usercache, uid);
    if (ie != NULL) {
        (void)strcpy(name, ie->nfsname.buf);
        status = ERROR_SUCCESS;
        goto out;
    }

    char localname[256];
    uid_t localuid;
    char nfsowner[256];
    uid_t nfsuid;

    if (!cygwin_getent_passwd(name,
        localname,
        &localuid,
        nfsowner,
        &nfsuid)) {
        DPRINTF(0, ("nfs41_idmap_uid_to_name(name='%s'): "
            "Adding new user entry localname='%s', localuid=%ld, nfsowner='%s', nfsuid=%ld\n",
            name,
            localname,
            (long)localuid,
            nfsowner,
            (long)nfsuid));

        ie = idmapcache_add(context->usercache,
            name/*localname*/,
            localuid,
            name/*nfsowner*/,
            localuid/*nfsuid*/);
        if (ie == NULL) {
            DPRINTF(0, ("nfs41_idmap_uid_to_name(name='%s'): idmapcache_add() failed\n", name));
        }
        else {
            (void)strcpy(name, ie->nfsname.buf);
            status = ERROR_SUCCESS;
        }
    }

out:
    DPRINTF(IDLVL, ("<-- nfs41_idmap_uid_to_name(uid=%u) "
        "returning status=%d, name='%s'\n",
        (unsigned int)uid,
        status,
        ((status == 0)?name:"<nothing>")));

    if (ie != NULL) {
        DPRINTF(0, ("nfs41_idmap_uid_to_name(uid=%u): "
            "returning *name='%s' / user ie(=0x%p)={ win32name='%s', localuid=%ld, nfsname='%s', nfsid=%ld\n",
            (unsigned int)uid,
            ((status == 0)?name:"<nothing>"),
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
        idmapcache_entry_refcount_dec(ie);
    }

    return status;
}

int nfs41_idmap_group_to_gid(
    struct idmap_context *context,
    const char *name,
    gid_t *gid_out)
{
    int status = ERROR_NOT_FOUND;

    DPRINTF(IDLVL, ("--> nfs41_idmap_group_to_gid(name='%s')\n", name));

    idmapcache_entry *ie = NULL;

    ie = idmapcache_lookup_by_nfsname(context->groupcache, name);
    if (ie != NULL) {
        *gid_out = ie->nfsid;
        status = ERROR_SUCCESS;
        goto out;
    }

    char localgroupname[256];
    gid_t localgid;
    char nfsownergroup[256];
    gid_t nfsgid;

    if (!cygwin_getent_group(name,
        localgroupname,
        &localgid,
        nfsownergroup,
        &nfsgid)) {
        DPRINTF(0, ("nfs41_idmap_group_to_gid(name='%s'): "
            "Adding new group entry localgroupname='%s', localgid=%ld, nfsownergroup='%s', nfsgid=%ld\n",
            name,
            localgroupname,
            (long)localgid,
            nfsownergroup,
            (long)nfsgid));

        ie = idmapcache_add(context->groupcache,
            name/*localgroupname*/,
            localgid,
            name/*nfsownergroup*/,
            localgid/*nfsgid*/);
        if (ie == NULL) {
            DPRINTF(0, ("nfs41_idmap_group_to_gid(name='%s'): idmapcache_add() failed\n", name));
        }
        else {
            *gid_out = ie->nfsid;
            status = ERROR_SUCCESS;
        }
    }

out:
    DPRINTF(IDLVL, ("<-- nfs41_idmap_group_to_gid(name='%s') "
        "returning status=%d, gid=%u\n",
        name,
        status,
        (unsigned int)*gid_out));

    if (ie != NULL) {
        DPRINTF(3, ("nfs41_idmap_group_to_gid(name='%s'): "
            "returning *gid_out=%u / group ie(=0x%p)={ win32name='%s', localgid=%ld, nfsname='%s', nfsid=%ld\n",
            name,
            (unsigned int)*gid_out,
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
        idmapcache_entry_refcount_dec(ie);
    }

    return status;
}

int nfs41_idmap_gid_to_group(
    struct idmap_context *context,
    gid_t gid,
    char *name,
    size_t len)
{
    int status = ERROR_NOT_FOUND;

    DPRINTF(IDLVL, ("--> nfs41_idmap_gid_to_group(gid=%u)\n", (unsigned int)gid));

    idmapcache_entry *ie = NULL;

    ie = idmapcache_lookup_by_nfsid(context->groupcache, gid);
    if (ie != NULL) {
        (void)strcpy(name, ie->nfsname.buf);
        status = ERROR_SUCCESS;
        goto out;
    }

    char localgroupname[256];
    gid_t localgid;
    char nfsownergroup[256];
    gid_t nfsgid;

    if (!cygwin_getent_group(name,
        localgroupname,
        &localgid,
        nfsownergroup,
        &nfsgid)) {
        DPRINTF(0, ("nfs41_idmap_group_to_gid(name='%s'): "
            "Adding new group entry localgroupname='%s', localgid=%ld, nfsownergroup='%s', nfsgid=%ld\n",
            name,
            localgroupname,
            (long)localgid,
            nfsownergroup,
            (long)nfsgid));

        ie = idmapcache_add(context->groupcache,
            name/*localgroupname*/,
            localgid,
            name/*nfsownergroup*/,
            localgid/*nfsgid*/);
        if (ie == NULL) {
            DPRINTF(0, ("nfs41_idmap_group_to_gid(name='%s'): idmapcache_add() failed\n", name));
        }
        else {
            (void)strcpy(name, ie->nfsname.buf);
            status = ERROR_SUCCESS;
        }
    }

out:
    DPRINTF(IDLVL, ("<-- nfs41_idmap_gid_to_group(gid=%u) "
        "returning status=%d, name='%s'\n",
        (unsigned int)gid,
        status,
        ((status == 0)?name:"<nothing>")));

    if (ie != NULL) {
        DPRINTF(0, ("nfs41_idmap_gid_to_group(gid=%u): "
            "returning *name='%s' / group ie(=0x%p)={ win32name='%s', localgid=%ld, nfsname='%s', nfsid=%ld\n",
            (unsigned int)gid,
            ((status == 0)?name:"<nothing>"),
            (void *)ie,
            ie->win32name.buf,
            (long)ie->localid,
            ie->nfsname.buf,
            (long)ie->nfsid));
        idmapcache_entry_refcount_dec(ie);
    }

    return status;
}
