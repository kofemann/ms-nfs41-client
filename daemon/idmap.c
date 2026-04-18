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
#include <stdlib.h> /* for strtoul() */
#include <errno.h>

#include "nfs41_build_features.h"
#include "idmap.h"
#include "nfs41_const.h"
#include "list.h"
#include "daemon_debug.h"
#include "aclutil.h"
#include "util.h"

/* configuration */
static const char CONFIG_FILENAME[] = "C:\\etc\\ms-nfs41-idmap.conf";


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


/* public idmap interface */
int nfs41_idmap_create(
    IN const char *configname,
    OUT struct idmap_context **context_out,
    IN const char *localdomain_name)
{
    struct idmap_context *context;
    int status = NO_ERROR;

    context = calloc(1, sizeof(struct idmap_context));
    if (context == NULL) {
        status = GetLastError();
        goto out;
    }

    (void)strcpy(context->config.configname, configname);

    /* load configuration from file */
    status = config_init(&context->config);
    if (status) {
        eprintf("config_init() failed with %d\n", status);
        goto out_err_free;
    }

    /*
     * Defaults for nobody/nogroup
     * These should really be per idmapper-config settings
     */
    context->config.default_nfs_uid = NFS_USER_NOBODY_UID;
    context->config.default_nfs_gid = NFS_GROUP_NOGROUP_GID;
    context->config.default_local_uid = NFS_USER_NOBODY_UID;
    context->config.default_local_gid = NFS_GROUP_NOGROUP_GID;

    /* initialize the caches */
    context->usercache = idmapcache_context_create();
    context->groupcache = idmapcache_context_create();

    if ((context->usercache == NULL) || (context->groupcache == NULL)) {
        eprintf("nfs41_idmap_create: Cannot create idmapcache\n");
        goto out_err_free;
    }

    /*
     * Enumerate the server principal names for Windows "well-known"
     * groups and ask the idmapper to get the localised NFS server names
     * We use this list in |convert_nfs4acl_2_dacl()| to set the
     * |ACE4_IDENTIFIER_GROUP| flag for groups where the NFS server might
     * not have set it
     */
    context->well_known_lgrouplist =
        build_well_known_localised_nfs_grouplist(context);
    if (context->well_known_lgrouplist == NULL) {
        eprintf("nfs41_idmap_create: "
            "build_well_known_localised_nfs_grouplist() failed\n");
        goto out_err_free;
    }

    DPRINTF(0,
        ("nfs41_idmap_create: well_known_lgrouplist='%s'\n",
        context->well_known_lgrouplist));

#ifdef NFS41_DRIVER_FEATURE_IDMAPPER_CYGWIN
    DPRINTF(1,
        ("nfs41_idmap_create: Force context->config.timeout = 6000;\n"));
    context->config.timeout = 6000;
    /* FIXME: |use_numeric_uidgid| should be a idmapper option */
    context->config.use_numeric_uidgid = false;
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
    if (context->usercache != NULL)
        idmapcache_context_destroy(context->usercache);
    if (context->groupcache != NULL)
        idmapcache_context_destroy(context->groupcache);

    free(context->well_known_lgrouplist);

    free(context);
}
