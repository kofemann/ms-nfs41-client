/* Copyright (c) 2010
 * The Regents of the University of Michigan
 * All Rights Reserved
 *
 * Permission is granted to use, copy and redistribute this software
 * for noncommercial education and research purposes, so long as no
 * fee is charged, and so long as the name of the University of Michigan
 * is not used in any advertising or publicity pertaining to the use
 * or distribution of this software without specific, written prior
 * authorization.  Permission to modify or otherwise create derivative
 * works of this software is not granted.
 *
 * This software is provided as is, without representation or warranty
 * of any kind either express or implied, including without limitation
 * the implied warranties of merchantability, fitness for a particular
 * purpose, or noninfringement.  The Regents of the University of
 * Michigan shall not be liable for any damages, including special,
 * indirect, incidental, or consequential damages, with respect to any
 * claim arising out of or in connection with the use of the software,
 * even if it has been or is hereafter advised of the possibility of
 * such damages.
 */
#include <Windows.h>
#include <strsafe.h>
#include <time.h>

#include "nfs41_ops.h"
#include "nfs41_compound.h"
#include "name_cache.h"
#include "util.h"
#include "rbtree.h"
#include "daemon_debug.h"


/* dprintf levels for name cache logging */
enum {
    NCLVL1 = 2,
    NCLVL2
};

#define NAME_CACHE_EXPIRATION 20 /* TODO: get from configuration */

/* allow up to 128K of memory for name and attribute cache entries */
#define NAME_CACHE_MAX_SIZE 131072


/* attribute cache */
struct attr_cache_entry {
    struct rb_node          rbnode;
    struct list_entry       free_entry;
    uint64_t                change;
    uint64_t                size;
    uint64_t                fileid;
    int64_t                 time_access_s;
    int64_t                 time_create_s;
    int64_t                 time_modify_s;
    uint32_t                time_access_ns;
    uint32_t                time_create_ns;
    uint32_t                time_modify_ns;
    uint32_t                numlinks;
    uint32_t                mode;
    unsigned short          ref_count;
    unsigned char           type;
    unsigned char           invalidated;
};
#define ATTR_ENTRY_SIZE sizeof(struct attr_cache_entry)

struct attr_cache {
    struct rb_root          root;
    struct attr_cache_entry *pool;
    struct list_entry       free_entries;
};


/* attr_cache_entry */
#define attr_entry(pos) list_container(pos, struct attr_cache_entry, free_entry)

static int attr_cache_entry_create(
    IN struct attr_cache *cache,
    IN uint64_t fileid,
    OUT struct attr_cache_entry **entry_out)
{
    struct attr_cache_entry *entry;
    int status = NO_ERROR;

    /* get the next entry from free_entries and remove it */
    if (list_empty(&cache->free_entries)) {
        status = ERROR_OUTOFMEMORY;
        goto out;
    }
    entry = attr_entry(cache->free_entries.next);
    list_remove(&entry->free_entry);

    entry->fileid = fileid;
    *entry_out = entry;
out:
    return status;
}

static __inline void attr_cache_entry_free(
    IN struct attr_cache *cache,
    IN struct attr_cache_entry *entry)
{
    dprintf(NCLVL1, "attr_cache_entry_free(%llu)\n", entry->fileid);
    rb_erase(&entry->rbnode, &cache->root);
    /* add it back to free_entries */
    list_add_tail(&cache->free_entries, &entry->free_entry);
}

static __inline void attr_cache_entry_ref(
    IN struct attr_cache *cache,
    IN struct attr_cache_entry *entry)
{
    const uint32_t previous = entry->ref_count++;
    dprintf(NCLVL2, "attr_cache_entry_ref(%llu) %u -> %u\n",
        entry->fileid, previous, entry->ref_count);
}

static __inline void attr_cache_entry_deref(
    IN struct attr_cache *cache,
    IN struct attr_cache_entry *entry)
{
    const uint32_t previous = entry->ref_count--;
    dprintf(NCLVL2, "attr_cache_entry_deref(%llu) %u -> %u\n",
        entry->fileid, previous, entry->ref_count);

    if (entry->ref_count == 0)
        attr_cache_entry_free(cache, entry);
}

/* attr_cache */
static int attr_cache_init(
    IN struct attr_cache *cache,
    IN uint32_t max_entries)
{
    uint32_t i;
    int status = NO_ERROR;

    /* allocate a pool of entries */
    cache->pool = calloc(max_entries, ATTR_ENTRY_SIZE);
    if (cache->pool == NULL) {
        status = GetLastError();
        goto out;
    }

    /* initialize the list of free entries */
    list_init(&cache->free_entries);
    for (i = 0; i < max_entries; i++) {
        list_init(&cache->pool[i].free_entry);
        list_add_tail(&cache->free_entries, &cache->pool[i].free_entry);
    }
out:
    return status;
}

static void attr_cache_free(
    IN struct attr_cache *cache)
{
    /* free the pool */
    free(cache->pool);
    cache->pool = NULL;
    list_init(&cache->free_entries);
}

static struct attr_cache_entry* attr_cache_search(
    IN struct attr_cache *cache,
    IN uint64_t fileid)
{
    struct rb_node *node;
    struct attr_cache_entry *entry;

    dprintf(NCLVL2, "--> attr_cache_search(%llu)\n", fileid);

    entry = NULL;
    node = cache->root.rb_node;

    while (node) {
        entry = rb_entry(node, struct attr_cache_entry, rbnode);

        if (fileid < entry->fileid)
            node = node->rb_left;
        else if (fileid > entry->fileid)
            node = node->rb_right;
        else {
            dprintf(NCLVL2, "<-- attr_cache_search() "
                "found existing entry 0x%p\n", entry);
            goto out_success;
        }
    }
    entry = NULL;
    dprintf(NCLVL2, "<-- attr_cache_search() returning NULL\n");

out_success:
    return entry;
}

static int attr_cache_insert(
    IN struct attr_cache *cache,
    IN struct attr_cache_entry *entry)
{
    int status = NO_ERROR;
    struct rb_node **node, *prev;
    struct attr_cache_entry *current;

    dprintf(NCLVL2, "--> attr_cache_insert(%llu)\n", entry->fileid);

    node = &cache->root.rb_node;
    prev = NULL;

    while (*node) {
        current = rb_entry(*node, struct attr_cache_entry, rbnode);

        prev = *node;
        if (entry->fileid < current->fileid)
            node = &(*node)->rb_left;
        else if (entry->fileid > current->fileid)
            node = &(*node)->rb_right;
        else {
            status = ERROR_FILE_EXISTS;
            goto out;
        }
    }

    rb_link_node(&entry->rbnode, prev, node);
    rb_insert_color(&entry->rbnode, &cache->root);
out:
    dprintf(NCLVL2, "<-- attr_cache_insert() returning %d\n", status);
    return status;
}

static int attr_cache_find_or_create(
    IN struct attr_cache *cache,
    IN uint64_t fileid,
    OUT struct attr_cache_entry **entry_out)
{
    struct attr_cache_entry *entry;
    int status = NO_ERROR;

    dprintf(NCLVL1, "--> attr_cache_find_or_create(%llu)\n", fileid);

    /* look for an existing entry */
    entry = attr_cache_search(cache, fileid);
    if (entry == NULL) {
        /* create and insert */
        status = attr_cache_entry_create(cache, fileid, &entry);
        if (status)
            goto out;

        status = attr_cache_insert(cache, entry);
        if (status)
            goto out_err_free;
    }

    /* take a reference on success */
    attr_cache_entry_ref(cache, entry);

out:
    *entry_out = entry;
    dprintf(NCLVL1, "<-- attr_cache_find_or_create() returning %d\n",
        status);
    return status;

out_err_free:
    attr_cache_entry_free(cache, entry);
    entry = NULL;
    goto out;
}

static void attr_cache_update(
    IN struct attr_cache_entry *entry,
    IN const nfs41_file_info *info)
{
    /* update the attributes present in mask */
    if (info->attrmask.count >= 1) {
        if (info->attrmask.arr[0] & FATTR4_WORD0_TYPE)
            entry->type = info->type & NFS_FTYPE_MASK;
        if (info->attrmask.arr[0] & FATTR4_WORD0_CHANGE) {
            entry->change = info->change;
            /* revalidate whenever we get a change attribute */
            entry->invalidated = 0;
        }
        if (info->attrmask.arr[0] & FATTR4_WORD0_SIZE)
            entry->size = info->size;
    }
    if (info->attrmask.count >= 2) {
        if (info->attrmask.arr[1] & FATTR4_WORD1_MODE)
            entry->mode = info->mode;
        if (info->attrmask.arr[1] & FATTR4_WORD1_NUMLINKS)
            entry->numlinks = info->numlinks;
        if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_ACCESS) {
            entry->time_access_s = info->time_access.seconds;
            entry->time_access_ns = info->time_access.nseconds;
        }
        if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_CREATE) {
            entry->time_create_s = info->time_create.seconds;
            entry->time_create_ns = info->time_create.nseconds;
        }
        if (info->attrmask.arr[1] & FATTR4_WORD1_TIME_MODIFY) {
            entry->time_modify_s = info->time_modify.seconds;
            entry->time_modify_ns = info->time_modify.nseconds;
        }
    }
}

static void copy_attrs(
    OUT nfs41_file_info *dst,
    IN const struct attr_cache_entry *src)
{
    dst->change = src->change;
    dst->size = src->size;
    dst->time_access.seconds = src->time_access_s;
    dst->time_access.nseconds = src->time_access_ns;
    dst->time_create.seconds = src->time_create_s;
    dst->time_create.nseconds = src->time_create_ns;
    dst->time_modify.seconds = src->time_modify_s;
    dst->time_modify.nseconds = src->time_modify_ns;
    dst->type = src->type;
    dst->numlinks = src->numlinks;
    dst->mode = src->mode;
}


/* name cache */
struct name_cache_entry {
    char                    component[NFS41_MAX_COMPONENT_SIZE];
    nfs41_fh                fh;
    struct rb_node          rbnode;
    struct rb_root          rbchildren;
    struct attr_cache_entry *attributes;
    struct name_cache_entry *parent;
    struct list_entry       exp_entry;
    time_t                  expiration;
    unsigned short          component_len;
};
#define NAME_ENTRY_SIZE sizeof(struct name_cache_entry)

struct nfs41_name_cache {
    struct name_cache_entry *root;
    struct name_cache_entry *pool;
    struct attr_cache       attributes;
    struct list_entry       exp_entries; /* list of entries by expiry */
    uint32_t                expiration;
    uint32_t                entries;
    uint32_t                max_entries;
    SRWLOCK                 lock;
};


/* internal name cache functions used by the public name cache interface;
 * these functions expect the caller to hold a lock on the cache */

#define name_entry(pos) list_container(pos, struct name_cache_entry, exp_entry)

static __inline bool_t name_cache_enabled(
    IN struct nfs41_name_cache *cache)
{
    return cache->expiration > 0;
}

static __inline void name_cache_entry_rename(
    OUT struct name_cache_entry *entry,
    IN const nfs41_component *component)
{
    StringCchCopyNA(entry->component, NFS41_MAX_COMPONENT_LEN,
        component->name, component->len);
    entry->component_len = component->len;
}

static __inline void name_cache_remove(
    IN struct name_cache_entry *entry,
    IN struct name_cache_entry *parent)
{
    rb_erase(&entry->rbnode, &parent->rbchildren);
    entry->parent = NULL;
}

static void name_cache_unlink_children_recursive(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *parent);

static __inline void name_cache_unlink(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *entry)
{
    /* remove the entry from the tree */
    if (entry->parent)
        name_cache_remove(entry, entry->parent);
    else if (entry == cache->root)
        cache->root = NULL;

    /* unlink all of its children */
    name_cache_unlink_children_recursive(cache, entry);
    /* release the cached attributes */
    if (entry->attributes) {
        attr_cache_entry_deref(&cache->attributes, entry->attributes);
        entry->attributes = NULL;
    }
    /* move it to the end of exp_entries for scavenging */
    list_remove(&entry->exp_entry);
    list_add_tail(&cache->exp_entries, &entry->exp_entry);
}

static void name_cache_unlink_children_recursive(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *parent)
{
    struct name_cache_entry *entry;
    struct rb_node *node = rb_first(&parent->rbchildren);

    while (node) {
        entry = rb_entry(node, struct name_cache_entry, rbnode);
        node = rb_next(node);
        name_cache_unlink(cache, entry);
    }
}

static int name_cache_entry_create(
    IN struct nfs41_name_cache *cache,
    IN const nfs41_component *component,
    OUT struct name_cache_entry **entry_out)
{
    int status = NO_ERROR;
    struct name_cache_entry *entry;

    if (cache->entries >= cache->max_entries) {
        /* scavenge the oldest entry */
        entry = name_entry(cache->exp_entries.prev);
        name_cache_unlink(cache, entry);

        dprintf(NCLVL2, "name_cache_entry_create('%s') scavenged 0x%p\n",
            component->name, entry);
    } else {
        /* take the next entry in the pool and add it to exp_entries */
        entry = &cache->pool[cache->entries++];
        list_init(&entry->exp_entry);
        list_add_tail(&cache->exp_entries, &entry->exp_entry);
    }

    name_cache_entry_rename(entry, component);

    *entry_out = entry;
    return status;
}

static void name_cache_entry_refresh(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *entry)
{
    /* update the expiration timer */
    entry->expiration = time(NULL) + cache->expiration;
    /* move the entry to the front of cache->exp_entries */
    list_remove(&entry->exp_entry);
    list_add_head(&cache->exp_entries, &entry->exp_entry);
}

static int name_cache_entry_update(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *entry,
    IN OPTIONAL const nfs41_fh *fh,
    IN OPTIONAL const nfs41_file_info *info)
{
    int status = NO_ERROR;

    if (fh)
        fh_copy(&entry->fh, fh);
    else
        entry->fh.len = 0;

    if (info) {
        /* negative -> positive entry, create the attributes */
        if (entry->attributes == NULL)
            status = attr_cache_find_or_create(&cache->attributes,
                info->fileid, &entry->attributes);

        if (status == NO_ERROR)
            attr_cache_update(entry->attributes, info);
    } else if (entry->attributes) {
        /* positive -> negative entry, deref the attributes */
        attr_cache_entry_deref(&cache->attributes, entry->attributes);
        entry->attributes = NULL;
    }
    name_cache_entry_refresh(cache, entry);
    return status;
}

static int name_cache_entry_changed(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *entry,
    IN const change_info4 *cinfo)
{
    if (cinfo->after == entry->attributes->change ||
            (cinfo->atomic && cinfo->before == entry->attributes->change)) {
        entry->attributes->change = cinfo->after;
        name_cache_entry_refresh(cache, entry);
        dprintf(NCLVL1, "name_cache_entry_changed('%s') has not changed. "
            "updated change=%llu\n", entry->component,
            entry->attributes->change);
        return FALSE;
    } else {
        dprintf(NCLVL1, "name_cache_entry_changed('%s') has changed: was %llu, "
            "got before=%llu\n", entry->component,
            entry->attributes->change, cinfo->before);
        return TRUE;
    }
}

static void name_cache_entry_invalidate(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *entry)
{
    dprintf(NCLVL1, "name_cache_entry_invalidate('%s')\n", entry->component);

    if (entry->attributes) {
        /* flag attributes so that entry_has_expired() will return true
         * if another entry attempts to use them */
        entry->attributes->invalidated = 1;
    }
    name_cache_unlink(cache, entry);
}

static struct name_cache_entry* name_cache_search(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *parent,
    IN const nfs41_component *component)
{
    char dbg_name[NFS41_MAX_COMPONENT_LEN];
    struct rb_node *node;
    struct name_cache_entry *entry;
    int result;

    StringCchCopyNA(dbg_name, NFS41_MAX_COMPONENT_LEN,
        component->name, component->len);
    dprintf(NCLVL2, "--> name_cache_search('%s' under '%s')\n",
        dbg_name, parent->component);

    entry = NULL;
    node = parent->rbchildren.rb_node;

    while (node) {
        entry = rb_entry(node, struct name_cache_entry, rbnode);

        result = strncmp(component->name, entry->component,
            max(component->len, entry->component_len));
        if (result < 0)
            node = node->rb_left;
        else if (result > 0)
            node = node->rb_right;
        else {
            dprintf(NCLVL2, "<-- name_cache_search() "
                "found existing entry 0x%p\n", entry);
            goto out_success;
        }
    }
    entry = NULL;
    dprintf(NCLVL2, "<-- name_cache_search() returning NULL\n");

out_success:
    return entry;
}

static int entry_has_expired(
    IN struct name_cache_entry *entry)
{
    /* invalidated by another entry or timer expired */
    const int expired = entry->attributes->invalidated
        || time(NULL) > entry->expiration;

    if (expired)
        dprintf(NCLVL2, "entry_has_expired('%s')\n", entry->component);
    return expired;
}

static int entry_invis(
    IN struct name_cache_entry *entry,
    OUT OPTIONAL bool_t *is_negative)
{
    if (entry_has_expired(entry))
        return 1;

    /* a negative lookup entry has an empty fh and no attributes */
    if (entry->attributes == NULL) {
        if (is_negative) *is_negative = 1;
        return 1;
    }
    return 0;
}

static int name_cache_lookup(
    IN struct nfs41_name_cache *cache,
    IN bool_t skip_invis,
    IN const char *path,
    IN const char *path_end,
    OUT OPTIONAL const char **remaining_path_out,
    OUT OPTIONAL struct name_cache_entry **parent_out,
    OUT OPTIONAL struct name_cache_entry **target_out,
    OUT OPTIONAL bool_t *is_negative)
{
    struct name_cache_entry *parent, *target, *tmp;
    nfs41_component component;
    const char *path_pos;
    int status = NO_ERROR;

    dprintf(NCLVL1, "--> name_cache_lookup('%s')\n", path);

    parent = NULL;
    target = cache->root;
    component.name = path_pos = path;

    if (target == NULL || (skip_invis && entry_invis(target, is_negative))) {
        target = NULL;
        status = ERROR_PATH_NOT_FOUND;
        goto out;
    }

    while (next_component(path_pos, path_end, &component)) {
        tmp = name_cache_search(cache, target, &component);
        if (tmp == NULL || (skip_invis && entry_invis(tmp, is_negative))) {
            if (is_last_component(component.name, path_end))
                status = ERROR_FILE_NOT_FOUND;
            else
                status = ERROR_PATH_NOT_FOUND;
            break;
        }
        parent = target;
        target = tmp;
        path_pos = component.name + component.len;
    }
out:
    if (remaining_path_out) *remaining_path_out = component.name;
    if (parent_out) *parent_out = parent;
    if (target_out) *target_out = target;
    dprintf(NCLVL1, "<-- name_cache_lookup() returning %d\n", status);
    return status;
}

static int name_cache_insert(
    IN struct name_cache_entry *entry,
    IN struct name_cache_entry *parent)
{
    int result, status = NO_ERROR;
    struct rb_node **node, *prev;
    struct name_cache_entry *current;

    dprintf(NCLVL2, "--> name_cache_insert('%s')\n", entry->component);

    node = &parent->rbchildren.rb_node;
    prev = NULL;

    while (*node) {
        current = rb_entry(*node, struct name_cache_entry, rbnode);

        result = strcmp(entry->component, current->component);

        prev = *node;
        if (result < 0)
            node = &(*node)->rb_left;
        else if (result > 0)
            node = &(*node)->rb_right;
        else {
            status = ERROR_FILE_EXISTS;
            goto out;
        }
    }
    current = NULL;

    rb_link_node(&entry->rbnode, prev, node);
    rb_insert_color(&entry->rbnode, &parent->rbchildren);
    entry->parent = parent;

out:
    dprintf(NCLVL2, "<-- name_cache_insert() returning %u\n", status);
    return status;
}

static int name_cache_find_or_create(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *parent,
    IN const nfs41_component *component,
    OUT struct name_cache_entry **target_out)
{
    char dbg_name[NFS41_MAX_COMPONENT_LEN];
    int status = NO_ERROR;

    StringCchCopyNA(dbg_name, NFS41_MAX_COMPONENT_LEN,
        component->name, component->len);
    dprintf(NCLVL1, "--> name_cache_find_or_create("
        "'%s' under '%s')\n", dbg_name, parent->component);

    *target_out = name_cache_search(cache, parent, component);
    if (*target_out)
        goto out;

    status = name_cache_entry_create(cache, component, target_out);
    if (status)
        goto out;

    status = name_cache_insert(*target_out, parent);
    if (status)
        goto out_err;

out:
    dprintf(NCLVL1, "<-- name_cache_find_or_create() returning %d\n",
        status);
    return status;

out_err:
    *target_out = NULL;
    goto out;
}

static void name_cache_rename(
    IN struct nfs41_name_cache *cache,
    IN struct name_cache_entry *src_dir,
    IN struct name_cache_entry *src,
    IN struct name_cache_entry *dst_dir,
    IN const nfs41_component *component,
    OUT struct name_cache_entry **dst_out)
{
    struct name_cache_entry *existing;

    name_cache_remove(src, src_dir);

    name_cache_entry_rename(src, component);

    existing = name_cache_search(cache, dst_dir, component);
    if (existing)
        name_cache_unlink(cache, existing);

    name_cache_insert(src, dst_dir);
}


/* public name cache interface, declared in name_cache.h */

/* assuming no hard links, calculate how many entries will fit in the cache */
#define SIZE_PER_ENTRY (ATTR_ENTRY_SIZE + NAME_ENTRY_SIZE)
#define NAME_CACHE_MAX_ENTRIES (NAME_CACHE_MAX_SIZE / SIZE_PER_ENTRY)

int nfs41_name_cache_create(
    OUT struct nfs41_name_cache **cache_out)
{
    struct nfs41_name_cache *cache;
    int status = NO_ERROR;

    dprintf(NCLVL1, "nfs41_name_cache_create()\n");

    /* allocate the cache */
    cache = calloc(1, sizeof(struct nfs41_name_cache));
    if (cache == NULL) {
        status = GetLastError();
        goto out;
    }

    list_init(&cache->exp_entries);
    cache->expiration = NAME_CACHE_EXPIRATION;
    cache->max_entries = NAME_CACHE_MAX_ENTRIES;
    InitializeSRWLock(&cache->lock);

    /* allocate a pool of entries */
    cache->pool = calloc(cache->max_entries, NAME_ENTRY_SIZE);
    if (cache->pool == NULL) {
        status = GetLastError();
        goto out_err_cache;
    }

    /* initialize the attribute cache */
    status = attr_cache_init(&cache->attributes, cache->max_entries);
    if (status)
        goto out_err_pool;

    *cache_out = cache;
out:
    return status;

out_err_pool:
    free(cache->pool);
out_err_cache:
    free(cache);
    goto out;
}

int nfs41_name_cache_free(
    IN struct nfs41_name_cache **cache_out)
{
    struct nfs41_name_cache *cache = *cache_out;
    int status = NO_ERROR;

    dprintf(NCLVL1, "nfs41_name_cache_free()\n");

    /* free the attribute cache */
    attr_cache_free(&cache->attributes);

    /* free the name entry pool */
    free(cache->pool);
    free(cache);
    *cache_out = NULL;
    return status;
}

static __inline void copy_fh(
    OUT nfs41_fh *dst,
    IN OPTIONAL const struct name_cache_entry *src)
{
    if (src)
        fh_copy(dst, &src->fh);
    else
        dst->len = 0;
}

int nfs41_name_cache_lookup(
    IN struct nfs41_name_cache *cache,
    IN const char *path,
    IN const char *path_end,
    OUT OPTIONAL const char **remaining_path_out,
    OUT OPTIONAL nfs41_fh *parent_out,
    OUT OPTIONAL nfs41_fh *target_out,
    OUT OPTIONAL nfs41_file_info *info_out,
    OUT OPTIONAL bool_t *is_negative)
{
    struct name_cache_entry *parent, *target;
    const char *path_pos = path;
    int status;

    AcquireSRWLockShared(&cache->lock);

    if (!name_cache_enabled(cache)) {
        status = ERROR_NOT_SUPPORTED;
        goto out_unlock;
    }

    status = name_cache_lookup(cache, 1, path, path_end,
        &path_pos, &parent, &target, is_negative);

    if (parent_out) copy_fh(parent_out, parent);
    if (target_out) copy_fh(target_out, target);
    if (info_out && target) copy_attrs(info_out, target->attributes);

out_unlock:
    ReleaseSRWLockShared(&cache->lock);
    if (remaining_path_out) *remaining_path_out = path_pos;
    return status;
}

int nfs41_attr_cache_lookup(
    IN struct nfs41_name_cache *cache,
    IN uint64_t fileid,
    OUT nfs41_file_info *info_out)
{
    struct attr_cache_entry *entry;
    int status = NO_ERROR;

    dprintf(NCLVL1, "--> nfs41_attr_cache_lookup(%llu)\n", fileid);

    AcquireSRWLockShared(&cache->lock);

    if (!name_cache_enabled(cache)) {
        status = ERROR_NOT_SUPPORTED;
        goto out_unlock;
    }

    entry = attr_cache_search(&cache->attributes, fileid);
    if (entry == NULL) {
        status = ERROR_FILE_NOT_FOUND;
        goto out_unlock;
    }

    copy_attrs(info_out, entry);

out_unlock:
    ReleaseSRWLockShared(&cache->lock);

    dprintf(NCLVL1, "<-- nfs41_attr_cache_lookup() returning %d\n", status);
    return status;
}

int nfs41_attr_cache_update(
    IN struct nfs41_name_cache *cache,
    IN uint64_t fileid,
    IN const nfs41_file_info *info)
{
    struct attr_cache_entry *entry;
    int status = NO_ERROR;

    dprintf(NCLVL1, "--> nfs41_attr_cache_update(%llu)\n", fileid);

    AcquireSRWLockExclusive(&cache->lock);

    if (!name_cache_enabled(cache)) {
        status = ERROR_NOT_SUPPORTED;
        goto out_unlock;
    }

    entry = attr_cache_search(&cache->attributes, fileid);
    if (entry == NULL) {
        status = ERROR_FILE_NOT_FOUND;
        goto out_unlock;
    }

    attr_cache_update(entry, info);

out_unlock:
    ReleaseSRWLockExclusive(&cache->lock);

    dprintf(NCLVL1, "<-- nfs41_attr_cache_update() returning %d\n", status);
    return status;
}

int nfs41_name_cache_insert(
    IN struct nfs41_name_cache *cache,
    IN const char *path,
    IN const nfs41_component *name,
    IN OPTIONAL const nfs41_fh *fh,
    IN OPTIONAL const nfs41_file_info *info,
    IN OPTIONAL const change_info4 *cinfo)
{
    char dbg_path[NFS41_MAX_PATH_LEN];
    struct name_cache_entry *grandparent, *parent, *target;
    int status;

    StringCchCopyNA(dbg_path, NFS41_MAX_PATH_LEN, path,
        name->name + name->len - path);
    dprintf(NCLVL1, "--> nfs41_name_cache_insert('%s')\n", dbg_path);

    AcquireSRWLockExclusive(&cache->lock);

    if (!name_cache_enabled(cache)) {
        status = ERROR_NOT_SUPPORTED;
        goto out_unlock;
    }

    /* an empty path or component implies the root entry */
    if (path == NULL || name == NULL || name->len == 0) {
        /* create the root entry if it doesn't exist */
        if (cache->root == NULL) {
            const nfs41_component name = { "ROOT", 4 };
            status = name_cache_entry_create(cache, &name, &cache->root);
            if (status)
                goto out_unlock;
        }

        status = name_cache_entry_update(cache, cache->root, fh, info);
        goto out_unlock;
    }

    status = name_cache_lookup(cache, 0, path, name->name,
        NULL, &grandparent, &parent, NULL);
    if (status)
        goto out_unlock;

    if (cinfo && name_cache_entry_changed(cache, parent, cinfo)) {
        name_cache_entry_invalidate(cache, parent);
        goto out_unlock;
    }

    status = name_cache_find_or_create(cache, parent, name, &target);
    if (status)
        goto out_unlock;

    status = name_cache_entry_update(cache, target, fh, info);

out_unlock:
    ReleaseSRWLockExclusive(&cache->lock);

    dprintf(NCLVL1, "<-- nfs41_name_cache_insert() returning %d\n",
        status);
    return status;
}

int nfs41_name_cache_remove(
    IN struct nfs41_name_cache *cache,
    IN const char *path,
    IN const nfs41_component *name,
    IN const change_info4 *cinfo)
{
    struct name_cache_entry *parent, *target;
    int status;

    dprintf(NCLVL1, "--> nfs41_name_cache_remove('%s')\n", path);

    AcquireSRWLockExclusive(&cache->lock);

    if (!name_cache_enabled(cache)) {
        status = ERROR_NOT_SUPPORTED;
        goto out_unlock;
    }

    status = name_cache_lookup(cache, 0, path,
        name->name + name->len, NULL, &parent, &target, NULL);
    if (status == ERROR_PATH_NOT_FOUND)
        goto out_unlock;

    if (cinfo && name_cache_entry_changed(cache, parent, cinfo)) {
        name_cache_entry_invalidate(cache, parent);
        goto out_unlock;
    }

    if (status == ERROR_FILE_NOT_FOUND)
        goto out_unlock;

    target->attributes->numlinks--;
    name_cache_unlink(cache, target);

out_unlock:
    ReleaseSRWLockExclusive(&cache->lock);

    dprintf(NCLVL1, "<-- nfs41_name_cache_remove() returning %d\n", status);
    return status;
}

int nfs41_name_cache_rename(
    IN struct nfs41_name_cache *cache,
    IN const char *src_path,
    IN const nfs41_component *src_name,
    IN const change_info4 *src_cinfo,
    IN const char *dst_path,
    IN const nfs41_component *dst_name,
    IN const change_info4 *dst_cinfo)
{
    struct name_cache_entry *src_parent, *target;
    struct name_cache_entry *dst_parent;
    int status = NO_ERROR;

    dprintf(NCLVL1, "--> nfs41_name_cache_rename('%s' to '%s')\n",
        src_path, dst_path);

    AcquireSRWLockExclusive(&cache->lock);

    if (!name_cache_enabled(cache)) {
        status = ERROR_NOT_SUPPORTED;
        goto out_unlock;
    }

    /* get src_parent and target */
    status = name_cache_lookup(cache, 0, src_path,
        src_name->name + src_name->len, NULL, &src_parent, &target, NULL);
    if (status)
        goto out_unlock;

    /* get dst_parent */
    status = name_cache_lookup(cache, 0, dst_path,
        dst_name->name, NULL, NULL, &dst_parent, NULL);
    if (status) {
        status = ERROR_PATH_NOT_FOUND;
        goto out_unlock;
    }

    if (name_cache_entry_changed(cache, dst_parent, dst_cinfo)) {
        name_cache_unlink(cache, target);
        name_cache_entry_invalidate(cache, dst_parent);
    } else
        name_cache_rename(cache, src_parent, target,
            dst_parent, dst_name, &target);

    if (dst_parent != src_parent
        && name_cache_entry_changed(cache, src_parent, src_cinfo))
        name_cache_entry_invalidate(cache, src_parent);

out_unlock:
    ReleaseSRWLockExclusive(&cache->lock);

    dprintf(NCLVL1, "<-- nfs41_name_cache_rename() returning %d\n", status);
    return status;
}

/* nfs41_name_cache_resolve_fh() */

#define MAX_PUTFH_PER_COMPOUND 16

static bool_t get_path_fhs(
    IN struct nfs41_name_cache *cache,
    IN nfs41_abs_path *path,
    IN OUT const char **path_pos,
    IN uint32_t max_components,
    OUT nfs41_path_fh *files,
    OUT uint32_t *count)
{
    struct name_cache_entry *target;
    const char *path_end = path->path + path->len;
    nfs41_component *name;
    uint32_t i;
    int status;

    *count = 0;

    AcquireSRWLockShared(&cache->lock);

    /* look up the parent of the first component */
    status = name_cache_lookup(cache, 1, path->path,
        *path_pos, NULL, NULL, &target, NULL);
    if (status)
        goto out_unlock;

    for (i = 0; i < max_components; i++) {
        files[i].path = path;
        name = &files[i].name;

        if (!next_component(*path_pos, path_end, name))
            break;
        *path_pos = name->name + name->len;

        target = name_cache_search(cache, target, name);
        if (target == NULL || entry_invis(target, NULL)) {
            if (is_last_component(name->name, path_end))
                status = ERROR_FILE_NOT_FOUND;
            else
                status = ERROR_PATH_NOT_FOUND;
            goto out_unlock;
        }
        /* make copies for use outside of cache->lock */
        fh_copy(&files[i].fh, &target->fh);
        (*count)++;
    }

out_unlock:
    ReleaseSRWLockShared(&cache->lock);
    return *count && status == 0;
}

static int rpc_array_putfh(
    IN nfs41_session *session,
    IN nfs41_path_fh *files,
    IN uint32_t count,
    OUT uint32_t *valid_out)
{
    nfs41_compound compound;
    nfs_argop4 argops[1+MAX_PUTFH_PER_COMPOUND];
    nfs_resop4 resops[1+MAX_PUTFH_PER_COMPOUND];
    nfs41_sequence_args sequence_args;
    nfs41_sequence_res sequence_res;
    nfs41_putfh_args putfh_args[MAX_PUTFH_PER_COMPOUND];
    nfs41_putfh_res putfh_res[MAX_PUTFH_PER_COMPOUND];
    uint32_t i;
    int status;

    *valid_out = 0;

    compound_init(&compound, argops, resops);

    compound_add_op(&compound, OP_SEQUENCE, &sequence_args, &sequence_res);
    status = nfs41_session_sequence(&sequence_args, session, 0);
    if (status)
        goto out;
    ZeroMemory(&sequence_res, sizeof(sequence_res));
    ZeroMemory(putfh_res, sizeof(putfh_res));

    for (i = 0; i < count; i++){
        compound_add_op(&compound, OP_PUTFH, &putfh_args[i], &putfh_res[i]);
        putfh_args[i].file = &files[i];
        putfh_args[i].in_recovery = 1;
    }

    status = compound_encode_send_decode(session, &compound, 0, 0);
    if (status) goto out;

    status = sequence_res.sr_status;
    if (status) goto out;

    for (i = 0; i < count; i++) {
        status = putfh_res[i].status;
        if (status) break;
    }
    *valid_out = i;
out:
    return status;
}

static int delete_stale_component(
    IN struct nfs41_name_cache *cache,
    IN nfs41_session *session,
    IN const nfs41_abs_path *path,
    IN const nfs41_component *component)
{
    struct name_cache_entry *target;
    int status;

    dprintf(NCLVL1, "--> delete_stale_component('%s')\n",
        component->name);

    AcquireSRWLockExclusive(&cache->lock);

    status = name_cache_lookup(cache, 0, path->path,
        component->name + component->len, NULL, NULL, &target, NULL);
    if (status == NO_ERROR)
        name_cache_unlink(cache, target);

    ReleaseSRWLockExclusive(&cache->lock);

    dprintf(NCLVL1, "<-- delete_stale_component() returning %d\n", status);
    return status;
}

static __inline uint32_t max_putfh_components(
    IN const nfs41_session *session)
{
    const uint32_t comps = session->fore_chan_attrs.ca_maxoperations - 1;
    return min(comps, MAX_PUTFH_PER_COMPOUND);
}

int nfs41_name_cache_remove_stale(
    IN struct nfs41_name_cache *cache,
    IN nfs41_session *session,
    IN nfs41_abs_path *path)
{
    nfs41_path_fh files[MAX_PUTFH_PER_COMPOUND];
    const char *path_pos = path->path;
    const char* const path_end = path->path + path->len;
    const uint32_t max_components = max_putfh_components(session);
    uint32_t count, index;
    int status = NO_ERROR;

    AcquireSRWLockShared(&cache->lock);

    /* if there's no cache, don't check any components */
    if (!name_cache_enabled(cache))
        path_pos = path_end;

    ReleaseSRWLockShared(&cache->lock);

    /* hold a lock on the path to protect against rename */
    AcquireSRWLockShared(&path->lock);

    while (get_path_fhs(cache, path, &path_pos, max_components, files, &count)) {
        status = rpc_array_putfh(session, files, count, &index);

        if (status == NFS4ERR_STALE || status == NFS4ERR_FHEXPIRED) {
            status = delete_stale_component(cache,
                session, path, &files[index].name);
            break;
        }
        if (status) {
            status = nfs_to_windows_error(status, ERROR_FILE_NOT_FOUND);
            break;
        }
    }

    ReleaseSRWLockShared(&path->lock);

    return status;
}