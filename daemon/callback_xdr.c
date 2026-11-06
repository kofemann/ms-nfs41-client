/* NFSv4.1 client for Windows
 * Copyright (C) 2012 The Regents of the University of Michigan
 * Copyright (C) 2024-2026 Roland Mainz <roland.mainz@nrubsig.org>
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

#include "nfs41_callback.h"
#include "nfs41_ops.h"
#include "nfs41_xdr.h"
#include "util.h"
#include "daemon_debug.h"


#define CBXLVL 0 /* dprintf level for callback xdr logging */
#define CBX_ERR(msg) DPRINTF(CBXLVL, ("'%s': failed at '%s'\n", __func__, (msg)))


/* common types */
bool_t xdr_bitmap4(XDR *xdr, bitmap4 *bitmap);
bool_t xdr_fattr4(XDR *xdr, fattr4 *fattr);
bool_t xdr_nfsace4(XDR *xdr, nfsace4 *ace);
bool_t xdr_limit_by4(XDR *xdr, enum limit_by4 *limitby);
bool_t xdr_stateid4(XDR *xdr, stateid4 *si);
bool_t xdr_fh(XDR *xdr, nfs41_fh *fh);
bool_t xdr_fsid(XDR *xdr, nfs41_fsid *fsid);
bool_t xdr_stable_how4(XDR *xdr, enum stable_how4 *sh);
bool_t xdr_state_owner4(XDR *xdr,state_owner4 *so);

/* Local prototypes */
static bool_t xdr_notify4(XDR *xdr, struct notify4 *notify);


static bool_t xdr_notify4(XDR *xdr, struct notify4 *notify)
{
    return xdr_bitmap4(xdr, &notify->mask)
        && xdr_bytes(xdr, &notify->list, &notify->len, NFS4_OPAQUE_LIMIT);
}

static bool_t op_cb_open_read_delegation(XDR *xdr,
    open_delegation4 *delegation)
{
    bool_t result;

    result = xdr_stateid4(xdr, &delegation->stateid);
    if (!result) { CBX_ERR("push_deleg.delegation.read.stateid"); goto out; }

    result = xdr_bool(xdr, &delegation->recalled);
    if (!result) { CBX_ERR("push_deleg.delegation.read.recalled"); goto out; }

    result = xdr_nfsace4(xdr, &delegation->permissions);
    if (!result) {
        CBX_ERR("push_deleg.delegation.read.permissions");
        goto out;
    }
out:
    return result;
}

static bool_t op_cb_open_write_delegation(XDR *xdr,
    open_delegation4 *delegation)
{
    enum limit_by4 limitby;
    uint32_t blocks, bytes_per_block;
    uint64_t filesize;
    bool_t result;

    result = xdr_stateid4(xdr, &delegation->stateid);
    if (!result) { CBX_ERR("push_deleg.delegation.write.stateid"); goto out; }

    result = xdr_bool(xdr, &delegation->recalled);
    if (!result) { CBX_ERR("push_deleg.delegation.write.recalled"); goto out; }

    result = xdr_limit_by4(xdr, &limitby);
    if (!result) { CBX_ERR("push_deleg.delegation.write.limitby"); goto out; }

    switch (limitby) {
    case NFS_LIMIT_SIZE:
        result = xdr_uint64_t(xdr, &filesize);
        if (!result) { CBX_ERR("push_deleg.delegation.write.filesize"); goto out; }
        break;
    case NFS_LIMIT_BLOCKS:
        result = xdr_uint32_t(xdr, &blocks);
        if (!result) { CBX_ERR("push_deleg.delegation.write.blocks"); goto out; }

        result = xdr_uint32_t(xdr, &bytes_per_block);
        if (!result) { CBX_ERR("push_deleg.delegation.write.bytes_per_block"); goto out; }
        break;
    default:
        eprintf("op_cb_open_write_delegation: "
            "unsupported space_limit4 limitby=%ld\n",
            (long)limitby);
        result = FALSE;
        goto out;
    }

    result = xdr_nfsace4(xdr, &delegation->permissions);
    if (!result) { CBX_ERR("push_deleg.delegation.write.permissions"); goto out; }
out:
    return result;
}

static bool_t op_cb_open_none_delegation(XDR *xdr)
{
    enum_t why_no_deleg;
    bool_t will_signal;
    bool_t result;

    result = xdr_enum(xdr, &why_no_deleg);
    if (!result) { CBX_ERR("push_deleg.delegation.none_ext.why_no_deleg"); goto out; }

    switch (why_no_deleg) {
    case WND4_CONTENTION:
    case WND4_RESOURCE:
        result = xdr_bool(xdr, &will_signal);
        if (!result) { CBX_ERR("push_deleg.delegation.none_ext.will_signal"); goto out; }
        break;
    default:
        result = TRUE;
        break;
    }
out:
    return result;
}

static bool_t op_cb_open_delegation(XDR *xdr,
    open_delegation4 *delegation)
{
    bool_t result;

    result = xdr_enum(xdr, (enum_t *)&delegation->type);
    if (!result) { CBX_ERR("push_deleg.delegation.type"); goto out; }

    switch (delegation->type) {
    case OPEN_DELEGATE_NONE:
        result = TRUE;
        break;
    case OPEN_DELEGATE_NONE_EXT:
        result = op_cb_open_none_delegation(xdr);
        break;
    case OPEN_DELEGATE_READ:
        result = op_cb_open_read_delegation(xdr, delegation);
        break;
    case OPEN_DELEGATE_WRITE:
        result = op_cb_open_write_delegation(xdr, delegation);
        break;
    default:
        eprintf("op_cb_open_delegation: "
            "unsupported delegation->type=%d\n",
            (int)delegation->type);
        result = FALSE;
        break;
    }
out:
    return result;
}


/* OP_CB_LAYOUTRECALL */
static bool_t op_cb_layoutrecall_file(XDR *xdr, struct cb_recall_file *args)
{
    bool_t result;

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("layoutrecall_file.fh"); goto out; }

    result = xdr_uint64_t(xdr, &args->offset);
    if (!result) { CBX_ERR("layoutrecall_file.offset"); goto out; }

    result = xdr_uint64_t(xdr, &args->length);
    if (!result) { CBX_ERR("layoutrecall_file.length"); goto out; }

    result = xdr_stateid4(xdr, &args->stateid);
    if (!result) { CBX_ERR("layoutrecall_file.stateid"); goto out; }
out:
    return result;
}

static bool_t op_cb_layoutrecall_fsid(XDR *xdr, union cb_recall_file_args *args)
{
    bool_t result;

    result = xdr_fsid(xdr, &args->fsid);
    if (!result) { CBX_ERR("layoutrecall_fsid.fsid"); goto out; }
out:
    return result;
}

static const struct xdr_discrim cb_layoutrecall_discrim[] = {
    { PNFS_RETURN_FILE,     (xdrproc_t)op_cb_layoutrecall_file },
    { PNFS_RETURN_FSID,     (xdrproc_t)op_cb_layoutrecall_fsid },
    { PNFS_RETURN_ALL,      (xdrproc_t)xdr_void },
    { 0,                    NULL_xdrproc_t }
};

static bool_t op_cb_layoutrecall_args(XDR *xdr, struct cb_layoutrecall_args *args)
{
    bool_t result;

    result = xdr_enum(xdr, (enum_t*)&args->type);
    if (!result) { CBX_ERR("layoutrecall_args.type"); goto out; }

    result = xdr_enum(xdr, (enum_t*)&args->iomode);
    if (!result) { CBX_ERR("layoutrecall_args.iomode"); goto out; }

    result = xdr_bool(xdr, &args->changed);
    if (!result) { CBX_ERR("layoutrecall_args.changed"); goto out; }

    result = xdr_union(xdr, (enum_t*)&args->recall.type,
        (char*)&args->recall.args, cb_layoutrecall_discrim, NULL_xdrproc_t);
    if (!result) { CBX_ERR("layoutrecall_args.recall"); goto out; }
out:
    return result;
}

static bool_t op_cb_layoutrecall_res(XDR *xdr, struct cb_layoutrecall_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("layoutrecall_res.status"); goto out; }
out:
    return result;
}


/* OP_CB_RECALL_SLOT */
static bool_t op_cb_recall_slot_args(XDR *xdr, struct cb_recall_slot_args *res)
{
    bool_t result;

    result = xdr_uint32_t(xdr, &res->target_highest_slotid);
    if (!result) { CBX_ERR("recall_slot.target_highest_slotid"); goto out; }
out:
    return result;
}

static bool_t op_cb_recall_slot_res(XDR *xdr, struct cb_recall_slot_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("recall_slot.status"); goto out; }
out:
    return result;
}


/* OP_CB_SEQUENCE */
static bool_t op_cb_sequence_ref(XDR *xdr, struct cb_sequence_ref *args)
{
    bool_t result;

    result = xdr_uint32_t(xdr, &args->sequenceid);
    if (!result) { CBX_ERR("sequence_ref.sequenceid"); goto out; }

    result = xdr_uint32_t(xdr, &args->slotid);
    if (!result) { CBX_ERR("sequence_ref.slotid"); goto out; }
out:
    return result;
}

static bool_t op_cb_sequence_ref_list(XDR *xdr, struct cb_sequence_ref_list *args)
{
    bool_t result;

    result = xdr_sessionid4(xdr, &args->sessionid);
    if (!result) { CBX_ERR("sequence_ref_list.sessionid"); goto out; }

    result = xdr_array(xdr, (char**)&args->calls, &args->call_count,
        64, sizeof(struct cb_sequence_ref), (xdrproc_t)op_cb_sequence_ref);
    if (!result) { CBX_ERR("sequence_ref_list.calls"); goto out; }
out:
    return result;
}

static bool_t op_cb_sequence_args(XDR *xdr, struct cb_sequence_args *args)
{
    bool_t result;

    result = xdr_sessionid4(xdr, &args->sessionid);
    if (!result) { CBX_ERR("sequence_args.sessionid"); goto out; }

    result = xdr_uint32_t(xdr, &args->sequenceid);
    if (!result) { CBX_ERR("sequence_args.sequenceid"); goto out; }

    result = xdr_uint32_t(xdr, &args->slotid);
    if (!result) { CBX_ERR("sequence_args.slotid"); goto out; }

    result = xdr_uint32_t(xdr, &args->highest_slotid);
    if (!result) { CBX_ERR("sequence_args.highest_slotid"); goto out; }

    result = xdr_bool(xdr, &args->cachethis);
    if (!result) { CBX_ERR("sequence_args.cachethis"); goto out; }

    result = xdr_array(xdr, (char**)&args->ref_lists,
        &args->ref_list_count, 64, sizeof(struct cb_sequence_ref_list),
        (xdrproc_t)op_cb_sequence_ref_list);
    if (!result) { CBX_ERR("sequence_args.ref_lists"); goto out; }
out:
    return result;
}

static bool_t op_cb_sequence_res_ok(XDR *xdr, struct cb_sequence_res_ok *res)
{
    bool_t result;

    result = xdr_sessionid4(xdr, &res->sessionid);
    if (!result) { CBX_ERR("sequence_res.sessionid"); goto out; }

    result = xdr_uint32_t(xdr, &res->sequenceid);
    if (!result) { CBX_ERR("sequence_res.sequenceid"); goto out; }

    result = xdr_uint32_t(xdr, &res->slotid);
    if (!result) { CBX_ERR("sequence_res.slotid"); goto out; }

    result = xdr_uint32_t(xdr, &res->highest_slotid);
    if (!result) { CBX_ERR("sequence_res.highest_slotid"); goto out; }

    result = xdr_uint32_t(xdr, &res->target_highest_slotid);
    if (!result) { CBX_ERR("sequence_res.target_highest_slotid"); goto out; }
out:
    return result;
}

static const struct xdr_discrim cb_sequence_res_discrim[] = {
    { NFS4_OK,              (xdrproc_t)op_cb_sequence_res_ok },
    { 0,                    NULL_xdrproc_t }
};

static bool_t op_cb_sequence_res(XDR *xdr, struct cb_sequence_res *res)
{
    bool_t result;

    result = xdr_union(xdr, &res->status, (char*)&res->ok,
        cb_sequence_res_discrim, (xdrproc_t)xdr_void);
    if (!result) { CBX_ERR("seq:argop.args"); goto out; }
out:
    return result;
}

/* OP_CB_GETATTR */
static bool_t op_cb_getattr_args(XDR *xdr, struct cb_getattr_args *args)
{
    bool_t result;

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("getattr.fh"); goto out; }

    result = xdr_bitmap4(xdr, &args->attr_request);
    if (!result) { CBX_ERR("getattr.attr_request"); goto out; }
out:
    return result;
}

static bool_t info_to_fattr4(nfs41_file_info *info, fattr4 *fattr)
{
    XDR fattr_xdr;
    bool_t result = TRUE;

    /* encode nfs41_file_info into fattr4 */
    xdrmem_create(&fattr_xdr, (char*)fattr->attr_vals,
        NFS4_OPAQUE_LIMIT, XDR_ENCODE);

    /* The only attributes that the server can reliably
     * query via CB_GETATTR are size and change.
     * FIXME: What about |FATTR4_WORD1_SPACE_USED| ?
     */
    if (bitmap_isset(&info->attrmask, 0, FATTR4_WORD0_CHANGE)) {
        result = xdr_uint64_t(&fattr_xdr, &info->change);
        if (!result) { CBX_ERR("getattr.info.change"); goto out; }
        bitmap_set(&fattr->attrmask, 0, FATTR4_WORD0_CHANGE);
    }
    if (bitmap_isset(&info->attrmask, 0, FATTR4_WORD0_SIZE)) {
        result = xdr_uint64_t(&fattr_xdr, &info->size);
        if (!result) { CBX_ERR("getattr.info.size"); goto out; }
        bitmap_set(&fattr->attrmask, 0, FATTR4_WORD0_SIZE);
    }
    fattr->attr_vals_len = xdr_getpos(&fattr_xdr);
out:
    return result;
}

static bool_t op_cb_getattr_res(XDR *xdr, struct cb_getattr_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("getattr.status"); goto out; }

    if (res->status == NFS4_OK) {
        fattr4 fattr = { 0 };

        result = info_to_fattr4(&res->info, &fattr);
        if (!result) { goto out; }

        result = xdr_fattr4(xdr, &fattr);
        if (!result) { CBX_ERR("getattr.obj_attributes"); goto out; }
    }
out:
    return result;
}

/* OP_CB_RECALL */
static bool_t op_cb_recall_args(XDR *xdr, struct cb_recall_args *args)
{
    bool_t result;

    result = xdr_stateid4(xdr, &args->stateid);
    if (!result) { CBX_ERR("recall.stateid"); goto out; }

    result = xdr_bool(xdr, &args->truncate);
    if (!result) { CBX_ERR("recall.truncate"); goto out; }

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("recall.fh"); goto out; }
out:
    return result;
}

static bool_t op_cb_recall_res(XDR *xdr, struct cb_recall_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("recall.status"); goto out; }
out:
    return result;
}

/* OP_CB_NOTIFY */
static bool_t op_cb_notify_args(XDR *xdr, struct cb_notify_args *args)
{
    bool_t result;

    result = xdr_stateid4(xdr, &args->stateid);
    if (!result) { CBX_ERR("notify.stateid"); goto out; }

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("notify.fh"); goto out; }

    result = xdr_array(xdr, (char **)&args->changes,
        &args->change_count, CB_COMPOUND_MAX_OPERATIONS,
        sizeof(struct notify4), (xdrproc_t)xdr_notify4);
    if (!result) { CBX_ERR("notify.changes"); goto out; }
out:
    return result;
}

static bool_t op_cb_notify_res(XDR *xdr, struct cb_notify_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("notify.status"); goto out; }
out:
    return result;
}

/* OP_CB_PUSH_DELEG */
static bool_t op_cb_push_deleg_args(XDR *xdr, struct cb_push_deleg_args *args)
{
    bool_t result;

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("push_deleg.fh"); goto out; }

    result = op_cb_open_delegation(xdr, &args->delegation);
    if (!result) { CBX_ERR("push_deleg.delegation"); goto out; }
out:
    return result;
}

static bool_t op_cb_push_deleg_res(XDR *xdr, struct cb_push_deleg_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("push_deleg.status"); goto out; }
out:
    return result;
}

/* OP_CB_RECALL_ANY */
static bool_t op_cb_recall_any_args(XDR *xdr, struct cb_recall_any_args *args)
{
    bool_t result;

    result = xdr_uint32_t(xdr, &args->objects_to_keep);
    if (!result) { CBX_ERR("recall_any.objects_to_keep"); goto out; }

    result = xdr_bitmap4(xdr, &args->type_mask);
    if (!result) { CBX_ERR("recall_any.type_mask"); goto out; }
out:
    return result;
}

static bool_t op_cb_recall_any_res(XDR *xdr, struct cb_recall_any_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("recall_any.status"); goto out; }
out:
    return result;
}

/* OP_CB_RECALLABLE_OBJ_AVAIL */
static bool_t op_cb_recallable_obj_avail_args(XDR *xdr,
    struct cb_recallable_obj_avail_args *args)
{
    bool_t result;

    result = xdr_uint32_t(xdr, &args->objects_to_keep);
    if (!result) { CBX_ERR("recallable_obj_avail.objects_to_keep"); goto out; }

    result = xdr_bitmap4(xdr, &args->type_mask);
    if (!result) { CBX_ERR("recallable_obj_avail.type_mask"); goto out; }
out:
    return result;
}

static bool_t op_cb_recallable_obj_avail_res(XDR *xdr, struct cb_recallable_obj_avail_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("recallable_obj_avail.status"); goto out; }
out:
    return result;
}

/* OP_CB_WANTS_CANCELLED */
static bool_t op_cb_wants_cancelled_args(XDR *xdr,
    struct cb_wants_cancelled_args *args)
{
    bool_t result;

    result = xdr_bool(xdr, &args->contended_wants_cancelled);
    if (!result) { CBX_ERR("wants_cancelled.contended"); goto out; }

    result = xdr_bool(xdr, &args->resourced_wants_cancelled);
    if (!result) { CBX_ERR("wants_cancelled.resourced"); goto out; }
out:
    return result;
}

static bool_t op_cb_wants_cancelled_res(XDR *xdr, struct cb_wants_cancelled_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("wants_cancelled.status"); goto out; }
out:
    return result;
}

/* OP_CB_NOTIFY_LOCK */
static bool_t op_cb_notify_lock_args(XDR *xdr,
    struct cb_notify_lock_args *args)
{
    bool_t result;

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("notify_lock.fh"); goto out; }

    result = xdr_state_owner4(xdr, &args->lock_owner);
    if (!result) { CBX_ERR("notify_lock.lock_owner"); goto out; }
out:
    return result;
}

static bool_t op_cb_notify_lock_res(XDR *xdr, struct cb_notify_lock_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("notify_lock.status"); goto out; }
out:
    return result;
}

/* OP_CB_NOTIFY_DEVICEID */
static bool_t cb_notify_deviceid_change(XDR *xdr, struct notify_deviceid4 *change)
{
    bool_t result;

    result = xdr_uint32_t(xdr, (uint32_t*)&change->layouttype);
    if (!result) { CBX_ERR("notify_deviceid.change.layouttype"); goto out; }

    result = xdr_opaque(xdr, (char*)change->deviceid, PNFS_DEVICEID_SIZE);
    if (!result) { CBX_ERR("notify_deviceid.change.deviceid"); goto out; }

    result = xdr_bool(xdr, &change->immediate);
    if (!result) { CBX_ERR("notify_deviceid.change.immediate"); goto out; }
out:
    return result;
}

static bool_t cb_notify_deviceid_delete(XDR *xdr, struct notify_deviceid4 *change)
{
    bool_t result;

    result = xdr_uint32_t(xdr, (uint32_t*)&change->layouttype);
    if (!result) { CBX_ERR("notify_deviceid.delete.layouttype"); goto out; }

    result = xdr_opaque(xdr, (char*)change->deviceid, PNFS_DEVICEID_SIZE);
    if (!result) { CBX_ERR("notify_deviceid.delete.deviceid"); goto out; }
out:
    return result;
}

static bool_t op_cb_notify_deviceid_args(XDR *xdr, struct cb_notify_deviceid_args *args)
{
    XDR notify_xdr;
    uint32_t i, j, c;
    bool_t result;

    /* decode the generic notify4 list */
    result = xdr_array(xdr, (char**)&args->notify_list,
        &args->notify_count, CB_COMPOUND_MAX_OPERATIONS,
        sizeof(struct notify4), (xdrproc_t)xdr_notify4);
    if (!result) { CBX_ERR("notify_deviceid.notify_list"); goto out; }

    switch (xdr->x_op) {
    case XDR_FREE:
        free(args->change_list);
    case XDR_ENCODE:
        return TRUE;
    default:
        eprintf("op_cb_notify_deviceid_args: Unexpected xdr->x_op=%d\n",
            (int)xdr->x_op);
        break;
    }

    /* count the number of device changes */
    args->change_count = 0;
    for (i = 0; i < args->notify_count; i++)
        args->change_count += args->notify_list[i].mask.count;

    args->change_list = calloc(args->change_count, sizeof(struct notify_deviceid4));
    if (args->change_list == NULL)
        return FALSE;

    c = 0;
    for (i = 0; i < args->notify_count; i++) {
        struct notify4 *notify = &args->notify_list[i];

        /* decode the device notifications out of the opaque buffer */
        xdrmem_create(&notify_xdr, notify->list, notify->len, XDR_DECODE);

        for (j = 0; j < notify->mask.count; j++) {
            struct notify_deviceid4 *change = &args->change_list[c++];
            change->type = notify->mask.arr[j];

            switch (change->type) {
            case NOTIFY_DEVICEID4_CHANGE:
                result = cb_notify_deviceid_change(&notify_xdr, change);
                if (!result) { CBX_ERR("notify_deviceid.change"); goto out; }
                break;
            case NOTIFY_DEVICEID4_DELETE:
                result = cb_notify_deviceid_delete(&notify_xdr, change);
                if (!result) { CBX_ERR("notify_deviceid.delete"); goto out; }
                break;
            }
        }
    }
out:
    return result;
}

static bool_t op_cb_notify_deviceid_res(XDR *xdr, struct cb_notify_deviceid_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("notify_deviceid.status"); goto out; }
out:
    return result;
}

/* OP_CB_OFFLOAD */
static bool_t op_cb_offload_write_response(XDR *xdr,
    struct cb_offload_write_response *response)
{
    bool_t result;

    result = xdr_uint32_t(xdr, &response->callback_id_count);
    if (!result) {
        CBX_ERR("offload.write_response.callback_id_count");
        goto out;
    }

    if (response->callback_id_count > 1) {
        eprintf("op_cb_offload_write_response: callback_id_count=%d invalid\n",
            (long)response->callback_id_count);
        result = FALSE;
        goto out;
    }

    if (response->callback_id_count == 1) {
        result = xdr_stateid4(xdr, &response->callback_id[0]);
        if (!result) {
            CBX_ERR("offload.write_response.callback_id");
            goto out;
        }
    }

    result = xdr_uint64_t(xdr, &response->count);
    if (!result) { CBX_ERR("offload.write_response.count"); goto out; }

    result = xdr_stable_how4(xdr, &response->committed);
    if (!result) { CBX_ERR("offload.write_response.committed"); goto out; }

    result = xdr_verifier4(xdr, &response->writeverf);
    if (!result) { CBX_ERR("offload.write_response.writeverf"); goto out; }
out:
    return result;
}

static bool_t op_cb_offload_info(XDR *xdr, struct cb_offload_info *info)
{
    bool_t result;

    result = xdr_enum(xdr, &info->status);
    if (!result) { CBX_ERR("offload.info.status"); goto out; }

    switch (info->status) {
    case NFS4_OK:
        result = op_cb_offload_write_response(xdr, &info->u.resok);
        if (!result) { CBX_ERR("offload.info.resok"); goto out; }
        break;
    default:
        result = xdr_uint64_t(xdr, &info->u.bytes_copied);
        if (!result) { CBX_ERR("offload.info.bytes_copied"); goto out; }
        break;
    }
out:
    return result;
}

static bool_t op_cb_offload_args(XDR *xdr, struct cb_offload_args *args)
{
    bool_t result;

    result = xdr_fh(xdr, &args->fh);
    if (!result) { CBX_ERR("offload.fh"); goto out; }

    result = xdr_stateid4(xdr, &args->stateid);
    if (!result) { CBX_ERR("offload.stateid"); goto out; }

    result = op_cb_offload_info(xdr, &args->offload_info);
    if (!result) { CBX_ERR("offload.info"); goto out; }
out:
    return result;
}

static bool_t op_cb_offload_res(XDR *xdr, struct cb_offload_res *res)
{
    bool_t result;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("offload.status"); goto out; }
out:
    return result;
}

/* CB_COMPOUND */
static bool_t cb_compound_tag(XDR *xdr, struct cb_compound_tag *args)
{
    if (!xdr_uint32_t(xdr, &args->len))
        return FALSE;

    if (args->len >= (CB_COMPOUND_MAX_TAG-1)) {
        eprintf("cb_compound_tag: CB_COMPOUND tag_len=%lu >= "
            "(CB_COMPOUND_MAX_TAG-1)=%ld\n",
            (long)args->len,
            (long)(CB_COMPOUND_MAX_TAG-1));

        return FALSE;
    }

    if (!xdr_opaque(xdr, args->str, args->len))
        return FALSE;

    /*
     * CB TAG is an XDR counted opaque string, but we also use
     * it as an ISO C string for debug output. Keep the in-memory copy
     * '\0'-terminated.
     */
    if (xdr->x_op == XDR_DECODE) {
        args->str[args->len] = '\0';
    }

    return TRUE;
}

static const struct xdr_discrim cb_argop_discrim[] = {
    { OP_CB_LAYOUTRECALL,   (xdrproc_t)op_cb_layoutrecall_args },
    { OP_CB_RECALL_SLOT,    (xdrproc_t)op_cb_recall_slot_args },
    { OP_CB_SEQUENCE,       (xdrproc_t)op_cb_sequence_args },
    { OP_CB_GETATTR,        (xdrproc_t)op_cb_getattr_args },
    { OP_CB_RECALL,         (xdrproc_t)op_cb_recall_args },
    { OP_CB_NOTIFY,         (xdrproc_t)op_cb_notify_args },
    { OP_CB_PUSH_DELEG,     (xdrproc_t)op_cb_push_deleg_args },
    { OP_CB_RECALL_ANY,     (xdrproc_t)op_cb_recall_any_args },
    { OP_CB_RECALLABLE_OBJ_AVAIL, (xdrproc_t)op_cb_recallable_obj_avail_args },
    { OP_CB_WANTS_CANCELLED, (xdrproc_t)op_cb_wants_cancelled_args },
    { OP_CB_NOTIFY_LOCK,     (xdrproc_t)op_cb_notify_lock_args },
    { OP_CB_NOTIFY_DEVICEID, (xdrproc_t)op_cb_notify_deviceid_args },
    { OP_CB_OFFLOAD,         (xdrproc_t)op_cb_offload_args },
    { OP_CB_ILLEGAL,         NULL_xdrproc_t },
};

static bool_t cb_compound_argop(XDR *xdr, struct cb_argop *args)
{
    bool_t result;

    result = xdr_union(xdr, &args->opnum, (char*)&args->args,
        cb_argop_discrim, NULL_xdrproc_t);
    if (!result) { CBX_ERR("cmb:argop.args"); goto out; }
out:
    return result;
}

bool_t proc_cb_compound_args(XDR *xdr, struct cb_compound_args *args)
{
    bool_t result;

    result = cb_compound_tag(xdr, &args->tag);
    if (!result) { CBX_ERR("compound.tag"); goto out; }

    result = xdr_uint32_t(xdr, &args->minorversion);
    if (!result) { CBX_ERR("compound.minorversion"); goto out; }

    /* "superfluous in NFSv4.1 and MUST be ignored by the client" */
    result = xdr_uint32_t(xdr, &args->callback_ident);
    if (!result) { CBX_ERR("compound.callback_ident"); goto out; }

    result = xdr_array(xdr, (char**)&args->argarray,
        &args->argarray_count, CB_COMPOUND_MAX_OPERATIONS,
        sizeof(struct cb_argop), (xdrproc_t)cb_compound_argop);
    if (!result) { CBX_ERR("compound.argarray"); goto out; }
out:
    return result;
}

static const struct xdr_discrim cb_resop_discrim[] = {
    { OP_CB_LAYOUTRECALL,   (xdrproc_t)op_cb_layoutrecall_res },
    { OP_CB_RECALL_SLOT,    (xdrproc_t)op_cb_recall_slot_res },
    { OP_CB_SEQUENCE,       (xdrproc_t)op_cb_sequence_res },
    { OP_CB_GETATTR,        (xdrproc_t)op_cb_getattr_res },
    { OP_CB_RECALL,         (xdrproc_t)op_cb_recall_res },
    { OP_CB_NOTIFY,         (xdrproc_t)op_cb_notify_res },
    { OP_CB_PUSH_DELEG,     (xdrproc_t)op_cb_push_deleg_res },
    { OP_CB_RECALL_ANY,     (xdrproc_t)op_cb_recall_any_res },
    { OP_CB_RECALLABLE_OBJ_AVAIL, (xdrproc_t)op_cb_recallable_obj_avail_res },
    { OP_CB_WANTS_CANCELLED, (xdrproc_t)op_cb_wants_cancelled_res },
    { OP_CB_NOTIFY_LOCK,     (xdrproc_t)op_cb_notify_lock_res },
    { OP_CB_NOTIFY_DEVICEID, (xdrproc_t)op_cb_notify_deviceid_res },
    { OP_CB_OFFLOAD,        (xdrproc_t)op_cb_offload_res },
    { OP_CB_ILLEGAL,        NULL_xdrproc_t },
};

static bool_t cb_compound_resop(XDR *xdr, struct cb_resop *res)
{
    /* save xdr encode/decode status to see which operation failed */
    res->xdr_ok = xdr_union(xdr, &res->opnum, (char*)&res->res,
        cb_resop_discrim, NULL_xdrproc_t);
    if (!res->xdr_ok) { CBX_ERR("resop.res"); goto out; }
out:
    return res->xdr_ok;
}

bool_t proc_cb_compound_res(XDR *xdr, struct cb_compound_res *res)
{
    bool_t result;

    if (res == NULL)
        return TRUE;

    result = xdr_enum(xdr, &res->status);
    if (!result) { CBX_ERR("compound_res.status"); goto out; }

    result = cb_compound_tag(xdr, &res->tag);
    if (!result) { CBX_ERR("compound_res.tag"); goto out; }

    result = xdr_array(xdr, (char**)&res->resarray,
        &res->resarray_count, CB_COMPOUND_MAX_OPERATIONS,
        sizeof(struct cb_resop), (xdrproc_t)cb_compound_resop);
    if (!result) { CBX_ERR("compound_res.resarray"); goto out; }
out:
    if (xdr->x_op == XDR_FREE)
        free(res);
    return result;
}
