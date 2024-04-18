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

#include <Windows.h>
#include <process.h>
#include <stdio.h>

#include "nfs41_build_features.h"
#include "nfs41_ops.h"
#include "nfs41_callback.h"
#include "util.h"
#include "daemon_debug.h"


/* after a CB_RECALL_SLOT or NFS4ERR_BADSLOT, wait a short time for the
 * SEQUENCE.target_highest_slotid to catch up before updating max_slots again */
#define MAX_SLOTS_DELAY 2000 /* in milliseconds */


/* predicate for nfs41_slot_table.cond */
static int slot_table_avail(
    IN const nfs41_slot_table *table)
{
    return table->num_used < table->max_slots;
}

/* session slot mechanism */
static void init_slot_table(nfs41_slot_table *table) 
{
    uint32_t i;
    EnterCriticalSection(&table->lock);
    table->max_slots = NFS41_MAX_NUM_SLOTS;
    for (i = 0; i < NFS41_MAX_NUM_SLOTS; i++) {
        table->seq_nums[i] = 1;
        table->used_slots[i] = 0;
    }
    table->highest_used = table->num_used = 0;
    table->target_delay = 0;

    /* wake any threads waiting on a slot */
    if (slot_table_avail(table))
        WakeAllConditionVariable(&table->cond);
    LeaveCriticalSection(&table->lock);
}

static void resize_slot_table(
    IN nfs41_slot_table *table,
    IN uint32_t target_highest_slotid)
{
    if (target_highest_slotid >= NFS41_MAX_NUM_SLOTS)
        target_highest_slotid = NFS41_MAX_NUM_SLOTS - 1;

    if (table->max_slots != target_highest_slotid + 1) {
        DPRINTF(2, ("updated max_slots %u to %u\n",
            table->max_slots, target_highest_slotid + 1));
        table->max_slots = target_highest_slotid + 1;

        if (slot_table_avail(table))
            WakeAllConditionVariable(&table->cond);
    }
}

void nfs41_session_bump_seq(
    IN nfs41_session *session,
    IN uint32_t slotid,
    IN uint32_t target_highest_slotid)
{
    nfs41_slot_table *table = &session->table;

    AcquireSRWLockShared(&session->client->session_lock);
    EnterCriticalSection(&table->lock);

    if (slotid < NFS41_MAX_NUM_SLOTS)
        table->seq_nums[slotid]++;

    /* adjust max_slots in response to changes in target_highest_slotid,
     * but not immediately after a CB_RECALL_SLOT or NFS4ERR_BADSLOT error */
    if (table->target_delay <= GetTickCount64())
        resize_slot_table(table, target_highest_slotid);

    LeaveCriticalSection(&table->lock);
    ReleaseSRWLockShared(&session->client->session_lock);
}

void nfs41_session_free_slot(
    IN nfs41_session *session,
    IN uint32_t slotid)
{
    nfs41_slot_table *table = &session->table;

    AcquireSRWLockShared(&session->client->session_lock);
    EnterCriticalSection(&table->lock);

    /* flag the slot as unused */
    if (slotid < NFS41_MAX_NUM_SLOTS && table->used_slots[slotid]) {
        table->used_slots[slotid] = 0;
        table->num_used--;
    }
    /* update highest_used if necessary */
    if (slotid == table->highest_used) {
        while (table->highest_used && !table->used_slots[table->highest_used])
            table->highest_used--;
    }
    DPRINTF(3, ("freeing slot#=%d used=%d highest=%d\n",
        slotid, table->num_used, table->highest_used));

    /* wake any threads waiting on a slot */
    if (slot_table_avail(table))
        WakeAllConditionVariable(&table->cond);

    LeaveCriticalSection(&table->lock);
    ReleaseSRWLockShared(&session->client->session_lock);
}

void nfs41_session_get_slot(
    IN nfs41_session *session,
    OUT uint32_t *slot,
    OUT uint32_t *seqid,
    OUT uint32_t *highest)
{
    nfs41_slot_table *table = &session->table;
    uint32_t i;

    AcquireSRWLockShared(&session->client->session_lock);
    EnterCriticalSection(&table->lock);

    /* wait for an available slot */
    while (!slot_table_avail(table))
        SleepConditionVariableCS(&table->cond, &table->lock, INFINITE);

    for (i = 0; i < table->max_slots; i++) {
        if (table->used_slots[i])
            continue;

        table->used_slots[i] = 1;
        table->num_used++;
        if (i > table->highest_used)
            table->highest_used = i;

        *slot = i;
        *seqid = table->seq_nums[i];
        *highest = table->highest_used;
        break;
    }
    LeaveCriticalSection(&table->lock);
    ReleaseSRWLockShared(&session->client->session_lock);

    DPRINTF(2, ("session 0x%p: using slot#=%d with seq#=%d highest=%d\n",
        session, *slot, *seqid, *highest));
}

int nfs41_session_recall_slot(
    IN nfs41_session *session,
    IN OUT uint32_t target_highest_slotid)
{
    nfs41_slot_table *table = &session->table;

    AcquireSRWLockShared(&session->client->session_lock);
    EnterCriticalSection(&table->lock);
    resize_slot_table(table, target_highest_slotid);
    table->target_delay = GetTickCount64() + MAX_SLOTS_DELAY;
    LeaveCriticalSection(&table->lock);
    ReleaseSRWLockShared(&session->client->session_lock);

    return NFS4_OK;
}

int nfs41_session_bad_slot(
    IN nfs41_session *session,
    IN OUT nfs41_sequence_args *args)
{
    nfs41_slot_table *table = &session->table;
    int status = NFS4ERR_BADSLOT;

    if (args->sa_slotid == 0) {
        eprintf("server bug detected: NFS4ERR_BADSLOT for slotid=0\n");
        goto out;
    }

    /* avoid using any slots >= bad_slotid */
    EnterCriticalSection(&table->lock);
    if (table->max_slots > args->sa_slotid) {
        resize_slot_table(table, args->sa_slotid);
        table->target_delay = GetTickCount64() + MAX_SLOTS_DELAY;
    }
    LeaveCriticalSection(&table->lock);

    /* get a new slot */
    nfs41_session_free_slot(session, args->sa_slotid);
    nfs41_session_get_slot(session, &args->sa_slotid,
        &args->sa_sequenceid, &args->sa_highest_slotid);
    status = NFS4_OK;
out:
    return status;
}

void nfs41_session_sequence(
    nfs41_sequence_args *args,
    nfs41_session *session,
    bool_t cachethis)
{
    nfs41_session_get_slot(session, &args->sa_slotid, 
        &args->sa_sequenceid, &args->sa_highest_slotid);
    args->sa_sessionid = session->session_id;
    args->sa_cachethis = cachethis;
}


/* session renewal */
static unsigned int WINAPI renew_session_thread(void *args)
{
    nfs41_session *session = (nfs41_session *)args;
    int status = NO_ERROR;
    int event_status;

    DPRINTF(1, ("renew_session_thread(session=0x%p): started thread 0x%p\n",
        session, session->renew.thread_handle));

    /* sleep for 2/3 of lease_time */
    const uint32_t sleep_time = (2UL * session->lease_time*1000UL)/3UL;

    EASSERT(sleep_time > 100UL);
    EASSERT(sleep_time < (60*60*1000UL));

    while(1) {
        DPRINTF(1, ("renew_session_thread(session=0x%p): "
            "Going to sleep for %dmsecs\n",
            session, (int)sleep_time));

        /*
         * sleep for |sleep_time| milliseconds, or until someone
         * sends an event
         */
        event_status = WaitForSingleObjectEx(session->renew.cancel_event,
            sleep_time, FALSE);
        if (event_status == WAIT_TIMEOUT) {
            DPRINTF(1, ("renew_session_thread(session=0x%p): "
                "renewing session...\n",
                session));
            status = nfs41_send_sequence(session);
            if (status) {
                eprintf("renew_session_thread(session=0x%p): "
                    "nfs41_send_sequence() failed status=%d\n",
                    session, status);
            }
        }
        else if (event_status == WAIT_OBJECT_0) {
            /* event received, renew thread should exit */
            break;
        }
        else {
            eprintf("renew_session_thread(session=0x%p): "
                "unexpected event_status=0x%x\n",
                session, (int)event_status);
        }
    }

    DPRINTF(1, ("renew_session_thread(session=0x%p): thread 0x%p exiting\n",
        session, session->renew.thread_handle));
    return 0;
}

/* session creation */
static int session_alloc(
    IN nfs41_client *client,
    OUT nfs41_session **session_out)
{
    nfs41_session *session;
    int status = NO_ERROR;

    session = calloc(1, sizeof(nfs41_session));
    if (session == NULL) {
        status = GetLastError();
        goto out;
    }
    session->client = client;
    session->renew.thread_handle = INVALID_HANDLE_VALUE;
    session->renew.cancel_event = INVALID_HANDLE_VALUE;
    session->isValidState = FALSE;

    InitializeCriticalSection(&session->table.lock);
    InitializeConditionVariable(&session->table.cond);

    init_slot_table(&session->table);

    //initialize session lock
    InitializeSRWLock(&client->session_lock);

    /* initialize the back channel */
    nfs41_callback_session_init(session);

    *session_out = session;
out:
    return status;
}

int nfs41_session_create(
    IN nfs41_client *client,
    IN nfs41_session **session_out)
{
    nfs41_session *session;
    int status;

    status = session_alloc(client, &session);
    if (status) {
        eprintf("session_alloc() failed with %d\n", status);
        goto out;
    }

    AcquireSRWLockShared(&client->exid_lock);
    if (client->rpc->needcb)
        session->flags |= CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
    session->flags |= CREATE_SESSION4_FLAG_PERSIST;
    ReleaseSRWLockShared(&client->exid_lock);

    status = nfs41_create_session(client, session, TRUE);
    if (status) {
        eprintf("nfs41_create_session failed %d\n", status);
        status = ERROR_BAD_NET_RESP;
        goto out_err;
    }

    AcquireSRWLockExclusive(&session->client->session_lock);
    client->session = session;
    session->isValidState = TRUE;
    ReleaseSRWLockExclusive(&session->client->session_lock);
    *session_out = session;
out:
    return status;

out_err:
    nfs41_session_free(session);
    goto out;
}

/* session renewal */
int nfs41_session_renew(
    IN nfs41_session *session)
{
    int status;

    AcquireSRWLockExclusive(&session->client->session_lock);
    session->cb_session.cb_seqnum = 0;
    init_slot_table(&session->table);

    status = nfs41_create_session(session->client, session, FALSE);
    ReleaseSRWLockExclusive(&session->client->session_lock);
    return status;
}

static
void cancel_renew_thread(
    IN nfs41_session *session)
{
    DWORD status;

    DPRINTF(1, ("cancel_renew_thread(session=0x%p): "
        "signal thread to exit\n", session));
    (void)SetEvent(session->renew.cancel_event);

    DPRINTF(1, ("cancel_renew_thread(session=0x%p): "
        "waiting for thread to exit\n", session));
    status = WaitForSingleObjectEx(session->renew.thread_handle,
        INFINITE, FALSE);
    EASSERT(status == WAIT_OBJECT_0);

    DPRINTF(1, ("cancel_renew_thread(session=0x%p): thread done\n",
        session));
    (void)CloseHandle(session->renew.cancel_event);
}

int nfs41_session_set_lease(
    IN nfs41_session *session,
    IN uint32_t lease_time)
{
    int status = NO_ERROR;
    uint32_t thread_id;

    if (valid_handle(session->renew.thread_handle)) {
        eprintf("nfs41_session_set_lease(): session "
            "renewal thread already started!\n");
        goto out;
    }

    if (lease_time == 0) {
        eprintf("nfs41_session_set_lease(): invalid lease_time=0\n");
        status = ERROR_INVALID_PARAMETER;
        goto out;
    }

    session->lease_time = lease_time;
    session->renew.cancel_event = CreateEventA(NULL, TRUE, FALSE,
        NULL);
    if (!valid_handle(session->renew.cancel_event)) {
        status = GetLastError();
        eprintf("nfs41_session_set_lease: CreateEventA() failed, status=%d\n",
            status);
        goto out;
    }
    session->renew.thread_handle = (HANDLE)_beginthreadex(NULL,
        0, renew_session_thread, session, 0, &thread_id);
    if (!valid_handle(session->renew.thread_handle)) {
        status = GetLastError();
        eprintf("nfs41_session_set_lease: _beginthreadex() failed %d\n",
            status);
        goto out;
    }
out:
    return status;
}

void nfs41_session_free(
    IN nfs41_session *session)
{
    AcquireSRWLockExclusive(&session->client->session_lock);
    if (valid_handle(session->renew.thread_handle)) {
        DPRINTF(1, ("nfs41_session_free: terminating session renewal thread\n"));
        cancel_renew_thread(session);
    }

    if (session->isValidState) {
        session->client->rpc->is_valid_session = FALSE;
        nfs41_destroy_session(session);
    }
    DeleteCriticalSection(&session->table.lock);
    ReleaseSRWLockExclusive(&session->client->session_lock);

#ifdef NFS41_DRIVER_WORKAROUND_FOR_GETATTR_AFTER_CLOSE_HACKS
    (void)memset(session, 0, sizeof(nfs41_session));
    debug_delayed_free(session);
#else
    free(session);
#endif /* NFS41_DRIVER_WORKAROUND_FOR_GETATTR_AFTER_CLOSE_HACKS */
}
