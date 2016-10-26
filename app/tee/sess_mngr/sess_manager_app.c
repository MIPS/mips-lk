/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>
#include <list.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "SM"
#define DEFAULT_TIMEOUT_MSECS 1000
struct ta_refcount {
    struct list_node ta_refcount_node;
    uuid_t ta_uuid;
    uint32_t refcount;
};

struct sess_message {
    struct list_node sess_message_node;
    uint8_t  op_id;
    uint32_t cmd_id;
    uint8_t *msg_buffer;
};

struct sess_context {
    struct list_node session_context_node;
    handle_t command_ch_id;
    handle_t session_ch_id;
    handle_t parent_sess_id;
    bool is_sess_busy;
    TEE_Identity ca_id;
    uuid_t ta_uuid;
    struct list_node sess_msg; /* list of messages for a session */
    uint32_t sess_msg_count;
    uint32_t closing; /* indicates that session is in process of closing */
    uintptr_t sess_ctx;
};

static struct list_node sessions_list = LIST_INITIAL_VALUE(sessions_list);
static struct list_node ta_list = LIST_INITIAL_VALUE(ta_list);

#define SM_Panic(_code) do { \
	fprintf(stderr, "--- SM_Panic (in %s:%d) 0x%lx ---\n", \
		__FUNCTION__, __LINE__, (unsigned long)(_code)); \
} while(0)

static status_t sm_get_msg(handle_t *channel, uint8_t *buffer)
{
    long sys_res;
    ipc_msg_info_t msg_info;
    ipc_msg_t msg;
    iovec_t iov;

    iov.base = buffer;
    iov.len = TEE_MAX_BUFFER_SIZE;

    msg.num_iov = 1;
    msg.iov= &iov;
    msg.num_handles = 0;
    msg.handles = NULL;

    sys_res = get_msg(*channel, &msg_info);
    if (sys_res < 0)
        return (status_t)sys_res;

    sys_res = read_msg(*channel, msg_info.id, 0, &msg);
    if (sys_res < 0)
        return (status_t)sys_res;
    /* TODO: Handle incomplete reads */

    /* Retire message */
    sys_res = put_msg(*channel, msg_info.id);
    if (sys_res < 0)
        return (status_t)sys_res;

    return (status_t)sys_res;
}

static long sm_send_params(handle_t *channel, uint8_t *buffer)
{
    long length;
    ipc_msg_t msg;
    iovec_t iov;

    iov.base = buffer;
    iov.len = TEE_MAX_BUFFER_SIZE;

    msg.num_iov = 1;
    msg.iov= &iov;
    msg.num_handles = 0;
    msg.handles = NULL;

    length = send_msg(*channel, &msg);

    return length;
}

static bool uuid_cmp(uuid_t *val1, uuid_t *val2)
{
    uint32_t retval = (uint32_t)((val1->time_low == val2->time_low) &&
                (val1->time_mid == val2->time_mid) &&
                (val1->time_hi_and_version == val2->time_hi_and_version));
    int i;
    for (i = 0; i < 8; i++)
        retval = retval && (val1->clock_seq_and_node[i] == val2->clock_seq_and_node[i]);
    return (bool)retval;
}

void copy_closesession_to_buffer(msg_map_t *msg_buff, uintptr_t sess_ctx)
{
    msg_buff->command_id = 0;
    msg_buff->operation_id = TEE_CLOSE_SESSION_ID;
    msg_buff->session_ctx = sess_ctx;
}

static void SM_CloseTASession(struct sess_context *sess)
{
    long sys_res;
    msg_map_t msg;
    struct ta_refcount *r;

    /* This can be initiated with HUP instead of message, so generate new
     * message every time.
     */
    memset(msg.buffer, 0, sizeof(msg.buffer));
    copy_closesession_to_buffer(&msg, sess->sess_ctx);
    TEE_DBG_MSG("close session... channel = %d, buffer = %lx\n",
           (uint32_t)(sess->session_ch_id), (uintptr_t)msg.buffer);

    /* Check number of sessions opened on this TA */
    list_for_every_entry(&ta_list, r, struct ta_refcount,
                         ta_refcount_node) {
        if (uuid_cmp(&r->ta_uuid, &sess->ta_uuid)) {
            if (!r->refcount) {
                /* If this is last opened session for TA,
                 * close TA instance.
                 */
                msg.operation_id = TEE_DESTROY_ID;
            }

            sys_res = sm_send_params(&sess->session_ch_id, msg.buffer);

            if (sys_res < NO_ERROR) {
                TEE_DBG_MSG("ERROR: Bad msg\n");
                return;
            }
            break;
        }
    }
}

/*
 *  Port event handler
 */
static TEE_Result accept_connection(uevent_t *ev, handle_t *channel)
{
    TEE_Result res = TEE_SUCCESS;
    long sys_res;
    /* TODO see if peer_uuid can be used instead of get_clientID */
    uuid_t peer_uuid;

    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) ||
        (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        TEE_DBG_MSG("Error: Bad event for port %d\n", ev->handle);
        res = TEE_ERROR_COMMUNICATION;
    }

    if (ev->event & IPC_HANDLE_POLL_READY) {
        /* Accept connection */
        sys_res = accept(ev->handle, &peer_uuid);
        if (sys_res < 0) {
            TEE_DBG_MSG("Error: Failed to accept connection on port %d\n", ev->handle);
            res = TEE_ERROR_COMMUNICATION;
        }

        *channel = (handle_t)sys_res;
    }
    return res;
}

/* Find session with appropriate handle in TA session list */
struct sess_context *sess_context_get(uint32_t ch_handle)
{
    struct sess_context *n;

    list_for_every_entry(&sessions_list, n, struct sess_context, session_context_node) {
        if (n->command_ch_id == ch_handle || n->session_ch_id == ch_handle)
            return n;
    }

    return NULL;
}

static long sm_connect_to_ta(uuid_t *uuid, unsigned long timeout_msecs, handle_t *channel)
{
    long sys_res = NO_ERROR;
    bool err_close_channel = false;
    uevent_t ev;

    sys_res = connect_to_ta((uuid_t*)uuid);
    if (sys_res < NO_ERROR) {
        TEE_DBG_MSG("Cannot connect to TA\n");
        goto connect_err_done;
    }

    *channel = (handle_t)sys_res;
    assert(*channel != INVALID_IPC_HANDLE);

    err_close_channel = true;

    sys_res = wait(*channel, &ev, timeout_msecs);
    if (sys_res < NO_ERROR)
        goto connect_err_done;

    if ((ev.event & IPC_HANDLE_POLL_HUP) &&
        !(ev.event & IPC_HANDLE_POLL_MSG)) {
            /* Hangup and no pending messages */
            TEE_DBG_MSG("Hangup and no pending messages\n");
            sys_res = ERR_CHANNEL_CLOSED;
            goto connect_err_done;
    }

    if (!(ev.event & IPC_HANDLE_POLL_READY)) {
            /* Not connected */
            TEE_DBG_MSG("TEE: Unexpected channel state: channel %d event %x\n",
                        *channel, ev.event);
            sys_res = ERR_NOT_READY;
            goto connect_err_done;
    }

connect_err_done:
    if (err_close_channel && (sys_res < NO_ERROR))
        close(*channel);

    return sys_res;
}

static TEE_Result session_add_cmd_message(struct sess_context *sess,
                                          msg_map_t *op_msg,
                                          uint8_t op_id)
{

    struct sess_message *new_cmd_msg = (struct sess_message *)calloc(1, sizeof(struct sess_message));
    if (!new_cmd_msg) {
        TEE_DBG_MSG("Cannot allocate memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    new_cmd_msg->op_id = op_id;
    new_cmd_msg->cmd_id = op_msg->command_id;
    new_cmd_msg->msg_buffer = (uint8_t *)malloc(TEE_MAX_BUFFER_SIZE * sizeof(uint8_t));
    if (!new_cmd_msg->msg_buffer) {
        TEE_DBG_MSG("Cannot allocate memory\n");
        free(new_cmd_msg);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memcpy((void *)new_cmd_msg->msg_buffer, (void *)op_msg->buffer, TEE_MAX_BUFFER_SIZE);
    list_add_tail(&sess->sess_msg, &new_cmd_msg->sess_message_node);
    sess->sess_msg_count++;
    return TEE_SUCCESS;
}

static TEE_Result handle_open_session(handle_t cmd_channel, msg_map_t *msg_buffer)
{
    struct sess_context *new_session;
    struct ta_refcount *r, *new_refcount;
    long sys_res = NO_ERROR;
    TEE_Result res;
    uuid_t ta_uuid;
    handle_t ta_channel = INVALID_IPC_HANDLE;
    bool close_ta_session = false;

    memcpy( (void *)&ta_uuid, (void *)&msg_buffer->ta_uuid, sizeof(uuid_t));

    /* Connect to TA, send open session command. */
    /* TODO: Should timeout be fixed, or not?
     * If it needs to be the same as set in CA,
     * it will have to be sent with messages.
     */
    sys_res = sm_connect_to_ta(&ta_uuid, DEFAULT_TIMEOUT_MSECS, &ta_channel);
    if (sys_res < NO_ERROR) {
        /* Failure in opening a channel to TA means that open session failed */
        /* Notify client of failure */
        msg_buffer->return_code = err_to_tee_err(sys_res);
        msg_buffer->return_origin = TEE_ORIGIN_TEE;
        sm_send_params(&cmd_channel, msg_buffer->buffer);
        res = err_to_tee_err(sys_res);
        goto open_session_err;
    }

    close_ta_session = true;
    /* Create new session list element */
    new_session = (struct sess_context *)calloc(1, sizeof(struct sess_context));
    if (!new_session) {
        TEE_DBG_MSG("Cannot allocate memory\n");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto open_session_err;
    }

    new_session->command_ch_id = cmd_channel;
    new_session->session_ch_id = ta_channel;
    new_session->parent_sess_id = msg_buffer->parent_id;
    new_session->is_sess_busy = 1;
    new_session->ca_id = msg_buffer->client_id;
    new_session->ta_uuid = ta_uuid;
    /* Initialize a list of command messages for this session and add open sess msg. */
    list_initialize(&new_session->sess_msg);
    new_session->sess_msg_count = 0;
    new_session->closing = 0;
    new_session->sess_ctx = msg_buffer->session_ctx = 0;

    /* Set the parent sess id in msg. */
    msg_buffer->parent_id = new_session->command_ch_id;
    sys_res = sm_send_params(&new_session->session_ch_id, msg_buffer->buffer);
    if (sys_res < NO_ERROR) {
        res = session_add_cmd_message(new_session, msg_buffer, TEE_OPEN_SESSION_ID);
        if (res != TEE_SUCCESS) {
            TEE_DBG_MSG("Failed to add message\n");
            free(new_session);
            close_ta_session = false;
            goto open_session_err;
        }
        res = err_to_tee_err(sys_res);
        goto open_session_err;
    }

    list_add_tail(&sessions_list, &new_session->session_context_node);

    /* Add this session in refcount for TA in TA list */
    list_for_every_entry(&ta_list, r, struct ta_refcount,
                         ta_refcount_node) {
        if (uuid_cmp(&r->ta_uuid, &new_session->ta_uuid)) {
            r->refcount++;
            goto open_session_ok;
        }
    }
    new_refcount = (struct ta_refcount *)calloc(1, sizeof(struct ta_refcount));
    new_refcount->ta_uuid = new_session->ta_uuid;
    new_refcount->refcount = 0;
    list_add_tail(&ta_list, &new_refcount->ta_refcount_node);

open_session_ok:
    return TEE_SUCCESS;

open_session_err:
    if (close_ta_session && (res != TEE_SUCCESS))
        close(ta_channel);

    return res;
}

/* Do a walktrough on a sessions list and try to handle first message
 * in each session's queue. */
static void handle_pending_messages(void)
{
    struct sess_context *n, *t;

    list_for_every_entry_safe(&sessions_list, n, t,
                              struct sess_context, session_context_node) {
        if (n->sess_msg_count) {
            struct sess_message *head_msg;
            handle_t ch = (handle_t)INVALID_IPC_HANDLE;
            long sys_res;
            msg_map_t *msg_buffer;

            head_msg = containerof(n->sess_msg.next, struct sess_message,
                                   sess_message_node);
            msg_buffer = (msg_map_t *)head_msg->msg_buffer;
            switch(head_msg->op_id) {
                case TEE_OPEN_SESSION_ID:
                    /* Open session cmd can be handled only with
                     * handle_open_session()
                     */
                    handle_open_session(n->command_ch_id, msg_buffer);
                    /* Since handle_open_session() adds message to a buffer if
                     * there is a failure in openning a session, remove message
                     * from the queue regardless of success of the function.
                     */
                    list_delete(&head_msg->sess_message_node);
                    free(head_msg);
                    n->sess_msg_count--;
                    continue;
                case TEE_INVOKE_COMMAND_ID:
                    /* If session (TA) is busy with previous command, skip
                     * sending a new one.
                     */
                    if (n->is_sess_busy || n->closing)
                        continue;
                    ch = n->session_ch_id;
                    break;
                case TEE_RETVAL_ID:
                    ch = n->command_ch_id;
                    break;
                default:
                    TEE_DBG_MSG("Error unexpected pending operation id %d\n", head_msg->op_id);
                    SM_Panic(0xbad00000 | __LINE__);
                    break;
            }
            TEE_DBG_MSG("Pending operation %d on channel %d\n",
                    head_msg->op_id, ch);
            if (ch != (handle_t)INVALID_IPC_HANDLE) {
                sys_res = sm_send_params(&ch, head_msg->msg_buffer);
                if (sys_res >= NO_ERROR) {
                    if (head_msg->op_id == TEE_INVOKE_COMMAND_ID)
                        n->is_sess_busy = 1;
                    else
                        n->is_sess_busy = 0;
                    list_delete(&head_msg->sess_message_node);
                    free(head_msg);
                    n->sess_msg_count--;
                }
            }
        } // if (n->sess_msg_count)
    }
}

static TEE_Result handle_invoke_command(handle_t channel, msg_map_t *op_msg)
{
    struct sess_context *sess = sess_context_get((uint32_t)channel);

    if (sess && !sess->closing) {
        /* Set the parent sess id in msg that needs to be sent to TA. */
        op_msg->parent_id = sess->command_ch_id;
        op_msg->client_id = sess->ca_id;
        op_msg->session_ctx = sess->sess_ctx;
        if (!sess->is_sess_busy) {
            long sys_res = sm_send_params(&sess->session_ch_id, op_msg->buffer);
            if (sys_res >= NO_ERROR) {
                sess->is_sess_busy = 1;
                return TEE_SUCCESS;
            }
        }
        /* If sending invoke cmd message to TA failed for some reason, put the
         * message into message queue.
         * TODO: Maybe this should be more fine-tuned on error messages.
         */
        return session_add_cmd_message(sess, op_msg, TEE_INVOKE_COMMAND_ID);
    } else {
        TEE_DBG_MSG("No session found\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
}

static TEE_Result handle_close_session(handle_t channel)
{
    TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
    struct sess_context *sess = sess_context_get((uint32_t)channel);

    if (sess) {
        if (!sess->sess_msg_count && !sess->is_sess_busy && !sess->closing) {
            struct sess_context *n;

            sess->closing = 1;
            sess->is_sess_busy = 1;
            /* First close all the child sessions. */
            list_for_every_entry(&sessions_list, n, struct sess_context,
                                 session_context_node) {
                if (n->parent_sess_id == sess->command_ch_id) {
                    SM_CloseTASession(n);
                }
            }

            /* Close the session. */
            SM_CloseTASession(sess);

            res = TEE_SUCCESS;
        } else {
            TEE_DBG_MSG("Session is busy\n");
            res = TEE_ERROR_BUSY;
        }
    }

    return res;
}

static void close_session_handles(struct sess_context *sess) {
    struct ta_refcount *r;

    close(sess->command_ch_id);
    close(sess->session_ch_id);

    /* Adjust number of sessions opened on this TA */
    list_for_every_entry(&ta_list, r, struct ta_refcount,
                         ta_refcount_node) {
        if (uuid_cmp(&r->ta_uuid, &sess->ta_uuid)) {
            if (r->refcount) {
                r->refcount--;
            } else {
                /* If this was last opened session for TA,
                 * delete TA element from the list.
                 */
                list_delete(&r->ta_refcount_node);
                free(r);
            }
            break;
        }
    }
    list_delete(&sess->session_context_node);
    free(sess);
}

/* Return value from TA to CA */
static TEE_Result handle_return_value(handle_t channel, msg_map_t *op_msg)
{
    struct sess_context *sess = sess_context_get((uint32_t)channel);
    bool close_handles = false;

    if (sess) {
        long sys_res;

        if (op_msg->command_id == TEE_OPEN_SESSION_ID) {
            sess->sess_ctx = op_msg->session_ctx;
            if (op_msg->return_code != TEE_SUCCESS)
                close_handles = true;
        }
        /* CA should not have any knowledge about sessionContext parameter */
        op_msg->session_ctx = 0;
        sys_res = sm_send_params(&sess->command_ch_id, op_msg->buffer);
        if (sys_res >= NO_ERROR) {
            sess->is_sess_busy = 0;
            if (close_handles || op_msg->command_id == TEE_CLOSE_SESSION_ID ||
                op_msg->command_id == TEE_DESTROY_ID)
                close_session_handles(sess);
            return TEE_SUCCESS;
        }
        /* If sending retval message to CA failed for some reason, put the
         * message into message queue.
         * TODO: Maybe this should be more fine-tuned on error messages.
         */
        return session_add_cmd_message(sess, op_msg, TEE_RETVAL_ID);
    } else {
        TEE_DBG_MSG("Cannot find session\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

}

/* Cancel an operation in a session. */
static TEE_Result handle_cancellation(handle_t channel, msg_map_t *op_msg)
{
#if 0
    struct sess_context *sess = sess_context_get((uint32_t)channel);
    uint32_t cancel_op_id;
    uint32_t cancel_cmd_id;

    if (sess) {
        TEE_Result res;
        long sys_res = sm_send_params(&sess->session_ch_id, buffer);
        if (sys_res >= NO_ERROR) {
            sess->is_sess_busy = 1;
            goto cancel_pending_ops;
        }
        /* If sending cancelation message to TA failed for some reason, put the
         * message into message queue.
         * TODO: Maybe this should be more fine-tuned on error messages. */
        res = session_add_cmd_message(sess, buffer, TEE_CANCEL_ID);
        if (res != TEE_SUCCESS)
            return res;
        goto cancel_pending_ops;
    } else
        return TEE_ERROR_ITEM_NOT_FOUND;

/* Remove messages that have cancled cmd_id from the queue. */
cancel_pending_ops:
    cancel_op_id = op_msg->operation_id;
    cancel_cmd_id = op_msg->command_id;
    /* Only open session and invoke command operations can be canceled */
    if (cancel_op_id != TEE_OPEN_SESSION_ID &&
       cancel_op_id != TEE_INVOKE_COMMAND_ID)
        return TEE_ERROR_BAD_PARAMETERS;
    else {
        struct sess_message *n, *t;
        list_for_every_entry_safe(&sess->sess_msg, n, t,
                                  struct sess_message, sess_message_node) {
            if (n->op_id == cancel_op_id && n->cmd_id == cancel_cmd_id) {
                list_delete(&n->sess_message_node);
                free(n);
                sess->sess_msg_count--;
            }
        }
    }
    return TEE_SUCCESS;
#else
    return TEE_ERROR_NOT_IMPLEMENTED;
#endif
}

static status_t sm_poll_msg(uevent_t *uev, handle_t priority_msg_handle, handle_t command_handle)
{
    handle_t channel = INVALID_IPC_HANDLE;
    status_t res = NO_ERROR;
    long sys_res;

    if (uev->handle == command_handle) {
        res = accept_connection(uev, &channel);
        if (res < 0)
            return res;
    } else if (uev->handle == priority_msg_handle) {
        return ERR_NOT_SUPPORTED;
    } else {
        channel = (handle_t)uev->handle;
    }

    if (uev->event & IPC_HANDLE_POLL_READY) {
        sys_res = wait(channel, uev, INFINITE_TIME);
        if (sys_res < 0)
            return (status_t)sys_res;

        assert(channel == (handle_t)uev->handle);
    }

    if ((uev->event & IPC_HANDLE_POLL_ERROR) ||
        (uev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        TEE_DBG_MSG("Error: Bad event %x for channel %d\n", uev->event, channel);
        return ERR_BAD_STATE;
    }

    return res;
}

static status_t sm_get_port(handle_t *cmd_port, handle_t *priority_port)
{
    long sys_res;

    /* If both ports are already created, exit function */
    if (*cmd_port != INVALID_IPC_HANDLE && *priority_port != INVALID_IPC_HANDLE)
        return NO_ERROR;

    if (*priority_port == INVALID_IPC_HANDLE) {
        sys_res = port_create(TEE_SESS_MANAGER_PRIORITY_MSG, 1, TEE_MAX_BUFFER_SIZE,
                                IPC_PORT_ALLOW_TA_CONNECT);
        if (sys_res < 0) {
            TEE_DBG_MSG("Error: Cannot create port for priority messages!\n");
            return (status_t)sys_res;
        }

        *priority_port = (handle_t)sys_res;
    }

    if (*cmd_port == INVALID_IPC_HANDLE) {
        sys_res = port_create(TEE_SESS_MANAGER_COMMAND_MSG, 1, TEE_MAX_BUFFER_SIZE,
                                IPC_PORT_ALLOW_TA_CONNECT);
        if (sys_res < 0) {
            TEE_DBG_MSG("Error: Cannot create command port!\n");
            return (status_t)sys_res;
        }

        *cmd_port = (handle_t)sys_res;
    }

    return NO_ERROR;
}

status_t sm_next_msg(uevent_t *user_event)
{
    status_t res;
    long sys_res;
    static handle_t command_handle = INVALID_IPC_HANDLE;
    static handle_t priority_msg_handle = INVALID_IPC_HANDLE;

    res = sm_get_port(&command_handle, &priority_msg_handle);
    if (res < 0)
        goto err_cleanup;

    sys_res = wait_any(user_event, DEFAULT_TIMEOUT_MSECS * 10);
    if (sys_res < 0) {
        res = (status_t)sys_res;
        goto err_cleanup;
    }

    res = sm_poll_msg(user_event, priority_msg_handle, command_handle);
    if (res < 0)
        goto err_cleanup;

    return NO_ERROR;

err_cleanup:
    if (res != ERR_TIMED_OUT)
        TEE_DBG_MSG("Error code = %d\n", res);

    return res;
}


int main(void)
{
    TEE_Result res = TEE_SUCCESS;
    status_t retval = INVALID_IPC_HANDLE;
    uevent_t ev;
    handle_t channel;
    msg_map_t _operation_msg;
    msg_map_t *operation_msg = &_operation_msg;

    TEE_DBG_MSG("START SESSION MANAGER\n");

    while (1) {
        int operation = -1;

        ev.handle = INVALID_IPC_HANDLE;
        ev.event = 0;
        ev.cookie = NULL;
        retval = sm_next_msg(&ev);
        TEE_DBG_MSG("ta_next_msg ev.handle %d ev.event %x retval %d\n",
                ev.handle, ev.event, retval);

        if (retval == ERR_TIMED_OUT)
            goto msg_handling_end;
        else if (retval < 0) {
            /* This should never happen. */
            SM_Panic(0xbad00000 | __LINE__);
            return TEE_ERROR_GENERIC;
        }


        channel = (handle_t)ev.handle;

        if (ev.event & IPC_HANDLE_POLL_MSG) {

            retval = sm_get_msg(&channel, operation_msg->buffer);
            if (retval < 0)
                SM_Panic(0xbad00000 | __LINE__);

        } else if (ev.event & IPC_HANDLE_POLL_HUP) {

            struct sess_context *sess = sess_context_get((uint32_t)channel);
            memset(operation_msg, 0, sizeof(*operation_msg));
            if (sess) {
                TEE_DBG_MSG("Error unexpected HUP event on handle %d\n", ev.handle);
                /* HUP from TA -> close session and clear */
                if (channel == sess->session_ch_id) {
                    /* Return info about failure to CA */
                    operation = TEE_RETVAL_ID;
                    operation_msg->operation_id = TEE_RETVAL_ID;
                    operation_msg->command_id = TEE_CLOSE_SESSION_ID;
                    operation_msg->return_origin = TEE_ORIGIN_TEE;
                    operation_msg->return_code = TEE_ERROR_COMMUNICATION;
                } else if (channel == sess->command_ch_id) {
                    /* HUP from CA -> close session */
                    operation = TEE_CLOSE_SESSION_ID;
                }
            } else {
                close(channel);
                goto msg_handling_end;
            }

        } else {

            TEE_DBG_MSG("Error unexpected %x event on handle %d\n", ev.event, ev.handle);
            SM_Panic(0xbad00000 | __LINE__);

        }

        if (operation == -1)
            operation = operation_msg->operation_id;

        TEE_DBG_MSG("Received operation %d on channel %d\n", operation, channel);

        switch (operation) {
            case TEE_OPEN_SESSION_ID:
                res = handle_open_session(channel, operation_msg);
                break;
            case TEE_INVOKE_COMMAND_ID:
                res = handle_invoke_command(channel, operation_msg);
                break;
            case TEE_CLOSE_SESSION_ID:
                res = handle_close_session(channel);
                break;
            case TEE_RETVAL_ID:
                res = handle_return_value(channel, operation_msg);
                break;
            case TEE_CANCEL_ID:
                res = handle_cancellation(channel, operation_msg);
                break;
            default:
                TEE_DBG_MSG("Unexpected operation %d on channel %d\n",
                        operation, channel);
                SM_Panic(0xbad00000 | __LINE__);
                break;
        }

/* If there was an event on handle that is handled correctly or if
 * wait_any() timed out, execute pending operations on all the sessions
 * in the list.
 */
msg_handling_end:
        handle_pending_messages();
    } // while (1)

    return res;
}
