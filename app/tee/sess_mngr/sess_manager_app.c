/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
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
#include <assert.h>
#include <tee_internal_api.h>
#include <tee_api_properties.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>
#include <list.h>
#include <bits.h>
#include "ree_interface.h"

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "SM"
#define DEFAULT_TIMEOUT_MSECS 1000
#define TEE_SM_NUM_RX_BUF 8

/* Session Manager UUID. It has to be kept in sync with changes to SM UUID in
 * appropriate manifest file.
 */
#ifdef SM_UUID
#undef SM_UUID
#endif
#define SM_UUID { 0x7ea5ad73, 0xd8eb, 0x4859, \
                  { 0xa2, 0x06, 0x17, 0x46, 0xd3, 0xc4, 0xcc, 0xdf } }

#define TEE_PARAM_TYPE_SET(t, i) (((t) & 0xF) << ((i) * 4))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* must match kernel */
#define IPC_MAX_HANDLES 256
#define ZERO_UUID { 0x0, 0x0, 0x0, { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0} }

struct ta_refcount {
    struct list_node ta_refcount_node;
    uuid_t ta_uuid;
    uint32_t prop_flags;
    uint32_t refcount;
};

struct sess_message {
    struct list_node sess_message_node;
    bool sent_to_ta;
    uint8_t *msg_buffer;
};

struct sess_context {
    struct list_node session_context_node;
    handle_t command_ch_id;
    handle_t session_ch_id;
    uint32_t parent_sess_id;
    uint32_t ca_id_login;
    uuid_t ca_id_uuid;
    uuid_t ta_uuid;
    struct list_node sess_msg; /* list of messages for a session */
    uint32_t closing; /* indicates that session is in process of closing */
    uint32_t ca_panic; /* indicates that the CA panicked */
    uint32_t ta_panic; /* indicates that the TA panicked */
    uint32_t ree_tag; /* used by REE to match reply with request */
    uintptr_t sess_ctx;
};

static struct list_node sessions_list = LIST_INITIAL_VALUE(sessions_list);
static struct list_node ta_list = LIST_INITIAL_VALUE(ta_list);

static const struct uuid zero_uuid = ZERO_UUID;
static const struct uuid sm_uuid = SM_UUID;
static unsigned long trusted_ch_map[BITMAP_NUM_WORDS(IPC_MAX_HANDLES)];

/* forward declarations */
static void force_close_session(struct sess_context *sess);
static struct sess_context *sess_context_get(uint32_t session_id);

static const char *id_str(unsigned int id)
{
    static const char * const id_str[] = {
        [TEE_OPEN_SESSION_ID] = "Open",
        [TEE_INVOKE_COMMAND_ID] = "Invoke",
        [TEE_CLOSE_SESSION_ID] = "Close",
        [TEE_CANCEL_ID] = "Cancel",
        [TEE_RETVAL_ID] = "RetVal",
        [TEE_DESTROY_ID] = "Destroy",
    };

    if ((id < ARRAY_SIZE(id_str)) && id_str[id])
        return id_str[id];

    return "Unknown";
}

static inline uint32_t sm_get_tag_field(msg_map_t *msg_buf)
{
    return msg_buf->ree_tag;
}

static inline uint32_t sm_get_data_tag(struct mipstee_tipc_msg *ree_buf)
{
    return ree_buf->hdr.data_tag;
}

static status_t msg_param_to_tee_param(struct mipstee_msg_param *msg_params,
                                     size_t msg_num_params,
                                     utee_params_t *uparam)
{
    size_t i;
    const uint8_t tee_param[] = {
        [MIPSTEE_MSG_ATTR_TYPE_NONE] = TEE_PARAM_TYPE_NONE,
        [MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT] = TEE_PARAM_TYPE_VALUE_INPUT,
        [MIPSTEE_MSG_ATTR_TYPE_VALUE_OUTPUT] = TEE_PARAM_TYPE_VALUE_OUTPUT,
        [MIPSTEE_MSG_ATTR_TYPE_VALUE_INOUT] = TEE_PARAM_TYPE_VALUE_INOUT,
        [MIPSTEE_MSG_ATTR_TYPE_RMEM_INPUT] = TEE_PARAM_TYPE_MEMREF_INPUT,
        [MIPSTEE_MSG_ATTR_TYPE_RMEM_OUTPUT] = TEE_PARAM_TYPE_MEMREF_OUTPUT,
        [MIPSTEE_MSG_ATTR_TYPE_RMEM_INOUT] = TEE_PARAM_TYPE_MEMREF_INOUT,
        [MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT] = TEE_PARAM_TYPE_MEMREF_INPUT,
        [MIPSTEE_MSG_ATTR_TYPE_TMEM_OUTPUT] = TEE_PARAM_TYPE_MEMREF_OUTPUT,
        [MIPSTEE_MSG_ATTR_TYPE_TMEM_INOUT] = TEE_PARAM_TYPE_MEMREF_INOUT,
    };

    uparam->param_types = 0;
    /*
     * GP API specification (and our implementation) supports up to 4
     * parameters in open session and invoke command operations.
     */
    if (msg_num_params > 4)
        msg_num_params = 4;

    for (i = 0; i < msg_num_params; i++) {
        struct mipstee_msg_param *mp = msg_params + i;

        if (mp->attr >= ARRAY_SIZE(tee_param))
            return ERR_INVALID_ARGS;

        uparam->param_types |= TEE_PARAM_TYPE_SET(tee_param[mp->attr], i);
        switch (mp->attr) {
        case MIPSTEE_MSG_ATTR_TYPE_NONE:
        case MIPSTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
            uparam->params[2 * i] = 0;
            uparam->params[2 * i + 1] = 0;
            break;
        case MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT:
        case MIPSTEE_MSG_ATTR_TYPE_VALUE_INOUT:
            uparam->params[2 * i] = mp->u.value.a;
            uparam->params[2 * i + 1] = mp->u.value.b;
            /*
             * GP API spec does not support the third value field,
             * so it is discarded here.
             */
            break;
        case MIPSTEE_MSG_ATTR_TYPE_RMEM_INPUT:
        case MIPSTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
        case MIPSTEE_MSG_ATTR_TYPE_RMEM_INOUT:
            // TODO: Check if this is enough for handling memrefs
            uparam->params[2 * i] = mp->u.rmem.shm_ref +
                                    mp->u.rmem.offs;
            uparam->params[2 * i + 1] = mp->u.rmem.size;
            break;
        case MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT:
        case MIPSTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
        case MIPSTEE_MSG_ATTR_TYPE_TMEM_INOUT:
            // TODO: Check if this is enough for handling memrefs
            uparam->params[2 * i] = mp->u.tmem.buf_ptr;
            uparam->params[2 * i + 1] = mp->u.tmem.size;
            break;
        default:
            return ERR_INVALID_ARGS;
        }
    }

    return NO_ERROR;
}

static enum tee_cmd_id ree_cmd_to_tee_cmd(uint32_t mipstee_cmd)
{
    const enum tee_cmd_id mipstee_cmd_to_tee[] = {
        [MIPSTEE_MSG_CMD_OPEN_SESSION] = TEE_OPEN_SESSION_ID,
        [MIPSTEE_MSG_CMD_INVOKE_COMMAND] = TEE_INVOKE_COMMAND_ID,
        [MIPSTEE_MSG_CMD_CLOSE_SESSION] = TEE_CLOSE_SESSION_ID,
        [MIPSTEE_MSG_CMD_CANCEL] = TEE_CANCEL_ID,
        [MIPSTEE_MSG_CMD_REGISTER_SHM] = (uint32_t)TEE_INVALID_ID,
        [MIPSTEE_MSG_CMD_UNREGISTER_SHM] = (uint32_t)TEE_INVALID_ID,
    };

    if (mipstee_cmd < ARRAY_SIZE(mipstee_cmd_to_tee))
        return mipstee_cmd_to_tee[mipstee_cmd];

    return TEE_INVALID_ID;
}

static uint32_t tee_cmd_to_ree_cmd(enum tee_cmd_id tee_cmd)
{
    const uint32_t tee_cmd_to_mipstee[] = {
        [TEE_OPEN_SESSION_ID] = MIPSTEE_MSG_CMD_OPEN_SESSION,
        [TEE_INVOKE_COMMAND_ID] = MIPSTEE_MSG_CMD_INVOKE_COMMAND,
        [TEE_CLOSE_SESSION_ID] = MIPSTEE_MSG_CMD_CLOSE_SESSION,
        [TEE_CANCEL_ID] = MIPSTEE_MSG_CMD_CANCEL,
        [TEE_RETVAL_ID] = MIPSTEE_MSG_CMD_INVALID,
        /* convert create and destroy */
        [TEE_DESTROY_ID] = MIPSTEE_MSG_CMD_CLOSE_SESSION,
    };

    if ((uint32_t)tee_cmd < ARRAY_SIZE(tee_cmd_to_mipstee))
        return tee_cmd_to_mipstee[tee_cmd];

    return (uint32_t)MIPSTEE_MSG_CMD_INVALID;
}

/* Check if the Client Application is on REE or TEE side. */
static bool is_ca_trusted(uint32_t login_type)
{
    return login_type == TEE_LOGIN_TRUSTED_APP;
}

static int is_trusted_ch(handle_t ch)
{
    ASSERT(BITMAP_NUM_WORDS(ch) <= sizeof(trusted_ch_map));
    return !bitmap_test(trusted_ch_map, (int)ch);
}

/* Check if channel is from REE or TEE side */
static status_t set_trusted_ch(handle_t ch, const uuid_t *peer_uuid)
{
    if (BITMAP_NUM_WORDS(ch) > sizeof(trusted_ch_map)) {
        /* Close a channel if resources (in this case trusted_ch_map) are
         * insufficient.
         */
        TEE_DBG_MSG(" Error: %d - channel exceeds the bitmap.\n",
            ERR_ACCESS_DENIED);
        close(ch);
        return ERR_ACCESS_DENIED;
    }

    /* only untrusted tipc_dev channels have a zero_uuid */
    if (memcmp(peer_uuid, &zero_uuid, sizeof(uuid_t)))
        bitmap_clear(trusted_ch_map, (int)ch);
    else
        bitmap_set(trusted_ch_map, (int)ch);

    TEE_DBG_MSG("ch %d is_trusted_ch %d\n", (int)ch,
            is_trusted_ch(ch));
    return NO_ERROR;
}

static unsigned int ree_num_params_from_tee_msg(const msg_map_t *tee_msg)
{
    if (tee_msg->cmd == TEE_OPEN_SESSION_ID ||
            (tee_msg->cmd == TEE_RETVAL_ID && tee_msg->func ==
             TEE_OPEN_SESSION_ID))
        return 6;
    else if (tee_msg->cmd == TEE_INVOKE_COMMAND_ID ||
            (tee_msg->cmd == TEE_RETVAL_ID && tee_msg->func ==
             TEE_INVOKE_COMMAND_ID))
        return 4;
    else
        return 0;
}

static status_t ree_msg_validate(struct mipstee_tipc_msg *ree_buf,
        size_t read_len)
{
    size_t min_len;
    size_t exp_len;

    min_len = MIPSTEE_TIPC_MSG_GET_SIZE(0);
    if (read_len < min_len) {
        TEE_DBG_MSG("ree msg fragment: read_len %zu < min_len %zu\n",
                read_len, min_len);
        return ERR_IO;
    }
    if (ree_buf->hdr.magic != REE_MAGIC) {
        TEE_DBG_MSG("ree msg header is invalid\n");
        return ERR_IO;
    }

    /* validate other fields after checking REE_MAGIC */
    exp_len = MIPSTEE_TIPC_MSG_GET_SIZE(ree_buf->msg.num_params);
    if (read_len != exp_len) {
        TEE_DBG_MSG("ree msg too small: read_len %zu != exp_len %zu\n",
                read_len, exp_len);
        return ERR_INVALID_ARGS;
    }
    if (ree_cmd_to_tee_cmd(ree_buf->msg.cmd) ==
            MIPSTEE_MSG_CMD_INVALID) {
        TEE_DBG_MSG("ree msg invalid cmd: %u\n", ree_buf->msg.cmd);
        return ERR_INVALID_ARGS;
    }
    return NO_ERROR;
}

static status_t ree_to_tee_msg(uint8_t *ns_data, size_t read_len,
        msg_map_t *msg_args)
{
    struct mipstee_tipc_msg *ree_buf;
    struct mipstee_msg_arg *ree_arg;
    struct mipstee_msg_param *ree_param;
    status_t sys_res;

    ree_buf = (struct mipstee_tipc_msg *)ns_data;
    sys_res = ree_msg_validate(ree_buf, read_len);
    if (sys_res)
        return sys_res;

    ree_arg = &ree_buf->msg;
    ree_param = ree_arg->params;

    msg_args->cmd = ree_cmd_to_tee_cmd(ree_arg->cmd);
    msg_args->func = ree_arg->func;
    msg_args->session = ree_arg->session;
    msg_args->cancel_id = ree_arg->cancel_id;
    msg_args->ree_tag = sm_get_data_tag(ree_buf);
    msg_args->ret = ree_arg->ret;
    msg_args->ret_origin = ree_arg->ret_origin;

    /*
     * The request is coming from the client, so there is no parent session
     * and no parent operation. Set client_ta pointer to NULL.
     */
    msg_args->session_ctx = 0;
    msg_args->parent_sess_id = 0;
    msg_args->parent_op_id = 0;
    msg_args->client_ta = 0;

    switch (msg_args->cmd) {
    case TEE_OPEN_SESSION_ID:
        memcpy((void *)&msg_args->client_id_uuid,
               (void *)&ree_arg->params[1].u.value,
               sizeof(uuid_t));
        memcpy((void *)&msg_args->ta_uuid,
               (void *)&ree_arg->params[0].u.value,
               sizeof(uuid_t));
        msg_args->client_id_login = ree_arg->params[1].u.value.c;
        ree_param += 2; // skip meta parameters
        // fall through
    case TEE_INVOKE_COMMAND_ID:
    case TEE_CANCEL_ID:
        sys_res = msg_param_to_tee_param(ree_param, ree_arg->num_params,
                               &msg_args->utee_params);
        if (sys_res)
            return sys_res;
        break;
    case TEE_CLOSE_SESSION_ID:
        break;
    default:
        return ERR_INVALID_ARGS;
    }

    return NO_ERROR;
}

static bool uuid_cmp(const uuid_t *val1, const uuid_t *val2)
{
    uint32_t retval = (uint32_t)((val1->time_low == val2->time_low) &&
                (val1->time_mid == val2->time_mid) &&
                (val1->time_hi_and_version == val2->time_hi_and_version));
    int i;

    for (i = 0; i < 8; i++)
        retval = retval && (val1->clock_seq_and_node[i] ==
                            val2->clock_seq_and_node[i]);
    return (bool)retval;
}

/* Sanity checks for new message. */
static long msg_validate(handle_t channel, msg_map_t *new_msg)
{
    long sys_res = ERR_INVALID_ARGS;
    uint32_t i;

    if (uuid_cmp((uuid_t *)new_msg->ta_uuid, (uuid_t *)&sm_uuid)) {
        // TODO: Consider closing the channel.
        TEE_DBG_MSG("ERROR - Operations should never target SM\n");
        sys_res = ERR_ACCESS_DENIED;
        goto msg_err;
    }

    /* Operation validations */

    /* Check operation ID validity.
     * SM does not expect TEE_DESTROY_ID.
     * SM does not expect TEE_RETVAL_ID from REE.
     */
    if (new_msg->cmd < TEE_OPEN_SESSION_ID || new_msg->cmd > TEE_RETVAL_ID ||
        (!is_trusted_ch(channel) && new_msg->cmd > TEE_CANCEL_ID)) {
        TEE_DBG_MSG("ERROR - Unexpected operation %s:%d on channel %d\n",
            id_str(new_msg->cmd), new_msg->cmd, channel);
        goto msg_err;
    }

    /* Session ID is valid. */
    if (new_msg->cmd == TEE_INVOKE_COMMAND_ID ||
        new_msg->cmd == TEE_CLOSE_SESSION_ID)
        if (sess_context_get(new_msg->session) == NULL) {
            TEE_DBG_MSG("ERROR - Invalid session ID: %08x\n",
                new_msg->session);
        goto msg_err;
    }

    if (new_msg->cmd == TEE_RETVAL_ID) {
        if (new_msg->func < TEE_OPEN_SESSION_ID ||
            new_msg->func > TEE_DESTROY_ID      ||
            new_msg->func == TEE_CANCEL_ID) {
            TEE_DBG_MSG(
                "WARNING - Unexpected return operation function ID: %08x\n",
                new_msg->func);
        }

        if (new_msg->ret_origin < TEE_ORIGIN_API ||
            new_msg->ret_origin > TEE_ORIGIN_TRUSTED_APP) {
            TEE_DBG_MSG(
                "WARNING - Invalid return origin ID: %08x\n",
                new_msg->ret_origin);
        }

        /* Return value validation */
        if (new_msg->ret != TEE_SUCCESS && new_msg->ret < 0xF0000000) {
            TEE_DBG_MSG("WARNING - Unsupported error code: %08x\n",
                new_msg->ret);
        }
    }

    if (new_msg->cmd == TEE_OPEN_SESSION_ID) {

        if (!is_trusted_ch(channel)) {
            /* REE specific validations */

            /* Check if login type is correct for REE CAs. */
            // NOTE:  This should be the only check for login type when all REE
            //        login types are supported.
            if (is_ca_trusted(new_msg->client_id_login)) {
                TEE_DBG_MSG(
                    "ERROR. REE CAs cannot have TEE_LOGIN_TRUSTED_APP for login type.\n");
                sys_res = ERR_ACCESS_DENIED;
                goto msg_err;
            }

            if (new_msg->client_id_login != TEE_LOGIN_PUBLIC) {
                /* Only TEE_LOGIN_PUBLIC is currently supported for REE. */
                // TODO: Change/remove this check once other login types are
                //       supported for REE.
                TEE_DBG_MSG("ERROR - Invalid login type %08x\n",
                    new_msg->client_id_login);
                goto msg_err;
            }
            if (!uuid_cmp((uuid_t *)new_msg->client_id_uuid,
                          (uuid_t *)&zero_uuid)) {
                TEE_DBG_MSG("ERROR - Client UUID other than zero for REE CA\n");
                goto msg_err;
            }
            if (new_msg->cmd == TEE_RETVAL_ID) {
                TEE_DBG_MSG(
                    "ERROR. REE CAs cannot use TEE_RETVAL_ID.\n");
                goto msg_err;
            }
        }

        if (uuid_cmp((uuid_t *)new_msg->ta_uuid, (uuid_t *)&zero_uuid)) {
            TEE_DBG_MSG("ERROR - TA UUID zero - cmd :%08x\n", new_msg->cmd);
            goto msg_err;
        }
    }

    /* Parameters validation. */
    if (new_msg->num_params > TEE_NUM_PARAMS) {
        TEE_DBG_MSG("ERROR - Number of parameters to big: %d.\n",
            new_msg->num_params);
        goto msg_err;
    }

    for (i = 0; i < new_msg->num_params; i++) {
        uint32_t paramtype =
                    TEE_PARAM_TYPE_GET(new_msg->utee_params.param_types, i);
        if (paramtype > TEE_PARAM_TYPE_MEMREF_INOUT) {
            TEE_DBG_MSG("ERROR - Unsupported parameter type :%d\n",
                paramtype);
            goto msg_err;
        }
    }

    return NO_ERROR;

msg_err:
    TEE_DBG_MSG("\t\tMessage format error on channel: %d\n", (uint32_t)channel);
    return sys_res;
}

static status_t sm_get_msg_buffer(handle_t channel, uint8_t *buffer,
                                  size_t buf_len)
{
    long sys_res;
    long put_res;
    ipc_msg_info_t msg_info;
    ipc_msg_t msg;
    iovec_t iov;
    size_t read_len;
    uint8_t in_msg_buf[2 * TEE_MAX_BUFFER_SIZE]; // Should be more than enough

    assert(buffer);

    iov.base = &in_msg_buf;
    iov.len = sizeof(in_msg_buf);

    msg.num_iov = 1;
    msg.iov = &iov;
    msg.num_handles = 0;
    msg.handles = NULL;

    sys_res = get_msg(channel, &msg_info);
    if (sys_res < 0)
        goto err_fail;

    sys_res = read_msg(channel, msg_info.id, 0, &msg);
    if (sys_res < 0)
        goto err_put_fail;

    read_len = (size_t)sys_res;
    sys_res = NO_ERROR;

    if (is_trusted_ch(channel)) {
        if (read_len != buf_len) {
            TEE_DBG_MSG(
                    "Msg buffer size invalid: read_len %zu != buf_len %zu\n",
                    read_len, buf_len);
            sys_res = ERR_IO;
            goto err_put_fail;
        }
        /* messages from TAs and client TAs are of the msg_map_t type */
        memcpy(buffer, in_msg_buf, buf_len);
    } else {
        /* messages from untrusted REE client TAs need to be adapted */
        sys_res = ree_to_tee_msg(in_msg_buf, read_len, (msg_map_t *)buffer);
        if (sys_res < 0) {
            TEE_DBG_MSG("Msg adaptation failed: ch %d error %ld\n", channel,
                    sys_res);
            goto err_put_fail;
        }
    }

    sys_res = msg_validate(channel, (msg_map_t *)buffer);

err_put_fail:
    /* If put_msg succeeds don't overwrite error result, overwrite sys_res
     * otherwise.
     */
    put_res = put_msg(channel, msg_info.id);
    if (put_res < 0 || (sys_res >= 0))
        sys_res = put_res;

err_fail:
    return (status_t)sys_res;
}

static status_t sm_send_buffer(handle_t channel, uint8_t *buffer,
        uint32_t buf_size)
{
    long length;
    status_t sys_res = NO_ERROR;
    ipc_msg_t msg;
    iovec_t iov;

    iov.base = buffer;
    iov.len = buf_size;

    msg.num_iov = 1;
    msg.iov = &iov;
    msg.num_handles = 0;
    msg.handles = NULL;

    length = send_msg(channel, &msg);
    if (length < NO_ERROR)
        sys_res = (status_t)length;

    return sys_res;
}

static void failure_notification(msg_map_t *msg,
                                 TEE_Result ret_code)
{
    msg->func = msg->cmd;
    msg->cmd = TEE_RETVAL_ID;
    msg->ret_origin = TEE_ORIGIN_TEE;
    msg->ret = ret_code;
}

/* Find TA for which session is opened in TA refcount list */
static struct ta_refcount *sess_ta_get(const uuid_t *ta_uuid)
{
    struct ta_refcount *r;

    list_for_every_entry(&ta_list, r, struct ta_refcount,
                         ta_refcount_node) {
        if (uuid_cmp(&r->ta_uuid, ta_uuid))
            return r;
    }

    return NULL;
}

static TEE_Result session_add_operation(struct sess_context *sess,
                                        msg_map_t *op_msg,
                                        bool sent_to_ta)
{
    struct sess_message *new_cmd_msg = (struct sess_message *)
                                         calloc(1, sizeof(struct sess_message));
    if (!new_cmd_msg) {
        TEE_DBG_MSG("Cannot allocate memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    new_cmd_msg->sent_to_ta = sent_to_ta;
    new_cmd_msg->msg_buffer = malloc(TEE_MAX_BUFFER_SIZE);

    if (!new_cmd_msg->msg_buffer) {
        TEE_DBG_MSG("Cannot allocate memory\n");
        free(new_cmd_msg);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memcpy((void *)new_cmd_msg->msg_buffer, (void *)op_msg->buffer,
           TEE_MAX_BUFFER_SIZE);
    list_add_tail(&sess->sess_msg, &new_cmd_msg->sess_message_node);
    return TEE_SUCCESS;
}

static bool handle_id_match(handle_t h1, handle_t h2)
{
    return ((h1 != TEE_HANDLE_NULL) && (h2 != TEE_HANDLE_NULL) && (h1 == h2));
}

static bool session_id_match(uint32_t s1, uint32_t s2)
{
    return ((s1) && (s2) && (s1 == s2));
}

static uint32_t get_session_id(struct sess_context *sess)
{
    return (uint32_t)sess;
}

/* Find session with appropriate handle in TA session list */
static struct sess_context *sess_context_get(uint32_t session_id)
{
    struct sess_context *n;

    if (!session_id) {
        TEE_DBG_MSG("Invalid session ID.\n");
        return NULL;
    }

    list_for_every_entry(&sessions_list, n, struct sess_context,
                         session_context_node) {
        if (session_id_match(get_session_id(n), session_id))
            return n;
    }

    TEE_DBG_MSG("Session %d NOT FOUND.\n", session_id);
    return NULL;
}

static TEE_Result sm_connect_to_ta(const uuid_t *uuid,
                                   unsigned long timeout_msecs,
                                   handle_t *channel)
{
    TEE_Result res;
    long sys_res = NO_ERROR;
    uevent_t ev;
    handle_t ch;

    res = connect_to_ta(uuid, &ch);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("Cannot connect to TA\n");
        *channel = INVALID_IPC_HANDLE;
        return res;
    }

    assert(ch != INVALID_IPC_HANDLE);

    sys_res = wait(ch, &ev, timeout_msecs);
    if (sys_res < NO_ERROR) {
        /* Accept not received, TA is busy */
        sys_res = ERR_BUSY;
        goto connect_err_close;
    }

    if ((ev.event & IPC_HANDLE_POLL_HUP) &&
        !(ev.event & IPC_HANDLE_POLL_MSG)) {
        /* Hangup and no pending messages */
        TEE_DBG_MSG("Hangup and no pending messages\n");
        sys_res = ERR_CHANNEL_CLOSED;
        goto connect_err_close;
    }

    if (!(ev.event & IPC_HANDLE_POLL_READY)) {
        /* Not connected */
        TEE_DBG_MSG("TEE: Unexpected channel state: channel %d event %x\n",
                    ch, ev.event);
        sys_res = ERR_NOT_READY;
        goto connect_err_close;
    }

connect_err_close:
    if (sys_res < NO_ERROR)
        close(ch);
    else {
        *channel = ch;
        sys_res = set_trusted_ch(ch, uuid);
    }

connect_err_done:
    return err_to_tee_err(sys_res);
}

/* Remove message from the queue. */
static void rm_queue_msg(struct sess_message *msg, struct sess_context *sess)
{
    list_delete(&msg->sess_message_node);
    free(msg->msg_buffer);
    free(msg);
}

/* Purge cancelled operation from session message queue and set cancellation bit
 * in appropriate TA if the operation has reached the TA.
 */
static TEE_Result cancel_operation(struct sess_context *sess,
                                   uint32_t cancel_id)
{
    struct sess_message *n;
    struct sess_context *t;

    /* First go through all the child sessions and cancel all the operations
     * for which this operation is a parent.
     */
    list_for_every_entry(&sessions_list, t, struct sess_context,
                         session_context_node) {
        if (session_id_match(t->parent_sess_id, get_session_id(sess))) {
            list_for_every_entry(&t->sess_msg, n, struct sess_message,
                sess_message_node) {
                msg_map_t *tmp_msg_buff = (msg_map_t *)n->msg_buffer;

                if (tmp_msg_buff->parent_op_id == cancel_id)
                    cancel_operation(t, tmp_msg_buff->parent_op_id);
            }
        }
    }

    list_for_every_entry(&sess->sess_msg, n, struct sess_message,
                         sess_message_node) {
        msg_map_t *tmp_msg_buff = (msg_map_t *)n->msg_buffer;

        if (tmp_msg_buff->cancel_id == cancel_id) {
            if (n->sent_to_ta) {
                uint32_t session_id = get_session_id(sess);
                TEE_Result res = set_cancel_flag(&sess->ta_uuid, &session_id);
                if (res != TEE_SUCCESS)
                    TEE_DBG_MSG("Cancellation failed... Err: %x\n", res);
            } else {
                /* If cancelled operation didn't reach TA yet, convert
                 * appropriate message to retval cancel message effectively
                 * purging original message from the queue.
                 */
                failure_notification(tmp_msg_buff, TEE_ERROR_CANCEL);
            }
            return TEE_SUCCESS;
        }
    }

    return TEE_ERROR_ITEM_NOT_FOUND;
}

/* Cancel an operation in a session. */
static void handle_cancellation(uint32_t cmd_channel, msg_map_t *op_msg,
                                struct sess_context *sess)
{
    TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

    if (sess) {
        cancel_operation(sess, op_msg->cancel_id);
        return;
    }

    TEE_DBG_MSG("Finding cancelled operation %08x using session id failed. "
                "Try to cancel operation according to command channel.\n",
                op_msg->cancel_id);
    /* Request for cancellation can be issued for Open Session operation, in
     * which case client does not have session id.
     * Try to find an operation in a session opened through this command
     * channel.
     * It is expected that cancel_id is unique at least across TEE context.
     */
    list_for_every_entry(&sessions_list, sess, struct sess_context,
                         session_context_node) {
        if (handle_id_match(sess->command_ch_id, cmd_channel)) {
            res = cancel_operation(sess, op_msg->cancel_id);
            /* If operation for which cancellation is requested is not found in
             * this session, continue search in other sessions on this channel.
             */
            if (res != TEE_ERROR_ITEM_NOT_FOUND)
                break;
        }
    }
    TEE_DBG_MSG("Operation that needs to be cancelled not found.\n");
}

static TEE_Result lists_add_session(struct sess_context *sess,
                                    struct ta_refcount *ta,
                                    uint32_t prop_flags,
                                    TEE_Result prop_ret)
{
    struct ta_refcount *new_refcount;
    TEE_Result res = TEE_SUCCESS;

    list_add_tail(&sessions_list, &sess->session_context_node);

    /* Add this session in refcount for TA in TA list */
    if (ta != NULL) {
        ta->refcount++;
        goto lists_add_session_end;
    }

    new_refcount = (struct ta_refcount *)calloc(1, sizeof(struct ta_refcount));
    if (new_refcount == NULL) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto lists_add_session_end;
    }
    new_refcount->ta_uuid = sess->ta_uuid;
    new_refcount->prop_flags = prop_flags;
    new_refcount->refcount = 1;
    list_add_tail(&ta_list, &new_refcount->ta_refcount_node);

lists_add_session_end:
    if (res == TEE_SUCCESS && prop_ret != TEE_SUCCESS) {
        /* Preserve error code if error occurred during retrieving
         * property flags.
         */
        res = prop_ret;
    }
    return res;
}

static void uuid_from_octets(uuid_t *uuid, uint8_t oct[TEE_UUID_LEN])
{
    uuid->time_low = ((uint32_t)oct[0] << 24) | ((uint32_t)oct[1] << 16) |
         ((uint32_t)oct[2] << 8) | oct[3];
    uuid->time_mid = ((uint16_t)oct[4] << 8) | oct[5];
    uuid->time_hi_and_version = ((uint16_t)oct[6] << 8) | oct[7];
    memcpy(uuid->clock_seq_and_node, oct + 8, sizeof(uuid->clock_seq_and_node));
}

static struct sess_context *create_new_session_element(handle_t channel,
                                                    msg_map_t *msg)
{
    struct sess_context *new_session;

    new_session = (struct sess_context *)calloc(1, sizeof(struct sess_context));
    if (new_session) {
        msg->session = get_session_id(new_session);
        new_session->command_ch_id = channel;
        new_session->parent_sess_id = msg->parent_sess_id;
        new_session->ca_id_login = msg->client_id_login;
        uuid_from_octets(&new_session->ca_id_uuid, msg->client_id_uuid);
        uuid_from_octets(&new_session->ta_uuid, msg->ta_uuid);
        /* Initialize a list of command messages for this session and add open
         * sess msg.
         */
        list_initialize(&new_session->sess_msg);
        new_session->closing = 0;
        new_session->ca_panic = 0;
        new_session->ta_panic = 0;
        new_session->sess_ctx = msg->session_ctx = 0;
        new_session->session_ch_id = INVALID_IPC_HANDLE;
        new_session->ree_tag = 0;
    } else
        TEE_DBG_MSG("ERROR: Not enough memory for new session element.\n");

    return new_session;
}

static TEE_Result check_ta_property_flags(const uuid_t *ta_uuid,
                               const struct ta_refcount *ta,
                               uint32_t *ta_property_flags)
{
    TEE_Result res;
    uint32_t prop_flags = 0;

    res = get_ta_flags(ta_uuid, &prop_flags);
    if (res != TEE_SUCCESS)
        goto check_ta_props_end;

    if (ta != NULL) {
        /* Sanity check: flags in ta_refcount structure should be the same as
         * flags in actual TA.
         */
        assert(ta->prop_flags == prop_flags);
        if (!(prop_flags & TA_FLAGS_KEEP_ALIVE) &&
            !ta->refcount) {
            TEE_DBG_MSG("refcount can be 0 only for keep alive instances\n");
            res = TEE_ERROR_BAD_STATE;
            goto check_ta_props_end;
        }
        if ((prop_flags & TA_FLAGS_SINGLE_INSTANCE) &&
            !(prop_flags & TA_FLAGS_MULTI_SESSION)  &&
            ta->refcount) {
            TEE_DBG_MSG("Single instance single session application already"
                        " started and a session is already opened on it.\n");
            res = TEE_ERROR_BUSY;
            goto check_ta_props_end;
        }
    }

check_ta_props_end:
    *ta_property_flags = prop_flags;

    return res;
}

static void close_ta_handle(struct sess_context *sess)
{
    if (sess->session_ch_id != INVALID_IPC_HANDLE) {
        close(sess->session_ch_id);
        sess->session_ch_id = INVALID_IPC_HANDLE;
    }
}

static void close_ca_handle(struct sess_context *sess)
{
    if (sess->command_ch_id != INVALID_IPC_HANDLE &&
            is_trusted_ch(sess->command_ch_id)) {
        close(sess->command_ch_id);
        sess->command_ch_id = INVALID_IPC_HANDLE;
    }
}

static void sess_refcount_dec(struct sess_context *sess)
{
    struct ta_refcount *r = sess_ta_get(&sess->ta_uuid);

    /* Adjust number of sessions opened on this TA */
    if (r != NULL) {
        if (r->refcount)
            r->refcount--;
        if (!r->refcount) {
            /* If this was last opened session for TA,
             * delete TA element from the list.
             */
            list_delete(&r->ta_refcount_node);
            free(r);
        }
    }
}

static void session_destroy(struct sess_context **sess)
{
    list_delete(&(*sess)->session_context_node);
    free(*sess);
    *sess = NULL;
}

static void close_session_handles(msg_map_t *msg,
                                  struct sess_context *sess,
                                  bool finalize_session)
{
    if (!((msg->func == TEE_OPEN_SESSION_ID && msg->ret != TEE_SUCCESS) ||
        msg->func == TEE_CLOSE_SESSION_ID || msg->func == TEE_DESTROY_ID))
        return;

    TEE_DBG_MSG("Closing handles for session %u func %s:%u ret code %08x)\n",
                msg->session, id_str(msg->func), msg->func, msg->ret);

    /* Since TA is closed, SM-to-TA channel has to be closed here. */
    close_ta_handle(sess);

    if (!finalize_session)
        return;

    /* Close command channel only for TEE applications since only for them
     * is each session has dedicated command channel.
     */
    close_ca_handle(sess);

    /* Adjust number of sessions opened on this TA */
    if (!sess->ta_panic)
        sess_refcount_dec(sess);

    session_destroy(&sess);
}

static void uuid_to_octets(uint8_t oct[TEE_UUID_LEN], uuid_t *uuid)
{
    oct[0] = uuid->time_low >> 24;
    oct[1] = uuid->time_low >> 16;
    oct[2] = uuid->time_low >> 8;
    oct[3] = uuid->time_low;
    oct[4] = uuid->time_mid >> 8;
    oct[5] = uuid->time_mid;
    oct[6] = uuid->time_hi_and_version >> 8;
    oct[7] = uuid->time_hi_and_version;
    memcpy(oct + 8, uuid->clock_seq_and_node, sizeof(uuid->clock_seq_and_node));
}

static TEE_Result cancel_session_operations(struct sess_context *sess)
{
    struct sess_message *n;
    struct sess_message *m;
    TEE_Result res = TEE_SUCCESS;

    if (!sess->closing) {
        TEE_DBG_MSG("Cancel all operations on a session %d\n", sess->session_ch_id);
        list_for_every_entry_safe(&sess->sess_msg, n, m, struct sess_message,
                                  sess_message_node) {
            msg_map_t *msg_buf = (msg_map_t *)n->msg_buffer;
            res = cancel_operation(sess, msg_buf->cancel_id);
            if (res != TEE_SUCCESS)
                break;
        }
    }
    return res;
}

static status_t msg_param_to_ree_param(struct mipstee_msg_param *msg_params,
                                   const utee_params_t *uparam)
{
    size_t i;
    const uint8_t ree_param[] = {
        [TEE_PARAM_TYPE_NONE] = MIPSTEE_MSG_ATTR_TYPE_NONE,
        [TEE_PARAM_TYPE_VALUE_INPUT] = MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT,
        [TEE_PARAM_TYPE_VALUE_OUTPUT] = MIPSTEE_MSG_ATTR_TYPE_VALUE_OUTPUT,
        [TEE_PARAM_TYPE_VALUE_INOUT] = MIPSTEE_MSG_ATTR_TYPE_VALUE_INOUT,
        [TEE_PARAM_TYPE_MEMREF_INPUT] = MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT,
        [TEE_PARAM_TYPE_MEMREF_OUTPUT] = MIPSTEE_MSG_ATTR_TYPE_TMEM_OUTPUT,
        [TEE_PARAM_TYPE_MEMREF_INOUT] = MIPSTEE_MSG_ATTR_TYPE_TMEM_INOUT,
    };

    for (i = 0; i < 4; i++) {
        struct mipstee_msg_param *mp = msg_params + i;
        uint32_t paramtype = TEE_PARAM_TYPE_GET(uparam->param_types, i);

        if (paramtype >= ARRAY_SIZE(ree_param))
            return ERR_INVALID_ARGS;

        mp->attr = (uint64_t)ree_param[paramtype];
        switch (paramtype) {
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            mp->u.value.a = uparam->params[2 * i];
            mp->u.value.b = uparam->params[2 * i + 1];
            /*
             * GP API spec does not support the third value field,
             * so it is not set here.
             */
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            /*
             * This covers adaptation for registered memrefs also since size
             * field is at the same offset in both tmem and rmem on REE side.
             */
            mp->u.tmem.size = uparam->params[2 * i + 1];
            break;
        default:
            break;
        }
    }
    return NO_ERROR;
}

static status_t tee_to_ree_msg(const msg_map_t *tee_msg,
        struct mipstee_msg_arg *ree_msg)
{
    struct mipstee_msg_param *ree_param;
    status_t sys_res = NO_ERROR;

    ree_msg->cmd = tee_cmd_to_ree_cmd(tee_msg->cmd);
    ree_msg->func = 0;
    ree_msg->session = tee_msg->session;
    ree_msg->cancel_id = tee_msg->cancel_id;
    ree_msg->pad = 0; // not used
    ree_msg->ret = tee_msg->ret;
    ree_msg->ret_origin = tee_msg->ret_origin;

    /* adapt a few differences */
    if (!ree_msg->num_params)
        ree_msg->num_params = tee_msg->num_params;

    if (tee_msg->cmd == TEE_INVOKE_COMMAND_ID)
        ree_msg->func = tee_msg->func;
    else if (tee_msg->cmd == TEE_RETVAL_ID)
        ree_msg->cmd = tee_cmd_to_ree_cmd(tee_msg->func);

    /* only need to adapt parameters for TEE_RETVAL_ID */
    if (tee_msg->cmd != TEE_RETVAL_ID)
        return NO_ERROR;

    ree_param = ree_msg->params;

    switch (ree_msg->cmd) {
    case MIPSTEE_MSG_CMD_OPEN_SESSION:
        ree_param += 2; // skip meta parameters
        // fall through
    case MIPSTEE_MSG_CMD_INVOKE_COMMAND:
        sys_res = msg_param_to_ree_param(ree_param, &tee_msg->utee_params);
        break;
    default:
        break;
    }

    return sys_res;
}

static struct mipstee_tipc_msg *ree_msg_alloc(unsigned int n_params,
        uint32_t data_tag)
{
    struct mipstee_tipc_msg *ree_buf;

    ree_buf = (struct mipstee_tipc_msg *)calloc(1,
            MIPSTEE_TIPC_MSG_GET_SIZE(n_params));
    if (!ree_buf)
        return NULL;

    ree_buf->hdr.magic = REE_MAGIC;
    ree_buf->hdr.data_tag = data_tag;
    ree_buf->msg.num_params = n_params;
    return ree_buf;
}

static void ree_msg_free(struct mipstee_tipc_msg *ree_msg)
{
    if (ree_msg)
        free(ree_msg);
}

/* Remove message sent to TA from the message queue. */
static void rm_sent_queue_msg(struct sess_context *sess)
{
    struct sess_message *n;
    struct sess_message *m;

    list_for_every_entry_safe(&sess->sess_msg, n, m, struct sess_message,
                              sess_message_node) {
        if (n->sent_to_ta) {
            rm_queue_msg(n, sess);
            break;
        }
    }
}

static status_t sm_get_port(handle_t *cmd_port)
{
    long sys_res;

    /* If port is already created, exit function */
    if (*cmd_port != INVALID_IPC_HANDLE)
        return NO_ERROR;

    sys_res = port_create(TEE_SESS_MANAGER_COMMAND_MSG, TEE_SM_NUM_RX_BUF,
                          TEE_MAX_BUFFER_SIZE, IPC_PORT_ALLOW_TA_CONNECT |
                          IPC_PORT_ALLOW_NS_CONNECT);
    if (sys_res < 0) {
        TEE_DBG_MSG("Error %ld: Cannot create command port!\n", sys_res);
        sys_res = ERR_BAD_STATE;
        return (status_t)sys_res;
    }
    *cmd_port = (handle_t)sys_res;

    return NO_ERROR;
}

/*
 *  Port event handler
 */
static status_t sm_accept_connection(const uevent_t *ev)
{
    status_t res = NO_ERROR;
    long sys_res;

    if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
        (ev->event & IPC_HANDLE_POLL_HUP) ||
        (ev->event & IPC_HANDLE_POLL_MSG) ||
        (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
        TEE_DBG_MSG("Error: Bad event for port %d\n", ev->handle);
        if (ev->event & IPC_HANDLE_POLL_ERROR) {
            /* Close port in case of internal error.
             * It will be created anew when next time sm_next_message() is
             * called.
             */
            close(ev->handle);
            res = ERR_BAD_STATE;
            goto accept_end;
        }
    }

    if (ev->event & IPC_HANDLE_POLL_READY) {
        uuid_t peer_uuid;
        sys_res = accept(ev->handle, &peer_uuid);
        if (sys_res < 0) {
            TEE_DBG_MSG("Warning %lx: Failed to accept connection on port %d\n",
                        sys_res, ev->handle);
        } else
            res = set_trusted_ch((handle_t)sys_res, &peer_uuid);
    }
accept_end:
    return res;
}

/*
 * Channel event handler
 */
static status_t sm_get_msg(uevent_t *ev, msg_map_t *msg_buf, size_t buf_len)
{
    status_t res = NO_ERROR;
    handle_t channel = (handle_t)ev->handle;

    if (ev->event & IPC_HANDLE_POLL_MSG) {
        res = sm_get_msg_buffer(channel, (uint8_t *)msg_buf, buf_len);
    } else if ((ev->event & IPC_HANDLE_POLL_HUP) ||
                (ev->event & IPC_HANDLE_POLL_ERROR)) {
        TEE_DBG_MSG("Error: HUP event or internal error on channel %d\n",
                channel);
        res = ERR_CHANNEL_CLOSED;
    } else if ((ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED) ||
                (ev->event & IPC_HANDLE_POLL_NONE) ||
                (ev->event & IPC_HANDLE_POLL_READY)) {
        /* a previous send operation failed because of insufficient buffers or
         * there is an event on the channel that doesn't need to be processed by
         * Session Manager.
         */
        res = ERR_ALREADY_STARTED;
    } else {
        /* This should never be reached. */
        TEE_DBG_MSG("Error unexpected %x event on channel %d\n",
                ev->event, channel);
        res = ERR_BAD_STATE;
    }
    return res;
}

status_t sm_next_msg(handle_t *channel, msg_map_t *msg_buf, size_t buf_len)
{
    status_t res;
    long sys_res;
    uevent_t ev;
    static handle_t command_handle = INVALID_IPC_HANDLE;

    ev.event = 0;
    ev.handle = INVALID_IPC_HANDLE;
    *channel = INVALID_IPC_HANDLE;

    res = sm_get_port(&command_handle);
    if (res < 0)
        goto err_cleanup;

    do {
        sys_res = wait_any(&ev, DEFAULT_TIMEOUT_MSECS * 10);
        /* Restart wait_any() on error. */
        if (sys_res < 0)
            continue;

        TEE_DBG_MSG("handle %d event %x\n", ev.handle, ev.event);

        if (ev.handle == command_handle) {
            res = sm_accept_connection(&ev);
            if (res == ERR_BAD_STATE)
                goto err_cleanup;
        } else {
            *channel = (handle_t)ev.handle;
            res = sm_get_msg(&ev, msg_buf, buf_len);
            if (res < 0)
                goto err_cleanup;
        }
    } while (*channel == INVALID_IPC_HANDLE);

err_cleanup:
    if (res && (res != ERR_TIMED_OUT) && (res != ERR_ALREADY_STARTED))
        TEE_DBG_MSG("Error (%d) on handle %d event %x\n", res, ev.handle,
                ev.event);

    return res;
}

/*
 * Set the ree_tag field to use while processing this message; this field is
 * only valid per-message, not per-session.  Currently ree_tag is only used for
 * the close session case. For other messages the tag is contained inside the
 * msg->ree_tag field.
 */
static void update_sess_ree_tag(struct sess_context *sess, uint32_t ree_tag)
{
    sess->ree_tag = ree_tag;
}

static uint32_t get_sess_ree_tag(const struct sess_context *sess)
{
    return sess->ree_tag;
}

static TEE_Result preprocess_open_session(msg_map_t *operation_msg,
                                          struct sess_context *new_session)
{
    TEE_Result res = TEE_SUCCESS;
    handle_t ta_channel = INVALID_IPC_HANDLE;
    uint32_t ta_property_flags = 0;
    struct ta_refcount *ta_started;

    ta_started = sess_ta_get(&new_session->ta_uuid);

    res = check_ta_property_flags(&new_session->ta_uuid, ta_started,
            &ta_property_flags);
    if (res != TEE_SUCCESS) {
        /* This error will be passed to lists_add_session() */
        TEE_DBG_MSG("Open session error: %08x. Failed to obtain properties\n",
                    res);
    }

    res = lists_add_session(new_session, ta_started, ta_property_flags, res);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("Open session error: Cannot allocate memory\n");
        goto open_session_err;
    }

    res = sm_connect_to_ta(&new_session->ta_uuid, DEFAULT_TIMEOUT_MSECS, &ta_channel);

    new_session->session_ch_id = ta_channel;

    /* Even if sm_connect_to_ta() failed finish as if all is ok.
     * Postprocess should do cleanup in this case.
     */

open_session_err:
    return res;
}

static TEE_Result preprocess_invoke_command(msg_map_t *op_msg,
                                            struct sess_context *sess)
{
    TEE_Result res = TEE_SUCCESS;

    op_msg->client_id_login = sess->ca_id_login;
    uuid_to_octets(op_msg->client_id_uuid, &sess->ca_id_uuid);
    op_msg->session_ctx = sess->sess_ctx;

    return res;
}

static TEE_Result prepare_close_session_msg(msg_map_t *msg,
                                            struct sess_context *sess)
{
    struct ta_refcount *r = sess_ta_get(&sess->ta_uuid);

    if (r == NULL && !sess->ta_panic) {
        // TODO This should never happen, but it should be handled nevertheless.
        TEE_DBG_MSG("session_ch_id %d, sess_ta_get not found\n",
                sess->session_ch_id);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    msg->session = get_session_id(sess);
    msg->func = 0;
    msg->cmd = TEE_CLOSE_SESSION_ID;

    /* this coordinates with update_sess_ree_tag() */
    msg->ree_tag = get_sess_ree_tag(sess);

    msg->session_ctx = sess->sess_ctx;

    /* For panicked TA, refcount is handled already */
    if (sess->ta_panic)
        return TEE_ERROR_TARGET_DEAD;

    /* Check number of sessions opened on this TA */
    if (!(r->prop_flags & TA_FLAGS_SINGLE_INSTANCE) ||
        ((r->refcount == 1) && !(r->prop_flags & TA_FLAGS_KEEP_ALIVE))) {
        /* If this is not single instance TA (meaning that each sesson is
         * opened in a new instance), or this is last opened session for
         * TA and TA is single instance, but is not keep alive,
         * close TA instance.
         */
        assert(r->refcount); // Sanity check for multi instance TAs
        msg->cmd = TEE_DESTROY_ID;
    }
    return TEE_SUCCESS;
}

static TEE_Result preprocess_close_session(msg_map_t *op_msg,
                                           struct sess_context *sess)
{
    struct sess_context *n;
    TEE_Result res = TEE_SUCCESS;

    sess->closing = 1;
    /* First close all the child sessions. */
    list_for_every_entry(&sessions_list, n, struct sess_context,
                         session_context_node) {
        if (session_id_match(n->parent_sess_id, get_session_id(sess)))
            force_close_session(n);
    }

    memset(op_msg, 0, sizeof(msg_map_t));
    res = prepare_close_session_msg(op_msg, sess);
    if (res != TEE_SUCCESS)
        goto preprocess_close_session_end;

    TEE_DBG_MSG("close session... channel = %d\n",
                (uint32_t)(sess->session_ch_id));
preprocess_close_session_end:
    return res;
}

static status_t prepare_ree_msg(uint8_t **msg_buff, uint32_t *ree_msg_size)
{
    struct mipstee_tipc_msg *ree_buf;
    msg_map_t *msg = (msg_map_t *)*msg_buff;
    uint ree_num_params;
    status_t sys_res = NO_ERROR;

    ree_num_params = ree_num_params_from_tee_msg(msg);
    ree_buf = ree_msg_alloc(ree_num_params, sm_get_tag_field(msg));
    if (!ree_buf)
        return ERR_NO_MEMORY;

    sys_res = tee_to_ree_msg(msg, &ree_buf->msg);
    if (sys_res) {
        TEE_DBG_MSG("ERROR %d - adaptation to REE msg layout failed.\n",
                sys_res);
        goto prepare_ree_msg_end;
    }

    *ree_msg_size = MIPSTEE_TIPC_MSG_GET_SIZE(ree_num_params);
    *msg_buff = (uint8_t *)ree_buf;

prepare_ree_msg_end:
    return sys_res;
}

static bool is_sess_busy(struct sess_context *sess)
{
    struct sess_message *x, *y;

    list_for_every_entry_safe(&sess->sess_msg, x, y, struct sess_message,
                     sess_message_node) {
        if (x->sent_to_ta) {
            msg_map_t *sent_msg = (msg_map_t *)x->msg_buffer;
            /* Prevent message sending only in case where message should be
             * sent to trusted application.
             */
            if (sent_msg->cmd != TEE_RETVAL_ID ||
                is_ca_trusted(sent_msg->client_id_login))
                return true;
        }
    }

    return false;
}

static uint32_t get_sess_ta_props(struct sess_context *sess)
{
    struct ta_refcount *r = sess_ta_get(&sess->ta_uuid);

    ASSERT(r != NULL);
    return r->prop_flags;
}

static bool is_ta_busy(struct sess_context *sess, msg_map_t *op_msg)
{
    struct sess_context *n, *t;
    uint32_t prop_flags = 0;

    prop_flags = get_sess_ta_props(sess);

    if (!(prop_flags & TA_FLAGS_SINGLE_INSTANCE) &&
        op_msg->cmd == TEE_OPEN_SESSION_ID)
        return false;

    /* For single session TAs, check if there is already message sent to TA.*/
    if (!(prop_flags & TA_FLAGS_SINGLE_INSTANCE) ||
        !(prop_flags & TA_FLAGS_MULTI_SESSION))
        return is_sess_busy(sess);

    /* For multi-session TAs, search for sent message in all the
     * sessions.
     */
    // TODO: This search should be optimised by grouping sessions
    //       that belong to a TA in one list.
    list_for_every_entry_safe(&sessions_list, n, t,
                            struct sess_context, session_context_node) {
         if (!memcmp(&sess->ta_uuid, &n->ta_uuid, sizeof(uuid_t))) {
            if (is_sess_busy(n))
                return true;
         }
    }

    return false;
}

static TEE_Result sm_send_msg(msg_map_t *operation_msg,
                              struct sess_context *sess,
                              handle_t ch,
                              TEE_Result preprocess_res)
{
    status_t sys_res = NO_ERROR;
    uint8_t *msg_buff = (uint8_t *)operation_msg->buffer;
    uint32_t msg_size = sizeof(msg_map_t);

    if (operation_msg->cmd != TEE_RETVAL_ID) {
        if (is_ta_busy(sess, operation_msg)) {
            if (operation_msg->cmd == TEE_OPEN_SESSION_ID) {
                if (!is_trusted_ch(sess->command_ch_id)) {
                    failure_notification(operation_msg, TEE_ERROR_BUSY);
                    ch = sess->command_ch_id;
                }
            } else {
                sys_res = ERR_BUSY;
                goto sm_send_msg_end;
            }
        }
    }

    if (operation_msg->cmd == TEE_RETVAL_ID ||
        preprocess_res != TEE_SUCCESS) {
        /* skip sending return value if CA which should receive it is dead */
        if (sess && sess->ca_panic) {
            TEE_DBG_MSG("Client application is dead.\n");
            goto sm_send_msg_end;
        }

        if (ch == INVALID_IPC_HANDLE) {
            sys_res = ERR_BAD_HANDLE;
            goto sm_send_msg_end;
        }

        if (!is_trusted_ch(ch)) {
            sys_res = prepare_ree_msg(&msg_buff, &msg_size);
            if (sys_res) {
                if (sys_res != ERR_NO_MEMORY)
                    goto sm_send_msg_err;
                goto sm_send_msg_end;
            }
        }
    }

    sys_res = sm_send_buffer(ch, msg_buff, msg_size);
    TEE_DBG_MSG("Sending message (cmd:ch) -(%s:%d)  ... result: %d\n", id_str(operation_msg->cmd), ch, sys_res);

sm_send_msg_err:
    if (!is_trusted_ch(ch))
        ree_msg_free((struct mipstee_tipc_msg *)msg_buff);

sm_send_msg_end:
    return err_to_tee_err(sys_res);
}

static TEE_Result postprocess_return_message(msg_map_t *op_msg,
                                             struct sess_context *sess,
                                             TEE_Result res)
{
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("Error (%08x) sending message to CA.\n",
                res);
        if (res == TEE_ERROR_COMMUNICATION) {
            /* ERR_CHANNEL_CLOSED is handled in main() on detecting HUP event on
             * command channel.
             */
            res = TEE_SUCCESS;
        }
    }

    return res;
}

static TEE_Result postprocess_messages(msg_map_t *operation_msg,
                                       struct sess_context *sess,
                                       TEE_Result res)
{
    bool transmitted = false;

    if (sess == NULL)
        goto postproc_end;

    if (res == TEE_SUCCESS)
        transmitted = true;

    if (operation_msg->cmd == TEE_RETVAL_ID) {
        res = postprocess_return_message(operation_msg, sess, res);
        close_session_handles(operation_msg, sess, (bool)(res == TEE_SUCCESS));
    }

    if (operation_msg->cmd != TEE_RETVAL_ID || res != TEE_SUCCESS) {
        /* Add message to message queue */
        res = session_add_operation(sess, operation_msg, transmitted);
        if (res != TEE_SUCCESS) {
            TEE_DBG_MSG("Failed to add a message to queue\n");
            /* Cancel operation so correct SM functioning is maintained. */
            if (transmitted)
                cancel_operation(sess, operation_msg->cancel_id);
        }
    }

postproc_end:
    return res;
}

static void force_close_session(struct sess_context *sess)
{
    msg_map_t close_message = { .buffer = { 0 } };
    TEE_Result res;

    res = cancel_session_operations(sess);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("Canceling operations for session %d failed. Error: %08x\n",
                    sess->session_ch_id, res);
    }
    res = preprocess_close_session(&close_message, sess);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("Closing session %d failed. Error: %08x\n",
                    sess->session_ch_id, res);
        return;
    }
    res = sm_send_msg(&close_message, sess, sess->session_ch_id, res);
    if (res != TEE_SUCCESS)
        TEE_DBG_MSG("Closing session %d failed. Error: %08x\n",
                    sess->session_ch_id, res);
    postprocess_messages(&close_message, sess, res);

    return;
}

static void close_all_ch_sessions(uint32_t cmd_channel)
{
    struct sess_context *n;

    TEE_DBG_MSG("Close all sessions for command channel %d\n", cmd_channel);
    /* Find and close all sessions opened through this command channel. */
    list_for_every_entry(&sessions_list, n, struct sess_context,
                         session_context_node) {
        if (handle_id_match(n->command_ch_id, cmd_channel))
            force_close_session(n);
    }
}

static struct sess_context *match_handle_in_sessions(handle_t channel)
{
    struct sess_context *m = NULL;

    list_for_every_entry(&sessions_list, m, struct sess_context,
                         session_context_node) {
        if (handle_id_match(channel, m->command_ch_id) ||
            handle_id_match(channel, m->session_ch_id))
            return m;
    }

    return NULL;
}

/* caller is responsible for zeroing msg */
static status_t handle_channel_hup_event(handle_t channel, msg_map_t *msg)
{
    struct sess_context *sess = match_handle_in_sessions(channel);

    /* No sessions with handles corresponding to channel */
    if (sess == NULL) {
        close(channel);
        return ERR_CHANNEL_CLOSED;
    }

    if (channel == sess->session_ch_id) {
        /* HUP from TA -> close session and clear */
        TEE_DBG_MSG("Unexpected HUP event on session channel %d\n",
                    channel);
        /* Return info about failure to CA */
        msg->cmd = TEE_RETVAL_ID;
        msg->func = TEE_CLOSE_SESSION_ID;
        msg->ret_origin = TEE_ORIGIN_TEE;
        msg->ret = TEE_ERROR_TARGET_DEAD;
        msg->session = get_session_id(sess);
        /* Set tag field of error message to a value of currently active
         * operation.
         */
        msg->ree_tag = get_sess_ree_tag(sess);
        return NO_ERROR;
    } else {
        /* HUP from CA -> close all the session opened through closed
         * command channel
         */
        TEE_DBG_MSG("CA channel %d closed\n", channel);
        close(channel);
        close_all_ch_sessions(channel);
        return ERR_CHANNEL_CLOSED;
    }
}

static void handle_ta_panic(struct sess_context *sess)
{
    /*
     * When the client of a Trusted Application dies or exits abruptly
     * and when it can be properly detected, then this MUST appear to the
     * Trusted Application as if the client requests cancellation of all
     * pending operations and gracefully closes all its client sessions.
     */
    struct sess_context *m;

    /* Set indicator that the TA has panicked */
    sess->ta_panic = 1;

    /* Close sessions for which panicked app is client */
    list_for_every_entry(&sessions_list, m, struct sess_context,
                         session_context_node) {
        if (session_id_match(m->parent_sess_id, get_session_id(sess))) {
            force_close_session(m);
            m->ca_panic = 1;
        }
    }
    close_ta_handle(sess);
    sess_refcount_dec(sess);
}

static bool is_sims_ta(struct sess_context *sess)
{
    uint32_t ta_props = get_sess_ta_props(sess);
    return ((ta_props & (uint32_t)(TA_FLAGS_SINGLE_INSTANCE |
        TA_FLAGS_MULTI_SESSION)) != 0);
}

static void handle_sims_ta_panic(struct sess_context *sess)
{
    struct sess_context *m;

    list_for_every_entry(&sessions_list, m, struct sess_context,
                session_context_node) {
        if (!memcmp(&sess->ta_uuid, &m->ta_uuid, sizeof(uuid_t)))
            handle_ta_panic(m);
    }
}

static TEE_Result preprocess_return_message(msg_map_t *op_msg,
                                            struct sess_context *sess)
{
    /* Remove from message queue operation for which value is returned. */
    rm_sent_queue_msg(sess);

    if ((op_msg->func == TEE_OPEN_SESSION_ID) && !sess->sess_ctx)
        sess->sess_ctx = op_msg->session_ctx;

    /* CA should not have any knowledge about sessionContext parameter */
    op_msg->session_ctx = 0;

    /* If the TA has panicked, handle it's client sessions, if any */
    if (op_msg->ret == TEE_ERROR_TARGET_DEAD &&
        op_msg->ret_origin == TEE_ORIGIN_TEE) {
        TEE_DBG_MSG("TA panicked\n");
        if (is_sims_ta(sess))
            handle_sims_ta_panic(sess);
        else
            handle_ta_panic(sess);
    }

    return TEE_SUCCESS;
}

static TEE_Result preprocess_operation_message(msg_map_t *operation_msg,
                                               struct sess_context *sess,
                                               handle_t *channel)
{
    TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;

    if (!sess) {
        if (operation_msg->cmd == TEE_OPEN_SESSION_ID)
            res = TEE_ERROR_OUT_OF_MEMORY;
        if (operation_msg->cmd == TEE_RETVAL_ID)
            *channel = INVALID_IPC_HANDLE;
        goto preprocess_operation_message_end;
    }

    if (sess->closing && operation_msg->cmd != TEE_RETVAL_ID) {
        res = TEE_ERROR_BUSY;
        goto preprocess_operation_message_end;
    }

    if (sess->ta_panic && operation_msg->cmd == TEE_INVOKE_COMMAND_ID) {
        res = TEE_ERROR_TARGET_DEAD;
        goto preprocess_operation_message_end;
    }

    // if (prep_msg->cmd != TEE_RETVAL_ID)
    //     update_sess_ree_tag(prep_msg);

    switch (operation_msg->cmd) {
    case TEE_OPEN_SESSION_ID:
        res = preprocess_open_session(operation_msg, sess);
        break;
    case TEE_INVOKE_COMMAND_ID:
        res = preprocess_invoke_command(operation_msg, sess);
        break;
    case TEE_CLOSE_SESSION_ID:
        if (operation_msg->func == MIPSTEE_MSG_CMD_CANCEL) {
            sess->ca_panic = 1;
            res = cancel_session_operations(sess);
            if (res != TEE_SUCCESS) {
                TEE_DBG_MSG("Canceling operations failed. Error: %08x\n", res);
                break;
            }
        }
        // TODO: check if this is needed:
        update_sess_ree_tag(sess, sm_get_tag_field(operation_msg));
        res = preprocess_close_session(operation_msg, sess);
        break;
    case TEE_RETVAL_ID:
        ASSERT(is_trusted_ch(*channel));
        /* TEE_CANCEL_ID will not be returned from TA in any regular
         * circumstances.
         */
        *channel = sess->command_ch_id;
        res = preprocess_return_message(operation_msg, sess);
        break;
    default:
        /* Should never be reached. */
        TEE_DBG_MSG("Wrong operation ID: %08x.\n", operation_msg->cmd);
        break;
    }

    /* Set the current session id as a parent sess id in msg for possible next
     * session.
     */
    operation_msg->parent_sess_id = get_session_id(sess);

preprocess_operation_message_end:
    /* Set out channel if everything is OK. */
    /* In case (res == TEE_SUCCESS && operation_msg->cmd != TEE_RETVAL_ID),
     * channel stays unchanged (command channel).
     */
    if (res == TEE_SUCCESS && operation_msg->cmd != TEE_RETVAL_ID)
        *channel = sess->session_ch_id;

    if (((operation_msg->cmd == TEE_OPEN_SESSION_ID   ||
        operation_msg->cmd == TEE_INVOKE_COMMAND_ID) && res != TEE_SUCCESS) ||
        (operation_msg->cmd == TEE_CLOSE_SESSION_ID &&
        res == TEE_ERROR_TARGET_DEAD)) {
        failure_notification(operation_msg, res);
    }

    return res;
}

struct sess_context *prepare_session_element(handle_t channel,
                                             msg_map_t *operation_msg)
{
    struct sess_context *session = NULL;

    if (operation_msg->cmd == TEE_OPEN_SESSION_ID) {
        session = create_new_session_element(channel, operation_msg);
    }
    else if (operation_msg->session) {
        session = sess_context_get((uint32_t)operation_msg->session);
        if (operation_msg->cmd == TEE_INVOKE_COMMAND_ID ||
            operation_msg->cmd == TEE_CLOSE_SESSION_ID ||
            operation_msg->cmd == TEE_CANCEL_ID) {
            /* Check validity of session element. */
            if (session->command_ch_id != channel) {
                TEE_DBG_MSG("Error: Session %d does not belong to a channel %d!\n",
                            session->session_ch_id, channel);
                session = NULL;
            }
        }
    }

    return session;
}

/* Do a walkthrough on a sessions list and try to handle first message
 * in each session's queue.
 */
static void handle_pending_messages(void)
{
    struct sess_context *n, *t;

    list_for_every_entry_safe(&sessions_list, n, t,
                              struct sess_context, session_context_node) {

        TEE_DBG_MSG("Session cmd_ch_id:sess_ch_id(%d:%d)\n",
                n->command_ch_id, n->session_ch_id);

        /* Don't handle messages that wait for closing of the sessions
         * opened by the panicked application
         */
        if (n->ta_panic)
            continue;

        struct sess_message *head_msg = list_peek_head_type(&n->sess_msg,
                                                            struct sess_message,
                                                            sess_message_node);
        if (head_msg) {
            handle_t ch = (handle_t)INVALID_IPC_HANDLE;
            TEE_Result res = TEE_ERROR_BAD_PARAMETERS;
            msg_map_t *msg_buffer;
            uint32_t cmd;
            int tag;

            /* Skip an operation that was already sent to a TA. */
            if (head_msg->sent_to_ta)
                continue;

            msg_buffer = (msg_map_t *)head_msg->msg_buffer;
            tag = sm_get_tag_field(msg_buffer);

            cmd = msg_buffer->cmd;

            if (cmd < TEE_OPEN_SESSION_ID || cmd > TEE_DESTROY_ID) {
                TEE_DBG_MSG("Error unsupported pending operation id %d\n", cmd);
                /* Remove operation with unsupported ID from the msg queue. */
                rm_queue_msg(head_msg, n);
                goto pending_message_end;
            }

            if (cmd == TEE_RETVAL_ID)
                ch = n->command_ch_id;
            else
                ch = n->session_ch_id;

            res = sm_send_msg(msg_buffer, n, ch, TEE_SUCCESS);
            if (!res) {
                if (cmd == TEE_RETVAL_ID) {
                    res = postprocess_return_message(msg_buffer, n, res);
                    close_session_handles(msg_buffer, n, false);
                    rm_queue_msg(head_msg, n);
                } else
                    head_msg->sent_to_ta = true;
            }

pending_message_end:
            TEE_DBG_MSG("Sending pending %s:%d %s on ch:tag(%d:%u)\n",
                    id_str(cmd), cmd, res ? "FAILED" : "OK", ch, tag);

        } // if (head_msg)
    }
}

int main(void)
{
    TEE_Result res = TEE_SUCCESS;
    status_t sys_res = NO_ERROR;
    handle_t channel;
    msg_map_t _operation_msg;
    msg_map_t *operation_msg = &_operation_msg;

    TEE_DBG_MSG("START SESSION MANAGER\n");

    while (1) {
        int operation = -1;
        int tag;
        channel = INVALID_IPC_HANDLE;
        sys_res = sm_next_msg(&channel, operation_msg, sizeof(msg_map_t));

        /* prevent processing of old or partial messages */
        if (sys_res && (sys_res != ERR_TIMED_OUT))
            memset(operation_msg, 0, sizeof(*operation_msg));

        if (sys_res == ERR_CHANNEL_CLOSED) {
            sys_res = handle_channel_hup_event(channel, operation_msg);
            if (sys_res == ERR_CHANNEL_CLOSED)
                goto msg_handling_end;
        } else if (sys_res < 0)
            goto msg_handling_end;

        ASSERT(channel != INVALID_IPC_HANDLE);

        operation = operation_msg->cmd;
        tag = sm_get_tag_field(operation_msg);

        TEE_DBG_MSG("Received operation %s:%d on %s channel:tag(%d:%u)\n",
                    id_str(operation), operation, (is_trusted_ch(channel) ?
                        "TEE" : "REE"), channel, tag);

        struct sess_context *sess = prepare_session_element(channel, operation_msg);

        if (operation == TEE_CANCEL_ID) {
            handle_cancellation(channel, operation_msg, sess);
            goto msg_handling_end;
        }

        res = preprocess_operation_message(operation_msg, sess, &channel);

send_cancel_return:
        if (channel != INVALID_IPC_HANDLE)
            res = sm_send_msg(operation_msg, sess, channel, res);

        res = postprocess_messages(operation_msg, sess, res);

/* If there was an event on handle that is handled correctly or if
 * wait_any() timed out, execute pending operations on all the sessions
 * in the list.
 */
msg_handling_end:
        if (res != TEE_SUCCESS)
            TEE_DBG_MSG("Operation %s:%d on channel %d returned %x\n",
                        id_str(operation), operation, channel, res);
        // TODO: Consider the way pending messages should be handled in case
        //       where there is an error and port is closed.
        if (sys_res != ERR_BAD_STATE)
            handle_pending_messages();
    } // while (1)

    return res;
}
