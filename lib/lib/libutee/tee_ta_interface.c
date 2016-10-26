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
#include <setjmp.h>
#include <tee_ta_interface.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <trusty_app_manifest.h>
#include <trusty_std.h>
#include <err.h>
#include <mm.h>

#define MAX_PORT_NAME_LENGTH    64

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "UTEE"

extern trusty_app_manifest_t trusty_app_manifest;

static handle_t ta_port = INVALID_IPC_HANDLE;
static struct ta_ctx __ta_context;
struct ta_ctx *ta_context = &__ta_context;
static msg_map_t ta_panic_msg_buffer;

/* forward declarations */
static void utee_send_panic_reply(handle_t *handle);

#define TIME_MULTIPLICATOR  1000000

TEE_Result tee_wait(uint32_t timeout) {
    int64_t start_time, curr_time;
    int32_t res;

    res = gettime(0, 0, &start_time);
    if (res < 0)
        TEE_Panic(err_to_tee_err(res));
    do {
        if (!ta_context->active_sess.cancel_masked &&
            ta_context->active_sess.cancel)
            return TEE_ERROR_CANCEL;
        res = gettime(0, 0, &curr_time);
        if (res < 0)
            TEE_Panic(err_to_tee_err(res));
        /* TODO: insert sleep if necessary */
    } while ((curr_time - start_time) < ((int64_t)timeout * TIME_MULTIPLICATOR));
    return TEE_SUCCESS;
}

static void set_ta_config_properties(void)
{
    bool value = false;

    ta_context->ta_flags = 0;

    TEE_GetPropertyAsBool((TEE_PropSetHandle)TEE_PROPSET_CURRENT_TA,
                          "gpd.ta.singleInstance", &value);
    ta_context->ta_flags |= value ? TA_FLAGS_SINGLE_INSTANCE : 0;
    TEE_GetPropertyAsBool((TEE_PropSetHandle)TEE_PROPSET_CURRENT_TA,
                          "gpd.ta.multiSession", &value);
    ta_context->ta_flags |= value ? TA_FLAGS_MULTI_SESSION : 0;
    TEE_GetPropertyAsBool((TEE_PropSetHandle)TEE_PROPSET_CURRENT_TA,
                          "gpd.ta.instanceKeepAlive", &value);
    ta_context->ta_flags |= value ? TA_FLAGS_KEEP_ALIVE : 0;
}

static TEE_Result set_ta_context_props_from_manifest(trusty_app_manifest_t *manifest)
{
    uint32_t config_cnt;
    uint32_t *config_blob;
    bool props_found = false;

    /* Set ta context uuid from manifest */
    memcpy(&ta_context->uuid, &manifest->uuid, sizeof(TEE_UUID));

    if (get_ta_props_cnt((uuid_t*)&(ta_context->uuid), &config_cnt) != NO_ERROR)
        return TEE_ERROR_ITEM_NOT_FOUND;

    config_blob = trusty_app_manifest.config_options;

    for (TRUSTY_APP_CFG_ITERATOR(config_blob, config_cnt, key, val)) {
        switch (key) {
            case TRUSTY_APP_CONFIG_KEY_EXTERN:
                /* EXTERN config takes 2 data values */
                ta_context->extern_props = (struct ta_property *)val[0];
                ta_context->extern_props_size = *(uint32_t *)val[1];
                props_found = true;
                continue;
            default:
                break;
        }
    }

    if (!props_found)
        return TEE_ERROR_ITEM_NOT_FOUND;

    set_ta_config_properties();

    return TEE_SUCCESS;
}

static TEE_Result init_ta_context(void)
{
    TEE_Result res;

    /* Initialize non-zero ta_context fields */
    ta_context->active_sess.cancel_masked = 1;

    res = set_ta_context_props_from_manifest(&trusty_app_manifest);

    return res;
}

static int get_msg_buffer_cmdid(msg_map_t *msg_buffer)
{
    return msg_buffer->command_id;
}

static int get_msg_buffer_parent_id(msg_map_t *msg_buffer)
{
    return msg_buffer->parent_id;
}

static void set_msg_buffer_parent_id(msg_map_t *msg_buffer)
{
    msg_buffer->parent_id = ta_context->active_sess.parent_sess_id;
}

static TEE_Identity get_msg_buffer_clientid(msg_map_t *msg_buffer)
{
    return msg_buffer->client_id;
}

static TEE_Result get_tee_params_from_msg_buffer(msg_map_t *msg_buffer,
        uint32_t *param_types, TEE_Param *params)
{
    int i;
    utee_params_t *utee_params = &msg_buffer->utee_params;
    uint64_t *tmp_ptr = utee_params->params;

    if (!param_types)
        return NO_ERROR;

    *param_types = utee_params->param_types;

    for (i = 0; i < 4; i++) {
        switch(TEE_PARAM_TYPE_GET(*param_types, i)) {

        case TEE_PARAM_TYPE_NONE:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
            params[i].value.a = 0;
            params[i].value.b = 0;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            params[i].value.a = (uint32_t)(tmp_ptr[2 * i]);
            params[i].value.b = (uint32_t)(tmp_ptr[2 * i + 1]);
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
        case TEE_PARAM_TYPE_MEMREF_INPUT:
            params[i].memref.buffer = (void*)((uintptr_t)(tmp_ptr[2 * i]));
            params[i].memref.size = (uint32_t)(tmp_ptr[2 * i + 1]);
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    return TEE_SUCCESS;
}

static void set_return_tee_params_in_msg_buffer(msg_map_t *msg_buffer,
        uint32_t param_types, TEE_Param *params)
{
    int i;
    utee_params_t *utee_params = &msg_buffer->utee_params;

    if (!params) {
        memset(utee_params, 0, sizeof(*utee_params));
        return;
    }

    utee_params->param_types = param_types;
    for (i = 0; i < 4; i++) {
        switch(TEE_PARAM_TYPE_GET(param_types, i)) {
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            utee_params->params[2 * i] = params[i].value.a;
            utee_params->params[2 * i + 1] = params[i].value.b;
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            utee_params->params[2 * i + 1] = (uintptr_t)params[i].memref.size;
            break;
        case TEE_PARAM_TYPE_NONE:
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        default:
            break;
        }
    }
}

static long utee_send_return_params(handle_t *channel, msg_map_t *msg_buffer)
{
    long length;
    ipc_msg_t msg;
    iovec_t iov;

    iov.base = msg_buffer->buffer;
    iov.len = TEE_MAX_BUFFER_SIZE;

    msg.num_iov = 1;
    msg.iov= &iov;
    msg.num_handles = 0;
    msg.handles = NULL;

    length = send_msg(*channel, &msg);

    return length;
}

static long utee_get_msg(handle_t *channel, msg_map_t *msg_buffer)
{
    long sys_res;
    ipc_msg_info_t msg_info;
    ipc_msg_t msg;
    iovec_t iov;

    iov.base = msg_buffer->buffer;
    iov.len = TEE_MAX_BUFFER_SIZE;

    msg.num_iov = 1;
    msg.iov= &iov;
    msg.num_handles = 0;
    msg.handles = NULL;

    sys_res = get_msg(*channel, &msg_info);
    if (sys_res < 0)
        return sys_res;

    sys_res = read_msg(*channel, msg_info.id, 0, &msg);
    if (sys_res < 0)
        return sys_res;
    /* TODO: Handle incomplete reads */

    /* Retire message */
    sys_res = put_msg(*channel, msg_info.id);
    if (sys_res < 0)
        return sys_res;

    return sys_res;
}

static void utee_set_return_param_buffer(msg_map_t *msg_buffer,
                                  uint32_t param_types, TEE_Param *params,
                                  uint32_t ret_orig, uint32_t ret_code,
                                  uint32_t ep_id)
{
    set_return_tee_params_in_msg_buffer(msg_buffer, param_types, params);
    msg_buffer->operation_id = TEE_RETVAL_ID;
    msg_buffer->return_origin = ret_orig;
    msg_buffer->return_code = ret_code;
    msg_buffer->command_id = ep_id;
    set_msg_buffer_parent_id(msg_buffer);
}

static long map_client_memrefs(uint32_t param_types, TEE_Param *params)
{
    int i;
    long sys_ret;
    uint32_t flags = 0;

    if (!param_types)
        return NO_ERROR;

    for (i = 0; i < 4; i++) {
        int p = TEE_PARAM_TYPE_GET(param_types, i);
        switch (p) {
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            if (p == TEE_PARAM_TYPE_MEMREF_INPUT)
                flags = MMAP_FLAG_PROT_READ;
            else if (p == TEE_PARAM_TYPE_MEMREF_OUTPUT)
                flags = MMAP_FLAG_PROT_WRITE;
            else
                flags = MMAP_FLAG_PROT_READ | MMAP_FLAG_PROT_WRITE;

            /* TODO validate that client has memory access rights */
            sys_ret = mmap_memref(params[i].memref.buffer, params[i].memref.size,
                       flags, (uint32_t)&ta_context->active_sess.client_id.uuid);
            if (sys_ret == -1)
                return sys_ret;

            params[i].memref.buffer = (void*)sys_ret;
            break;
        default:
            break;
        }
    }
    return NO_ERROR;
}

static long unmap_client_memrefs(uint32_t param_types, TEE_Param *params)
{
    int i;
    long sys_ret;

    if (!param_types)
        return NO_ERROR;

    for (i = 0; i < 4; i++) {
        switch (TEE_PARAM_TYPE_GET(param_types, i)) {
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            sys_ret = munmap_memref(params[i].memref.buffer, params[i].memref.size);
            if (sys_ret != NO_ERROR)
                return sys_ret;

            break;
        default:
            break;
        }
    }
    return NO_ERROR;
}

static TEE_Result preprocess_entry(uint32_t handle, uint32_t ep_id,
                                   msg_map_t *msg_buffer, uint32_t *param_types,
                                   TEE_Param params[4], uint32_t *cmd_id) {
    long sys_res = NO_ERROR;
    TEE_Result res;

    /* TODO: Check if this needs to be protected by mutex once mechanism
     * for reading messages from the channel is implemented
     */
    ta_context->active_sess.sess_channel = TEE_MASK_HANDLE_ID(handle);
    ta_context->active_sess.ep_id = ep_id;
    ta_context->active_sess.client_id = get_msg_buffer_clientid(msg_buffer);
    ta_context->active_sess.session_ctx = (void *)msg_buffer->session_ctx;

    if (ep_id != TEE_CLOSE_SESSION_ID && ep_id != TEE_DESTROY_ID) {
        res = get_tee_params_from_msg_buffer(msg_buffer, param_types, params);
        if (res)
            return TEE_ERROR_BAD_PARAMETERS;
        sys_res = map_client_memrefs(*param_types, params);
        if (sys_res < 0)
            return TEE_ERROR_ACCESS_DENIED;
    }
    if (ep_id == TEE_INVOKE_COMMAND_ID)
        *cmd_id = get_msg_buffer_cmdid(msg_buffer);

    return TEE_SUCCESS;
}

static TEE_Result postprocess_entry(uint32_t param_types, TEE_Param params[4],
                                    TEE_Result res, uint32_t *ret_orig,
                                    uint32_t ep_id) {
    if (ep_id != TEE_CLOSE_SESSION_ID && ep_id != TEE_DESTROY_ID) {
        long sys_res = NO_ERROR;

        sys_res = unmap_client_memrefs(param_types, params);
        if (sys_res < 0)
            return err_to_tee_err(sys_res);
    }

    if (ta_context->panicked) {
        assert(res == TEE_ERROR_TARGET_DEAD);
        /* ret_orig = TEE_ORIGIN_TEE; */
        return res;
    }

    /* GP API spec - origin should always be the TA after TA execution */
    *ret_orig = TEE_ORIGIN_TRUSTED_APP;
    return res;
}

static TEE_Result finish_entry(handle_t channel, msg_map_t *msg_buffer,
                               uint32_t param_types, TEE_Param params[4],
                               uint32_t ret_orig, TEE_Result res, uint32_t ep_id)
{
    /* If res is TEE_ERROR_COMMUNICATION there was some error either on port or in a
     * communcation channel so there is no point in trying to send info back to client.
     * TODO: Should this be handled in some way? */
    if (res == TEE_ERROR_TARGET_DEAD) {
        utee_send_panic_reply(&channel);
        return res;
    } else if (res != TEE_ERROR_COMMUNICATION) {
        long sys_res = NO_ERROR;
        /* Send result to client */
        utee_set_return_param_buffer(msg_buffer, param_types, params, ret_orig, res, ep_id);
        sys_res = utee_send_return_params(&channel, msg_buffer);

        /* Unable to send parameters back to client */
        if (sys_res < 0 && res == TEE_SUCCESS)
            return TEE_ERROR_COMMUNICATION;
    }
    return res;
}

static TEE_Result entry_create_once(void)
{
    static bool once = false;

    if (once)
        return TEE_SUCCESS;

    once = true;

    TEE_DBG_MSG("\n");
    return call_ta_create_entry_point();
}

static void entry_destroy(handle_t channel, msg_map_t *msg_buffer)
{
    TEE_DBG_MSG("\n");
    TEE_Result res = TEE_SUCCESS;
    uint32_t session_id = channel;
    uint32_t ret_orig = TEE_ORIGIN_TEE;

    preprocess_entry(session_id, TEE_DESTROY_ID, msg_buffer,
                     NULL, NULL, NULL);

    if (!ta_context->panicked){
        res = call_ta_close_session_entry_point(ta_context->active_sess.session_ctx);
        if (ta_context->panicked) {
            res = TEE_ERROR_TARGET_DEAD;
            goto destroy_end;
        }

    }

    /* Preserve single-instance keep-alive TA instance context when there are
     * no sessions connected.  For multi-instance TA or for a single-instance
     * non keep-alive TA, if the session closed was the last session on the
     * instance then exit
     */
    if (!(ta_context->ta_flags & TA_FLAGS_SINGLE_INSTANCE) ||
            !(ta_context->ta_flags & TA_FLAGS_KEEP_ALIVE)) {
        if (!ta_context->panicked) {
            res = call_ta_destroy_entry_point();
            res = postprocess_entry(0, NULL, res, &ret_orig, TEE_DESTROY_ID);
        }

        /* Mark TA as dead to prevent accepting new connections */
        ta_dead();
    }

destroy_end:
    finish_entry(channel, msg_buffer, 0, NULL, ret_orig, TEE_SUCCESS, TEE_DESTROY_ID);
    close(session_id);
    ta_context->active_sess.sess_channel = (uint32_t)TEE_HANDLE_NULL;
}

static void entry_open_session(handle_t channel, msg_map_t *msg_buffer)
{
    TEE_Result res = TEE_ERROR_COMMUNICATION;
    uint32_t param_types = 0;
    TEE_Param params[4];
    uint32_t ret_orig = TEE_ORIGIN_TEE;

    if (ta_context->panicked) {
        /* ret_orig = TEE_ORIGIN_TEE; */
        res = TEE_ERROR_TARGET_DEAD;
        goto open_sess_end;
    }

    /* Create session context */
    res = preprocess_entry((uint32_t)channel, TEE_OPEN_SESSION_ID, msg_buffer,
                           &param_types, params, NULL);
    if (res)
        goto open_sess_end;

    res = call_ta_open_session_entry_point(param_types, params,
                                           &ta_context->active_sess.session_ctx);

    res = postprocess_entry(param_types, params, res, &ret_orig, TEE_OPEN_SESSION_ID);

open_sess_end:
    msg_buffer->session_ctx = (uintptr_t)ta_context->active_sess.session_ctx;
    res = finish_entry(channel, msg_buffer, param_types, params, ret_orig, res, TEE_OPEN_SESSION_ID);

    if (res != TEE_SUCCESS)
        close(channel);
}

static void entry_close_session(handle_t channel, msg_map_t *msg_buffer)
{
    TEE_Result res = TEE_SUCCESS;
    uint32_t session_id = channel;
    uint32_t ret_orig = TEE_ORIGIN_TEE;

    preprocess_entry(session_id, TEE_CLOSE_SESSION_ID, msg_buffer,
                     NULL, NULL, NULL);

    if (!ta_context->panicked)
        res = call_ta_close_session_entry_point(ta_context->active_sess.session_ctx);

    res = postprocess_entry(0, NULL, res, &ret_orig, TEE_CLOSE_SESSION_ID);

    finish_entry(channel, msg_buffer, 0, NULL, ret_orig, TEE_SUCCESS, TEE_CLOSE_SESSION_ID);
    close(session_id);
    ta_context->active_sess.sess_channel = (uint32_t)TEE_HANDLE_NULL;
}

static void entry_invoke_command(handle_t channel, msg_map_t *msg_buffer)
{
    TEE_Result res;
    uint32_t session_id = channel;
    uint32_t param_types;
    TEE_Param params[4];
    uint32_t cmd_id;
    uint32_t ret_orig = TEE_ORIGIN_TEE;

    if (ta_context->panicked) {
        res = TEE_ERROR_TARGET_DEAD;
        goto invoke_cmd_end;
    }
    res = preprocess_entry(session_id, TEE_INVOKE_COMMAND_ID, msg_buffer,
                           &param_types, params, &cmd_id);
    if (res)
        goto invoke_cmd_end;

    res = call_ta_invoke_command_entry_point(ta_context->active_sess.session_ctx,
                                             cmd_id, param_types, params);

    res = postprocess_entry(param_types, params, res, &ret_orig, TEE_INVOKE_COMMAND_ID);

invoke_cmd_end:
    res = finish_entry(channel, msg_buffer, param_types, params, ret_orig, res, TEE_INVOKE_COMMAND_ID);

    /* If there is an error on communication channel close the session. */
    if (res == TEE_ERROR_COMMUNICATION)
        entry_close_session(session_id, msg_buffer);
}

static void utee_send_panic_reply(handle_t *handle)
{
    int32_t sys_res;
    uint32_t ret_orig = TEE_ORIGIN_TEE;
    TEE_Result res = TEE_ERROR_TARGET_DEAD;

    utee_set_return_param_buffer(&ta_panic_msg_buffer, 0, NULL, ret_orig, res,
                                 ta_context->active_sess.ep_id);
    sys_res = utee_send_return_params(handle, &ta_panic_msg_buffer);

    /* Unable to send parameters back to client */
    if (sys_res < 0) {
        TEE_DBG_MSG("Error: Failed to send panic reply on handle %x\n", *handle);
    }
}

static void set_panic(TEE_Result panic_code)
{
    ta_context->panicked = 1;
    ta_context->panic_code = panic_code;
    ta_dead();
}

/* TODO How to do generic cleanup (and still meet spec requirements) after a
 * panic is caught outside of the entrypoint functions?
 */
static __NO_RETURN void default_panic_handler_fn(void *args)
{
    TEE_DBG_MSG("--- Panic default handler called... ---\n");

    set_panic(TEE_ERROR_TARGET_DEAD);

    /* TODO cancel any pending operations started FROM this TA. */

    if (ta_context->active_sess.sess_channel)
        close(TEE_UNMASK_HANDLE_ID(ta_context->active_sess.sess_channel));

    close(ta_port);

    TEE_DBG_MSG("--- Panic default handler exiting thread!!! ---\n");
    exit(0);
}

static __NO_RETURN void panic_longjmp_fn(void *args)
{
    TEE_DBG_MSG("--- Panic longjmp called... ---\n");

    set_panic(TEE_ERROR_TARGET_DEAD);

    if (ta_context->setjmp_env_p)
        longjmp(*ta_context->setjmp_env_p, 1);
    else
        default_panic_handler_fn(NULL);
}

/*
 * Register a panic callback with the kernel
 */
void ta_set_default_panic_handler(void)
{
    ta_context->setjmp_env_p = NULL;
    set_panic_handler(&default_panic_handler_fn, NULL);
}

void ta_set_entrypoint_panic_handler(void)
{
    set_panic_handler(&panic_longjmp_fn, NULL);
    ta_context->setjmp_env_p = &ta_context->setjmp_env;
}

__NO_RETURN void ta_entrypoint_panic_return(void)
{
    panic_longjmp_fn(NULL);
}

int main(void)
{
    TEE_Result create_res;
    long sys_res;
    uevent_t ev;
    msg_map_t _operation_msg;
    msg_map_t *operation_msg = &_operation_msg;
    handle_t channel;

    ta_set_default_panic_handler();

    create_res = init_ta_context();
    if (create_res != TEE_SUCCESS)
        goto instance_exit;

    /* TODO move this within ta_next_msg and loop and send result to SM */
    /* Temporary workaround, since tee_unittest needs to call
     * TA_CreateEntryPoint before the main loop
     */
    create_res = entry_create_once();
    TEE_DBG_MSG("create_once: %x\n", create_res);

    while (1) {

        uuid_t peer_uuid;
        int operation = -1;

        ev.handle = INVALID_IPC_HANDLE;
        ev.event = 0;
        ev.cookie = NULL;
        sys_res = ta_next_msg(&ev, &peer_uuid);
        TEE_DBG_MSG("ta_next_msg ev.handle %d ev.event %x sys_res %ld\n",
                ev.handle, ev.event, sys_res);

        if (sys_res < 0)
            TEE_Panic(0xbad00000 | __LINE__);

        ta_port = (handle_t)sys_res;
        channel = (handle_t)ev.handle;

        /* Create entry point returned error */
        if (create_res != TEE_SUCCESS) {
            memset(operation_msg, 0, sizeof(*operation_msg));
            operation_msg->operation_id = TEE_RETVAL_ID;
            operation_msg->return_origin = TEE_ORIGIN_TRUSTED_APP;
            operation_msg->return_code = create_res;
            operation_msg->command_id = TEE_OPEN_SESSION_ID;

            sys_res = utee_send_return_params(&channel, operation_msg);
            goto instance_exit;
        }

        if (ev.event & IPC_HANDLE_POLL_MSG) {

            sys_res = utee_get_msg(&channel, operation_msg);
            if (sys_res < 0)
                TEE_Panic(0xbad00000 | __LINE__);

        } else if (ev.event & IPC_HANDLE_POLL_HUP) {

            /* TODO need to come back and test this error case some more.
             * Might be triggered if client panics
             */
            memset(operation_msg, 0, sizeof(*operation_msg));
            TEE_DBG_MSG("Error unexpected HUP event on handle %d\n", ev.handle);
            operation = TEE_CLOSE_SESSION_ID;

        } else {

            TEE_DBG_MSG("Error unexpected %x event on handle %d\n", ev.event, ev.handle);
            TEE_Panic(0xbad00000 | __LINE__);

        }

        if (operation == -1)
            operation = operation_msg->operation_id;

        ta_context->active_sess.parent_sess_id = get_msg_buffer_parent_id(operation_msg);

        switch (operation) {
            case TEE_OPEN_SESSION_ID:
                entry_open_session(channel, operation_msg);
                break;
            case TEE_INVOKE_COMMAND_ID:
                entry_invoke_command(channel, operation_msg);
                break;
            case TEE_CLOSE_SESSION_ID:
                entry_close_session(channel, operation_msg);
                break;
            case TEE_DESTROY_ID:
                entry_destroy(channel, operation_msg);
                goto instance_exit;
            default:
                TEE_DBG_MSG("Error unexpected operation %d on handle %d\n",
                        operation, ev.handle);
                TEE_Panic(0xbad00000 | __LINE__);
                break;
        }
    } // while (1)

instance_exit:
    close(ta_port);

    return 0;
}
