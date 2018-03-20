/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <assert.h>
#include <tee_ta_interface.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <tee_arith_internal.h>
#include <trusty_std.h>
#include <err.h>

#define MAX_PORT_NAME_LENGTH    64

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "UTEE"

static bool ta_create_done = false;
static struct ta_ctx __ta_context;
struct ta_ctx *ta_context = &__ta_context;
static msg_map_t _ep_msg;

#define TIME_MULTIPLICATOR  1000000

void tee_get_ta_client_id(TEE_Identity *client_id)
{
    memcpy(client_id, &ta_context->active_sess.client_id,
            sizeof(TEE_Identity));
}

TEE_Result get_rng_array(void *buf, size_t blen)
{
    return utee_cryp_random_number_generate(buf, blen);
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
        switch (TEE_PARAM_TYPE_GET(*param_types, i)) {
        case TEE_PARAM_TYPE_NONE:
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
            params[i].value.a = 0;
            params[i].value.b = 0;
            break;
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            params[i].value.a = (uint32_t)(tmp_ptr[2 * i]);
            params[i].value.b = (uint32_t)(tmp_ptr[2 * i + 1]);
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
        case TEE_PARAM_TYPE_MEMREF_INPUT:
            params[i].memref.buffer = (void *)((uintptr_t)(tmp_ptr[2 * i]));
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
    if (!param_types)
        return;

    for (i = 0; i < 4; i++) {
        switch (TEE_PARAM_TYPE_GET(param_types, i)) {
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

static void tee_uuid_from_octets(TEE_UUID *uuid, uint8_t oct[TEE_UUID_LEN])
{
    uuid->timeLow = ((uint32_t)oct[0] << 24) | ((uint32_t)oct[1] << 16) |
                    ((uint32_t)oct[2] << 8) | oct[3];
    uuid->timeMid = ((uint16_t)oct[4] << 8) | oct[5];
    uuid->timeHiAndVersion = ((uint16_t)oct[6] << 8) | oct[7];
    memcpy(uuid->clockSeqAndNode, oct + 8, sizeof(uuid->clockSeqAndNode));
}

static TEE_Result preprocess_entry(uint32_t ep_id, msg_map_t *msg_buffer,
                                   uint32_t *param_types, TEE_Param params[4],
                                   uint32_t *cmd_id)
{
    TEE_Result res;

    ta_context->active_sess.client_id.login = msg_buffer->client_id_login;
    tee_uuid_from_octets(&ta_context->active_sess.client_id.uuid,
                         msg_buffer->client_id_uuid);
    ta_context->active_sess.session_ctx = (void *)msg_buffer->session_ctx;

    if (ep_id == TEE_INVOKE_COMMAND_ID)
        *cmd_id = msg_buffer->func;

    if (ep_id == TEE_OPEN_SESSION_ID || ep_id == TEE_INVOKE_COMMAND_ID) {
        res = get_tee_params_from_msg_buffer(msg_buffer, param_types, params);
        if (res)
            return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ta_context->panicked)
        return TEE_ERROR_TARGET_DEAD;

    return TEE_SUCCESS;
}

static void postprocess_entry(uint32_t ep_id, msg_map_t *msg_buffer,
                              uint32_t param_types, TEE_Param params[4],
                              TEE_Result ret_code)
{
    uint32_t ret_orig;

    if (ta_context->panicked) {
        ret_code = TEE_ERROR_TARGET_DEAD;
        ret_orig = TEE_ORIGIN_TEE;
    } else {
        /* GP API spec - origin should always be the TA after TA execution */
        ret_orig = TEE_ORIGIN_TRUSTED_APP;
    }

    set_return_tee_params_in_msg_buffer(msg_buffer, param_types, params);

    msg_buffer->cmd = ep_id;
    msg_buffer->ret_origin = ret_orig;
    msg_buffer->ret = ret_code;
}

static TEE_Result entry_create(void)
{
    TEE_Result res;

    if (ta_create_done)
        return TEE_SUCCESS;

    res = call_ta_create_entry_point();

    if (res != TEE_SUCCESS)
        ta_dead();
    else
        ta_create_done = true;

    return res;
}

static void entry_open_session(msg_map_t *msg_buffer)
{
    TEE_Result res;
    uint32_t param_types = 0;
    TEE_Param params[4];

    res = preprocess_entry(TEE_OPEN_SESSION_ID, msg_buffer,
                           &param_types, params, NULL);
    if (res)
        goto open_sess_end;

    res = entry_create();
    if (res)
        goto open_sess_end;

    res = call_ta_open_session_entry_point(param_types, params,
                                         &ta_context->active_sess.session_ctx);
    msg_buffer->session_ctx = (uintptr_t)ta_context->active_sess.session_ctx;

open_sess_end:
    postprocess_entry(TEE_OPEN_SESSION_ID, msg_buffer,
                      param_types, params, res);

}

static void entry_invoke_command(msg_map_t *msg_buffer)
{
    TEE_Result res;
    uint32_t param_types = 0;
    TEE_Param params[4];
    uint32_t cmd_id;

    res = preprocess_entry(TEE_INVOKE_COMMAND_ID, msg_buffer,
                           &param_types, params, &cmd_id);
    if (res)
        goto invoke_cmd_end;

    res = call_ta_invoke_command_entry_point(ta_context->active_sess.session_ctx,
                                             cmd_id, param_types, params);

invoke_cmd_end:
    postprocess_entry(TEE_INVOKE_COMMAND_ID, msg_buffer,
                      param_types, params, res);
}

static void entry_close_session(msg_map_t *msg_buffer)
{
    TEE_Result res;

    res = preprocess_entry(TEE_CLOSE_SESSION_ID, msg_buffer, NULL,
                           NULL, NULL);
    if (res)
        goto close_sess_end;

    res = call_ta_close_session_entry_point(ta_context->active_sess.session_ctx);

close_sess_end:
    postprocess_entry(TEE_CLOSE_SESSION_ID, msg_buffer, 0, NULL, res);
}

static void entry_destroy(msg_map_t *msg_buffer)
{
    TEE_DBG_MSG("\n");
    TEE_Result res = TEE_SUCCESS;

    if (!ta_create_done)
        goto destroy_end;

    entry_close_session(msg_buffer);

    res = preprocess_entry(TEE_DESTROY_ID, msg_buffer, NULL, NULL,
                           NULL);
    if (res)
        goto destroy_end;

    res = call_ta_destroy_entry_point();

destroy_end:
    postprocess_entry(TEE_DESTROY_ID, msg_buffer, 0, NULL, res);
}

static void set_panic(TEE_Result panic_code)
{
    ta_context->panicked = 1;
    ta_context->panic_code = panic_code;
    ta_dead();
}

static void default_panic_handler_end_loop(msg_map_t *ep_msg)
{
    long sys_res;
    uint32_t ep_id;

    while (1) {
        sys_res = ta_next_msg(ep_msg);
        if (sys_res < NO_ERROR)
            return;
        ep_id = ep_msg->cmd;
        if (ep_id != TEE_DESTROY_ID)
            postprocess_entry(TEE_RETVAL_ID, ep_msg, 0, NULL,
                              TEE_ERROR_TARGET_DEAD);
        else
            postprocess_entry(TEE_DESTROY_ID, ep_msg, 0, NULL,
                              TEE_ERROR_TARGET_DEAD);
    }
}

static __NO_RETURN void default_panic_handler_fn(void *args)
{
    TEE_DBG_MSG("--- Panic default handler called... ---\n");

    set_panic(TEE_ERROR_TARGET_DEAD);

    TEE_DBG_MSG("--- Panic default handler exiting thread!!! ---\n");
    postprocess_entry(TEE_RETVAL_ID, &_ep_msg, 0, NULL, TEE_ERROR_TARGET_DEAD);
    default_panic_handler_end_loop(&_ep_msg);
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
    long sys_res;
    msg_map_t *ep_msg = &_ep_msg;

    ta_set_default_panic_handler();
    _TEE_MathAPI_Init();

    while (1) {

        uint32_t ep_id;

        sys_res = ta_next_msg(ep_msg);
        if (sys_res < NO_ERROR)
            goto instance_exit;

        ep_id = ep_msg->cmd;

        switch (ep_id) {
        case TEE_OPEN_SESSION_ID:
            entry_open_session(ep_msg);
            break;
        case TEE_INVOKE_COMMAND_ID:
            entry_invoke_command(ep_msg);
            break;
        case TEE_CLOSE_SESSION_ID:
            entry_close_session(ep_msg);
            break;
        case TEE_DESTROY_ID:
            entry_destroy(ep_msg);
            break;
        default:
            TEE_DBG_MSG("Error unexpected ep_id %d\n", ep_id);
            TEE_Panic(0xbad00000 | __LINE__);
            break;
        }
    }

instance_exit:

    return 0;
}
