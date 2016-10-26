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
#include <tee_ta_interface.h>
#include <trusty_std.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "UTEE"

static void params_to_utee_params(utee_params_t *utee_params, uint32_t param_types,
                           TEE_Param *params)
{
    int i;
    utee_params->param_types = param_types;

    for (i = 0; i < 4; i++) {
        switch(TEE_PARAM_TYPE_GET(param_types, i)) {
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            utee_params->params[2 * i] = params[i].value.a;
            utee_params->params[2 * i + 1] = params[i].value.b;
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            utee_params->params[2 * i] = (uintptr_t)params[i].memref.buffer;
            /* GP API spec: The buffer can be NULL, in which case size MUST be set to 0. */
            if (params[i].memref.buffer == NULL)
                utee_params->params[2 * i + 1] = 0;
            else
                utee_params->params[2 * i + 1] = (uintptr_t)params[i].memref.size;
            break;
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_NONE:
        default:
            break;
        }
    }
}

static void utee_params_to_params(utee_params_t *utee_params, uint32_t *param_types,
                           TEE_Param *params)
{
    int i;
    *param_types = utee_params->param_types;

    for (i = 0; i < 4; i++) {
        switch(TEE_PARAM_TYPE_GET(*param_types, i)) {
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            params[i].value.a = (uint32_t)utee_params->params[2 * i];
            params[i].value.b = (uint32_t)utee_params->params[2 * i + 1];
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            params[i].memref.buffer = (void*)(uintptr_t)utee_params->params[2 * i];
            params[i].memref.size = (uint32_t)utee_params->params[2 * i + 1];
            break;
        case TEE_PARAM_TYPE_NONE:
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        default:
            break;
        }
    }
}

/*
 * The function TEE_OpenTASession opens a new session with
 * a Trusted Application.
 *
 * The destination Trusted Application is identified by its UUID passed in
 * destination. This UUID can be hardcoded in the caller code.
 * An initial set of four parameters can be passed during the operation.
 * The result of this function is returned both in the return code and the
 * return origin, stored in the variable pointed to by returnOrigin.
 * When the session is successfully opened, i.e. when the function returns
 * TEE_SUCCESS, a valid session handle is written into *session.
 * Otherwise, the value TEE_HANDLE_NULL is written into *session.
 *
 * Return values (returnOrigin different from TEE_ORIGIN_TRUSTED_APP):
 * 1) TEE_ERROR_OUT_OF_MEMORY : If not enough resources are available
 *                              to open the session
 * 2) TEE_ERROR_ITEM_NOT_FOUND : If no Trusted Application matches the
 *                               requested destination UUID
 * 3) TEE_ERROR_ACCESS_DENIED : If access to the destination Trusted Application
 *                              is denied
 * 4) TEE_ERROR_BUSY : If the destination Trusted Application does not allow
 *                     more than one session at a time and already has a session
 *                     in progress
 * 5) TEE_ERROR_TARGET_DEAD : If the destination Trusted Application has
 *                            panicked during the operation
 */
TEE_Result TEE_OpenTASession(const TEE_UUID *destination,
                             uint32_t cancellationRequestTimeout,
                             uint32_t paramTypes,
                             TEE_Param params[4],
                             TEE_TASessionHandle *session,
                             uint32_t *returnOrigin)
{
    TEE_Result res = TEE_ERROR_GENERIC;
    utee_params_t utee_params;
    uint32_t ret_orig;
    uint32_t uint_args[2];

    ret_orig = TEE_ORIGIN_TEE;

    if (paramTypes && params == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto open_ta_session_end;
    }

    if (session == NULL || destination == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto open_ta_session_end;
    }

    params_to_utee_params(&utee_params, paramTypes, params);

    /* Copy uint arguments to array */
    uint_args[0] = cancellationRequestTimeout;
    uint_args[1] = (uint32_t)destination;
    res = open_session((uint32_t*)session, &utee_params, &ret_orig, uint_args);

    if (ret_orig == TEE_ORIGIN_TRUSTED_APP)
        utee_params_to_params(&utee_params, &paramTypes, params);

    if (res != TEE_SUCCESS || ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        *session = TEE_HANDLE_NULL;
        TEE_DBG_MSG("TEE_OpenTASession failed return code %x orig %x\n", res, ret_orig);
        goto open_ta_session_end;
    }

open_ta_session_end:
    if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        if (res != TEE_ERROR_ITEM_NOT_FOUND &&
            res != TEE_ERROR_ACCESS_DENIED  &&
            res != TEE_ERROR_OUT_OF_MEMORY  &&
            res != TEE_ERROR_TARGET_DEAD    &&
            res != TEE_ERROR_BUSY)
        {
            TEE_DBG_MSG("TEE_OpenTASession panic: return code %x orig %x\n", res, ret_orig);
            TEE_Panic(res);
        }
    }

    if (returnOrigin != NULL)
        *returnOrigin = ret_orig;
    return res;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
    int32_t tr_res;

    /* Move everything to syscall */
    if (session == TEE_HANDLE_NULL)
        return;

    tr_res = close_session((uint32_t)session);
    if (tr_res < 0) {
        TEE_DBG_MSG("ERROR: failed session closing\n");
        TEE_Panic(err_to_tee_err(tr_res));
    }
    TEE_DBG_MSG("TEE_CloseTASession client side closed\n");

}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle session,
                               uint32_t cancellationRequestTimeout,
                               uint32_t commandID, uint32_t paramTypes,
                               TEE_Param params[4], uint32_t *returnOrigin)
{
    TEE_Result res = TEE_ERROR_GENERIC;
    utee_params_t utee_params;
    uint32_t ret_orig;
    uint32_t uint_args[2];

    ret_orig = TEE_ORIGIN_TEE;

    if (paramTypes && params == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto invoke_ta_command_end;
    }

    if (session == TEE_HANDLE_NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto invoke_ta_command_end;
    }

    params_to_utee_params(&utee_params, paramTypes, params);

    /* Copy args */
    uint_args[0] = cancellationRequestTimeout;
    uint_args[1] = commandID;
    res = invoke_command((uint32_t)session, &utee_params, &ret_orig, uint_args);

    if (ret_orig == TEE_ORIGIN_TRUSTED_APP)
        utee_params_to_params(&utee_params, &paramTypes, params);

invoke_ta_command_end:
    if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        if (res != TEE_ERROR_OUT_OF_MEMORY &&
            res != TEE_ERROR_TARGET_DEAD)
            TEE_Panic(res);
    }

    if (returnOrigin != NULL)
        *returnOrigin = ret_orig;

    return res;
}
