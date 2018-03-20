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
#include <err.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "UTEE"

static void params_to_utee_params(utee_params_t *utee_params,
                                  uint32_t param_types, TEE_Param *params)
{
    int i;

    utee_params->param_types = param_types;

    for (i = 0; i < 4; i++) {
        switch (TEE_PARAM_TYPE_GET(param_types, i)) {
        case TEE_PARAM_TYPE_VALUE_INPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            utee_params->params[2 * i] = params[i].value.a;
            utee_params->params[2 * i + 1] = params[i].value.b;
            break;
        case TEE_PARAM_TYPE_MEMREF_INPUT:
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            utee_params->params[2 * i] = (uintptr_t)params[i].memref.buffer;
            /* GP API spec: The buffer can be NULL,
             * in which case size MUST be set to 0.
             */
            if (params[i].memref.buffer == NULL)
                utee_params->params[2 * i + 1] = 0;
            else
                utee_params->params[2 * i + 1] =
                    (uintptr_t)params[i].memref.size;
            break;
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_NONE:
        default:
            break;
        }
    }
}

static void utee_params_to_params(utee_params_t *utee_params,
                                  uint32_t *param_types, TEE_Param *params)
{
    int i;

    *param_types = utee_params->param_types;

    for (i = 0; i < 4; i++) {
        switch (TEE_PARAM_TYPE_GET(*param_types, i)) {
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
        case TEE_PARAM_TYPE_VALUE_INOUT:
            params[i].value.a = (uint32_t)utee_params->params[2 * i];
            params[i].value.b = (uint32_t)utee_params->params[2 * i + 1];
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
        case TEE_PARAM_TYPE_MEMREF_INOUT:
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
    uint32_t uint_args[4];
    teec_session_t *teec_session = (teec_session_t *)session;

    ret_orig = TEE_ORIGIN_TEE;

    if (session)
        *session = TEE_HANDLE_NULL;

    if (paramTypes && params == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto open_ta_session_end;
    }

    if (session == NULL || destination == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto open_ta_session_end;
    }

    teec_session = (teec_session_t *)calloc(1, sizeof(teec_session_t));
    if (teec_session == NULL) {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto open_ta_session_end;
    }

    res = connect_to_sm((uint32_t *)&teec_session->sm_channel);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("TEE_OpenTASession failed to connect. Return code %x orig %x\n",
                    res, ret_orig);
        goto open_ta_session_end;
    }

    params_to_utee_params(&utee_params, paramTypes, params);

    /* Copy uint arguments to array */
    uint_args[0] = cancellationRequestTimeout;
    uint_args[1] = (uint32_t)destination;
    uint_args[2] = (uint32_t)TEEC_CMD_OPEN_SESSION;
    uint_args[3] = 0;

    res = invoke_operation((void *)teec_session, &utee_params, &ret_orig,
                           uint_args);

    if (ret_orig == TEE_ORIGIN_TRUSTED_APP)
        utee_params_to_params(&utee_params, &paramTypes, params);

open_ta_session_end:
    if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        if (res == TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            TEE_DBG_MSG("Erroneous TEE_SUCCESS code changed to %x orig %x\n",
                        res, ret_orig);
        }
        if (res != TEE_ERROR_ITEM_NOT_FOUND &&
            res != TEE_ERROR_ACCESS_DENIED  &&
            res != TEE_ERROR_OUT_OF_MEMORY  &&
            res != TEE_ERROR_TARGET_DEAD    &&
            res != TEE_ERROR_BUSY) {
            TEE_DBG_MSG("TEE_OpenTASession panic: return code %x orig %x\n",
                        res, ret_orig);
            TEE_Panic(res);
        }
    }

    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("TEE_OpenTASession failed return code %x orig %x\n",
                    res, ret_orig);
        if (teec_session)
            free(teec_session);
        if (session)
            *session = TEE_HANDLE_NULL;
    } else
        *session = (TEE_TASessionHandle)teec_session;

    if (returnOrigin != NULL)
        *returnOrigin = ret_orig;

    return res;
}

void TEE_CloseTASession(TEE_TASessionHandle session)
{
    TEE_Result res;
    teec_session_t *teec_session = (teec_session_t *)session;

    /* Move everything to syscall */
    if (session == TEE_HANDLE_NULL)
        return;

    res = close_session((void *)teec_session);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("ERROR: failed session closing\n");
        TEE_Panic(res);
    }
    free(teec_session);
    session = TEE_HANDLE_NULL;
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
    uint32_t uint_args[4];
    teec_session_t *teec_session = (teec_session_t *)session;

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
    uint_args[2] = (uint32_t)TEEC_CMD_INVOKE;
    uint_args[3] = 0;

    res = invoke_operation((void *)teec_session, &utee_params, &ret_orig,
                           uint_args);

    if (ret_orig == TEE_ORIGIN_TRUSTED_APP)
        utee_params_to_params(&utee_params, &paramTypes, params);

invoke_ta_command_end:
    if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        if (res == TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            TEE_DBG_MSG("Erroneous TEE_SUCCESS code changed to %x orig %x\n",
                    res, ret_orig);
        }
        if (res != TEE_ERROR_OUT_OF_MEMORY &&
            res != TEE_ERROR_TARGET_DEAD)
            TEE_Panic(res);
    }

    if (returnOrigin != NULL)
        *returnOrigin = ret_orig;

    return res;
}
