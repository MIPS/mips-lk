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

#include <string.h>
#include <stdlib.h>
#include <tee_client_api.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>
#include <bits.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "CTEE"

static void convert_teec_params_to_utee_params(TEEC_Operation *operation,
                                               utee_params_t *utee_params)
{
    uint32_t tee_paramtype[4];
    uint32_t flags;
    int i;
    TEEC_Parameter *teec_params = operation->params;

    for (i = 0; i < 4; i++) {
        uint32_t teec_paramtype = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);

        switch (teec_paramtype) {
        case TEEC_NONE:
            utee_params->params[2 * i] = 0;
            utee_params->params[2 * i + 1] = 0;
            tee_paramtype[i] = teec_paramtype;
            break;
        case TEEC_VALUE_INPUT:
        case TEEC_VALUE_OUTPUT:
        case TEEC_VALUE_INOUT:
            utee_params->params[2 * i] = teec_params[i].value.a;
            utee_params->params[2 * i + 1] = teec_params[i].value.b;
            tee_paramtype[i] = teec_paramtype;
            break;
        case TEEC_MEMREF_TEMP_INPUT:
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
            utee_params->params[2 * i] =
                (uintptr_t)teec_params[i].tmpref.buffer;
            utee_params->params[2 * i + 1] = teec_params[i].tmpref.size;
            tee_paramtype[i] = teec_paramtype;
            break;
        case TEEC_MEMREF_WHOLE:
            flags = operation->params[i].memref.parent->flags & (TEEC_MEM_INPUT
                            | TEEC_MEM_OUTPUT);

            if (flags == TEEC_MEM_INPUT)
                tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_INPUT;
            else if (flags == TEEC_MEM_OUTPUT)
                tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_OUTPUT;
            else
                tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_INOUT;
            utee_params->params[2 * i] =
                (uintptr_t)teec_params[i].memref.parent->buffer;
            utee_params->params[2 * i + 1] = teec_params[i].memref.parent->size;
            break;
        case TEEC_MEMREF_PARTIAL_INPUT:
            tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_INPUT;
            utee_params->params[2 * i] = (uintptr_t)((uint8_t *)
                                          (teec_params[i].memref.parent->buffer)
                                         + teec_params[i].memref.offset);
            utee_params->params[2 * i + 1] = teec_params[i].memref.size;
            break;
        case TEEC_MEMREF_PARTIAL_OUTPUT:
            tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_OUTPUT;
            utee_params->params[2 * i] = (uintptr_t)((uint8_t *)
                                          (teec_params[i].memref.parent->buffer)
                                         + teec_params[i].memref.offset);
            utee_params->params[2 * i + 1] = teec_params[i].memref.size;
            break;
        case TEEC_MEMREF_PARTIAL_INOUT:
            tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_INOUT;
            utee_params->params[2 * i] = (uintptr_t)((uint8_t *)
                                          (teec_params[i].memref.parent->buffer)
                                         + teec_params[i].memref.offset);
            utee_params->params[2 * i + 1] = teec_params[i].memref.size;
            break;
        default:
            break;
        }
    }

    utee_params->param_types = TEE_PARAM_TYPES(tee_paramtype[0],
                                               tee_paramtype[1],
                                               tee_paramtype[2],
                                               tee_paramtype[3]);
}

static void teec_pre_process_operation(TEEC_Operation *operation,
                                       utee_params_t *utee_params)
{
    convert_teec_params_to_utee_params(operation, utee_params);
}

static void copy_output_params_to_teecparams(TEEC_Operation *operation,
                                             utee_params_t *utee_params)
{
    TEEC_Parameter *teec_params = operation->params;
    uint32_t param_types = operation->paramTypes;
    int i;

    for (i = 0; i < 4; i++) {
        switch (TEE_PARAM_TYPE_GET(param_types, i)) {
        case TEEC_VALUE_OUTPUT:
        case TEEC_VALUE_INOUT:
            teec_params[i].value.a = (uint32_t)utee_params->params[2 * i];
            teec_params[i].value.b = (uint32_t)utee_params->params[2 * i + 1];
            break;
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
            teec_params[i].tmpref.size =
                (uint32_t)utee_params->params[2 * i + 1];
            break;
        case TEEC_MEMREF_WHOLE:
        case TEEC_MEMREF_PARTIAL_OUTPUT:
        case TEEC_MEMREF_PARTIAL_INOUT:
            teec_params[i].memref.size =
                (uint32_t)utee_params->params[2 * i + 1];
            break;
        default:
            break;
        }
    }
}

static void teec_post_process_operation(TEEC_Operation *operation,
                                        utee_params_t *utee_params)
{
    copy_output_params_to_teecparams(operation, utee_params);
}

/*
 * Internal function for handling an open session request.
 * This function is based on TEE_OpenTASession Internal Client function.
 */
static TEEC_Result teec_open_ta_session(const TEE_UUID *destination,
                                       uint32_t cancellationRequestTimeout,
                                       TEEC_Operation *operation,
                                       TEE_TASessionHandle *session,
                                       uint32_t *returnOrigin)
{
    TEEC_Result res = TEE_ERROR_GENERIC;
    utee_params_t utee_params;
    uint32_t ret_orig = TEE_ORIGIN_TEE;
    uint32_t uint_args[4];
    TEEC_Session *teec_session = (TEEC_Session *)session;

    if (session)
        *session = TEE_HANDLE_NULL;

    if (operation == NULL || session == NULL || destination == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto open_ta_session_end;
    }

    if (operation->paramTypes && operation->params == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto open_ta_session_end;
    }

    teec_pre_process_operation(operation, &utee_params);

    res = connect_to_sm((uint32_t *)&teec_session->sm_channel);
    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("TEEC_OpenSession failed to connect. Return code %x orig %x\n",
                    res, ret_orig);
        goto open_ta_session_end;
    }

    /* Copy uint arguments to array */
    uint_args[0] = cancellationRequestTimeout;
    uint_args[1] = (uint32_t)destination;
    uint_args[2] = (uint32_t)TEEC_CMD_OPEN_SESSION;
    uint_args[3] = 0;

    /* invoke_operation will cleanup session handle when res != TEE_SUCCESS */
    res = invoke_operation((void *)teec_session, &utee_params, &ret_orig,
                           uint_args);

    if (ret_orig == TEE_ORIGIN_TRUSTED_APP)
        teec_post_process_operation(operation, &utee_params);

open_ta_session_end:
    if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        if (res == TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            TEE_DBG_MSG("Erroneous TEE_SUCCESS code changed to %x orig %x\n",
                        res, ret_orig);
        }
    }

    if (res != TEE_SUCCESS) {
        TEE_DBG_MSG("TEEC_OpenSession failed return code %x orig %x\n",
                    res, ret_orig);
        if (session)
            *session = TEE_HANDLE_NULL;
    }

    if (returnOrigin != NULL)
        *returnOrigin = ret_orig;

    return res;
}

/*
 * Internal function for handling a close session request.
 * This function is based on TEE_CloseTASession Internal Client function.
 */
static void teec_close_ta_session(TEE_TASessionHandle *session)
{
    TEEC_Result res;
    TEEC_Session *teec_session = (TEEC_Session *)session;

    /* Move everything to syscall */
    if (session == TEE_HANDLE_NULL)
        return;

    res = close_session((void *)teec_session);
    if (res != TEE_SUCCESS)
        TEE_DBG_MSG("ERROR: TEEC_CloseSession failed\n");
    TEE_DBG_MSG("TEEC_CloseSession client side closed\n");

}

/*
 * Internal function for handling an invoke command request.
 * This function is based on TEE_InvokeTACommand Internal Client function.
 */
static TEEC_Result teec_invoke_ta_command(TEE_TASessionHandle *session,
                                  uint32_t cancellationRequestTimeout,
                                  uint32_t commandID, TEEC_Operation *operation,
                                  uint32_t *returnOrigin)
{
    TEEC_Result res = TEE_ERROR_GENERIC;
    utee_params_t utee_params;
    uint32_t ret_orig = TEE_ORIGIN_TEE;
    uint32_t uint_args[4];
    TEEC_Session *teec_session = (TEEC_Session *)session;

    if (operation == NULL || session == TEE_HANDLE_NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto invoke_ta_command_end;
    }

    if (operation->paramTypes && operation->params == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto invoke_ta_command_end;
    }

    teec_pre_process_operation(operation, &utee_params);

    /* Copy uint arguments to array */
    uint_args[0] = cancellationRequestTimeout;
    uint_args[1] = commandID;
    uint_args[2] = (uint32_t)TEEC_CMD_INVOKE;
    uint_args[3] = 0;

    res = invoke_operation((void *)teec_session, &utee_params, &ret_orig,
                           uint_args);
    if (ret_orig == TEE_ORIGIN_TRUSTED_APP)
        teec_post_process_operation(operation, &utee_params);

invoke_ta_command_end:
    if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        if (res == TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            TEE_DBG_MSG("Erroneous TEE_SUCCESS code changed to %x orig %x\n",
                    res, ret_orig);
        }
    }

    if (returnOrigin != NULL)
        *returnOrigin = ret_orig;

    return res;
}

static uint32_t cancel_timeout = 5000;

TEEC_Result TEEC_OpenSession(TEEC_Context *context,
                             TEEC_Session *session,
                             const TEEC_UUID *destination,
                             uint32_t connectionMethod,
                             const void *connectionData,
                             TEEC_Operation *operation,
                             uint32_t *returnOrigin)
{
    TEEC_Result res;
    TEEC_Operation dummy_op;

    TEE_TASessionHandle *session_handle = (TEE_TASessionHandle *)session;
    *returnOrigin = TEE_ORIGIN_TEE;

    switch (connectionMethod) {
    case TEEC_LOGIN_PUBLIC:
    case TEEC_LOGIN_USER:
    case TEEC_LOGIN_APPLICATION:
    case TEEC_LOGIN_USER_APPLICATION:
        if (connectionData != NULL)
            return TEE_ERROR_GENERIC;
        break;
    case TEEC_LOGIN_GROUP:
    case TEEC_LOGIN_GROUP_APPLICATION:
        if (connectionData == NULL)
            return TEE_ERROR_GENERIC;
        break;
    default:
        return TEE_ERROR_GENERIC;
    }

    if (operation == NULL) {
        memset(&dummy_op, 0, sizeof(TEEC_Operation));
        operation = &dummy_op;
    }
    res = teec_open_ta_session(destination, cancel_timeout, operation,
                session_handle, returnOrigin);
    if (res == TEEC_SUCCESS)
        session->ctx = context;

    return res;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
                   uint32_t commandID,
                   TEEC_Operation *operation,
                   uint32_t *returnOrigin)
{
    TEEC_Result res;
    TEEC_Operation dummy_op;
    TEE_TASessionHandle *session_handle = (TEE_TASessionHandle *)session;

    if (operation == NULL) {
        memset(&dummy_op, 0, sizeof(TEEC_Operation));
        operation = &dummy_op;
    }
    res = teec_invoke_ta_command(session_handle, cancel_timeout, commandID,
        operation, returnOrigin);
    return res;
}

void TEEC_CloseSession(TEEC_Session *session)
{
    if (!session)
        return;

    TEE_TASessionHandle *session_handle = (TEE_TASessionHandle *)session;

    teec_close_ta_session(session_handle);
}


TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
                                      TEEC_SharedMemory *sharedMem)
{
    if (!context || !sharedMem)
        return TEEC_ERROR_BAD_PARAMETERS;

#ifndef WITH_REE
    sharedMem->buffer = malloc(sharedMem->size);
    if (!sharedMem->buffer)
        return TEEC_ERROR_OUT_OF_MEMORY;

    sharedMem->registered = 0;
    return TEEC_SUCCESS;
#else
#warning WITH_REE shared memory not implemented
    return TEEC_ERROR_NOT_IMPLEMENTED;
#endif
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
                                      TEEC_SharedMemory *sharedMem)
{
    if (!context || !sharedMem)
        return TEEC_ERROR_BAD_PARAMETERS;

    sharedMem->registered = 1;
    return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem)
{
    if (!sharedMem || sharedMem->registered)
        return;

#ifndef WITH_REE
    free(sharedMem->buffer);
#endif

    sharedMem->buffer = NULL;
    sharedMem->size = 0;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
    /* Not implemented */
    return;
}

/* Wrappers for REE Client API functions */
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context)
{
    return TEEC_SUCCESS;
}

void TEEC_FinalizeContext(TEEC_Context *context)
{
    return;
}

