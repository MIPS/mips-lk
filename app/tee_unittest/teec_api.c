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
#include <teec_api.h>
#include <stdio.h>
#include <stdlib.h>
#include <mm.h>

static uint32_t cancel_timeout = 5000;

static void copy_teecparams_to_params(TEEC_Operation *operation,
                                      TEE_Param *params)
{
    TEEC_Parameter *teec_params = operation->params;
    uint32_t param_types = operation->paramTypes;
    int i;

    for (i = 0; i < 4; i ++) {
        switch (TEEC_PARAM_TYPE_GET(param_types, i)) {
        case TEEC_NONE:
            params[i].value.a = 0;
            params[i].value.b = 0;
            break;
        case TEEC_VALUE_INPUT:
        case TEEC_VALUE_OUTPUT:
        case TEEC_VALUE_INOUT:
            params[i].value.a = teec_params[i].value.a;
            params[i].value.b = teec_params[i].value.b;
            break;
        case TEEC_MEMREF_TEMP_INPUT:
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
            params[i].memref.buffer = teec_params[i].tmpref.buffer;
            params[i].memref.size = teec_params[i].tmpref.size;
            break;
        case TEEC_MEMREF_WHOLE:
        case TEEC_MEMREF_PARTIAL_INPUT:
        case TEEC_MEMREF_PARTIAL_OUTPUT:
        case TEEC_MEMREF_PARTIAL_INOUT:
            params[i].memref.buffer = teec_params[i].memref.parent->buffer;
            params[i].memref.size = teec_params[i].memref.size;
            break;
        default:
            break;
        }
    }
}

static void convert_teec_paramtypes_to_tee_paramtypes(TEEC_Operation *operation,
                                                      uint32_t *param_types)
{
    uint32_t tee_paramtype[4];
    uint32_t flags;
    int i;

    for (i = 0; i < 4; i ++) {
        uint32_t teec_paramtype = TEEC_PARAM_TYPE_GET(operation->paramTypes, i);
        switch (teec_paramtype) {
        case TEEC_NONE:
        case TEEC_VALUE_INPUT:
        case TEEC_VALUE_OUTPUT:
        case TEEC_VALUE_INOUT:
        case TEEC_MEMREF_TEMP_INPUT:
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
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
            break;
        case TEEC_MEMREF_PARTIAL_INPUT:
            tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_INPUT;
            break;
        case TEEC_MEMREF_PARTIAL_OUTPUT:
            tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_OUTPUT;
            break;
        case TEEC_MEMREF_PARTIAL_INOUT:
            tee_paramtype[i] = TEE_PARAM_TYPE_MEMREF_INOUT;
            break;
        default:
            break;
        }
    }

    *param_types = TEE_PARAM_TYPES(tee_paramtype[0], tee_paramtype[1],
                                   tee_paramtype[2], tee_paramtype[3]);
}

static void teec_pre_process_operation(TEEC_Operation *operation,
                                              TEE_Param *params,
                                              uint32_t *param_types)
{
    copy_teecparams_to_params(operation, params);
    convert_teec_paramtypes_to_tee_paramtypes(operation, param_types);
}

static void copy_output_params_to_teecparams(TEEC_Operation *operation,
                                      TEE_Param *params)
{
    TEEC_Parameter *teec_params = operation->params;
    uint32_t param_types = operation->paramTypes;
    int i;

    for (i = 0; i < 4; i ++) {
        switch(TEE_PARAM_TYPE_GET(param_types, i)) {
        case TEEC_VALUE_OUTPUT:
        case TEEC_VALUE_INOUT:
            teec_params[i].value.a = params[i].value.a;
            teec_params[i].value.b = params[i].value.b;
            break;
        case TEEC_MEMREF_TEMP_OUTPUT:
        case TEEC_MEMREF_TEMP_INOUT:
            teec_params[i].tmpref.size = params[i].memref.size;
            break;
        case TEEC_MEMREF_WHOLE:
        case TEEC_MEMREF_PARTIAL_OUTPUT:
        case TEEC_MEMREF_PARTIAL_INOUT:
            teec_params[i].memref.size = params[i].memref.size;
            break;
        default:
            break;
        }
    }
}

static void teec_post_process_operation(TEEC_Operation *operation,
                                              TEE_Param *params)
{
    copy_output_params_to_teecparams(operation, params);
}

TEEC_Result TEEC_OpenSession(TEEC_Context *context,
                             TEEC_Session *session,
                             const TEEC_UUID *destination,
                             uint32_t connectionMethod,
                             const void *connectionData,
                             TEEC_Operation *operation,
                             uint32_t *returnOrigin)
{
    uint32_t param_types;
    TEE_Param params[4];
    TEEC_Result res;
    TEEC_Operation dummy_op;

    TEE_TASessionHandle *session_handle = (TEE_TASessionHandle*)session;
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
    teec_pre_process_operation(operation, params, &param_types);
    res = TEE_OpenTASession(destination, cancel_timeout, param_types,
                params, session_handle, returnOrigin);
    teec_post_process_operation(operation, params);
    return res;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
                   uint32_t commandID,
                   TEEC_Operation *operation,
                   uint32_t *returnOrigin)
{
    uint32_t param_types;
    TEE_Param params[4];
    TEEC_Result res;
    TEEC_Operation dummy_op;

    TEE_TASessionHandle *session_handle = (TEE_TASessionHandle*)session;
    if (operation == NULL) {
        memset(&dummy_op, 0, sizeof(TEEC_Operation));
        operation = &dummy_op;
    }
    teec_pre_process_operation(operation, params, &param_types);
    res = TEE_InvokeTACommand(*session_handle, cancel_timeout, commandID,
        param_types, params, returnOrigin);
    teec_post_process_operation(operation, params);
    return res;
}

void TEEC_CloseSession(TEEC_Session *session) {
    if (!session)
        return;

    TEE_TASessionHandle *session_handle = (TEE_TASessionHandle*)session;
    TEE_CloseTASession(*session_handle);
}


TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
                                      TEEC_SharedMemory *sharedMem)
{
    if (!context || !sharedMem)
        return TEEC_ERROR_BAD_PARAMETERS;

#if !WITH_RICH_OS
    sharedMem->buffer = malloc(sharedMem->size);
    if (!sharedMem->buffer)
        return TEEC_ERROR_OUT_OF_MEMORY;

    sharedMem->registered = 0;
    return TEEC_SUCCESS;
#else
#warning WITH_RICH_OS shared memory not implemented
    return TEEC_ERROR_NOT_IMPLEMENTED;
#endif
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
                                      TEEC_SharedMemory* sharedMem)
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

#if !WITH_RICH_OS
    free(sharedMem->buffer);
#endif

    sharedMem->buffer = NULL;
    sharedMem->size = 0;
}
