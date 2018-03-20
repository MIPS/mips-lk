/*
 * Copyright (c) 2016-218, MIPS Tech, LLC and/or its affiliated group companies
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

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_internal_api.h>
#include "ta_test_server.h"

#define PREFIX_STR "Server TA: "
#define DPRINTF(...) printf(PREFIX_STR __VA_ARGS__)

// server TA instance should exit after client closes all sessions
void test_panic(void)
{
    // cause div 0 panic
    //volatile int a = 8/0; (void)a;

    TEE_Panic(0xdeadbeef);
}

TEE_Result TA_CreateEntryPoint(void)
{
    DPRINTF("%s\n", __func__);
    //test_panic();
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DPRINTF("%s\n", __func__);
    //test_panic();
}

TEE_Result TA_OpenSessionEntryPoint(
                uint32_t    paramTypes,
                TEE_Param   params[4],
                void **sessionContext)
{
    DPRINTF("%s\n", __func__);
    //test_panic();
    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
    DPRINTF("%s\n", __func__);
    //test_panic();
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    params[0].value.a++;
    return TEE_SUCCESS;
}

static TEE_Result inc_memref(uint32_t param_types, TEE_Param params[4])
{
    uint32_t value;
    uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE,
                           TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;
    if (!params[0].memref.buffer ||
            (params[0].memref.size != sizeof(uint32_t)))
        return TEE_ERROR_BAD_PARAMETERS;

    value = *(uint32_t *)params[0].memref.buffer + 1;
    *(uint32_t *)params[0].memref.buffer = value;
    DPRINTF("%s %d\n", __func__, *(uint32_t *)params[0].memref.buffer);
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(
                void *sessionContext,
                uint32_t    commandID,
                uint32_t    paramTypes,
                TEE_Param   params[4])
{

    DPRINTF("%s\n", __func__);
    //test_panic();
    switch (commandID) {
    case TA_HELLO_WORLD_CMD_INC_VALUE:
        return inc_value(paramTypes, params);
    case TA_HELLO_WORLD_CMD_INC_MEMREF:
        return inc_memref(paramTypes, params);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
