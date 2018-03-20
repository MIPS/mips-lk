/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
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

#include <tee_internal_api.h>
#include <stdio.h>
#include <ta_uuids.h>
#include <client_ta.h>

static TEE_TASessionHandle sess;
extern void ta_set_default_panic_handler(void);

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes, TEE_Param pParams[4],
                                    void **ppSessionContext)
{
    (void)(nParamTypes);
    (void)(pParams);
    (void)(ppSessionContext);

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
    (void)(pSessionContext);
    printf("Client TA Close EP\n");
}

TEE_Result cmd_open_session(void *pSessionContext, uint32_t nParamTypes,
                            TEE_Param pParams[4])
{
    TEE_UUID target_uuid;
    TEE_Result res;
    uint32_t ret_orig;
    uint32_t param_types;
    TEE_Param params[4];

    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_GENERIC;

    TEE_MemMove(&target_uuid, pParams[0].memref.buffer, pParams[0].memref.size);
    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    res = TEE_OpenTASession(&target_uuid, TEE_TIMEOUT_INFINITE, param_types,
                            params, &sess, &ret_orig);
    return res;
}

TEE_Result cmd_close_session(void *pSessionContext)
{
    TEE_CloseTASession(sess);
    return TEE_SUCCESS;
}

TEE_Result cmd_test_malloc_alignement(void *pSessionContext)
{
    (void)pSessionContext;
    void *buffer;
    uint32_t size = 32;
    bool test_bool = true;
    char test_char = 0xdd;
    uint16_t test_u16 = 0xbeef;
    uint32_t test_u32 = 0xdeadbeef;
    uint64_t test_u64 = 0xdeadbeeffeedbeef;

    buffer = TEE_Malloc(size, 0);
    if (buffer == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    *((bool *)buffer) = test_bool;
    *((char *)buffer) = *((char *)buffer) + test_char;
    *((uint16_t *)buffer) = *((uint16_t *)buffer) + test_u16;
    *((uint32_t *)buffer) = *((uint32_t *)buffer) + test_u32;
    *((uint64_t *)buffer) = *((uint64_t *)buffer) + test_u64;

    if (*((uint64_t *)buffer) > test_u64) {
        TEE_Free(buffer);
        return TEE_SUCCESS;
    } else {
        TEE_Free(buffer);
        return TEE_ERROR_GENERIC;
    }
}

TEE_Result cmd_test_malloc_size_zero(void *pSessionContext)
{
    (void)pSessionContext;
    void *buffer;

    buffer = TEE_Malloc(0, 0);
    if (buffer == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    /* TA should panic if it tries to access buffer*/
    *((uint32_t *)buffer) = 0;
    return TEE_ERROR_GENERIC;
}

TEE_Result cmd_test_realloc_content(void *pSessionContext)
{
    (void)pSessionContext;
    void *buffer;
    void *buffer1;
    uint8_t content[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    uint8_t content_zero[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

    buffer = TEE_Malloc(8, 0);
    if (buffer == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_MemMove(buffer, content, 8);
    if (TEE_MemCompare(buffer, content, 8)) {
        TEE_Free(buffer);
        return TEE_ERROR_GENERIC;
    }
    buffer1 = TEE_Realloc(buffer, 16);
    if (buffer1 == NULL) {
        TEE_Free(buffer);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (TEE_MemCompare(buffer1, content, 8) ||
            TEE_MemCompare((uint8_t *)buffer1 + 8, content_zero, 8)) {
        TEE_Free(buffer1);
        return TEE_ERROR_GENERIC;
    }
    TEE_Free(buffer1);
    return TEE_SUCCESS;
}

TEE_Result cmd_test_realloc_illegal_pointer(void *pSessionContext)
{
    (void)pSessionContext;
    uint32_t content[4] = { 0x0, 0x0, 0x0, 0x0 };
    void *buffer_1;
    void *buffer_2;
    uint32_t object_size = 8;

    buffer_1 = (void *)content;
    buffer_2 = TEE_Realloc(buffer_1, object_size);
    TEE_Free(buffer_2);
    return TEE_SUCCESS;
}

TEE_Result cmd_test_realloc_size_zero(void *pSessionContext)
{
    (void)pSessionContext;
    void *buffer_1;
    void *buffer_2;
    uint8_t content[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

    buffer_1 = TEE_Malloc(0, 0);
    buffer_2 = TEE_Realloc(buffer_1, 8);
    TEE_MemMove(buffer_2, content, 8);
    if (TEE_MemCompare(content, buffer_2, 8)) {
        TEE_Free(buffer_2);
        return TEE_ERROR_GENERIC;
    }
    TEE_Free(buffer_2);
    return TEE_SUCCESS;
}

TEE_Result cmd_test_default_panic_handler(void *pSessionContext)
{
    (void)pSessionContext;
    ta_set_default_panic_handler();
    TEE_Panic(TEE_ERROR_GENERIC);
    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
                                      uint32_t nCommandID, uint32_t nParamTypes,
                                      TEE_Param pParams[4])
{
    switch (nCommandID) {
    case TA_CLIENT_CMD_OPENSESSION:
        return cmd_open_session(pSessionContext, nParamTypes, pParams);
    case TA_CLIENT_CMD_CLOSESESSION:
        return cmd_close_session(pSessionContext);
    case TA_CLIENT_CMD_PANIC:
        TEE_Panic(TEE_ERROR_GENERIC);
        break;
    case TA_CLIENT_CMD_TEST_MALLOC_ALIGNEMENT:
        return cmd_test_malloc_alignement(pSessionContext);
    case TA_CLIENT_CMD_TEST_MALLOC_SIZE_ZERO:
        return cmd_test_malloc_size_zero(pSessionContext);
    case TA_CLIENT_CMD_TEST_REALLOC_CONTENT:
        return cmd_test_realloc_content(pSessionContext);
    case TA_CLIENT_CMD_TEST_REALLOC_ILLEGAL_PTR:
        return cmd_test_realloc_illegal_pointer(pSessionContext);
    case TA_CLIENT_CMD_TEST_REALLOC_SIZE_ZERO:
        return cmd_test_realloc_size_zero(pSessionContext);
    case TA_CLIENT_CMD_DEFAULT_PANIC:
        return cmd_test_default_panic_handler(pSessionContext);
    case TA_CLIENT_CMD_SUCCESS:
        return TEE_SUCCESS;
    default:
        return TEE_ERROR_GENERIC;
    }
}

