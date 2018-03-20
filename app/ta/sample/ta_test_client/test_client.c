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
#include <ta_test_server.h>

#define PREFIX_STR "Client TA #1: "
#define DPRINTF(...) printf(PREFIX_STR __VA_ARGS__)

/* adapted from OPTEE os_test.c */
static TEE_Result test_mem_local_access_right(uint32_t param_types,
          TEE_Param params[4])
{
  TEE_Result res;

  if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 0, 0, 0))
    return TEE_ERROR_GENERIC;

  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
                                    TEE_MEMORY_ACCESS_ANY_OWNER,
                                    params[0].memref.buffer,
                                    params[0].memref.size);
  if (res != TEE_SUCCESS)
    return res;

  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ,
                                    params[0].memref.buffer,
                                    params[0].memref.size);
  if (res != TEE_SUCCESS)
    return res;

  return TEE_SUCCESS;
}

static TEE_Result test_mem_access_right_denied(uint32_t param_types,
          TEE_Param params[4])
{
  TEE_Result res;

  if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, 0, 0, 0))
    return TEE_ERROR_GENERIC;

  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ |
                                    TEE_MEMORY_ACCESS_ANY_OWNER,
                                    params[0].memref.buffer,
                                    params[0].memref.size);
  if (res != TEE_ERROR_ACCESS_DENIED)
    return TEE_ERROR_GENERIC;

  res = TEE_CheckMemoryAccessRights(TEE_MEMORY_ACCESS_READ,
                                    params[0].memref.buffer,
                                    params[0].memref.size);
  if (res != TEE_ERROR_ACCESS_DENIED)
    return TEE_ERROR_GENERIC;

  return TEE_SUCCESS;
}

static const char buffer_readonly[] = "const buffer_readonly";

static void test_mem_access(void)
{
  TEE_Result res;
  uint32_t  paramTypes;
  TEE_Param   params[4];
  char buffer_readwrite[4];

  paramTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  /* positive tests */
  params[0].memref.buffer = &buffer_readwrite;
  params[0].memref.size = sizeof(buffer_readwrite);
  res = test_mem_local_access_right(paramTypes, params);
  DPRINTF("TEE_CheckMemoryAccessRights readwrite %s\n",
      (res == TEE_SUCCESS) ? "PASSED" : "FAILED");

  params[0].memref.buffer = &buffer_readonly;
  params[0].memref.size = sizeof(buffer_readonly);
  res = test_mem_local_access_right(paramTypes, params);
  DPRINTF("TEE_CheckMemoryAccessRights readonly %s\n",
      (res == TEE_SUCCESS) ? "PASSED" : "FAILED");

  /* negative tests */
  params[0].memref.buffer = (void *)1;
  params[0].memref.size = sizeof(int);
  res = test_mem_access_right_denied(paramTypes, params);
  DPRINTF("TEE_CheckMemoryAccessRights zero %s\n",
      (res == TEE_SUCCESS) ? "PASSED" : "FAILED");
}

TEE_Result TA_CreateEntryPoint(void)
{
  DPRINTF("%s\n", __func__);
  return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
  DPRINTF("%s\n", __func__);
  DPRINTF("End of Test Client Application!!!\n\n");
}

TEE_Result TA_OpenSessionEntryPoint(
        uint32_t  paramTypes,
        TEE_Param params[4],
        void **sessionContext)
{
  TEE_TASessionHandle session;
  uint32_t returnOrigin;
  uint32_t res;
  uint32_t paramTypes_2;
  TEE_Param params_2[4];
  TEE_UUID server_uuid = TA_TEST_SERVER_UUID;
  const uint32_t TEST_VALUE = 11;

  DPRINTF("%s\n", __func__);

  (void)paramTypes;
  (void)params;
  (void)sessionContext;

  /* define our own params for internal client API calls */
  paramTypes_2 = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  params_2[0].value.a = TEST_VALUE;

  DPRINTF("Calling TEE_OpenTASession with Server TA...\n");
  res = TEE_OpenTASession(&server_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
          &session, &returnOrigin);
  DPRINTF("TEE_OpenTASession returned\n");
  if (res) {
    DPRINTF("TEE_OpenTASession error: %x\n", res);
    return TEE_ERROR_GENERIC;
  }

  DPRINTF("Calling TEE_InvokeTACommand on Server TA with param:%d\n",
          params_2[0].value.a);
  res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE,
          TA_HELLO_WORLD_CMD_INC_VALUE, paramTypes_2, params_2, &returnOrigin);
  DPRINTF("TEE_InvokeTACommand returned\n");

  if (res != TEE_SUCCESS) {
    DPRINTF("TEE_InvokeTACommand error: %x\n", res);
    TEE_CloseTASession(session);
    return TEE_ERROR_GENERIC;
  }

  DPRINTF("Server TA incremented value to %d. %s\n", params_2[0].value.a,
          (params_2[0].value.a == (TEST_VALUE + 1)) ? "PASSED" : "FAILED");

  test_mem_access();

  DPRINTF("Calling TEE_CloseTASession...\n");
  TEE_CloseTASession(session);
  DPRINTF("TEE_CloseTASession returned\n");

  return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
  DPRINTF("%s\n", __func__);
}

TEE_Result TA_InvokeCommandEntryPoint(
        void *sessionContext,
        uint32_t  commandID,
        uint32_t  paramTypes,
        TEE_Param   params[4])
{
  DPRINTF("%s\n", __func__);
  return TEE_SUCCESS;
}
