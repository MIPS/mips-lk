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

#define PREFIX_STR "Client TA #2: "
#define DPRINTF(...) printf(PREFIX_STR __VA_ARGS__)

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
  const uint32_t TEST_VALUE = 22;
  uint32_t value = TEST_VALUE;

  DPRINTF("%s\n", __func__);

  (void)paramTypes;
  (void)params;
  (void)sessionContext;

  /* define our own params for internal client API calls */
  paramTypes_2 = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  params_2[0].memref.buffer = &value;
  params_2[0].memref.size = sizeof(value);

  DPRINTF("Calling TEE_OpenTASession with Server TA...\n");
  res = TEE_OpenTASession(&server_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
          &session, &returnOrigin);
  DPRINTF("TEE_OpenTASession returned\n");
  if (res) {
    DPRINTF("TEE_OpenTASession error: %x\n", res);
    return TEE_ERROR_GENERIC;
  }

  DPRINTF("Calling TEE_InvokeTACommand on Server TA with MEMREF param:%d\n",
          value);
  res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE,
          TA_HELLO_WORLD_CMD_INC_MEMREF, paramTypes_2, params_2, &returnOrigin);
  DPRINTF("TEE_InvokeTACommand returned\n");

  if (res != TEE_SUCCESS) {
    DPRINTF("TEE_InvokeTACommand error: %x\n", res);
    TEE_CloseTASession(session);
    return TEE_ERROR_GENERIC;
  }

  DPRINTF("Server TA incremented MEMREF param value to %d. %s\n", value,
          (value == (TEST_VALUE + 1)) ? "PASSED" : "FAILED");

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
