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

#include <stdbool.h>
#include <stdio.h>
#include <tee_unittest.h>

#define LOG_TAG "tee_unittest"

extern void register_tee_test_basic_tee_features(void);
extern void register_tee_test_extra_tests(void);

/* TODO: Enable user to choose which tests are registered */
void tee_unittest_entry(void)
{
    printf("TEE unittest suite\n\n");
    register_tee_test_basic_tee_features();
    register_tee_test_extra_tests();
    run_all_tests();
}

#if WITH_RICH_OS

int main(void)
{
    tee_test_init_ctx();
    tee_unittest_entry();
    tee_test_deinit_ctx();
    return 0;
}

#else

TEE_Result TA_CreateEntryPoint(void)
{
    tee_unittest_entry();
    return TEE_ERROR_GENERIC;
}

void TA_DestroyEntryPoint(void) {
  // DBG_PRINT_INFO("Client TA: destroy entry point\n");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4],
                                    void **sessionContext)
{
  // DBG_PRINT_INFO("Client TA: open session entry point\n");
  return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sessionContext)
{
  // DBG_PRINT_INFO("Client TA: close session entry point\n");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID,
                                      uint32_t paramTypes, TEE_Param params[4])
{
  // DBG_PRINT_INFO("Client TA: invoke command entry point\n");
  return TEE_SUCCESS;
}

#endif
