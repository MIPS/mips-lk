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

#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>
#include <ta_uuids.h>
#include "ta_defines.h"
#include <ta_common.h>

static TEE_TASessionHandle st_sess = { 0 };
static uint32_t shared_value = 0xfeeddead;

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

static TEE_Result core_ta_wait(uint32_t timeout, uint32_t unmask);

TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes, TEE_Param pParams[4],
                                    void **ppSessionContext)
{
    int cmdId = TA_CORE_TEST_CMD_SUCCESS;
    (void)(ppSessionContext);

    if (TEE_PARAM_TYPE_GET(nParamTypes, 3) == TEE_PARAM_TYPE_VALUE_INPUT)
        cmdId = pParams[3].value.a;

    switch (cmdId) {
    case TA_CORE_TEST_CMD_SUCCESS:
        break;
    case TA_CORE_TEST_CMD_WAIT:
        if (TEE_PARAM_TYPE_GET(nParamTypes, 0) == TEE_PARAM_TYPE_VALUE_INPUT)
            return core_ta_wait(pParams[0].value.a, pParams[0].value.b);
        else
            return TEE_ERROR_BAD_PARAMETERS;
    default:
        break;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
    (void)(pSessionContext);
}

#define NR_ITERATIONS       1000

static TEE_Result test_handles_leak(void)
{
    TEE_Result res;
    TEE_UUID dest_uuid = TA_CREATE_FAIL_TEST_UUID;
    TEE_TASessionHandle session;
    uint32_t ret_orig;
    uint32_t count;

    for (count = 0; count < NR_ITERATIONS; count++) {
        res = TEE_OpenTASession(&dest_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
                                &session, &ret_orig);
        if (ret_orig != TEE_ORIGIN_TRUSTED_APP) {
            printf("ERROR ORIGIN NOT TRUSTED APP\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (res != TEE_ERROR_GENERIC) {
            printf("Open Session bad error code: %x\n", res);
            return TEE_ERROR_GENERIC;
        }
    }
    return TEE_SUCCESS;
}

#undef NR_ITERATIONS
#define NR_ITERATIONS       10

static uint32_t get_elapsed_time(TEE_Time start, TEE_Time end)
{
    uint32_t res;
    uint32_t rollover = (end.millis < start.millis) ? 1 : 0;

    if (rollover)
        res = (end.seconds - start.seconds - 1) * 1000 + 1000 - start.millis +
              end.millis;
    else
        res = (end.seconds - start.seconds) * 1000 + end.millis - start.millis;
    return res;
}

static TEE_Result test_wait_interval(void)
{
    TEE_Time start_time, end_time;
    uint32_t timeout = 10;
    uint32_t count;

    for (count = 0; count < NR_ITERATIONS; count++) {
        TEE_GetSystemTime(&start_time);
        TEE_Wait(timeout);
        TEE_GetSystemTime(&end_time);
        if (get_elapsed_time(start_time, end_time) < timeout) {
            return TEE_ERROR_GENERIC;
        }
        timeout *= 2;
    }
    return TEE_SUCCESS;
}

static TEE_Result open_sims_session(void)
{
    TEE_UUID dest_uuid = TA_SIMS_UUID;

    return TEE_OpenTASession(&dest_uuid, TEE_TIMEOUT_INFINITE, 0, NULL,
                             &st_sess, NULL);
}

static TEE_Result share_buffer_with_ta(bool panic)
{
    TEE_Result res;
    TEE_Param params[4];
    uint32_t param_types;
    uint32_t ret_orig;

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                                  TEE_PARAM_TYPE_MEMREF_INOUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);
    params[0].value.a = shared_value;
    params[0].value.b = 0;
    params[1].memref.buffer = (void *)(&shared_value);
    params[1].memref.size = sizeof(uint32_t);

    res = TEE_InvokeTACommand(st_sess, TEE_TIMEOUT_INFINITE,
                              TA_SIMS_CMD_GET_MEMREF_UINT,
                              param_types, params, &ret_orig);

    if (panic)
        TEE_Panic(TEE_ERROR_GENERIC);

    return res;
}

static TEE_Result check_ta_buffer_mapping(void)
{
    TEE_Result res;
    TEE_Param params[4];
    uint32_t param_types;
    uint32_t ret_orig;

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);

    res = TEE_InvokeTACommand(st_sess, TEE_TIMEOUT_INFINITE,
                              TA_SIMS_CMD_CHECK_BUFFER,
                              param_types, params, &ret_orig);

    return res;
}

static TEE_Result invoke_wait(uint32_t timeout, uint32_t wait_time,
                              uint32_t unmask)
{
    TEE_Result res;
    TEE_TASessionHandle sess;
    TEE_UUID dest_uuid = TA_CORE_TEST_UUID;
    TEE_Param params[4];
    uint32_t param_types;
    uint32_t ret_orig;

    res = TEE_OpenTASession(&dest_uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess,
                            &ret_orig);
    if (res != TEE_SUCCESS)
        return res;

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE);
    params[0].value.a = wait_time; // TEE_Wait interval
    params[0].value.b = unmask; // do not unmask cancellations

    res = TEE_InvokeTACommand(sess, timeout, TA_CORE_TEST_CMD_WAIT,
                              param_types, params, &ret_orig);

    TEE_CloseTASession(sess);
    return res;
}

static TEE_Result invoke_opensession_timeout(uint32_t timeout,
        uint32_t wait_time, uint32_t unmask)
{
    TEE_Result res;
    TEE_TASessionHandle sess;
    TEE_UUID dest_uuid = TA_CORE_TEST_UUID;
    TEE_Param params[4];
    uint32_t param_types;

    param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_NONE,
                                  TEE_PARAM_TYPE_VALUE_INPUT);
    params[0].value.a = wait_time; // TEE_Wait interval
    params[0].value.b = unmask; // (do not) unmask cancellations
    params[3].value.a = TA_CORE_TEST_CMD_WAIT;

    res = TEE_OpenTASession(&dest_uuid, timeout, param_types, params, &sess,
                            NULL);
    if (res == TEE_SUCCESS)
        TEE_CloseTASession(sess);
    return res;
}

static TEE_Result core_ta_wait(uint32_t timeout, uint32_t unmask)
{
    if (unmask)
        TEE_UnmaskCancellation();
    else
        TEE_MaskCancellation();
    printf("%s: waiting %d masked %d\n", __func__,
           (unsigned int)timeout, !unmask);
    return TEE_Wait(timeout);
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
                                      uint32_t nCommandID,
                                      uint32_t nParamTypes,
                                      TEE_Param pParams[4])
{
    (void)(pSessionContext);

    switch (nCommandID) {
    case TA_CORE_TEST_CMD_SUCCESS:
        return TEE_SUCCESS;
    case TA_CORE_TEST_CMD_SESSION_LEAK:
        return test_handles_leak();
    case TA_CORE_TEST_CMD_WAIT_TIMEOUT:
        return test_wait_interval();
    case TA_CORE_TEST_CMD_SHARE_BUFFER_AND_PANIC:
        return share_buffer_with_ta(true);
    case TA_CORE_TEST_CMD_CHECK_BUFFER_MAPPING:
        return check_ta_buffer_mapping();
    case TA_CORE_TEST_CMD_OPEN_SIMS_SESSION:
        return open_sims_session();
    case TA_CORE_TEST_CMD_SHARE_BUFFER:
        return  share_buffer_with_ta(false);
    case TA_CORE_TEST_CMD_INVOKE_TIMEOUT:
        return invoke_wait(pParams[0].value.a, pParams[0].value.b,
                           pParams[1].value.a);
    case TA_CORE_TEST_CMD_WAIT:
        return core_ta_wait(pParams[0].value.a, pParams[0].value.b);
    case TA_CORE_TEST_CMD_INVOKE_OPENSESSION_TIMEOUT:
        return invoke_opensession_timeout(pParams[0].value.a,
                                          pParams[0].value.b,
                                          pParams[1].value.a);

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

