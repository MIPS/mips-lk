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
#include <ta_common.h>
#include <ta_uuids.h>

/*
 * The purpose of this test is to verify that memory references are properly
 * mapped when multi-instance TAs use the Internal Client API to invoke
 * commands with memref parameters on other TAs.
 */

static TEE_UUID sims_test_ta_uuid = TA_SIMS_UUID;
static uint8_t in[32] = { 0 };
static uint8_t out[32] = { -1 };

static TEE_TASessionHandle sess;

TEE_Result invoke_sims_ta(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_Param targetParams[4];
    uint32_t targetParamTypes;
    uint32_t retOrig = 0;
    TEE_TASessionHandle session;
    TEE_Result res;
    TEE_UUID uuid = sims_test_ta_uuid;

    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) {
        printf("multi_instance_memref: Bad expected parameter type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    in[0] = pParams[0].value.a;
    targetParams[0].value.a = 0;
    targetParams[1].memref.buffer = &in;
    targetParams[1].memref.size = sizeof(in);
    targetParamTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_INPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE);

    res = TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &session,
                            &retOrig);
    if (res != TEE_SUCCESS) {
        printf("multi_instance_memref: Failed to open TA_SIMS_UUID\n");
        return res;
    }

    res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE, TA_SIMS_CMD_WRITE,
                              targetParamTypes, targetParams, &retOrig);
    if (res != TEE_SUCCESS) {
        printf("multi_instance_memref: Failed to invoke TA_SIMS_CMD_WRITE\n");
        goto close_session_exit;
    }

    targetParams[0].value.a = 0;
    targetParams[1].memref.buffer = &out;
    targetParams[1].memref.size = sizeof(out);
    targetParamTypes = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
                                       TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE);

    res = TEE_InvokeTACommand(session, TEE_TIMEOUT_INFINITE, TA_SIMS_CMD_READ,
                              targetParamTypes, targetParams, &retOrig);
    if (res != TEE_SUCCESS) {
        printf("multi_instance_memref: Failed to invoke TA_SIMS_CMD_READ\n");
        goto close_session_exit;
    }

    pParams[0].value.b = out[0];

close_session_exit:
    TEE_CloseTASession(session);

    return res;
}

static TEE_Result invoke_open(uint32_t nParamTypes, TEE_Param pParams[4])
{
    TEE_UUID uuid;

    TEE_MemMove(&uuid, pParams[0].memref.buffer, sizeof(TEE_UUID));
    return TEE_OpenTASession(&uuid, TEE_TIMEOUT_INFINITE, 0, NULL, &sess, NULL);
}

static TEE_Result invoke_invoke(uint32_t nParamTypes, TEE_Param pParams[4])
{
    uint32_t param_types;
    TEE_Param params[4];

    param_types = nParamTypes >> 4;

    if (TEE_PARAM_TYPE_GET(nParamTypes, 1) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        params[0].memref.buffer = pParams[1].memref.buffer;
        params[0].memref.size = pParams[1].memref.size;
    } else if (TEE_PARAM_TYPE_GET(nParamTypes, 1) == TEE_PARAM_TYPE_VALUE_INPUT)
        params[0].value.a = pParams[1].value.a;

    if (TEE_PARAM_TYPE_GET(nParamTypes, 2) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        params[1].memref.buffer = pParams[2].memref.buffer;
        params[1].memref.size = pParams[2].memref.size;
    } else if (TEE_PARAM_TYPE_GET(nParamTypes, 2) == TEE_PARAM_TYPE_VALUE_INPUT)
        params[1].value.a = pParams[2].value.a;

    if (TEE_PARAM_TYPE_GET(nParamTypes, 3) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        params[2].memref.buffer = pParams[3].memref.buffer;
        params[2].memref.size = pParams[3].memref.size;
    } else if (TEE_PARAM_TYPE_GET(nParamTypes, 3) == TEE_PARAM_TYPE_VALUE_INPUT)
        params[2].value.a = pParams[3].value.a;

    return TEE_InvokeTACommand(sess, TEE_TIMEOUT_INFINITE, pParams[0].value.a,
                               param_types, params, NULL);
}

static TEE_Result invoke_command(uint32_t nParamTypes, TEE_Param pParams[4])
{
    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) == TEE_PARAM_TYPE_MEMREF_INPUT)
        return invoke_open(nParamTypes, pParams);
    else if (TEE_PARAM_TYPE_GET(nParamTypes, 0) == TEE_PARAM_TYPE_VALUE_INPUT)
        return invoke_invoke(nParamTypes, pParams);
    else
        return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result TA_CreateEntryPoint(void)
{
    //printf("multi_instance_memref: TA_CreateEntryPoint\n");

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    //printf("multi_instance_memref: TA_DestroyEntryPoint\n");
}

static TEE_Result multi_instance_memref_wait(uint32_t param_types,
        TEE_Param params[4])
{
    TEE_Result res = TEE_SUCCESS;

    if (TEE_PARAM_TYPE_GET(param_types, 0) == TEE_PARAM_TYPE_VALUE_INPUT) {
        uint32_t timeout_ms = params[0].value.a;
        bool unmask = params[0].value.b;

        if (unmask)
            TEE_UnmaskCancellation();
        else
            TEE_MaskCancellation();

        printf("%s: waiting %d masked %d\n", __func__,
               (unsigned int)timeout_ms, !unmask);
        res = TEE_Wait(timeout_ms);
    } else
        res = TEE_ERROR_BAD_PARAMETERS;

    return res;
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes, TEE_Param pParams[4],
                                    void **ppSessionContext)
{
    TEE_Result res = TEE_SUCCESS;
    bool isSingleInstance = false;
    int cmdId = TA_MULTI_INSTANCE_RETURN_CMD;
    (void)(ppSessionContext);

    //printf("multi_instance_memref: TA_OpenSessionEntryPoint\n");

    res = TEE_GetPropertyAsBool((TEE_PropSetHandle)TEE_PROPSET_CURRENT_TA,
                                "gpd.ta.singleInstance", &isSingleInstance);
    if (res != TEE_SUCCESS) {
        printf("multi_instance_memref: TEE_GetPropertyAsBool failed\n");
        return res;
    }

    if (isSingleInstance) {
        printf("multi_instance_memref: config error, TA is not multi-instance\n");
        return TEE_ERROR_GENERIC;
    }

    if (TEE_PARAM_TYPE_GET(nParamTypes, 3) == TEE_PARAM_TYPE_VALUE_INPUT)
        cmdId = pParams[3].value.a;

    switch (cmdId) {
    case TA_MULTI_INSTANCE_RETURN_CMD:
        break;
    case TA_MULTI_INSTANCE_WAIT_CMD:
        return multi_instance_memref_wait(nParamTypes, pParams);
    default:
        break;
    }

    return res;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
    (void)(pSessionContext);

    //printf("multi_instance_memref: TA_CloseSessionEntryPoint\n");
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
                                      uint32_t nCommandID,
                                      uint32_t nParamTypes,
                                      TEE_Param pParams[4])
{
    (void)pSessionContext;

    switch (nCommandID) {
    case TA_MULTI_INSTANCE_MEMREF_CMD:
        return invoke_sims_ta(nParamTypes, pParams);
    case TA_MULTI_INSTANCE_INVOKE_CMD:
        return invoke_command(nParamTypes, pParams);

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

