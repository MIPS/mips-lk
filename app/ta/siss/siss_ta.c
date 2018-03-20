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
#include <ta_defines.h>

TEE_Result TA_CreateEntryPoint(void)
{
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result siss_entry_wait(uint32_t param_types, TEE_Param params[4])
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
    int cmdId = TA_SISS_CMD_SUCCESS;
    (void)(ppSessionContext);

    if (TEE_PARAM_TYPE_GET(nParamTypes, 3) == TEE_PARAM_TYPE_VALUE_INPUT)
        cmdId = pParams[3].value.a;

    switch (cmdId) {
    case TA_SISS_CMD_SUCCESS:
        break;
    case TA_SISS_CMD_FAILURE:
        printf("TA_OpenSessionEntryPoint: Fail Open Session Entry Point.\n");
        return TEE_ERROR_GENERIC;
    case TA_SISS_CMD_WAIT:
        return siss_entry_wait(nParamTypes, pParams);
    default:
        break;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
    (void)(pSessionContext);
    printf("SISS TA close EP\n");
}

static TEE_Result siss_ta_return_th_id(uint32_t param_types,
                                       TEE_Param params[4])
{
    if (param_types != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
                                       TEE_PARAM_TYPE_VALUE_INOUT,
                                       TEE_PARAM_TYPE_NONE,
                                       TEE_PARAM_TYPE_NONE))
        return TEE_ERROR_GENERIC;

    params[0].value.b = params[0].value.a;
    params[1].value.b = params[1].value.a;

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
                                      uint32_t nCommandID,
                                      uint32_t nParamTypes,
                                      TEE_Param pParams[4])
{
    (void)pSessionContext;
    switch (nCommandID) {
    case TA_SISS_CMD_SUCCESS:
        return TEE_SUCCESS;
    case TA_SISS_CMD_FAILURE:
        return TEE_ERROR_GENERIC;
    case TA_SISS_CMD_PANIC:
        TEE_Panic(TEE_ERROR_GENERIC);
        break;
    case TA_SISS_CMD_RETURN_TH_ID:
        return siss_ta_return_th_id(nParamTypes, pParams);
    case TA_SISS_CMD_WAIT:
        return siss_entry_wait(nParamTypes, pParams);
    default:
        break;
    }
    return TEE_ERROR_GENERIC;
}

