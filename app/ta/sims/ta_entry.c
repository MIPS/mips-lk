/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#include <tee_internal_api.h>
#include <ta_sims.h>
#include <stdio.h>
#include <trace.h>

#define LOCAL_TRACE 0

/*
 * Trusted Application Entry Points
 */

/* Called each time a new instance is created */
TEE_Result TA_CreateEntryPoint(void)
{
    LTRACEF("SIMS create entry point\n\n");
    return TEE_SUCCESS;
}

/* Called each time an instance is destroyed */
void TA_DestroyEntryPoint(void)
{
    LTRACEF("SIMS destroy entry point\n\n");
}

/* Called each time a session is opened */
TEE_Result TA_OpenSessionEntryPoint(uint32_t nParamTypes, TEE_Param pParams[4],
                                    void **ppSessionContext)
{
    int cmdId = TA_SIMS_CMD_SUCCESS;

    LTRACEF("SIMS open session entry point\n\n");

    if (TEE_PARAM_TYPE_GET(nParamTypes, 3) == TEE_PARAM_TYPE_VALUE_INPUT)
        cmdId = pParams[3].value.a;

    switch (cmdId) {
    case TA_SIMS_CMD_SUCCESS:
        break;
    case TA_SIMS_CMD_FAILURE:
        printf("TA_OpenSessionEntryPoint: Fail Open Session Entry Point.\n");
        return TEE_ERROR_GENERIC;
    case TA_SIMS_CMD_WAIT:
        return sims_entry_wait(nParamTypes, pParams);
    default:
        break;
    }

    return sims_open_session(ppSessionContext);
}

/* Called each time a session is closed */
void TA_CloseSessionEntryPoint(void *pSessionContext)
{
    LTRACEF("SIMS close session entry point\n\n");
    sims_close_session(pSessionContext);
}

/* Called when a command is invoked */
TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
                                      uint32_t nCommandID, uint32_t nParamTypes,
                                      TEE_Param pParams[4])
{
    LTRACEF("SIMS invoke entry point\n\n");
    switch (nCommandID) {
    case TA_SIMS_CMD_SUCCESS:
        return TEE_SUCCESS;

    case TA_SIMS_CMD_READ:
        return sims_read(nParamTypes, pParams);

    case TA_SIMS_CMD_WRITE:
        return sims_write(nParamTypes, pParams);

    case TA_SIMS_CMD_GET_COUNTER:
        return sims_get_counter(pSessionContext, nParamTypes, pParams);

    case TA_SIMS_CMD_GET_MEMREF_UINT:
        return sims_get_memref_uint(nParamTypes, pParams);

    case TA_SIMS_CMD_CHECK_BUFFER:
        return sims_check_buffer_mapping(nParamTypes, pParams);

    case TA_SIMS_CMD_FAILURE:
        return TEE_ERROR_GENERIC;

    case TA_SIMS_CMD_WAIT:
        return sims_entry_wait(nParamTypes, pParams);

    case TA_SIMS_CMD_PANIC:
        TEE_Panic(TEE_ERROR_GENERIC);
        /* Should not get here */
        return TEE_SUCCESS;

    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}
