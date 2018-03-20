#include <stdio.h>
#include <tee_internal_api.h>
#include <tee_common_uapi.h>
#include <trusty_std.h>
#include "ta_defines.h"

static uint32_t keep_alive_test = 0;

TEE_Result ta_entry_inc(uint32_t nParamTypes, TEE_Param pParams[4])
{
    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INOUT) {
        printf("ta_entry_inc: Bad expected parameter type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keep_alive_test += pParams[0].value.a;
    pParams[0].value.b = keep_alive_test;

    return TEE_SUCCESS;
}

TEE_Result CmdTEEAllocatePropertyEnumerator(
    void       *pSessionContext,
    uint32_t    nParamTypes,
    TEE_Param   pParams[4])
{
    /** VARIABLES **/
    TEE_Result cmdResult;

    (void)(pSessionContext);

    /** CODE **/
    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_OUTPUT)
        return TRUSTED_APP_ERROR_BAD_PARAMETERS;

    cmdResult = TEE_AllocatePropertyEnumerator((TEE_PropSetHandle *)
                &pParams[0].value.a);

    return cmdResult;
}

TEE_Result CmdTEEStartPropertyEnumerator(
    void       *pSessionContext,
    uint32_t    nParamTypes,
    TEE_Param   pParams[4])
{
    /** VARIABLES **/

    (void)(pSessionContext);

    /** CODE **/
    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) ||
            (TEE_PARAM_TYPE_GET(nParamTypes, 1) != TEE_PARAM_TYPE_VALUE_INPUT))
        return TRUSTED_APP_ERROR_BAD_PARAMETERS;

    TEE_StartPropertyEnumerator((TEE_PropSetHandle) pParams[0].value.a,
                                (TEE_PropSetHandle) pParams[1].value.a);

    return TEE_SUCCESS;
}

TEE_Result CmdTEEGetPropertyNameAndAdvance(void *pSessionContext,
        uint32_t nParamTypes,
        TEE_Param pParams[4])
{
    /** VARIABLES **/
    TEE_Result cmdResult = TEE_SUCCESS;

    /** CODE **/
    if ((TEE_PARAM_TYPE_GET(nParamTypes, 0) != TEE_PARAM_TYPE_VALUE_INPUT) &&
            (TEE_PARAM_TYPE_GET(nParamTypes, 1) !=
             TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        printf("CmdTEEGetPropertyNameAndAdvance: Bad expected parameter types\n");
        return TRUSTED_APP_ERROR_BAD_PARAMETERS;
    }

    /* Assign parameters */

    /* call the main functions */
    cmdResult = TEE_GetPropertyName((TEE_PropSetHandle) pParams[0].value.a,
                                    pParams[1].memref.buffer,
                                    &pParams[1].memref.size);
    if (cmdResult != TEE_SUCCESS)
        return cmdResult;
    cmdResult = TEE_GetNextProperty((TEE_PropSetHandle) pParams[0].value.a);
    return cmdResult;
}

TEE_Result CmdTEETestPrivilegedSyscalls(uint32_t nParamTypes,
                                        TEE_Param pParams[4])
{
    long expected = ERR_NOT_SUPPORTED;
    const char *sm_port = TEE_SESS_MANAGER_COMMAND_MSG;
    uint32_t arg_uint32 = 0;
    const uuid_t ta_props_uuid = TA_PROPS_UUID;
    int n = 1;

    printf("%d\n", n++);
    if (expected != port_create(sm_port, 1, TEE_MAX_BUFFER_SIZE, arg_uint32))
        goto priv_exit;

    printf("%d\n", n++);
    if (expected != connect(TEE_SESS_MANAGER_COMMAND_MSG, arg_uint32))
        goto priv_exit;

    printf("%d\n", n++);
    if (expected != accept(arg_uint32, (uuid_t *)&ta_props_uuid))
        goto priv_exit;

    printf("%d\n", n++);
    if (expected != (long)connect_to_ta(&ta_props_uuid, &arg_uint32))
        goto priv_exit;

    printf("%d\n", n++);
    if (expected != (long)set_cancel_flag((uuid_t *)&ta_props_uuid,
                                          &arg_uint32))
        goto priv_exit;

    printf("%d\n", n++);
    if (expected != (long)get_ta_flags(&ta_props_uuid, &arg_uint32))
        goto priv_exit;

    return err_to_tee_err(expected);

priv_exit:
    return TEE_ERROR_GENERIC;
}

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

    if (TEE_PARAM_TYPE_GET(nParamTypes, 0) == TEE_PARAM_TYPE_VALUE_OUTPUT) {
        printf("TA_OpenSessionCommandEntryPoint: Fail Open Session Entry Point.\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *pSessionContext)
{
    (void)(pSessionContext);
}

TEE_Result TA_InvokeCommandEntryPoint(void *pSessionContext,
                                      uint32_t nCommandID,
                                      uint32_t nParamTypes,
                                      TEE_Param pParams[4])
{
    (void)(pSessionContext);

    switch (nCommandID) {
    case TA_KEEP_ALIVE_CMD_INC:
        return ta_entry_inc(nParamTypes, pParams);
    case CMD_TEE_AllocatePropertyEnumerator:
        return CmdTEEAllocatePropertyEnumerator(pSessionContext, nParamTypes,
                                                pParams);
    case CMD_TEE_StartPropertyEnumerator:
        return CmdTEEStartPropertyEnumerator(pSessionContext, nParamTypes,
                                             pParams);
    case CMD_TEE_GetPropertyNameAndAdvance:
        return CmdTEEGetPropertyNameAndAdvance(pSessionContext, nParamTypes,
                                               pParams);
    case CMD_TEE_TestPrivilegedSyscalls:
        return CmdTEETestPrivilegedSyscalls(nParamTypes, pParams);
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }
}

