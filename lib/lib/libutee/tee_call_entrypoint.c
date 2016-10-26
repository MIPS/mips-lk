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
#include <trusty_std.h>
#include <setjmp.h>
#include <assert.h>
#include <tee_api_types.h>
#include <tee_ta_interface.h>
#include <tee_internal_api.h>

enum ta_entrypoint_fn {
    TA_CREATE_FN = 1,
    TA_DESTROY_FN,
    TA_OPEN_SESSION_FN,
    TA_CLOSE_SESSION_FN,
    TA_INVOKE_CMD_FN,
};

static TEE_Result call_ta_entrypoint(enum ta_entrypoint_fn fn,
                                     void **session_context,
                                     uint32_t command_id,
                                     uint32_t param_types,
                                     TEE_Param params[4])
{
    TEE_Result res = TEE_SUCCESS;

    ta_set_entrypoint_panic_handler();

    if (!setjmp(ta_context->setjmp_env)) {
        switch (fn) {
            case TA_CREATE_FN:
                res = TA_CreateEntryPoint();
                break;
            case TA_DESTROY_FN:
                TA_DestroyEntryPoint();
                break;
            case TA_OPEN_SESSION_FN:
                res = TA_OpenSessionEntryPoint(param_types, params,
                        session_context);
                break;
            case TA_CLOSE_SESSION_FN:
                TA_CloseSessionEntryPoint(*session_context);
                break;
            case TA_INVOKE_CMD_FN:
                res = TA_InvokeCommandEntryPoint(*session_context, command_id,
                        param_types, params);
                break;
            default:
                TEE_Panic(0xbad00000 | __LINE__);
                break;
        }
    } else {
        // panic return via longjmp
        assert(ta_context->panicked);
        res = TEE_ERROR_TARGET_DEAD;
    }

    ta_set_default_panic_handler();

    return res;
}

TEE_Result call_ta_create_entry_point(void)
{
    return call_ta_entrypoint(TA_CREATE_FN, NULL, 0, 0, NULL);
}

TEE_Result call_ta_destroy_entry_point(void)
{
    return call_ta_entrypoint(TA_DESTROY_FN, NULL, 0, 0, NULL);
}

TEE_Result call_ta_open_session_entry_point(uint32_t param_types,
                                            TEE_Param params[4],
                                            void **session_context)
{
    return call_ta_entrypoint(TA_OPEN_SESSION_FN, session_context, 0, param_types, params);
}

TEE_Result call_ta_close_session_entry_point(void *session_context)
{
    return call_ta_entrypoint(TA_CLOSE_SESSION_FN, &session_context, 0, 0, NULL);
}

TEE_Result call_ta_invoke_command_entry_point(void *session_context,
                                              uint32_t command_id,
                                              uint32_t param_types,
                                              TEE_Param params[4])
{
    return call_ta_entrypoint(TA_INVOKE_CMD_FN, &session_context, command_id,
            param_types, params);
}
