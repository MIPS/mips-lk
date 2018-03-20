/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
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
                                     uint32_t func,
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
            res = TA_InvokeCommandEntryPoint(*session_context, func,
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
    return call_ta_entrypoint(TA_OPEN_SESSION_FN, session_context, 0,
                              param_types, params);
}

TEE_Result call_ta_close_session_entry_point(void *session_context)
{
    return call_ta_entrypoint(TA_CLOSE_SESSION_FN, &session_context, 0, 0,
                              NULL);
}

TEE_Result call_ta_invoke_command_entry_point(void *session_context,
                                              uint32_t func,
                                              uint32_t param_types,
                                              TEE_Param params[4])
{
    return call_ta_entrypoint(TA_INVOKE_CMD_FN, &session_context, func,
                              param_types, params);
}
