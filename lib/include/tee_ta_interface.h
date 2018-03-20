/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __TEE_TA_INTERFACE_H
#define __TEE_TA_INTERFACE_H

#include <stdint.h>
#include <stdbool.h>
#include <setjmp.h>
#include <trusty_std.h>
#include <tee_api_types.h>
#include <tee_common_uapi.h>

struct sess_status {
    void *session_ctx;  /* Session context parameter */
    TEE_Identity client_id; /* Client's identity */
};

/* Context of a loaded TA */
struct ta_ctx {
    uint32_t panicked;      /* True if TA has panicked */
    uint32_t panic_code;    /* Code supplied for panic */
    jmp_buf setjmp_env;     /* setjmp buffer for panic handling */
    jmp_buf *setjmp_env_p;
    struct sess_status active_sess; /* Currently active session (session and entry point id) */
};

extern struct ta_ctx *ta_context;

void ta_set_default_panic_handler(void);
void ta_set_entrypoint_panic_handler(void);
__NO_RETURN void ta_entrypoint_panic_return(void);

void tee_get_ta_client_id(TEE_Identity *client_id);
TEE_Result libutee_reset_persistent_time(void);

TEE_Result call_ta_create_entry_point(void);
TEE_Result call_ta_destroy_entry_point(void);
TEE_Result call_ta_open_session_entry_point(uint32_t param_types,
                                            TEE_Param params[4],
                                            void **session_context);
TEE_Result call_ta_close_session_entry_point(void *session_context);
TEE_Result call_ta_invoke_command_entry_point(void *session_context,
                                              uint32_t func,
                                              uint32_t param_types,
                                              TEE_Param params[4]);
#endif

