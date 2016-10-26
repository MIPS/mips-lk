/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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

#ifndef TEE_COMMON_UAPI_H
#define TEE_COMMON_UAPI_H

#include <err.h>
#include <tee_api_defines.h>

/*
 * Header for common definitions between user space libutee, session manager,
 * and kernel tee library.
 */

#define TEE_MAX_BUFFER_SIZE 256
#define TEE_SESS_MANAGER_PRIORITY_MSG "tee.sess_manager.priority_msg"
#define TEE_SESS_MANAGER_COMMAND_MSG "tee.sess_manager.command_msg"

#define TEE_MIPS_LK_HANDLE_MAGIC (0x40000000u)
#define TEE_MASK_HANDLE_ID(handle_id) ((handle_id) | TEE_MIPS_LK_HANDLE_MAGIC)
#define TEE_UNMASK_HANDLE_ID(handle_id) ((handle_id) ^ TEE_MIPS_LK_HANDLE_MAGIC)

/*
 * Layout for passing GP tee paramTypes and TEE_Params in a flat message buffer
 */
typedef struct __attribute__((__packed__)) {
    /* params are either value.a and value.b or memref and size */
    uint64_t    params[8];
    uint32_t    param_types;
} utee_params_t;

/*
 * The msg_map union defines layout for message buffer that is sent
 * over the channels.
 */
typedef union  __attribute__((__packed__)) {
    uint8_t buffer[TEE_MAX_BUFFER_SIZE];
    struct {
        utee_params_t utee_params;
        uint32_t operation_id; // also entrypoint_id
        uint32_t command_id;
        uint32_t return_origin;
        uint32_t return_code;
        uint32_t parent_id;
        TEE_Identity client_id;
        TEE_UUID ta_uuid;
        uintptr_t session_ctx;
    };
} msg_map_t;

STATIC_ASSERT(sizeof(msg_map_t) <= TEE_MAX_BUFFER_SIZE);

enum tee_sess_operation_id {
    TEE_OPEN_SESSION_ID = 1,
    TEE_INVOKE_COMMAND_ID,
    TEE_CLOSE_SESSION_ID,
    TEE_RETVAL_ID,
    TEE_CANCEL_ID,
    TEE_DESTROY_ID,
};

/*
 * Map lk error codes to GP API error codes.
 */
inline uint32_t err_to_tee_err(int32_t lk_err) {
    switch(lk_err) {
        case NO_ERROR:
            return TEE_SUCCESS;
        case ERR_NOT_FOUND:
            return TEE_ERROR_ITEM_NOT_FOUND;
        case ERR_BUSY:
        case ERR_ALREADY_STARTED:
            return TEE_ERROR_BUSY;
        case ERR_OBJECT_DESTROYED:
            return TEE_ERROR_CORRUPT_OBJECT;
        case ERR_NOT_ALLOWED:
        case ERR_FAULT:
        case ERR_ACCESS_DENIED:
            return TEE_ERROR_ACCESS_DENIED;
        case ERR_TIMED_OUT:
        case ERR_CANCELLED:
            return TEE_ERROR_CANCEL;
        case ERR_INVALID_ARGS:
            return TEE_ERROR_BAD_PARAMETERS;
        case ERR_NOT_VALID:
            return TEE_ERROR_BAD_STATE;
        case ERR_NOT_IMPLEMENTED:
        case ERR_CMD_UNKNOWN:
            return TEE_ERROR_NOT_IMPLEMENTED;
        case ERR_NOT_SUPPORTED:
            return TEE_ERROR_NOT_SUPPORTED;
        case ERR_NO_MEMORY:
            return TEE_ERROR_OUT_OF_MEMORY;
        case ERR_NO_MSG:
        case ERR_NOT_READY:
        case ERR_BAD_HANDLE:
        case ERR_BAD_STATE:
        case ERR_CHANNEL_CLOSED:
            return TEE_ERROR_COMMUNICATION;
        case ERR_NOT_ENOUGH_BUFFER:
            return TEE_ERROR_SHORT_BUFFER;
        case ERR_NOT_SUSPENDED:
        case ERR_GENERIC:
        default:
            return TEE_ERROR_GENERIC;
    };
}

/*
 * Debug and trace macro definitions.
 */
#define TEE_TRACE_MSG(fmt, x...) \
    do { printf("%-4s ... %s(#%d): " fmt, TEE_TAG, __PRETTY_FUNCTION__, __LINE__, ## x); } while(0)
#define TEE_DBG_MSG(x...) do { if (TEE_LOCAL_TRACE) { TEE_TRACE_MSG(x); } } \
                          while(0)

#endif /* TEE_COMMON_UAPI_H */
