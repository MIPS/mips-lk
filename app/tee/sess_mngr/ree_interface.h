/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
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

#ifndef REE_INTERFACE_H
#define REE_INTERFACE_H

#include <stdint.h>

/*****************************************************************************
 * Formatting of messages exchanged with REE side
 * NOTE: this has to be always in sync with definitions in file mipstee_msg.h
 *       on REE side.
 *****************************************************************************/

#define MIPSTEE_MSG_ATTR_TYPE_NONE          0x0
#define MIPSTEE_MSG_ATTR_TYPE_VALUE_INPUT   0x1
#define MIPSTEE_MSG_ATTR_TYPE_VALUE_OUTPUT  0x2
#define MIPSTEE_MSG_ATTR_TYPE_VALUE_INOUT   0x3
#define MIPSTEE_MSG_ATTR_TYPE_RMEM_INPUT    0x5
#define MIPSTEE_MSG_ATTR_TYPE_RMEM_OUTPUT   0x6
#define MIPSTEE_MSG_ATTR_TYPE_RMEM_INOUT    0x7
#define MIPSTEE_MSG_ATTR_TYPE_TMEM_INPUT    0x9
#define MIPSTEE_MSG_ATTR_TYPE_TMEM_OUTPUT   0xa
#define MIPSTEE_MSG_ATTR_TYPE_TMEM_INOUT    0xb

#define MIPSTEE_MSG_ATTR_TYPE_MASK          GENMASK(7, 0)

/*
 * Meta parameter to be absorbed by the Secure OS and not passed
 * to the Trusted Application.
 *
 * Currently only used with MIPSTEE_MSG_CMD_OPEN_SESSION.
 */
#define MIPSTEE_MSG_ATTR_META               BIT(8)

/*
 * The temporary shared memory object is not physically contigous and this
 * temp memref is followed by another fragment until the last temp memref
 * that doesn't have this bit set.
 */
#define MIPSTEE_MSG_ATTR_FRAGMENT           BIT(9)

/*
 * Memory attributes for caching passed with temp memrefs. The actual value
 * used is defined outside the message protocol with the exception of
 * MIPSTEE_MSG_ATTR_CACHE_PREDEFINED which means the attributes already
 * defined for the memory range should be used.
 */
#define MIPSTEE_MSG_ATTR_CACHE_SHIFT        16
#define MIPSTEE_MSG_ATTR_CACHE_MASK         GENMASK(2, 0)
#define MIPSTEE_MSG_ATTR_CACHE_PREDEFINED   0

/*
 * Same values as TEE_LOGIN_* from TEE Internal API
 */
#define MIPSTEE_MSG_LOGIN_PUBLIC            0x00000000
#define MIPSTEE_MSG_LOGIN_USER              0x00000001
#define MIPSTEE_MSG_LOGIN_GROUP             0x00000002
#define MIPSTEE_MSG_LOGIN_APPLICATION       0x00000004
#define MIPSTEE_MSG_LOGIN_APPLICATION_USER  0x00000005
#define MIPSTEE_MSG_LOGIN_APPLICATION_GROUP 0x00000006


#define MIPSTEE_MSG_CMD_INVALID                 (-1)
#define MIPSTEE_MSG_CMD_OPEN_SESSION            0
#define MIPSTEE_MSG_CMD_INVOKE_COMMAND          1
#define MIPSTEE_MSG_CMD_CLOSE_SESSION           2
#define MIPSTEE_MSG_CMD_CANCEL                  3
#define MIPSTEE_MSG_CMD_REGISTER_SHM            4
#define MIPSTEE_MSG_CMD_UNREGISTER_SHM          5
#define MIPSTEE_MSG_FUNCID_CALL_WITH_ARG        0x0004

/**
 * struct mipstee_msg_param_tmem - temporary memory reference parameter
 * @buf_ptr:    Address of the buffer as an offset into shared memory.
 * @size:       Size of the buffer
 * @shm_ref:    Temporary shared memory reference, pointer to a struct tee_shm
 *
 * TEE and REE communicate using a predefined shared memory block.
 * Buffer pointers are passed as offsets into the shared memory block.
 */
struct mipstee_msg_param_tmem {
    uint64_t buf_ptr;
    uint64_t size;
    uint64_t shm_ref;
} __PACKED;

/**
 * struct mipstee_msg_param_rmem - registered memory reference parameter
 * @offs:   Offset into shared memory reference
 * @size:   Size of the buffer
 * @shm_ref:    Shared memory reference, pointer to a struct tee_shm
 */
struct mipstee_msg_param_rmem {
    uint64_t offs;
    uint64_t size;
    uint64_t shm_ref;
} __PACKED;

/**
 * struct mipstee_msg_param_value - opaque value parameter
 *
 * Value parameters are passed unchecked between normal and secure world.
 */
struct mipstee_msg_param_value {
    uint64_t a;
    uint64_t b;
    uint64_t c;
} __PACKED;

/**
 * struct mipstee_msg_param - parameter used together with struct
 * mipstee_msg_arg
 * @attr:   attributes
 * @tmem:   parameter by temporary memory reference
 * @rmem:   parameter by registered memory reference
 * @value:  parameter by opaque value
 *
 * @attr & MIPSTEE_MSG_ATTR_TYPE_MASK indicates if tmem, rmem or value is used
 * in the union.
 * MIPSTEE_MSG_ATTR_TYPE_VALUE_* indicates value,
 * MIPSTEE_MSG_ATTR_TYPE_TMEM_* indicates tmem and
 * MIPSTEE_MSG_ATTR_TYPE_RMEM_* indicates rmem.
 * MIPSTEE_MSG_ATTR_TYPE_NONE indicates that none of the members are used.
 */
struct mipstee_msg_param {
    uint64_t attr;
    union {
        struct mipstee_msg_param_tmem tmem;
        struct mipstee_msg_param_rmem rmem;
        struct mipstee_msg_param_value value;
    } u;
} __PACKED;

/**
 * struct mipstee_msg_arg - call argument
 * @cmd: Command, one of MIPSTEE_MSG_CMD_* or MIPSTEE_MSG_RPC_CMD_*
 * @func: Trusted Application function, specific to the Trusted Application,
 *       used if cmd == MIPSTEE_MSG_CMD_INVOKE_COMMAND
 * @session: In parameter for all MIPSTEE_MSG_CMD_* except
 *       MIPSTEE_MSG_CMD_OPEN_SESSION where it's an output parameter instead
 * @cancel_id: Cancellation id, a unique value to identify this request
 * @pad: not used
 * @ret: return value
 * @ret_origin: origin of the return value
 * @num_params: number of parameters supplied to the OS Command
 * @params: the parameters supplied to the OS Command
 *
 * All normal calls to Trusted OS uses this struct. If cmd requires further
 * information than what these field holds it can be passed as a parameter
 * tagged as meta (setting the MIPSTEE_MSG_ATTR_META bit in corresponding
 * attrs field). All parameters tagged as meta has to come first.
 *
 * Temp memref parameters can be fragmented if supported by the Trusted OS
 * If a logical memref parameter is fragmented then has all but the last
 * fragment the MIPSTEE_MSG_ATTR_FRAGMENT bit set in attrs. Even if a memref is
 * fragmented it will still be presented as a single logical memref to the
 * Trusted Application.
 */
struct mipstee_msg_arg {
    uint32_t cmd;
    uint32_t func;
    uint32_t session;
    uint32_t cancel_id;
    uint32_t pad;
    uint32_t ret;
    uint32_t ret_origin;
    uint32_t num_params;

    /* num_params tells the actual number of element in params */
    struct mipstee_msg_param params[0];
} __PACKED;

/**
 * MIPSTEE_MSG_GET_ARG_SIZE - return size of struct mipstee_msg_arg
 *
 * @num_params: Number of parameters embedded in the struct mipstee_msg_arg
 *
 * Returns the size of the struct mipstee_msg_arg together with the number
 * of embedded parameters.
 */
#define MIPSTEE_MSG_GET_ARG_SIZE(num_params) \
    (sizeof(struct mipstee_msg_arg) + \
     sizeof(struct mipstee_msg_param) * (num_params))

/**
 * struct mipstee_msg_hdr
 * @magic    - set to REE_MAGIC
 * @data_tag - used to match synchronous requests and replies on the REE side
 */
struct mipstee_msg_hdr {
   uint32_t magic;
   uint32_t data_tag;
} __PACKED;

/**
 * struct mipstee_tipc_msg
 * @hdr - header for the message
 * @msg - the bulk of the sender's message
 */
struct mipstee_tipc_msg {
   struct mipstee_msg_hdr hdr;
   struct mipstee_msg_arg msg;
} __PACKED;

#define REE_MAGIC (0x52454520) /* "REE " */

#define MIPSTEE_TIPC_MSG_GET_SIZE(num_params) \
    (sizeof(struct mipstee_msg_hdr) + \
     MIPSTEE_MSG_GET_ARG_SIZE(num_params))

#endif /* REE_INTERFACE_H */
