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

#ifndef TEE_CLIENT_API_H
#define TEE_CLIENT_API_H

#include <stdint.h>
#include <stddef.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

typedef uint32_t TEEC_Context;

typedef struct {
    /* Implementation defined */
    uint32_t sm_channel;
    uint32_t session_id;
    TEEC_Context *ctx;
} TEEC_Session;

typedef struct {
    uint32_t a;
    uint32_t b;
} TEEC_Value;

typedef struct {
    union {
        void *buffer;
        uint64_t padding_ptr;
    };
    union {
        size_t size;
        uint64_t padding_sz;
    };
    uint32_t flags;
    /*
     * Implementation-Defined, must match what the kernel driver have
     *
     * Identifier can store a handle (int) or a structure pointer (void *).
     * Define this union to match case where sizeof(int)!=sizeof(void *).
     */
    uint32_t reserved;
    union {
        int fd;
        void *ptr;
        uint64_t padding_d;
    } d;
    uint64_t registered;
} TEEC_SharedMemory;

typedef struct {
    union {
        void *buffer;
        uint64_t padding_ptr;
    };
    union {
        size_t size;
        uint64_t padding_sz;
    };
} TEEC_TempMemoryReference;

typedef struct {
    union {
        TEEC_SharedMemory *parent;
        uint64_t padding_ptr;
    };
    union {
        size_t size;
        uint64_t padding_sz;
    };
    union {
        size_t offset;
        uint64_t padding_off;
    };
} TEEC_RegisteredMemoryReference;

typedef union {
    TEEC_TempMemoryReference tmpref;
    TEEC_RegisteredMemoryReference memref;
    TEEC_Value value;
} TEEC_Parameter;

typedef TEE_Result TEEC_Result;
typedef TEE_UUID TEEC_UUID;

#define TEEC_PARAM_TYPES TEE_PARAM_TYPES
#define TEEC_PARAM_TYPE_GET TEE_PARAM_TYPE_GET

typedef struct {
    uint32_t started;
    uint32_t paramTypes;
    TEEC_Parameter params[4];
} TEEC_Operation;

#define TEEC_CONFIG_SHAREDMEM_MAX_SIZE      0x80000

#define TEEC_NONE                   0x00000000
#define TEEC_VALUE_INPUT            0x00000001
#define TEEC_VALUE_OUTPUT           0x00000002
#define TEEC_VALUE_INOUT            0x00000003
#define TEEC_MEMREF_TEMP_INPUT      0x00000005
#define TEEC_MEMREF_TEMP_OUTPUT     0x00000006
#define TEEC_MEMREF_TEMP_INOUT      0x00000007
#define TEEC_MEMREF_WHOLE           0x0000000C
#define TEEC_MEMREF_PARTIAL_INPUT   0x0000000D
#define TEEC_MEMREF_PARTIAL_OUTPUT  0x0000000E
#define TEEC_MEMREF_PARTIAL_INOUT   0x0000000F

#define TEEC_LOGIN_PUBLIC               0x00000000
#define TEEC_LOGIN_USER                 0x00000001
#define TEEC_LOGIN_GROUP                0x00000002
#define TEEC_LOGIN_APPLICATION          0x00000004
#define TEEC_LOGIN_USER_APPLICATION     0x00000005
#define TEEC_LOGIN_GROUP_APPLICATION    0x00000006

#define TEEC_MEM_INPUT   0x00000001
#define TEEC_MEM_OUTPUT  0x00000002
#define TEEC_MEM_INOUT   (TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)
#define TEEC_MEM_DMABUF  0x00010000
#define TEEC_MEM_KAPI    0x00020000

#define TEEC_SUCCESS                0x00000000
#define TEEC_ERROR_GENERIC          0xFFFF0000
#define TEEC_ERROR_ACCESS_DENIED    0xFFFF0001
#define TEEC_ERROR_CANCEL           0xFFFF0002
#define TEEC_ERROR_ACCESS_CONFLICT  0xFFFF0003
#define TEEC_ERROR_EXCESS_DATA      0xFFFF0004
#define TEEC_ERROR_BAD_FORMAT       0xFFFF0005
#define TEEC_ERROR_BAD_PARAMETERS   0xFFFF0006
#define TEEC_ERROR_BAD_STATE        0xFFFF0007
#define TEEC_ERROR_ITEM_NOT_FOUND   0xFFFF0008
#define TEEC_ERROR_NOT_IMPLEMENTED  0xFFFF0009
#define TEEC_ERROR_NOT_SUPPORTED    0xFFFF000A
#define TEEC_ERROR_NO_DATA          0xFFFF000B
#define TEEC_ERROR_OUT_OF_MEMORY    0xFFFF000C
#define TEEC_ERROR_BUSY             0xFFFF000D
#define TEEC_ERROR_COMMUNICATION    0xFFFF000E
#define TEEC_ERROR_SECURITY         0xFFFF000F
#define TEEC_ERROR_SHORT_BUFFER     0xFFFF0010
#define TEEC_ERROR_EXTERNAL_CANCEL  0xFFFF0011
#define TEEC_ERROR_TARGET_DEAD      0xFFFF3024

#define TEEC_ORIGIN_API             0x00000001
#define TEEC_ORIGIN_COMMS           0x00000002
#define TEEC_ORIGIN_TEE             0x00000003
#define TEEC_ORIGIN_TRUSTED_APP     0x00000004

TEEC_Result TEEC_OpenSession(TEEC_Context *context,
                 TEEC_Session *session,
                 const TEEC_UUID *destination,
                 uint32_t connectionMethod,
                 const void *connectionData,
                 TEEC_Operation *operation,
                 uint32_t *returnOrigin);

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session,
                   uint32_t commandID,
                   TEEC_Operation *operation,
                   uint32_t *returnOrigin);

void TEEC_CloseSession(TEEC_Session *session);

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context,
                                      TEEC_SharedMemory *sharedMem);

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context,
                                      TEEC_SharedMemory *sharedMem);

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem);

void TEEC_RequestCancellation(TEEC_Operation *operation);

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context);

void TEEC_FinalizeContext(TEEC_Context *context);

#endif
