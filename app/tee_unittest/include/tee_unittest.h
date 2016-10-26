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
#ifndef _TEEUNITTEST_INCLUDE_TEEUNITTEST_H_
#define _TEEUNITTEST_INCLUDE_TEEUNITTEST_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#if WITH_RICH_OS
#include <tee_client_api.h>
#else
#include <teec_api.h>
#endif

#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)

TEEC_Context teetest_teec_ctx;

TEE_Result teetest_teec_open_session(TEEC_Session *session,
                                     const TEEC_UUID *uuid, TEEC_Operation *op,
                                     uint32_t *ret_orig);

TEEC_Result RegisterSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm,
                                 uint32_t size, uint32_t flags);

TEEC_Result AllocateSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm,
                                 uint32_t size, uint32_t flags);

void teec_set_operation_parameter_value(TEEC_Operation *op, size_t n,
                                        uint32_t a, uint32_t b);

void teec_set_operation_parameter_memref(TEEC_Operation *op, size_t n,
                                         TEEC_SharedMemory *parent,
                                         unsigned offset, unsigned size);

void teec_set_operation_parameter_tmpref(TEEC_Operation *op, size_t n,
                                         uint8_t *buffer, unsigned size);

#define TEEC_OPERATION_INITIALIZER { 0 }

#define TEE_ORIGIN_NOT_TRUSTED_APP 5 /* Not defined in GP API specs */

/* temporary hacks */
/* os_test TA CMD codes */
#define TA_OS_TEST_CMD_INIT                 0
#define TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT  1
#define TA_OS_TEST_CMD_BASIC                5
#define TA_OS_TEST_CMD_PANIC                6
#define TA_OS_TEST_CMD_CLIENT               7
#define TA_OS_TEST_CMD_PRIVATE_PARAMS       8
#define TA_OS_TEST_CMD_WAIT                 9
#define TA_OS_TEST_CMD_BAD_MEM_ACCESS       10

/* sims TA CMD codes */
#define TA_SIMS_CMD_READ                    1
#define TA_SIMS_CMD_WRITE                   2
#define TA_SIMS_CMD_GET_COUNTER             3

/* concurrent TA CMD codes */
#define TA_CONCURRENT_CMD_BUSY_LOOP 0
#define TA_CONCURRENT_CMD_SHA256    1

/* crypto TA CMD codes*/
#define TA_CRYPT_CMD_SHA256                 2

/* GP testing client API CMD codes */
#define COMMAND_TTA_Remember_Expected_ParamTypes      0x00000002
#define COMMAND_TTA_Copy_ParamIn_to_ParamOut          0x00000001
#define COMMAND_TTA_Check_ParamTypes                  0x00000003
#define COMMAND_TTA_To_Be_Cancelled                   0x00000004

/* GP Internal API TCF CMD codes */
#define CMD_TEE_GetPropertyAsString_withoutEnum             0x00000010
#define CMD_TEE_GetPropertyAsBool_withoutEnum               0x00000015
#define CMD_TEE_GetPropertyAsInt_withoutEnum                0x00000020
#define CMD_TEE_GetPropertyAsU32_withoutEnum                0x00000020
#define CMD_TEE_GetPropertyAsBinaryBlock_withoutEnum        0x00000025
#define CMD_TEE_GetPropertyAsUUID_withoutEnum               0x00000030
#define CMD_TEE_GetPropertyAsIdentity_withoutEnum           0x00000035
#define CMD_TEE_GetPropertyAsXXXX_fromEnum                  0x00000045
#define CMD_TEE_AllocatePropertyEnumerator                  0x00000060
#define CMD_TEE_StartPropertyEnumerator                     0x00000065
#define CMD_TEE_ResetPropertyEnumerator                     0x00000070
#define CMD_TEE_FreePropertyEnumerator                      0x00000075
#define CMD_TEE_GetPropertyName                             0x00000080
#define CMD_TEE_Malloc                                      0x00000100
#define CMD_TEE_Realloc                                     0x00000110
#define CMD_TEE_MemMove                                     0x00000120
#define CMD_TEE_MemCompare                                  0x00000130
#define CMD_TEE_MemFill                                     0x00000140
#define CMD_TEE_Panic                                       0x00000104
#define CMD_TEE_CheckMemoryAccessRight                      0x00000103
#define CMD_TEE_GetCancellationFlag_RequestedCancel         0x00000105
#define CMD_TEE_MaskUnmaskCancellations                     0x00000106
#define CMD_TEE_Free                                        0x00000107
#define CMD_ProcessInvokeTAOpenSession                      0x00000200
#define CMD_ProcessTAInvokeTA_simple                        0x00000201
#define CMD_ProcessTAInvokeTA_PayloadValue                  0x00000202
#define CMD_TEE_GetNextPropertyEnumerator_notStarted        0x00000203
#define CMD_ProcessTAInvokeTA_PayloadMemref                 0x00000204
#define CMD_ProcessTAInvokeTA_PayloadValue_In_Out           0x00000205

/* GP Internal API TCF Multi Instance CMD codes */
#define CMD_TEE_GetInstanceData                             0x00000101
#define CMD_TEE_SetInstanceData                             0x00000102

/* GP Internal API Time CMD codes */
#define CMD_TEE_GetSystemTime                                        0x00000010
#define CMD_TEE_Wait                                                 0x00000011
#define CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTime          0x00000012
#define CMD_TEE_GetREETime                                           0x00000013
#define CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTimeOverflow  0x00000014
#define CMD_TEE_GetTAPersistentTimeNotSetAndSetTAPersistentTime      0x00000015
#define CMD_TEE_ResetPersistentTime                                  0x00000016

/* Miscellaneous */
static char *VALUE_NONE;

#define OFFSET0 0
#define INVALID_CONNECTION_METHODS          0x0A
#define BIG_SIZE                    1024
#define TOO_SHORT_BUFFER 0
#define NORMAL_SIZE_BUFFER 1
#define HINT_ZERO 0
#define SIZE_ZERO 0
#define SMALL_SIZE 0xA

#define ANY_OWNER_NOT_SET 0
#define ANY_OWNER_SET_ACCESS_READ (TEE_MEMORY_ACCESS_ANY_OWNER | \
                   TEE_MEMORY_ACCESS_READ)
#define ANY_OWNER_SET_ACCESS_WRITE (TEE_MEMORY_ACCESS_ANY_OWNER | \
                    TEE_MEMORY_ACCESS_WRITE)
#define ANY_OWNER_SET_ACCESS_READ_WRITE (TEE_MEMORY_ACCESS_ANY_OWNER | \
                     TEE_MEMORY_ACCESS_READ | \
                     TEE_MEMORY_ACCESS_WRITE)


#define CASE_SUCCESS 0
#define CASE_TARGET_DEAD_ICA2 1
#define CASE_TARGET_DEAD 1
#define CASE_CANCEL_TIMEOUT 2
#define CASE_SUCCESS_ICA2 2
#define CASE_ERROR_ICA2 3
#define CASE_ITEM_NOT_FOUND 3
#define CASE_TARGET_BUSY 4
#define CASE_EQUAL 0
#define CASE_BUFFER1_DIFFERS_FIRST 1
#define CASE_BUFFER2_DIFFERS_FIRST 2
#define CASE_NULL 0
#define RESULT_EQUAL 0
#define RESULT_INTEGER_GREATER_THAN_ZERO 1
#define RESULT_INTEGER_LOWER_THAN_ZERO 2
#define CASE_WAIT_CANCELLED 1
#define CASE_WAIT_SUCCESS 2

/* Imported from lk/lib/unittest */
/*
 * The list of test cases is made up of these elements.
 */
struct test_case_element {
    struct test_case_element *next;
    struct test_case_element *failed_next;
    const char *name;
    bool (*test_case)(void);
};

void unittest_register_test_case(struct test_case_element *elem);
void run_all_tests(void);

#define OPERATION_TEEC_PARAM_TYPES(op, p0, p1, p2, p3) \
    (op)->paramTypes = TEE_PARAM_TYPES(p0, p1, p2, p3)

#define TEEC_checkMemoryContent_sharedMemory(op, param_num, shrm, exp_buf,  \
                                             exp_blen)                      \
    do {                                                                    \
        if ((exp_buf) == IGNORE) {                                          \
            TEE_EXPECT_EQ(exp_blen, (op)->params[(param_num)].memref.size,  \
                          "");                                              \
        } else {                                                            \
            TEE_EXPECT_EQ((shrm), (op)->params[(param_num)].memref.parent,  \
                          "");                                              \
            TEE_EXPECT_BUFFER(&(exp_buf), (exp_blen), (shrm)->buffer,       \
                              (op)->params[(param_num)].memref.size);       \
        }                                                                   \
    } while (0)

#define TEEC_checkMemoryContent_tmpMemory(op, param_num, buf, exp_buf,      \
                                          exp_blen)                         \
    do {                                                                    \
        if ((exp_buf) == 0) {                                               \
            TEE_EXPECT_EQ(exp_blen, (op)->params[(param_num)].tmpref.size,  \
                          "");                                              \
        } else {                                                            \
            TEE_EXPECT_EQ((buf), (op)->params[(param_num)].tmpref.buffer,   \
                           "");                                             \
            TEE_EXPECT_BUFFER(&(exp_buf), (exp_blen), (buf),                \
                              (op)->params[(param_num)].memref.size);       \
        }                                                                   \
    } while (0)

#define TEEC_checkContent_Parameter_value(op, param_num, exp_a, exp_b)      \
    do {                                                                    \
        if (IGNORE != exp_a)                                                \
            TEE_EXPECT_EQ(exp_a, (op)->params[(param_num)].value.a, "");    \
        if (IGNORE != exp_b)                                                \
            TEE_EXPECT_EQ(exp_b, (op)->params[(param_num)].value.b, "");    \
    } while (0)

#define AllocateTempMemory(temp_mem, size)  temp_mem = malloc(size)

/*Releases temporary memory area*/
#define ReleaseTempMemory(temp_mem)                                         \
    do {                                                                    \
        if (temp_mem != NULL) {                                             \
            free(temp_mem);                                                 \
            temp_mem = NULL;                                                \
        }                                                                   \
    } while (0)

#define ALLOCATE_SHARED_MEMORY(context, sharedMemory, sharedMemorySize,     \
                               memoryType)                                  \
    res = AllocateSharedMemory(context, sharedMemory, sharedMemorySize,     \
                               memoryType);                                 \
    if (res != TEE_SUCCESS)                                                 \
        goto exit;                                                          \
    memset(sharedMemory->buffer, 0, sharedMemorySize)

#define ALLOCATE_AND_FILL_SHARED_MEMORY(context, sharedMemory,              \
                                        sharedMemorySize, memoryType,       \
                                        copySize, data)                     \
    res = AllocateSharedMemory(context, sharedMemory, sharedMemorySize,     \
                                        memoryType);                        \
    if (res != TEE_SUCCESS)                                                 \
        goto exit;                                                          \
    if (data != NULL)                                                       \
        memcpy(sharedMemory->buffer, data, copySize)

#define SET_SHARED_MEMORY_OPERATION_PARAMETER(parameterNumber,              \
                                              sharedMemoryOffset,           \
                                              sharedMemory,                 \
                                              sharedMemorySize)             \
    op.params[parameterNumber].memref.offset = sharedMemoryOffset;          \
    op.params[parameterNumber].memref.size = sharedMemorySize;              \
    op.params[parameterNumber].memref.parent = sharedMemory


#define Invoke_GetPropertyAsBool_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsU32_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsUUID_withoutEnum Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsIdentity_withoutEnum \
    Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsBinaryBlock_withoutEnum \
    Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsString_withoutEnum \
    Invoke_GetPropertyAsXXX_withoutEnum
#define Invoke_GetPropertyAsXXXX_fromEnum Invoke_StartPropertyEnumerator
#define Invoke_FreePropertyEnumerator Invoke_ResetPropertyEnumerator
#define Invoke_GetNextProperty_enumNotStarted Invoke_ResetPropertyEnumerator
#define Invoke_ProcessTAInvoke_DeadErrorSuccess \
    Invoke_ProcessInvokeTAOpenSession

static TEEC_Result Invoke_GetPropertyAsXXX_withoutEnum(TEEC_Session *sess,
                        uint32_t cmdId, TEE_PropSetHandle propSet, char *name,
                        uint32_t kindBuffer, char *expectedValue)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    TEEC_SharedMemory *shm01, *shm02;
    uint32_t org;
    uint32_t nameLen = 0;
    uint32_t expectedValueLen = 0;

    nameLen = strlen(name) + 1;
    shm01 = malloc(sizeof(TEEC_SharedMemory));
    shm02 = malloc(sizeof(TEEC_SharedMemory));

    ALLOCATE_AND_FILL_SHARED_MEMORY(&teetest_teec_ctx, shm01, BIG_SIZE,
                                    TEEC_MEMREF_PARTIAL_INPUT, nameLen, name);

    if (kindBuffer == TOO_SHORT_BUFFER) {
        ALLOCATE_SHARED_MEMORY(&teetest_teec_ctx, shm02, 1,
                               TEEC_MEMREF_PARTIAL_OUTPUT);
    } else {
        ALLOCATE_SHARED_MEMORY(&teetest_teec_ctx, shm02, BIG_SIZE,
                               TEEC_MEMREF_PARTIAL_OUTPUT);
    }

    op.params[0].value.a = (uint32_t)propSet;
    SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, shm01, nameLen);
    SET_SHARED_MEMORY_OPERATION_PARAMETER(2, 0, shm02, shm02->size);

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    if (res != TEE_SUCCESS)
        goto exit;

    if (expectedValue != VALUE_NONE) {
        expectedValueLen = strlen(expectedValue) + 1;
        if (memcmp(op.params[2].memref.parent->buffer, expectedValue,
                   expectedValueLen)) {
            printf("Bad buffer values!\n");
        }
    }

exit:
    TEEC_ReleaseSharedMemory(shm01);
    TEEC_ReleaseSharedMemory(shm02);
    free(shm01);
    free(shm02);
    return res;
}

static TEEC_Result Invoke_ProcessInvokeTAOpenSession(TEEC_Session *sess,
                                                     uint32_t cmdId,
                                                     uint32_t TACmd,
                                                     TEEC_UUID *UUID,
                                                     uint32_t returnOrigin)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    TEEC_SharedMemory *shm01;
    uint32_t org;

    shm01 = malloc(sizeof(TEEC_SharedMemory));

    ALLOCATE_AND_FILL_SHARED_MEMORY(&teetest_teec_ctx, shm01, BIG_SIZE,
                                    TEEC_MEMREF_PARTIAL_INPUT, 16, UUID);

    op.params[0].value.a = TACmd;
    SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, shm01, 16);
    op.params[2].value.a = returnOrigin;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_PARTIAL_INPUT,
                                     TEEC_VALUE_OUTPUT, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    if (TEE_ORIGIN_NOT_TRUSTED_APP == returnOrigin) {
        if (op.params[2].value.a == TEE_ORIGIN_TRUSTED_APP)
            printf("Return origin has unexpected value\n");
    } else {
        if (op.params[2].value.a != returnOrigin)
            printf("Return origin has unexpected value\n");
    }

exit:
    TEEC_ReleaseSharedMemory(shm01);
    free(shm01);
    return res;
}

static TEEC_Result Invoke_CheckMemoryAccessRight(TEEC_Session *sess,
                                                 uint32_t cmdId,
                                                 uint32_t memoryParamType,
                                                 uint32_t memoryAccessFlags)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    TEEC_SharedMemory *shm01;
    uint32_t org;

    shm01 = malloc(sizeof(TEEC_SharedMemory));
    ALLOCATE_SHARED_MEMORY(&teetest_teec_ctx, shm01, BIG_SIZE, memoryParamType);

    op.params[0].value.a = memoryAccessFlags;
    SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, shm01, shm01->size);

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, memoryParamType,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

exit:
    TEEC_ReleaseSharedMemory(shm01);
    free(shm01);
    return res;
}

static TEEC_Result Invoke_AllocatePropertyEnumerator(TEEC_Session *sess,
                                                     uint32_t cmdId,
                                                     uint32_t *enumerator)
{
  TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
  TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
  uint32_t org;

  op.params[0].value.a = 0;

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

  res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

  if (res != TEE_SUCCESS)
    goto exit;

  *enumerator = op.params[0].value.a;

exit:
  return res;
}

static TEEC_Result Invoke_StartPropertyEnumerator(TEEC_Session *sess,
                                                  uint32_t cmdId,
                                                  uint32_t enumerator,
                                                  TEE_PropSetHandle propSet)
{
  TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
  TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
  uint32_t org;

  op.params[0].value.a = enumerator;
  op.params[1].value.a = (uint32_t)propSet;

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_VALUE_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
  res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

  return res;
}

static TEEC_Result Invoke_ResetPropertyEnumerator(TEEC_Session *sess,
                                                  uint32_t cmdId,
                                                  uint32_t enumerator)
{
  TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
  TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
  uint32_t org;

  op.params[0].value.a = enumerator;

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

  res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

  return res;
}

static TEEC_Result Invoke_GetPropertyName(TEEC_Session *sess,
                                          uint32_t cmdId,
                                          uint32_t enumerator,
                                          char *propertyName,
                                          uint32_t kindBuffer,
                                          bool *pass_ok)
{
  TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
  TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
  uint32_t org;
  uint32_t strLen = 0;
  TEEC_SharedMemory *shm01;
  int help_cmp;

  shm01 = malloc(sizeof(TEEC_SharedMemory));

  if (kindBuffer == TOO_SHORT_BUFFER) {
    ALLOCATE_SHARED_MEMORY(&teetest_teec_ctx, shm01, 1, TEEC_MEMREF_PARTIAL_OUTPUT);
  } else {
    ALLOCATE_SHARED_MEMORY(&teetest_teec_ctx, shm01, BIG_SIZE, TEEC_MEMREF_PARTIAL_OUTPUT);
  }

  op.params[0].value.a = enumerator;
  SET_SHARED_MEMORY_OPERATION_PARAMETER(1, 0, shm01,
                shm01->size);

  op.paramTypes = TEEC_PARAM_TYPES(
    TEEC_VALUE_INPUT, TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
    TEEC_NONE);

  res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

  if (res != TEE_SUCCESS)
    goto exit;

  strLen = strlen(propertyName) + 1;

  if (op.params[1].memref.size != strLen) {
        printf("Invoke_GetPropertyName command returned error: expected (%x), "
          "actual (%x)\n", (int)op.params[1].memref.size, (int) strLen);
        *pass_ok = false;
  }

  help_cmp = memcmp(shm01->buffer, propertyName, strLen);
  if (0 != help_cmp) {
        printf("Invoke_GetPropertyName command returned error: expected (0), "
          "actual (%x)\n", (int)help_cmp);
        *pass_ok = false;
  }

exit:
  TEEC_ReleaseSharedMemory(shm01);
  free(shm01);
  return res;
}

static TEEC_Result Invoke_SetInstanceData(TEEC_Session *sess, uint32_t cmdId,
                                          char *data)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    TEEC_SharedMemory *shm01;
    uint32_t org;

    shm01 = malloc(sizeof(TEEC_SharedMemory));
    ALLOCATE_AND_FILL_SHARED_MEMORY(&teetest_teec_ctx, shm01, BIG_SIZE,
                                    TEEC_MEMREF_PARTIAL_INPUT, strlen(data) + 1,
                                    data);

    SET_SHARED_MEMORY_OPERATION_PARAMETER(0, 0, shm01, shm01->size);

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

exit:
    TEEC_ReleaseSharedMemory(shm01);
    free(shm01);
    return res;
}

static TEEC_Result Invoke_GetInstanceData(TEEC_Session *sess, uint32_t cmdId,
                                          char *expectedData,
                                          uint32_t expectedDataSize)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    TEEC_SharedMemory *shm01;
    uint32_t org;

    shm01 = malloc(sizeof(TEEC_SharedMemory));
    ALLOCATE_SHARED_MEMORY(&teetest_teec_ctx, shm01, BIG_SIZE,
                           TEEC_MEMREF_PARTIAL_OUTPUT);

    SET_SHARED_MEMORY_OPERATION_PARAMETER(0, 0, shm01, shm01->size);

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_OUTPUT, TEEC_NONE,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    if (res != TEE_SUCCESS)
        goto exit;

    if (res != TEE_ERROR_GENERIC) {
        if (op.params[0].memref.size != expectedDataSize)
            printf("Memref size different than expected\n");
        if (memcmp(shm01->buffer, expectedData, expectedDataSize))
            printf("Memref content different than expected\n");
    }

exit:
    TEEC_ReleaseSharedMemory(shm01);
    free(shm01);
    return res;
}

static TEEC_Result Invoke_MemFill(TEEC_Session *sess, uint32_t cmdId,
                                  uint32_t memoryFillSize, uint8_t *charFill)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.params[0].value.a = memoryFillSize;
    op.params[1].value.a = *charFill;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    return res;
}

static TEEC_Result Invoke_MemCompare(TEEC_Session *sess, uint32_t cmdId,
                                     uint32_t memorySize, uint32_t Case,
                                     uint32_t compareResult, bool *pass_ok)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;
    uint32_t outValue = 0;

    op.params[0].value.a = memorySize;
    op.params[1].value.a = Case;
    op.params[2].value.a = outValue;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                     TEEC_VALUE_OUTPUT, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    if (res != TEE_SUCCESS)
        goto exit;

    if (compareResult == RESULT_EQUAL) {
        if (op.params[2].value.a != 0)
            *pass_ok = false;
    } else if (compareResult == RESULT_INTEGER_GREATER_THAN_ZERO) {
        if ((int32_t)(op.params[2].value.a) <= 0)
            *pass_ok = false;
    } else if (compareResult == RESULT_INTEGER_LOWER_THAN_ZERO) {
        if ((int32_t)(op.params[2].value.a) >= 0)
            *pass_ok = false;
    }

exit:
    return res;
}

static TEEC_Result Invoke_MemMove(TEEC_Session *sess, uint32_t cmdId,
                                  uint32_t memorySize)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.params[0].value.a = memorySize;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    return res;
}

static TEEC_Result Invoke_Malloc(TEEC_Session *sess, uint32_t cmdId,
                                 uint32_t memorySize, uint32_t hint)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.params[0].value.a = memorySize;
    op.params[1].value.a = hint;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    return res;
}

static TEEC_Result Invoke_Realloc(TEEC_Session *sess, uint32_t cmdId,
                                  uint32_t oldMemorySize,
                                  uint32_t newMemorySize)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.params[0].value.a = oldMemorySize;
    op.params[1].value.a = newMemorySize;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    return res;
}

static TEEC_Result Invoke_Free(TEEC_Session *sess, uint32_t cmdId,
                               uint32_t Case)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.params[0].value.a = Case;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    return res;
}

#define Invoke_GetSystemTime Invoke_Simple_Function
#define Invoke_GetREETime Invoke_Simple_Function
#define Invoke_SetTAPersistentTime_and_GetTAPersistentTime_Overflow \
            Invoke_Simple_Function
#define Invoke_SetTAPersistentTime_and_GetTAPersistentTime \
            Invoke_Simple_Function
#define Invoke_GetTAPersistentTime_NotSet_and_SetTAPersistentTime \
            Invoke_Simple_Function
#define Invoke_ResetPersistentTime Invoke_Simple_Function

#define CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTime_Overflow \
    CMD_TEE_SetTAPersistentTime_and_GetTAPersistentTimeOverflow

static TEEC_Result Invoke_Simple_Function(TEEC_Session *sess, uint32_t cmdId)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);
    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);

    return res;
}

static TEEC_Result Invoke_Wait(TEEC_Session *sess, uint32_t cmdId,
                               uint32_t Case)
{
    TEEC_Result res = TEE_ERROR_NOT_SUPPORTED;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t org;

    op.params[0].value.a = Case;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(sess, cmdId, &op, &org);
    return res;
}

#endif
