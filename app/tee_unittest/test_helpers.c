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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <tee_unittest.h>

extern uint32_t IGNORE;

TEE_Result teetest_teec_open_session(TEEC_Session *session,
                                     const TEEC_UUID *uuid, TEEC_Operation *op,
                                     uint32_t *ret_orig)
{
    return TEEC_OpenSession(&teetest_teec_ctx, session, uuid,
                TEEC_LOGIN_PUBLIC, NULL, op, ret_orig);
}

TEEC_Result RegisterSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm,
                                 uint32_t size, uint32_t flags)
{
    shm->flags = flags;
    shm->size = size;
    shm->buffer = malloc(size);
    return TEEC_RegisterSharedMemory(ctx, shm);
}

TEEC_Result AllocateSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm,
                                 uint32_t size, uint32_t flags)
{
    shm->flags = flags;
    shm->size = size;
    return TEEC_AllocateSharedMemory(ctx, shm);
}

void teec_set_operation_parameter_value(TEEC_Operation *op, size_t n,
                                        uint32_t a, uint32_t b)
{
    if (IGNORE != a)
        op->params[n].value.a = a;
    if (IGNORE != b)
        op->params[n].value.b = b;
}

void teec_set_operation_parameter_memref(TEEC_Operation *op, size_t n,
                                         TEEC_SharedMemory *parent,
                                         unsigned offset, unsigned size)
{
    op->params[n].memref.parent = parent;
    op->params[n].memref.offset = offset;
    op->params[n].memref.size = size;
}

void teec_set_operation_parameter_tmpref(TEEC_Operation *op, size_t n,
                                         uint8_t *buffer, unsigned size)
{
    op->params[n].tmpref.buffer = buffer;
    op->params[n].tmpref.size = size;
}

/* Functions imported from lk/lib/unittest */
static struct test_case_element *test_case_list = NULL;
static struct test_case_element *failed_test_case_list = NULL;

/*
 * Registers a test case with the unit test framework.
 */
void unittest_register_test_case(struct test_case_element *elem)
{
    DEBUG_ASSERT(elem);
    DEBUG_ASSERT(elem->next == NULL);
    elem->next = test_case_list;
    test_case_list = elem;
}

/*
 * Runs all registered test cases.
 */
void run_all_tests(void)
{
    unsigned int n_tests   = 0;
    unsigned int n_success = 0;
    unsigned int n_failed  = 0;

    bool all_success = true;
    struct test_case_element *current = test_case_list;
    while (current) {
        if (!current->test_case()) {
            current->failed_next = failed_test_case_list;
            failed_test_case_list = current;
            all_success = false;
        }
        current = current->next;
        n_tests++;
    }

    if (all_success) {
        n_success = n_tests;
        printf("SUCCESS!  All test cases passed!\n");
    } else {
        struct test_case_element *failed = failed_test_case_list;
        while (failed) {
            struct test_case_element *failed_next =
                        failed->failed_next;
            failed->failed_next = NULL;
            failed = failed_next;
            n_failed++;
        }
        n_success = n_tests - n_failed;
        failed_test_case_list = NULL;
    }

    printf("\n====================================================\n");
    printf  ("    CASES:  %d     SUCCESS:  %d     FAILED:  %d   ",
                      n_tests, n_success, n_failed);
    printf("\n====================================================\n");
}
