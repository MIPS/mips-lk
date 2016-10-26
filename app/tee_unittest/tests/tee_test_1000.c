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
#include <tee_unittest.h>
#include <uthread.h>

#if WITH_RICH_OS
#include <tee_client_api.h>
#else
// #include <tee_internal_api.h>
#include <teec_api.h>
#endif

#include <ta_uuids.h>
#include <tee_test_case.h>

#define LOG_TAG "tee_unittest"

static TEEC_UUID os_test_ta_uuid = TA_OS_TEST_UUID;
static TEEC_UUID create_fail_test_ta_uuid = TA_CREATE_FAIL_TEST_UUID;
static TEEC_UUID sims_test_ta_uuid = TA_SIMS_UUID;
static TEEC_UUID concurrent_ta_uuid = TA_CONCURRENT_UUID;

bool tee_test_many_sessions(void)
{
    TEEC_Result res;
    uint32_t ret_orig;
#define MAX_SESSIONS    3
    TEEC_Session sessions[MAX_SESSIONS];
    int i;

    TEE_TEST_BEGIN("tee_test_many_sessions");
    for (i = 0; i < MAX_SESSIONS; i++) {
        res = teetest_teec_open_session(&sessions[i], &os_test_ta_uuid,
                                        NULL, &ret_orig);
        TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
        if (res != TEE_SUCCESS)
            break;
    }

    for (; --i >= 0; )
        TEEC_CloseSession(&sessions[i]);

    TEE_TEST_END;
}

bool tee_test_basic_os_features(void)
{
    TEEC_Result res;
    TEEC_Session session = { 0 };
    uint32_t ret_orig;
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint8_t buf[32];

    TEE_TEST_BEGIN("tee_test_basic_os_features");
    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    if (res != TEE_SUCCESS) {
        TEE_TEST_END;
    }

    op.params[0].tmpref.buffer = buf;
    op.params[0].tmpref.size = sizeof(buf);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BASIC, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed invoking TA_OS_TEST_CMD_BASIC");

    TEEC_CloseSession(&session);
    TEE_TEST_END;
}

bool tee_test_panic(void)
{
    TEEC_Result res;
    TEEC_Session session = { 0 };
    uint32_t ret_orig;

    TEE_TEST_BEGIN("tee_test_panic");
    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    if (res != TEE_SUCCESS) {
        TEE_TEST_END;
    }

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_PANIC, NULL, &ret_orig);
    TEE_EXPECT_EQ(TEE_ERROR_TARGET_DEAD, res,
		    "Invoking TA_OS_TEST_CMD_PANIC. Invalid TEE_Panic return code.");

    TEE_EXPECT_EQ(TEE_ORIGIN_TEE, ret_orig, "Invalid TEE_Panic return origin");

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_INIT, NULL, &ret_orig);
    TEE_EXPECT_EQ(TEE_ERROR_TARGET_DEAD, res,
		    "Invoking command on panicked TA. Invalid panic return code.");

    TEE_EXPECT_EQ(TEE_ORIGIN_TEE, ret_orig, "Invalid panic return origin");

    TEEC_CloseSession(&session);
    TEE_TEST_END;
}

// static void load_fake_ta(void)
// {
//     static const TEEC_UUID fake_uuid = {
//         0x7e0a0900, 0x586b, 0x11e5,
//         { 0x93, 0x1f, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b }
//     };
//     TEEC_Session session = { 0 };
//     TEEC_Result res;
//     uint32_t ret_orig;
//     bool r;

//     r = copy_file(&create_fail_test_ta_uuid, NULL, &fake_uuid, NULL);

//     if (ADBG_EXPECT_TRUE(c, r)) {
//         res = xtest_teec_open_session(&session, &fake_uuid, NULL,
//                           &ret_orig);
//         if (res == TEEC_SUCCESS)
//             TEEC_CloseSession(&session);
//         ADBG_EXPECT_TEEC_RESULT(c, TEEC_ERROR_SECURITY, res);
//     }

//     ADBG_EXPECT_TRUE(c, rm_file(&fake_uuid, NULL));
// }

/* TODO: Split this test into multiple separate tests */
bool tee_test_invoke_command(void)
{
    TEEC_Result res;
    TEEC_Session session = { 0 };
    uint32_t ret_orig;

    TEE_TEST_BEGIN("tee_test_invoke_command");

    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                        &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    if (res != TEE_SUCCESS) {
        TEE_TEST_END;
    }

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CLIENT, NULL,
                             &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed invoking TA_OS_TEST_CMD_CLIENT");
    TEEC_CloseSession(&session);

    TEE_TEST_END;
}

bool tee_test_invoke_command_with_timeout(void)
{
    TEEC_Result res;
    TEEC_Session session = { 0 };
    uint32_t ret_orig;

    TEE_TEST_BEGIN("tee_test_invoke_command_with_timeout");

    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    op.params[0].value.a = 2000;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    if (res != TEE_SUCCESS) {
        TEE_TEST_END;
    }

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT,
                             &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res,
                  "Failed invoking TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT");

    TEEC_CloseSession(&session);

    TEE_TEST_END;
}

bool tee_test_create_session_fail(void)
{
    TEEC_Result res;
    TEEC_Session session_crypt = { 0 };
    uint32_t ret_orig;
    size_t n;

    TEE_TEST_BEGIN("tee_test_create_session_fail");

    res = teetest_teec_open_session(&session_crypt, &create_fail_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_ERROR_GENERIC, res,
                  "Open Session returned bad error code");

    /*
     * Run this several times to see that there's no memory leakage.
     */
    for (n = 0; n < 100; n++) {
        // printf("n = %zu", n);
        res = teetest_teec_open_session(&session_crypt, &create_fail_test_ta_uuid, NULL,
                                        &ret_orig);
        TEE_EXPECT_EQ(TEE_ERROR_GENERIC, res,
                      "Open Session returned bad error code");
    }

    TEE_TEST_END;
}

bool tee_test_load_fake_ta(void)
{
    TEE_TEST_BEGIN("tee_test_load_fake_ta");
    // load_fake_ta();
    TEE_TEST_END;
}

bool tee_test_load_corrupt_ta(void)
{
    //bool load;
    TEE_TEST_BEGIN("tee_test_load_corrupt_ta");

    // load = load_corrupt_ta(offsetof(struct shdr, magic), 1);
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(offsetof(struct shdr, img_size), 1);
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(offsetof(struct shdr, algo), 1);
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(offsetof(struct shdr, hash_size), 1);
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(offsetof(struct shdr, sig_size), 1);
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(sizeof(struct shdr), 1); /* hash */
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(sizeof(struct shdr) + 32, 1); /* sig */
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(3000, 1); /* payload */
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    // load = load_corrupt_ta(30000, 1); /* payload */
    // TEE_EXPECT_EQ(true, load, "Successfully loaded corrupt TA");

    TEE_TEST_END;
}

bool tee_test_invalid_memory_access(void)
{
    unsigned n;

    TEE_TEST_BEGIN("tee_test_invalid_memory_access");

    for (n = 1; n <= 5; n++) {
        TEEC_Result res;
        TEEC_Session session = { 0 };
        TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
        uint32_t ret_orig;

        res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                        &ret_orig);
        TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");

        if (res != TEE_SUCCESS)
            break;

        op.params[0].value.a = n;
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                         TEEC_NONE);

        res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_BAD_MEM_ACCESS, &op,
                                 &ret_orig);
        TEE_EXPECT_EQ(TEE_ERROR_TARGET_DEAD, res,
                      "Invoking command causing bad mem access. Invalid panic return code");

        TEE_EXPECT_EQ(TEE_ORIGIN_TEE, ret_orig, "Invalid panic return origin");

        TEEC_CloseSession(&session);
    }

    TEE_TEST_END;
}

bool tee_test_single_instance_multi_session(void)
{
    TEEC_Result res;
    TEEC_Session session1 = { 0 };
    TEEC_Session session2 = { 0 };
    uint32_t ret_orig;
    TEEC_UUID uuid = sims_test_ta_uuid;

    TEE_TEST_BEGIN("tee_test_single_instance_multi_session");

    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    static const uint8_t in[] = {
        0x5A, 0x6E, 0x04, 0x57, 0x08, 0xFB, 0x71, 0x96,
        0xF0, 0x2E, 0x55, 0x3D, 0x02, 0xC3, 0xA6, 0x92,
        0xE9, 0xC3, 0xEF, 0x8A, 0xB2, 0x34, 0x53, 0xE6,
        0xF0, 0x74, 0x9C, 0xD6, 0x36, 0xE7, 0xA8, 0x8E
    };
    uint8_t out[32] = { 0 };
    int i;

    res = teetest_teec_open_session(&session1, &uuid, NULL, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    if (res != TEE_SUCCESS) {
        TEE_TEST_END;
    }

    op.params[0].value.a = 0;
    op.params[1].tmpref.buffer = (void *)in;
    op.params[1].tmpref.size = sizeof(in);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&session1, TA_SIMS_CMD_WRITE, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed invoking TA_SIMS_CMD_WRITE");

    for (i = 1; i < 1000; i++) {
        res = teetest_teec_open_session(&session2, &uuid, NULL, &ret_orig);
        TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a second session");
        if (res != TEE_SUCCESS)
            break;

        op.params[0].value.a = 0;
        op.params[1].tmpref.buffer = out;
        op.params[1].tmpref.size = sizeof(out);
        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                         TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
                                         TEEC_NONE);

        res = TEEC_InvokeCommand(&session2, TA_SIMS_CMD_READ, &op, &ret_orig);
        TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed invoking TA_SIMS_CMD_READ");

        TEE_EXPECT_BUFFER(in, sizeof(in), out, sizeof(out));

        op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE,
                                         TEEC_NONE, TEEC_NONE);

        res = TEEC_InvokeCommand(&session1, TA_SIMS_CMD_GET_COUNTER, &op,
                                 &ret_orig);
        TEE_EXPECT_EQ(TEE_SUCCESS, res,
                      "Failed invoking TA_SIMS_CMD_GET_COUNTER - session#1");

        TEE_EXPECT_EQ(0, op.params[0].value.a,
                      "Bad parameter value - session#1");

        res = TEEC_InvokeCommand(&session2, TA_SIMS_CMD_GET_COUNTER, &op,
                                 &ret_orig);
        TEE_EXPECT_EQ(TEE_SUCCESS, res,
                      "Failed invoking TA_SIMS_CMD_GET_COUNTER - session#2");

        TEE_EXPECT_EQ(i, op.params[0].value.a,
                      "Bad parameter value - session#2");

        TEEC_CloseSession(&session2);
    }

    memset(out, 0, sizeof(out));
    op.params[0].value.a = 0;
    op.params[1].tmpref.buffer = out;
    op.params[1].tmpref.size = sizeof(out);
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                     TEEC_NONE, TEEC_NONE);

    res = TEEC_InvokeCommand(&session1, TA_SIMS_CMD_READ, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed invoking TA_SIMS_CMD_READ");

    TEE_EXPECT_BUFFER(in, sizeof(in), out, sizeof(out));

    TEEC_CloseSession(&session1);

    TEE_TEST_END;
}

struct test_concurrency_thread_arg {
    uint32_t cmd;
    uint32_t repeat;
    TEEC_SharedMemory *shm;
    uint32_t error_orig;
    TEEC_Result res;
    uint32_t max_concurrency;
    const uint8_t *in;
    size_t in_len;
    uint8_t *out;
    size_t out_len;
};

static void *test_concurrency_thread(void *arg)
{
    struct test_concurrency_thread_arg *a = arg;
    TEEC_Session session = { 0 };
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint8_t p2 = TEEC_NONE;
    uint8_t p3 = TEEC_NONE;

    a->res = teetest_teec_open_session(&session, &concurrent_ta_uuid, NULL,
                                       &a->error_orig);
    if (a->res != TEE_SUCCESS)
        return NULL;

    op.params[0].memref.parent = a->shm;
    op.params[0].memref.size = a->shm->size;
    op.params[0].memref.offset = 0;
    op.params[1].value.a = a->repeat;
    op.params[1].value.b = 0;
    op.params[2].tmpref.buffer = (void *)a->in;
    op.params[2].tmpref.size = a->in_len;
    op.params[3].tmpref.buffer = a->out;
    op.params[3].tmpref.size = a->out_len;

    if (a->in_len)
        p2 = TEEC_MEMREF_TEMP_INPUT;
    if (a->out_len)
        p3 = TEEC_MEMREF_TEMP_OUTPUT;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INOUT,
                                     TEEC_VALUE_INOUT, p2, p3);

    a->res = TEEC_InvokeCommand(&session, a->cmd, &op, &a->error_orig);
    a->max_concurrency = op.params[1].value.b;
    a->out_len = op.params[3].tmpref.size;
    TEEC_CloseSession(&session);
    return NULL;
}

#define NUM_THREADS 3

struct ta_concurrent_shm {
    uint32_t active_count;
};

static bool tee_test_concurrency_single(double *mean_concurrency)
{
#if 1 // NOT_YET
    (void)mean_concurrency;
    TEE_TEST_BEGIN("Test 1013 concurrency single");
    TEE_EXPECT_EQ(0, false, "Concurrency not implemented");
    TEE_TEST_END;
#else // NOT_YET
    TEEC_Result res;
    size_t num_threads = NUM_THREADS;
    size_t nt;
    size_t n;
    uthread_t thr[num_threads];
    int thr_ret;
    TEEC_SharedMemory shm;
    size_t max_concurrency;
    struct test_concurrency_thread_arg arg[num_threads];
    static const uint8_t sha256_in[] = { 'a', 'b', 'c' };
    static const uint8_t sha256_out[] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t out[32] = { 0 };

    *mean_concurrency = 0;

    TEE_TEST_BEGIN("Test 1013 single");

    memset(&shm, 0, sizeof(shm));
    shm.size = sizeof(struct ta_concurrent_shm);
    shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
    res = TEEC_AllocateSharedMemory(&teetest_teec_ctx, &shm);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to allocate shared memory");
    if (res != TEE_SUCCESS)
        return false;

    memset(shm.buffer, 0, shm.size);
    memset(arg, 0, sizeof(arg));
    max_concurrency = 0;
    nt = num_threads;

    for (n = 0; n < nt; n++) {
        arg[n].cmd = TA_CONCURRENT_CMD_BUSY_LOOP;
        arg[n].repeat = 10000;
        arg[n].shm = &shm;
        thr_ret = uthread_create("concurrent", test_concurrency_thread, 0, NULL,
                                 NULL, arg + n);
        TEE_EXPECT_EQ(0, thr_ret, "Failed to create thread");
        if (thr_ret)
            nt = n; /* break loop and start cleanup */
    }

    for (n = 0; n < nt; n++) {
        // thr_ret = uthread_exit(thr[n], NULL);
        TEE_EXPECT_EQ(0, thr_ret, "Failed joining the thread");
        TEE_EXPECT_EQ(TEE_SUCCESS, arg[n].res, "Bad value for the argument");
        if (arg[n].max_concurrency > max_concurrency)
            max_concurrency = arg[n].max_concurrency;
    }

    /*
     * Concurrency can be limited by several factors, for instance in a
     * single CPU system it's dependent on the Preemtion Model used by
     * the kernel (Preemptible Kernel (Low-Latency Desktop) gives the
     * best result there).
     */
    TEE_EXPECT_GT(max_concurrency, 0, "max_concurrency is <= 0");
    TEE_EXPECT_GT(num_threads, max_concurrency,
                  "num_threads is > max_concurrency");
    *mean_concurrency += max_concurrency;

    memset(shm.buffer, 0, shm.size);
    memset(arg, 0, sizeof(arg));
    max_concurrency = 0;
    nt = num_threads;

    for (n = 0; n < nt; n++) {
        arg[n].cmd = TA_CONCURRENT_CMD_SHA256;
        arg[n].repeat = 1000;
        arg[n].shm = &shm;
        arg[n].in = sha256_in;
        arg[n].in_len = sizeof(sha256_in);
        arg[n].out = out;
        arg[n].out_len = sizeof(out);
        thr_ret = uthread_create("concurrent", test_concurrency_thread, 0, NULL,
                                 NULL, arg + n);
        TEE_EXPECT_EQ(0, thr_ret, "Failed to create a pthread");
        if (thr_ret)
            nt = n; /* break loop and start cleanup */
    }

    for (n = 0; n < nt; n++) {
        // thr_ret = uthread_exit(thr[n], NULL);
        TEE_EXPECT_EQ(0, thr_ret, "Failed joining the thread");
        TEE_EXPECT_EQ(TEE_SUCCESS, arg[n].res, "Bad value for the argument");
        if ((thr_ret != 0) && (arg[n].res != TEE_SUCCESS)) {
            TEE_EXPECT_BUFFER(sha256_out, sizeof(sha256_out),
                              arg[n].out, arg[n].out_len);
        }
        if (arg[n].max_concurrency > max_concurrency)
            max_concurrency = arg[n].max_concurrency;
    }
    *mean_concurrency += max_concurrency;

    *mean_concurrency /= 2.0;
    TEEC_ReleaseSharedMemory(&shm);

    TEE_TEST_END;
#endif // NOT_YET
}

bool tee_test_concurrency(void)
{
    int i;
    double mean_concurrency;
    double concurrency;
    const int nb_loops = 50;
    bool test_passed = true;

    TEE_TEST_BEGIN("tee_test_concurrency");

    mean_concurrency = 0;
    for (i = 0; i < nb_loops; i++) {
        if (!tee_test_concurrency_single(&concurrency))
            test_passed = false;
        mean_concurrency += concurrency;
    }
    TEE_EXPECT_EQ(true, test_passed, "Concurrency test failed");
    mean_concurrency /= nb_loops;

    printf("    Number of parallel threads: %d", NUM_THREADS);
    printf("    Mean concurrency: %g", mean_concurrency);

    TEE_TEST_END;
}

bool tee_test_wait_01s(void)
{
    TEEC_Session session = { 0 };
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t ret_orig;
    TEEC_Result res;

    TEE_TEST_BEGIN("tee_test_wait_01s");

    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    TEE_EXPECT_EQ(TEE_ORIGIN_TRUSTED_APP, ret_orig, "Bad return origin value");
    if (res != TEE_SUCCESS || ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        TEE_TEST_END;
    }

    op.params[0].value.a = 100;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "InvokeCommand returned error");
    TEEC_CloseSession(&session);
    TEE_TEST_END;
}

bool tee_test_wait_05s(void)
{
    TEEC_Session session = { 0 };
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t ret_orig;
    TEEC_Result res;

    TEE_TEST_BEGIN("tee_test_wait_05s");

    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    TEE_EXPECT_EQ(TEE_ORIGIN_TRUSTED_APP, ret_orig, "Bad return origin value");
    if (res != TEE_SUCCESS || ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        TEE_TEST_END;
    }

    op.params[0].value.a = 500;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "InvokeCommand returned error");
    TEEC_CloseSession(&session);
    TEE_TEST_END;
}

#ifdef CANCELLATION_SUPPORT
bool tee_test_wait_2s_cancel(void)
{
    TEEC_Session session = { 0 };
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    pthread_t thr;
    uint32_t ret_orig, tmp_res;
    TEEC_Result res;

    TEE_TEST_BEGIN("tee_test_wait_2s_cancel");

    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    TEE_EXPECT_EQ(TEE_ORIGIN_TRUSTED_APP, ret_orig, "Bad return origin value");
    if (res != TEE_SUCCESS || ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        TEE_TEST_END;
    }

    op.params[0].value.a = 2000;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);
    tmp_res = pthread_create(&thr, NULL, cancellation_thread, &op);
    TEE_EXPECT_EQ(0, tmp_res, "Cannot create cancellation thread");

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_ERROR_CANCEL, res,
                  "InvokeCommand did not return ERROR_CANCEL");
    TEE_EXPECT_EQ(TEE_ORIGIN_TRUSTED_APP, ret_orig, "Bad return origin value");
    tmp_res = pthread_join(thr, NULL);
    TEE_EXPECT_EQ(0, tmp_res, "Cannot join thread");
    TEEC_CloseSession(&session);
    TEE_TEST_END;
}
#endif

bool tee_test_wait_2s(void)
{
    TEEC_Session session = { 0 };
    TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
    uint32_t ret_orig;
    TEEC_Result res;

    TEE_TEST_BEGIN("tee_test_wait_2s");

    res = teetest_teec_open_session(&session, &os_test_ta_uuid, NULL,
                                    &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "Failed to open a session");
    TEE_EXPECT_EQ(TEE_ORIGIN_TRUSTED_APP, ret_orig, "Bad return origin value");
    if (res != TEE_SUCCESS || ret_orig != TEE_ORIGIN_TRUSTED_APP) {
        TEE_TEST_END;
    }

    op.params[0].value.a = 2000;
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(&session, TA_OS_TEST_CMD_WAIT, &op, &ret_orig);
    TEE_EXPECT_EQ(TEE_SUCCESS, res, "InvokeCommand returned error");
    TEEC_CloseSession(&session);
    TEE_TEST_END;
}

BEGIN_TEST_CASE(tee_test_basic_tee_features);
/*
 * Placeholder for actual test functions:
 * RUN_TEST(test_function)
 */
RUN_TEST(tee_test_many_sessions);
// RUN_TEST(tee_test_basic_os_features);
RUN_TEST(tee_test_panic);
// RUN_TEST(tee_test_invoke_command);
// RUN_TEST(tee_test_invoke_command_with_timeout);
// RUN_TEST(tee_test_create_session_fail);
// RUN_TEST(tee_test_load_fake_ta);
// RUN_TEST(tee_test_load_corrupt_ta);
RUN_TEST(tee_test_invalid_memory_access);
RUN_TEST(tee_test_single_instance_multi_session);
// RUN_TEST(tee_test_concurrency);
RUN_TEST(tee_test_wait_01s);
RUN_TEST(tee_test_wait_05s);
RUN_TEST(tee_test_wait_2s);
#ifdef CANCELLATION_SUPPORT
RUN_TEST(tee_test_wait_2s_cancel);
#endif
END_TEST_CASE(tee_test_basic_tee_features);

void register_tee_test_basic_tee_features(void)
{
    unittest_register_test_case(&_tee_test_basic_tee_features_element);
}
