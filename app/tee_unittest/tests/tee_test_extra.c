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
#warning revisit or skip tee_test_privileged_syscall when run with WITH_RICH_OS
#else
// #include <tee_internal_api.h>
#include <teec_api.h>
#endif

#include <ta_uuids.h>
#include <tee_test_case.h>

#define LOG_TAG "tee_unittest"

bool tee_test_privileged_syscall(void)
{
    int res;
    handle_t handle;
    const char *path = "tee_test_privileged_syscall_port";

    TEE_TEST_BEGIN("tee_test_privileged_syscall");
    res = port_create(path, 1, 64, 0);
    TEE_EXPECT_EQ(ERR_NOT_SUPPORTED, res, "Failed to deny privileged syscall: port_create");

    res = connect(path, 0);
    TEE_EXPECT_EQ(ERR_NOT_SUPPORTED, res, "Failed to deny privileged syscall: connect");

    handle = (handle_t)res;
    res = accept(handle, (uuid_t*)0);
    TEE_EXPECT_EQ(ERR_NOT_SUPPORTED, res, "Failed to deny privileged syscall: accept");

    TEE_TEST_END;
}

BEGIN_TEST_CASE(tee_test_extra_tests);
RUN_TEST(tee_test_privileged_syscall);
END_TEST_CASE(tee_test_extra_tests);

void register_tee_test_extra_tests(void)
{
    unittest_register_test_case(&_tee_test_extra_tests_element);
}
