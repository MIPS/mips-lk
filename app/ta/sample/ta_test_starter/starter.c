/*
 * Copyright (c) 2016-218, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
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

#include <stddef.h>
#include <stdio.h>
#include <tee_client_api.h>
#include <ta_test_server.h>

#define PREFIX_STR "TA Starter:   "
#define DPRINTF(...) printf(PREFIX_STR __VA_ARGS__)

TEEC_Context teetest_teec_ctx;

void start_ta_test(void)
{
    TEEC_Result res = TEE_SUCCESS;
    uint32_t ret_orig;
#define MAX_SESSIONS    2
    TEEC_Session sessions[MAX_SESSIONS];
    TEEC_UUID uuids[MAX_SESSIONS] = {
        TA_TEST_CLIENT_UUID,
        TA_TEST_CLIENT2_UUID,
    };
    int i;

    for (i = 0; i < MAX_SESSIONS; i++) {
        res = TEEC_OpenSession(&teetest_teec_ctx, &sessions[i], &uuids[i],
                    TEEC_LOGIN_PUBLIC, NULL, NULL, &ret_orig);

        if (res != TEE_SUCCESS)
            DPRINTF("TEEC_OpenSession sessions[%d] returned %x. FAILED\n", i, res);
    }

    for (; --i >= 0; )
        TEEC_CloseSession(&sessions[i]);

}

int main(void)
{
    start_ta_test();
    return 0;
}
