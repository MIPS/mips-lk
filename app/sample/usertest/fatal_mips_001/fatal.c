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

#include <trusty_std.h>
#include <trusty_unittest.h>

#define LOG_TAG "usertest"

/* force this test code into non-executatble .data section
 * over-ride default "ax" with "a" and # to ignore to end of line
 */
#warning run_in_data_section is purposely in .data.usertest and not .text
__attribute__ ((noinline, section (".data.usertest,\"a\" #")))
int run_in_data_section(void)
{
	return (volatile int)12345678;
}

static void userspace_fatal_execute_from_data_segment(void)
{
	TEST_BEGIN(__func__);

	long ret;

	TLOGI("Try to execute code in data segment @ %p\n", &run_in_data_section);
	ret = run_in_data_section();
	EXPECT_EQ(ERR_FAULT, ret, "userspace execute from data segment");

	TEST_END;
}

int main(void) {
	userspace_fatal_execute_from_data_segment();

	TLOGI("Conditions checked: %d\n", _tests_total);
	TLOGI("Conditions failed:  %d\n", _tests_failed);
	if (_tests_failed == 0)
		TLOGI("All tests PASSED\n");
	else
		TLOGI("Some tests FAILED\n");
}
