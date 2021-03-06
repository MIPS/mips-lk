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

#include <trusty_std.h>
#include <trusty_unittest.h>

#define LOG_TAG "usertest"

static void userspace_fatal_test_cop0_instr(void)
{
	TEST_BEGIN(__func__);
	int var;
	asm volatile (
		"mfc0 %0, $15, 0 \n"
		: "=r"(var));
	EXPECT_EQ(0, 1, "cop0 instruction");
	TEST_END;
}

int main(void) {
	userspace_fatal_test_cop0_instr();

	TLOGI("Conditions checked: %u\n", _tests_total);
	TLOGI("Conditions failed:  %u\n", _tests_failed);
	if (_tests_failed == 0)
		TLOGI("All tests PASSED\n");
	else
		TLOGI("Some tests FAILED\n");
}
