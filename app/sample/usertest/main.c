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

/*
 * Tests:
 * - TODO
 * -
 *
 */

#include <string.h>
#include <stdlib.h>
#include <trusty_std.h>

#include <trusty_unittest.h>

#define LOG_TAG "usertest"
#define MSEC 1000000UL

int main(void);

static void syscall_from_userspace_positive_test(void)
{
	long ret;
	int64_t time = 0;
	int64_t later_time = 0;
	uintptr_t uaddr = (uintptr_t)&time;
	int64_t *uaddr_not_aligned = (int64_t*)(uaddr | 0x1);
	long heap_cur_brk;

	TEST_BEGIN(__func__);

	ret = gettime(0, 0, &time);
	EXPECT_GE_ZERO(ret, "syscall gettime");

	ret = nanosleep (0, 0, 100 * MSEC);
	EXPECT_GE_ZERO(ret, "syscall nanosleep");

	ret = gettime(0, 0, &later_time);
	EXPECT_GT(later_time, time, "syscall gettime, time has incremented");

	ret = gettime(0, 0, uaddr_not_aligned);
	EXPECT_EQ(0, ret, "syscall handle user address not word aligned");

	heap_cur_brk = brk(0);
	EXPECT_GE_ZERO(heap_cur_brk, "syscall brk");

	heap_cur_brk = (heap_cur_brk & (PAGE_SIZE - 1));
	EXPECT_EQ(0, heap_cur_brk, "syscall brk aligned to PAGE_SIZE");

	TEST_END;
}

static void syscall_from_userspace_negative_test(void)
{
	long ret;
	int64_t time = 0;
	uintptr_t uaddr = (uintptr_t)&time;
	uintptr_t high_usr_va = 0x80000000U;
	int64_t *uaddr_above_max_usr_va = (int64_t*)(uaddr | high_usr_va);
	long heap_cur_brk;
	int64_t *uaddr_above_heap_cur_brk;

	TEST_BEGIN(__func__);

	/* tests arch_copy_to_user ability to detect user address out of range */
	ret = gettime(0, 0, uaddr_above_max_usr_va);
	EXPECT_EQ(ERR_FAULT, ret, "syscall handle user address above MAX_USR_VA");

	/* tests tlb exception handler for unmapped user address */
	heap_cur_brk = brk(0);
	uaddr_above_heap_cur_brk = (int64_t*)(heap_cur_brk + 8);
	ret = gettime(0, 0, (int64_t*)uaddr_above_heap_cur_brk);
	EXPECT_EQ(ERR_FAULT, ret, "syscall handle user address above heap brk");

	TEST_END;
}

extern unsigned int __bss_start;
extern unsigned int __bss_end__;
static int data_in_bss = 0;

static void userspace_memory_access_positive_test(void)
{
	TEST_BEGIN(__func__);

	EXPECT_EQ(1, (&data_in_bss >= (int*)&__bss_start), "data in bss segment");
	EXPECT_EQ(1, (&data_in_bss < (int*)&__bss_end__), "data in bss segment");
	EXPECT_EQ(0, data_in_bss, "userspace read of data segment");

	data_in_bss = 0xff;
	EXPECT_EQ(0xff, data_in_bss, "userspace write of data segment");

	TEST_END;
}

static void userspace_memory_access_negative_test(void)
{
	TEST_BEGIN(__func__);

	long ret;
	char *main_addr = (char*)&main;

	ret = gettime(0, 0, (int64_t*)main_addr);
	EXPECT_EQ(ERR_FAULT, ret, "userspace write of text segment");

	TEST_END;
}

static void run_all_tests(void) {
	TLOGI("Starting USERTEST\n");

	/* reset test state */
	_tests_total  = 0;
	_tests_failed = 0;

	/* positive tests */
	syscall_from_userspace_positive_test();
	userspace_memory_access_positive_test();

	/* negative tests */
	syscall_from_userspace_negative_test();
	userspace_memory_access_negative_test();

	TLOGI("Conditions checked: %u\n", _tests_total);
	TLOGI("Conditions failed:  %u\n", _tests_failed);
	if (_tests_failed == 0)
		TLOGI("All tests PASSED\n");
	else
		TLOGI("Some tests FAILED\n");
}

int main(void) {
	run_all_tests();
}
