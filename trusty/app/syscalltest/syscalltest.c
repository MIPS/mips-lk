/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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

#include <lk/init.h>
#include <stdint.h>
#include <stdio.h>
#include <generated_syscalls.h>

#define TIME_TESTVAL (0x1122334455667788)

long sys_gettime(uint32_t clock_id, uint32_t flags, int64_t *time)
{
	*time = TIME_TESTVAL;
	return 0;
}

static int syscall_from_kernel(void)
{
	long ret;
	int64_t time = 0;
	const char* result_str = "PASSED";

	ret = gettime(0, 0, &time);
	if (ret || (time != TIME_TESTVAL))
		result_str = "*FAILED*";

	printf("%s - gettime - expected %llx, got %llx. ret %ld\n",
			result_str, TIME_TESTVAL, time, ret);

	return ret;
}

static void print_result(int ret, const char *funcname, int expect)
{
	if (ret == expect) {
		printf("PASSED - %s\n", funcname);
	} else {
		printf("*FAILED* - %s - expected %d, got %d\n", funcname, expect, ret);
	}
}

#define RUN_TEST(name, expect) \
	print_result(name(), #name, expect)

static void syscall_test_init(uint level)
{
	RUN_TEST(syscall_from_kernel, 0);
}

LK_INIT_HOOK(syscall_test, syscall_test_init, LK_INIT_LEVEL_APPS);
