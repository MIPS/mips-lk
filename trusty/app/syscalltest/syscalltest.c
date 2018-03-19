/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
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

#include <lk/init.h>
#include <stdint.h>
#include <stdio.h>
#include <generated_syscalls.h>

#define TIME_TESTVAL (0x1122334455667788)

#define PASSED 0
#define FAILED 1
static const char* result_str[] = { "PASSED", "*FAILED*" };

long sys_gettime(uint32_t clock_id, uint32_t flags, int64_t *time)
{
	*time = TIME_TESTVAL;
	return PASSED;
}

#define RET_0()               (0)
#define RET_1(_a)             ((_a) << 0)
#define RET_2(_a, _b)         ((_a) << 0 | (_b) << 4)
#define RET_3(_a, _b, _c)     ((_a) << 0 | (_b) << 4 | (_c) << 8)
#define RET_4(_a, _b, _c, _d) ((_a) << 0 | (_b) << 4 | (_c) << 8 | (_d) << 12)
#define RET_5(_a, _b, _c, _d, _e) \
	((_a) << 0 | (_b) << 4 | (_c) << 8 | (_d) << 12 | \
	(_e) << 16)
#define RET_6(_a, _b, _c, _d, _e, _f) \
	((_a) << 0 | (_b) << 4 | (_c) << 8 | (_d) << 12 | \
	(_e) << 16 | (_f) << 20)
#define RET_7(_a, _b, _c, _d, _e, _f, _g) \
	((_a) << 0 | (_b) << 4 | (_c) << 8 | (_d) << 12 | \
	(_e) << 16 | (_f) << 20 | (_g) << 24)
#define RET_8(_a, _b, _c, _d, _e, _f, _g, _h) \
	((_a) << 0 | (_b) << 4 | (_c) << 8 | (_d) << 12 | \
	(_e) << 16 | (_f) << 20 | (_g) << 24 | (_h) << 28)

static long generic_syscall_8(uint64_t a, uint64_t b, uint64_t c, uint64_t d,
		uint64_t e, uint64_t f, uint64_t g, uint64_t h) {
	if ((a | b | c | d | e | f | g | h) & ~0xf)
		return -1;
	else
		return RET_8(a, b, c, d, e, f, g, h);
}

long sys_test_syscall_0(void)
{
	return generic_syscall_8(0, 0, 0, 0, 0, 0, 0, 0);
}

long sys_test_syscall_1(uint32_t a)
{
	return generic_syscall_8(a, 0, 0, 0, 0, 0, 0, 0);
}

long sys_test_syscall_2(uint32_t a, uint32_t b)
{
	return generic_syscall_8(a, b, 0, 0, 0, 0, 0, 0);
}

long sys_test_syscall_3(uint32_t a, uint32_t b, uint32_t c)
{
	return generic_syscall_8(a, b, c, 0, 0, 0, 0, 0);
}

long sys_test_syscall_4(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
{
	return generic_syscall_8(a, b, c, d, 0, 0, 0, 0);
}

long sys_test_syscall_4a(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
	return generic_syscall_8(a, b, c, d, 0, 0, 0, 0);
}

long sys_test_syscall_4b(uint64_t a, uint64_t b, uint64_t c, uint32_t d)
{
	return generic_syscall_8(a, b, c, d, 0, 0, 0, 0);
}

long sys_test_syscall_4c(uint32_t a, uint64_t b, uint64_t c, uint32_t d)
{
	return generic_syscall_8(a, b, c, d, 0, 0, 0, 0);
}

long sys_test_syscall_4d(uint32_t a, uint64_t b, uint32_t c, uint64_t d)
{
	return generic_syscall_8(a, b, c, d, 0, 0, 0, 0);
}

long sys_test_syscall_5(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t e) {
	return generic_syscall_8(a, b, c, d, e, 0, 0, 0);
}

long sys_test_syscall_5a(uint64_t a, uint64_t b, uint64_t c, uint32_t d,
		uint32_t e) {
	return generic_syscall_8(a, b, c, d, e, 0, 0, 0);
}

long sys_test_syscall_5b(uint32_t a, uint32_t b, uint64_t c, uint64_t d,
		uint64_t e) {
	return generic_syscall_8(a, b, c, d, e, 0, 0, 0);
}

long sys_test_syscall_5c(uint64_t a, uint32_t b, uint32_t c, uint64_t d,
		uint32_t e) {
	return generic_syscall_8(a, b, c, d, e, 0, 0, 0);
}

long sys_test_syscall_5d(uint32_t a, uint32_t b, uint32_t c, uint64_t d,
		uint64_t e) {
	return generic_syscall_8(a, b, c, d, e, 0, 0, 0);
}

long sys_test_syscall_6(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t e, uint32_t f) {
	return generic_syscall_8(a, b, c, d, e, f, 0, 0);
}

long sys_test_syscall_7(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t e, uint32_t f, uint32_t g) {
	return generic_syscall_8(a, b, c, d, e, f, g, 0);
}

long sys_test_syscall_8(uint32_t a, uint32_t b, uint32_t c, uint32_t d,
		uint32_t e, uint32_t f, uint32_t g, uint32_t h) {
	return generic_syscall_8(a, b, c, d, e, f, g, h);
}

#define CALL_TEST_SYSCALL(_rc, _fn, _expfn, _fargs...) \
	do { \
		long _exp, _ret; \
		\
		_exp = _expfn(_fargs); \
		_ret = _fn(_fargs); \
		/* preserve old error value */ \
		_rc |= _ret != _exp; \
		printf("%s - %s - exp %lx, ret %lx\n", #_fn, \
			result_str[_ret != _exp], _exp, _ret); \
	} while(0)

static int syscall_test_n_args(void)
{
	int ret = 0;
	uint32_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;

	CALL_TEST_SYSCALL(ret, test_syscall_0, RET_0);
	CALL_TEST_SYSCALL(ret, test_syscall_1, RET_1, a);
	CALL_TEST_SYSCALL(ret, test_syscall_2, RET_2, a, b);
	CALL_TEST_SYSCALL(ret, test_syscall_3, RET_3, a, b, c);

	CALL_TEST_SYSCALL(ret, test_syscall_4, RET_4, a, b, c, d);
	CALL_TEST_SYSCALL(ret, test_syscall_4a, RET_4, a, b, c, d);
	CALL_TEST_SYSCALL(ret, test_syscall_4b, RET_4, a, b, c, d);
	CALL_TEST_SYSCALL(ret, test_syscall_4c, RET_4, a, b, c, d);
	CALL_TEST_SYSCALL(ret, test_syscall_4d, RET_4, a, b, c, d);

	CALL_TEST_SYSCALL(ret, test_syscall_5, RET_5, a, b, c, d, e);
	CALL_TEST_SYSCALL(ret, test_syscall_5a, RET_5, a, b, c, d, e);
	CALL_TEST_SYSCALL(ret, test_syscall_5b, RET_5, a, b, c, d, e);
	CALL_TEST_SYSCALL(ret, test_syscall_5c, RET_5, a, b, c, d, e);
	CALL_TEST_SYSCALL(ret, test_syscall_5d, RET_5, a, b, c, d, e);

	CALL_TEST_SYSCALL(ret, test_syscall_6, RET_6, a, b, c, d, e, f);
	CALL_TEST_SYSCALL(ret, test_syscall_7, RET_7, a, b, c, d, e, f, g);
	CALL_TEST_SYSCALL(ret, test_syscall_8, RET_8, a, b, c, d, e, f, g, h);

	return ret;
}

static int syscall_from_kernel(void)
{
	int ret;
	int64_t time = 0;

	gettime(0, 0, &time);
	ret = (time == TIME_TESTVAL) ? PASSED : FAILED;
	printf("%s - gettime - expected %llx, got %llx\n",
			result_str[ret], TIME_TESTVAL, time);

	return ret;
}

static void print_result(int ret, const char *funcname, int exp)
{
	if (ret == exp)
		printf("%s - %s\n", result_str[PASSED], funcname);
	else
		printf("%s - %s - expected %d, got %d\n",
				result_str[FAILED], funcname, exp, ret);
}

#define RUN_TEST(_name, _exp) \
	print_result(_name(), #_name, _exp)

static void syscall_test_init(uint level)
{
	RUN_TEST(syscall_from_kernel, PASSED);
	RUN_TEST(syscall_test_n_args, PASSED);
}

LK_INIT_HOOK(syscall_test, syscall_test_init, LK_INIT_LEVEL_APPS);
