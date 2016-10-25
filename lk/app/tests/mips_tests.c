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

#include <err.h>
#include <mips/m32c0.h>
#include <app/tests.h>
#include <kernel/thread.h>
#include <unittest.h>

#define THREAD_JOIN_TIMEOUT (1000)

#define LOG_TAG "mips_tests"
#define TLOGI(fmt, ...) \
    unittest_printf("%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)

#define RUN_TEST_THREAD(test)                           \
    unittest_printf("    %-50s [RUNNING]\n",  #test );  \
    if (! run_test_in_thread(&test)) {                  \
         all_success = false;                           \
    } else {                                            \
        unittest_printf(" [PASSED] \n");                \
    }

bool run_test_in_thread(int (*test_fn)(void *arg))
{
    BEGIN_TEST;

    thread_t *t1 = thread_create( "test_thread", test_fn,
                       NULL, DEFAULT_PRIORITY, DEFAULT_STACK_SIZE);
    thread_resume(t1);

    int retcode = -1;
    status_t err = thread_join(t1, &retcode, THREAD_JOIN_TIMEOUT);
    EXPECT_EQ(NO_ERROR, err, "expecting thread_join with thread running fatal test");
    if (retcode != ERR_CANCELLED)
        EXPECT_EQ(ERR_GENERIC, retcode, "expecting thread_exit to be called on fatal test");

    END_TEST;
}

static int fatal_test_reserved_instruction(void* arg)
{
    BEGIN_TEST;
    TLOGI("Expect reserved instruction exception\n");
    asm volatile (".word   0xffffffff \n");
	END_TEST;
}

static int fatal_test_fpu_access(void* arg)
{
    BEGIN_TEST;

    int skip_fpu_test = 0;

    /* if no FP support then likely using softfloat library */
    if (!(mips_read_c0_config1() & CFG1_FP))
        skip_fpu_test = 1;

    /* if FPU enabled then no exception expected */
    if (mips_read_c0_status() & SR_CU1)
        skip_fpu_test = 1;

    if (skip_fpu_test) {
        TLOGI("Skip fpu access test\n");
        return ERR_CANCELLED;
    }

    TLOGI("Expect fpu access exception\n");
    volatile double a = (double)1;
    volatile double b = (double)3;
    double c;
    c = a / b;
    (void)c;
    EXPECT_EQ(0, 1, "fpu access");

	END_TEST;
}

static int fatal_test_integer_overflow(void* arg)
{
	BEGIN_TEST;
	int max_int = INT_MAX;
	asm volatile (
		"add %0, %1, %2 \n"
		: "=r"(max_int)
		: "r"(max_int), "r"(max_int));
	EXPECT_EQ(0, 1, "integer overflow");
	END_TEST;
}

static int fatal_test_div0(void *arg)
{
    BEGIN_TEST;
	volatile int a = 1;
	int b = 0;
	a = a / b;
	EXPECT_EQ(0, 1, "divide by zero");
    END_TEST;
}

static int fatal_test_kernel_unmapped_read_access(void *arg)
{
    BEGIN_TEST;
	volatile int *addr = (int*)PAGE_SIZE;
    int data;

	TLOGI("Try to read unmapped page @ %p\n", addr);
	data = *addr;
    (void)data;

	EXPECT_EQ(0, 1, "read unmapped page");
	END_TEST;
}

static int fatal_test_kernel_unmapped_write_access(void *arg)
{
    BEGIN_TEST;
	volatile int *addr = (int*)PAGE_SIZE;

	TLOGI("Try to write unmapped page @ %p\n", addr);
	*addr = 0xdeadbeef;

	EXPECT_EQ(0, 1, "write unmapped page");
	END_TEST;
}

static int fatal_test_syscall_in_delay_slot(void *arg)
{
    BEGIN_TEST;

	asm volatile (
		".set push      \n"
		".set noreorder \n"
		"b 1f           \n"
		"syscall        \n"
        "1:             \n"
		".set pop       \n"
        );

	EXPECT_EQ(0, 1, "syscall in branch delay slot not supported");
	END_TEST;
}

static int fatal_test_break_in_delay_slot(void *arg)
{
    BEGIN_TEST;

	asm volatile (
		".set push      \n"
		".set noreorder \n"
		"b 1f           \n"
		"break          \n"
        "1:             \n"
		".set pop       \n"
        );

	EXPECT_EQ(0, 1, "break in branch delay slot not supported");
	END_TEST;
}

BEGIN_TEST_CASE(fatal_mips_tests);
RUN_TEST_THREAD(fatal_test_fpu_access);
RUN_TEST_THREAD(fatal_test_reserved_instruction);
RUN_TEST_THREAD(fatal_test_integer_overflow);
RUN_TEST_THREAD(fatal_test_div0);
RUN_TEST_THREAD(fatal_test_kernel_unmapped_read_access);
RUN_TEST_THREAD(fatal_test_kernel_unmapped_write_access);
RUN_TEST_THREAD(fatal_test_syscall_in_delay_slot);
RUN_TEST_THREAD(fatal_test_break_in_delay_slot);
END_TEST_CASE(fatal_mips_tests);

void mips_tests(void)
{
    run_all_tests();
}
