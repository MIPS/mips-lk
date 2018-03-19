/*
 * Copyright (c) 2013, Google Inc. All rights reserved
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

#include <debug.h>
#include <assert.h>
#include <sys/types.h>
#include <uthread.h>
#include <arch/uthread_mmu.h>
#include <lk/init.h>
#include <trusty_unittest.h>

#define LOG_TAG "uthread_test"

#define PAGE_MASK (PAGE_SIZE - 1)

extern void umain(void);

void uthread_test(void)
{
	TEST_BEGIN(__func__);

	status_t err;
	vaddr_t entry = 0x8000;
	vaddr_t stack_top = MAX_USR_VA >> 1;
	vaddr_t stack_size = PAGE_SIZE;

	ASSERT(!(entry & PAGE_MASK));
	ASSERT(!((vaddr_t)umain & PAGE_MASK));

	uthread_t *ut1 = uthread_create("test_ut1", entry,
				DEFAULT_PRIORITY, stack_top, stack_size, NULL);

	EXPECT_NE(0, ut1, "uthread_create test_ut1");
	if (!ut1) {
		TLOGI("uthread_create failed\n");
		return;
	}

	/* Map the code section at specified location using UTM_FIXED */
	err = uthread_map_contig(ut1, &entry, vaddr_to_paddr(umain),
			(size_t)PAGE_SIZE,
			UTM_R | UTM_W | UTM_X | UTM_FIXED,
			UT_MAP_ALIGN_DEFAULT);

	EXPECT_EQ(0, err, "uthread_map_contig, map code section with UTM_FIXED");
	if (err) {
		TLOGI("Error mapping code section %d\n", err);
		return;
	}


	/* Map in another time and remove it to test map/unmap; clearing
	 * UTM_FIXED selects a map address above stack top */
	vaddr_t map_addr1, map_addr2;
	err = uthread_map_contig(ut1, &map_addr1, vaddr_to_paddr(umain),
			(size_t)PAGE_SIZE,
			UTM_R | UTM_W | UTM_X,
			UT_MAP_ALIGN_DEFAULT);

	EXPECT_EQ(0, err, "uthread_map_contig, map again (1) not UTM_FIXED");
	if (err) {
		TLOGI("Error mapping sample segment (1) %d\n",
				err);
		return;
	}

	TLOGI("uthread_map_contig returned map_addr1 = 0x%lx\n", map_addr1);

	err = uthread_map_contig(ut1, &map_addr2, vaddr_to_paddr(umain),
			(size_t)0x10000,
			UTM_R | UTM_W | UTM_X,
			UT_MAP_ALIGN_1MB);

	EXPECT_EQ(0, err, "uthread_map_contig, map again (2) not UTM_FIXED");
	if (err) {
		TLOGI("Error mapping sample segment (2) %d\n",
				err);
		return;
	}

	TLOGI("uthread_map_contig returned map_addr2 = 0x%lx\n", map_addr2);

	/* Start unmapping sample segments */
	err = uthread_unmap(ut1, map_addr1, PAGE_SIZE);

	EXPECT_EQ(0, err, "uthread_unmap (1)");
	if (err) {
		TLOGI("Error unmapping sample segment (1) %d\n",
				err);
		return;
	} else {
		TLOGI("Successfully unmapped sample segment (1) \n");
	}

	err = uthread_unmap(ut1, map_addr2, 0x10000);

	EXPECT_EQ(0, err, "uthread_unmap (2)");
	if (err) {
		TLOGI("Error unmapping sample segment (2) %d\n",
				err);
		return;
	} else {
		TLOGI("Successfully unmapped sample segment (2)\n");
	}

	uthread_t *ut2 = uthread_create("test_ut2", entry,
			DEFAULT_PRIORITY, stack_top, stack_size, NULL);

	EXPECT_NE(0, ut2, "uthread_create test_ut2");
	if (!ut2) {
		TLOGI("uthread_create failed\n");
		return;
	}

	err = uthread_map_contig(ut2, &entry, vaddr_to_paddr(umain), PAGE_SIZE,
			UTM_R | UTM_W | UTM_X | UTM_FIXED,
			UT_MAP_ALIGN_DEFAULT);

	EXPECT_EQ(0, err, "uthread_map_contig, map code section with UTM_FIXED");
	if (err) {
		TLOGI("Error mapping code section %d\n", err);
		return;
	}

	/* start the uthread! */
	TLOGI("Starting uthread (1)\n");
	uthread_start(ut1);

	TLOGI("Starting uthread (2)\n");
	uthread_start(ut2);

	TEST_END

	TLOGI("Conditions checked: %u\n", _tests_total);
	TLOGI("Conditions failed:  %u\n", _tests_failed);
	if (_tests_failed == 0)
		TLOGI("All tests PASSED\n");
	else
		TLOGI("Some tests FAILED\n");
}

void uthread_test_run(uint level)
{
	uthread_test();
}

LK_INIT_HOOK(uthreadtest, uthread_test_run, LK_INIT_LEVEL_APPS);
