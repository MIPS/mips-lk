/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2013, Google Inc. All rights reserved
 * Copyright (c) 2012-2013, NVIDIA CORPORATION. All rights reserved
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
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arch.h>
#include <arch/mips.h>
#include <arch/tlb.h>
#include <arch/mips/mmu.h>
#include <arch/uthread_mmu.h>
#include <lk/init.h>
#include <uthread.h>
#include <bits.h>

#define PAGE_MASK (PAGE_SIZE - 1)

static void mips_uthread_mmu_init(uint level)
{
	STATIC_ASSERT(KERNEL_BASE > MAX_USR_VA);
	STATIC_ASSERT(MAX_USR_VA ==
		((MMU_L1_SIZE / 4) * ((MMU_L2_SIZE / 4) * PAGE_SIZE)));

	mips_invalidate_tlb_global();
}

LK_INIT_HOOK_FLAGS(libuthreadmipsmmu, mips_uthread_mmu_init,
                   LK_INIT_LEVEL_ARCH_EARLY, LK_INIT_FLAG_ALL_CPUS);

static u_int *mips_uthread_mmu_alloc_pgtbl(pgtbl_lvl_t type)
{
	u_int size;
	u_int *pgtable = NULL;

	switch (type) {
	case PGTBL_LEVEL_1_USER:
		size = MMU_L1_SIZE;
		break;
// TODO currently no distinct privileged L1 table
//	case PGTBL_LEVEL_1_PRIV:
//		size = MMU_MEMORY_TTBR1_L1_SIZE;
//		break;
	case PGTBL_LEVEL_2:
		size = MMU_L2_SIZE;
		break;
	default:
		dprintf(CRITICAL, "unrecognized pgtbl_type %d\n", type);
		return pgtable;
	}
	pgtable = memalign(size, size);
	if (pgtable)
		memset(pgtable, 0, size);
	return pgtable;
}

static inline bool invalid_uaddr(vaddr_t vaddr)
{
	return vaddr & MAX_USR_VA_MASK;
}

static status_t pgd_walk(uint32_t *page_table, vaddr_t vaddr,
		u_int** pte_ptr, u_int *flags, int l2_alloc)
{
	u_int *level_2;
	addr_t level_2_addr;
	u_int idx;
	status_t err = NO_ERROR;

	if (!page_table) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	if (invalid_uaddr(vaddr)) {
		err = ERR_ACCESS_DENIED;
		goto done;
	}

	idx = vaddr >> MMU_L1_INDEX;
	idx &= MMU_L1_INDEX_MASK;

	level_2_addr = page_table[idx] & ~(MMU_L2_SIZE - 1);
	if (!level_2_addr && l2_alloc) {
		u_int l1_flags = *flags;

		/* alloc level 2 page table */
		level_2 = mips_uthread_mmu_alloc_pgtbl(PGTBL_LEVEL_2);
		if (level_2 == NULL) {
			dprintf(CRITICAL, "unable to allocate LEVEL_2 page table\n");
			err = ERR_NO_MEMORY;
			goto done;
		}

		/* install in level_1 */
		page_table[idx] = (typeof(*page_table))level_2;
		page_table[idx] |= l1_flags;
	} else if (!level_2_addr) {
		err = ERR_INVALID_ARGS;
		goto done;
	} else {
		level_2 = (typeof(level_2))level_2_addr;
	}

	idx = vaddr >> MMU_L2_INDEX;
	idx &= MMU_L2_INDEX_MASK;

	if (pte_ptr)
		*pte_ptr = &level_2[idx];

	if (flags && !l2_alloc)
		*flags = level_2[idx] & MMU_FLAGS;

done:
	return err;
}

void mips_uthread_mmu_free_pgtbl(uthread_t *ut)
{
	u_int idx;
	uint32_t *page_table;
	u_int *level_2;

	page_table = (uint32_t *)(ut->page_table);
	if (!page_table)
		return;

	for (idx = 0; idx < (MMU_L1_INDEX_MASK + 1); idx++) {
		level_2 = (typeof(level_2))page_table[idx];
		if (!level_2)
			continue;
		free(level_2);
	}
	free(page_table);
}

static status_t mips_uthread_mmu_pgd_walk_alloc(uint32_t *page_table, vaddr_t vaddr,
		u_int** pte_ptr, u_int flags)
{
	return pgd_walk(page_table, vaddr, pte_ptr, &flags, 1);
}

static status_t mips_uthread_mmu_pgd_walk(uint32_t *page_table, vaddr_t vaddr,
		u_int** pte_ptr, u_int *flags)
{
	return pgd_walk(page_table, vaddr, pte_ptr, flags, 0);
}

static inline paddr_t pte_ptr_to_paddr(u_int* pte_ptr) {
	return (*pte_ptr >> MMU_FLAG_BITS) << SHIFT_4K;
}

status_t mips_uthread_mmu_query(uthread_t *ut, vaddr_t vaddr, paddr_t *paddr,
		u_int *flags)
{
	status_t err;
	u_int *pte_ptr = NULL;
	uint32_t *page_table;

	page_table = (uint32_t *)(ut->page_table);
	if (!page_table)
		return ERR_INVALID_ARGS;

	err = pgd_walk(page_table, vaddr, &pte_ptr, flags, 0);
	if (err)
		return err;

	if (!pte_ptr || !(*pte_ptr & MMU_VALID))
		return ERR_ACCESS_DENIED;

	if (paddr)
		*paddr = pte_ptr_to_paddr(pte_ptr) | (vaddr & PAGE_MASK);

	return NO_ERROR;
}

status_t mips_uthread_mmu_map(uthread_t *ut, paddr_t paddr,
		vaddr_t vaddr, uint l1_flags, uint l2_flags)
{
	uint32_t *page_table;
	u_int *level_2_pte;
	status_t err = NO_ERROR;

	if (ut->page_table == NULL) {
		ut->page_table = mips_uthread_mmu_alloc_pgtbl(PGTBL_LEVEL_1_USER);
		if (ut->page_table == NULL) {
			dprintf(CRITICAL,
				"unable to allocate LEVEL_1 page table\n");
			err = ERR_NO_MEMORY;
			goto done;
		}
	}

	page_table = (uint32_t *)(ut->page_table);
	ASSERT(page_table);

	err = mips_uthread_mmu_pgd_walk_alloc(page_table, vaddr, &level_2_pte,
			l1_flags);
	if (err)
		goto done;

	ASSERT(!(*level_2_pte));

	/* install level_2 PAGE_SIZE entries */
	/* store pte such that tlb_refill can do ROTR to align paddr with tlb
	 * entrylo.PFN field and get RIXI flags into entrylo high order bits */
	*level_2_pte = ((paddr >> SHIFT_4K) << MMU_FLAG_BITS) | (l2_flags &
			MMU_FLAGS);

done:
	return err;
}

status_t mips_uthread_mmu_unmap(uthread_t *ut, vaddr_t vaddr)
{
	uint32_t *page_table;
	u_int *level_2_pte;
	status_t err = NO_ERROR;

	page_table = (uint32_t *)(ut->page_table);
	if (!page_table) {
		err = ERR_INVALID_ARGS;
		goto done;
	}

	err = mips_uthread_mmu_pgd_walk(page_table, vaddr, &level_2_pte, NULL);
	if (err)
		goto done;

	*level_2_pte = 0;	/* invalid entry */
	SYNC;
	mips_invalidate_tlb_asid(vaddr, mips_cpu_asid(ut, arch_curr_cpu_num()));

done:
	return err;
}
