/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
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
#ifndef __LIB_UTHREAD_ARCH_MIPS_MMU_H
#define __LIB_UTHREAD_ARCH_MIPS_MMU_H

#include <arch/defines.h>

#define MMU_USER_SIZE_SHIFT	(25)
#define MAX_USR_VA		(1 << MMU_USER_SIZE_SHIFT)
#define MAX_USR_VA_MASK		(~(MAX_USR_VA - 1))

#define MMU_L1_INDEX		(20)
#define MMU_L1_INDEX_WIDTH	((MMU_USER_SIZE_SHIFT) - (MMU_L1_INDEX))
#define MMU_L1_INDEX_MASK	((1 << MMU_L1_INDEX_WIDTH) - 1)
#define MMU_L1_SIZE		(1 << (MMU_L1_INDEX_WIDTH + 2))

#define MMU_L2_INDEX		(PAGE_SIZE_SHIFT)
#define MMU_L2_INDEX_WIDTH	(MMU_L1_INDEX - MMU_L2_INDEX)
#define MMU_L2_INDEX_MASK	((1 << MMU_L2_INDEX_WIDTH) - 1)
#define MMU_L2_SIZE		(1 << (MMU_L2_INDEX_WIDTH + 2))

#ifndef ASSEMBLY

#include <arch.h>
#include <uthread.h>

typedef enum {
	PGTBL_NONE = 0,
	PGTBL_LEVEL_1_USER,
	PGTBL_LEVEL_1_PRIV,
	PGTBL_LEVEL_2,
} pgtbl_lvl_t;

void mips_uthread_mmu_free_pgtbl(uthread_t *ut);
status_t mips_uthread_mmu_query(uthread_t *ut, vaddr_t vaddr, paddr_t *paddr,
		u_int *flags);
status_t mips_uthread_mmu_map(uthread_t *ut, paddr_t paddr,
		vaddr_t vaddr, uint l1_flags, uint l2_flags);
status_t mips_uthread_mmu_unmap(uthread_t *ut, vaddr_t vaddr);

#endif // ASSEMBLY

#endif
