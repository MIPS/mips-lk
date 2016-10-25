/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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

#include <uthread.h>
#include <stdlib.h>
#include <assert.h>
#include <debug.h>
#include <arch.h>
#include <arch/mips.h>
#include <arch/tlb.h>
#include <arch/mips/mmu.h>
#include <arch/uthread_mmu.h>
#include <uthread.h>

#define PAGE_MASK (PAGE_SIZE - 1)

vaddr_t kernel_sp[SMP_MAX_CPUS];
vaddr_t user_pgd[SMP_MAX_CPUS];
asid_t asid_version[SMP_MAX_CPUS];

uint32_t mips_cpu_asid(struct uthread *ut, uint cpu)
{
	return ut->arch.asid[cpu] & ASID_MASK;
}

static void mips_asid_init(struct uthread *ut)
{
	for (uint i = 0; i < SMP_MAX_CPUS; i++)
		ut->arch.asid[i] = ASID_RESERVED;
}

static void mips_asid_alloc(struct uthread *ut, uint cpu)
{
	asid_t asid = asid_version[cpu];

	asid += 1;
	if (!(asid & ASID_MASK))
	{
		mips_invalidate_tlb_global();

		if (!asid)
			asid = ASID_GEN_FIRST;
	}
	ut->arch.asid[cpu] = asid;
	asid_version[cpu] = asid;
}

static bool mips_asid_expired(struct uthread *ut, uint cpu)
{
	return (asid_version[cpu] & ASID_GEN_MASK) !=
		(ut->arch.asid[cpu] & ASID_GEN_MASK);
}

static void mips_clr_context(void)
{
	mips_write_c0_entryhi(ASID_RESERVED);
}

static void mips_set_context(struct uthread *ut, uint cpu)
{
	if (mips_asid_expired(ut, cpu))
		mips_asid_alloc(ut, cpu);
	mips_write_c0_entryhi(mips_cpu_asid(ut, cpu));
}

void arch_uthread_init()
{
	for (uint i = 0; i < SMP_MAX_CPUS; i++)
		asid_version[i] = ASID_INITIAL_VERSION;
}

void arch_uthread_startup(void)
{
	struct uthread *ut = (struct uthread *) tls_get(TLS_ENTRY_UTHREAD);
	vaddr_t stack = ROUNDDOWN(ut->start_stack, 8);
	uint32_t status = mips_read_c0_status();

	/* set user mode, enable interrupts and set EXL for eret to user mode */
	status &= ~(3<<3); // clear KSU_MASK
	status |= (1<<4); // set UM user mode
	status |= (1<<1); // set EXL
	status |= (1<<0); // set IE

	__asm__ volatile(
		"mtc0	%[epc], $14		\n"
		"mtc0	%[sr], $12		\n"
		"move	$sp, %[stack]		\n"
		"ehb				\n"
		"eret				\n"
		: : [stack] "r" (stack),
		    [epc] "r" (ut->entry),
		    [sr] "r" (status)
	);
}

static inline void set_kernel_sp(vaddr_t ksp, uint cpu)
{
	kernel_sp[cpu] = ksp;
}

static inline void set_user_pgd(vaddr_t pgd, uint cpu)
{
	user_pgd[cpu] = pgd;
}

static inline void clear_uthread_context(struct uthread *ut)
{
	uint cpu = arch_curr_cpu_num();

	(void)ut;
	set_kernel_sp(0, cpu);
	set_user_pgd(0, cpu);
	mips_clr_context();
}

static inline void set_uthread_context(struct uthread *ut)
{
	uint cpu = arch_curr_cpu_num();

	set_kernel_sp(ut->arch.kernel_stack, cpu);
	set_user_pgd((vaddr_t)ut->page_table, cpu);
	mips_set_context(ut, cpu);
}

void arch_uthread_context_switch(struct uthread *old_ut, struct uthread *new_ut)
{
	if (!old_ut && !new_ut)
		return;

	if (old_ut && !new_ut)
		clear_uthread_context(old_ut);

	if (new_ut)
		set_uthread_context(new_ut);
}

status_t arch_uthread_create(struct uthread *ut)
{
	ut->arch.kernel_stack = ut->thread->arch.cs_frame.sp;
	mips_asid_init(ut);
	return NO_ERROR;
}

void arch_uthread_free(struct uthread *ut)
{
	mips_uthread_mmu_free_pgtbl(ut);
}

status_t arch_uthread_map(struct uthread *ut, struct uthread_map *mp)
{
	addr_t vaddr, paddr;
	u_int pg;
	u_int l1_flags = 0;
	u_int l2_flags = 0;
	status_t err = NO_ERROR;

	if (mp->size > MAX_USR_VA || mp->vaddr > (MAX_USR_VA - mp->size)) {
		dprintf(CRITICAL, "virtual address exceeds max: 0x%x\n",
			MAX_USR_VA);

		err = ERR_INVALID_ARGS;
		goto done;
	}

	ASSERT(!(mp->size & PAGE_MASK));

	// TODO UTM_NS_MEM not supported
	//l1_flags = (mp->flags & UTM_NS_MEM) ? MMU_MEMORY_L1_PAGETABLE_NON_SECURE : 0;

	l2_flags = MMU_NO_PERM | MMU_VALID;
	if (mp->flags & UTM_R)
		l2_flags &= ~MMU_NO_READ;
	if (mp->flags & UTM_W)
		l2_flags |= MMU_DIRTY;
	if (mp->flags & UTM_X)
		l2_flags &= ~MMU_NO_EXEC;

	l2_flags |= (mp->flags & UTM_IO) ? MMU_UNCACHED : MMU_CACHED;

	for (pg = 0; pg < (mp->size / PAGE_SIZE); pg++) {
		if (mp->flags & UTM_PHYS_CONTIG)
			paddr = mp->pfn_list[0] + (pg * PAGE_SIZE);
		else
			paddr = mp->pfn_list[pg];

		if (paddr & PAGE_MASK) {
			dprintf(CRITICAL,
				"physical address not page aligned: 0x%lx\n",
				paddr);
			err = ERR_INVALID_ARGS;
			goto err_undo_maps;
		}

		vaddr = mp->vaddr + (pg * PAGE_SIZE);

		err = mips_uthread_mmu_map(ut, paddr, vaddr,
					l1_flags, l2_flags);

		if (err)
			goto err_undo_maps;
	}

	return NO_ERROR;

err_undo_maps:
	for(u_int p = 0; p < pg; p++) {
		mips_uthread_mmu_unmap(ut,
			mp->vaddr + (p * PAGE_SIZE));
	}
done:
	return err;
}

status_t arch_uthread_unmap(struct uthread *ut, struct uthread_map *mp)
{
	addr_t vaddr;
	u_int pg;
	status_t err = NO_ERROR;

	for (pg = 0; pg < (mp->size / PAGE_SIZE); pg++) {
		vaddr = mp->vaddr + (pg * PAGE_SIZE);
		err = mips_uthread_mmu_unmap(ut, vaddr);

		if (err)
			goto done;
	}

done:
	return err;
}
