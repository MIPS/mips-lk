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
#include <sys/types.h>
#include <assert.h>
#include <err.h>
#include <trace.h>
#include <kernel/vm.h>
#include <arch/mips/mmu.h>

#define LOCAL_TRACE 0

static_assert(MMU_FLAG_BITS - TLB_ENTRYLO_RIXI_ROTR == TLB_ENTRYLO_PFN_SHIFT);

#if !(WITH_KERNEL_VM)
inline paddr_t vaddr_to_paddr(void *ptr)
{
    uintptr_t addr = (uintptr_t)ptr;

    if (is_kseg0(addr))
        return kseg0_to_phys(addr);
    else if (is_kseg1(addr))
        return kseg1_to_phys(addr);
    else if (is_kseg2(addr))
        return (paddr_t)NULL;
    else // is a KUSEG address
        return addr;
}
inline void *paddr_to_kvaddr(paddr_t pa)
{
    if (is_low_512mb(pa))
        return (void*)phys_to_kseg0(pa);
    else
        return (void*)NULL;
}
#else /* WITH_KERNEL_VM */

uint32_t mips_kernel_translation_table[256] __ALIGNED(PAGE_SIZE) __SECTION(".bss.prebss.translation_table");

static inline bool is_valid_vaddr(arch_aspace_t *aspace, vaddr_t vaddr)
{
    return (vaddr >= aspace->base && vaddr <= aspace->base + aspace->size - 1);
}

status_t arch_mmu_query(arch_aspace_t *aspace, vaddr_t vaddr, paddr_t *paddr, uint *flags)
{
    LTRACEF("aspace %p, vaddr 0x%lx\n", aspace, vaddr);

    DEBUG_ASSERT(aspace);
    DEBUG_ASSERT(aspace->tt_virt);

    DEBUG_ASSERT(is_valid_vaddr(aspace, vaddr));
    if (!is_valid_vaddr(aspace, vaddr))
        return ERR_OUT_OF_RANGE;

    /* TODO temporary... */
    if (is_kseg0(vaddr))
    {
        if (paddr)
            *paddr = kseg0_to_phys(vaddr);

        if (flags) {
            *flags = 0;
        }

        return NO_ERROR;
    }

    if (is_kseg1(vaddr))
    {
        if (paddr)
            *paddr = kseg1_to_phys(vaddr);

        if (flags) {
            *flags = 0; // TODO
        }

        return NO_ERROR;
    }

    /* TODO not implemented */
    return ERR_OUT_OF_RANGE;
}

int arch_mmu_map(arch_aspace_t *aspace, vaddr_t vaddr, paddr_t paddr, uint count, uint flags)
{
    LTRACEF("vaddr 0x%lx paddr 0x%lx count %u flags 0x%x\n", vaddr, paddr, count, flags);

    DEBUG_ASSERT(aspace);
    DEBUG_ASSERT(aspace->tt_virt);

    DEBUG_ASSERT(is_valid_vaddr(aspace, vaddr));
    if (!is_valid_vaddr(aspace, vaddr))
        return ERR_OUT_OF_RANGE;

    /* paddr and vaddr must be aligned */
    DEBUG_ASSERT(IS_PAGE_ALIGNED(vaddr));
    DEBUG_ASSERT(IS_PAGE_ALIGNED(paddr));
    if (!IS_PAGE_ALIGNED(vaddr) || !IS_PAGE_ALIGNED(paddr))
        return ERR_INVALID_ARGS;

    if (count == 0)
        return NO_ERROR;

    /* TODO not implemented */
    return NO_ERROR;
}

int arch_mmu_unmap(arch_aspace_t *aspace, vaddr_t vaddr, uint count)
{
    LTRACEF("vaddr 0x%lx count %u\n", vaddr, count);

    DEBUG_ASSERT(aspace);
    DEBUG_ASSERT(aspace->tt_virt);

    DEBUG_ASSERT(is_valid_vaddr(aspace, vaddr));
    if (!is_valid_vaddr(aspace, vaddr))
        return ERR_OUT_OF_RANGE;

    DEBUG_ASSERT(IS_PAGE_ALIGNED(vaddr));
    if (!IS_PAGE_ALIGNED(vaddr))
        return ERR_INVALID_ARGS;

    if (count == 0)
        return NO_ERROR;

    /* TODO not implemented */
    return NO_ERROR;
}

/*
 * mips only supports the kernel address space at the moment
 */
status_t arch_mmu_init_aspace(arch_aspace_t *aspace, vaddr_t base, size_t size, uint flags)
{
    LTRACEF("aspace %p, base 0x%lx, size 0x%zx, flags 0x%x\n", aspace, base, size, flags);

    DEBUG_ASSERT(aspace);

    /* validate that the base + size is sane and doesn't wrap */
    DEBUG_ASSERT(size > PAGE_SIZE);
    DEBUG_ASSERT(base + size - 1 > base);

    if (flags & ARCH_ASPACE_FLAG_KERNEL) {
        aspace->base = base;
        aspace->size = size;
        aspace->tt_virt = mips_kernel_translation_table;
        aspace->tt_phys = vaddr_to_paddr(aspace->tt_virt);
    } else {
        /* user address spaces not implemented */
        return ERR_NOT_SUPPORTED;
    }

    LTRACEF("tt_phys 0x%lx tt_virt %p\n", aspace->tt_phys, aspace->tt_virt);

    return NO_ERROR;
}

status_t arch_mmu_destroy_aspace(arch_aspace_t *aspace)
{
    return NO_ERROR;
}

void arch_mmu_context_switch(arch_aspace_t *aspace)
{
    if (aspace != NULL) {
        PANIC_UNIMPLEMENTED;
    }
}

#endif /* WITH_KERNEL_VM */
