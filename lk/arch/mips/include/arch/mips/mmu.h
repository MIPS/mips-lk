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
#pragma once

#define TLB_ENTRYLO_PFN_SHIFT	(6)
#define TLB_ENTRYLO_RIXI_ROTR	(2)

/* mmu flags in TLB hardware */
#define MMU_NO_EXEC	(1 << 0)
#define MMU_NO_READ	(1 << 1)
#define MMU_GLOBAL	(1 << 2)
#define MMU_VALID	(1 << 3)
#define MMU_DIRTY	(1 << 4)
#define MMU_UNCACHED	(2 << 5)
#define MMU_CACHED	(3 << 5)
#define MMU_CACHE_MASK	(7 << 5)
#define MMU_FLAG_BITS	(8)
#define MMU_FLAGS	((1UL << MMU_FLAG_BITS)-1)

#define MMU_NO_PERM	(MMU_VALID | MMU_NO_EXEC | MMU_NO_READ)
#define MMU_RO		(MMU_VALID | MMU_NO_EXEC)
#define MMU_RW		(MMU_VALID | MMU_NO_EXEC | MMU_DIRTY)
#define MMU_RX		(MMU_VALID)
#define MMU_RWX		(MMU_VALID | MMU_DIRTY)

#ifndef ASSEMBLY

#define LOW_512MB_MASK  ((uintptr_t)0x1fffffff)
#define KUSEG           ((uintptr_t)0x00000000)
#define KSEG0           ((uintptr_t)0x80000000)
#define KSEG1           ((uintptr_t)0xa0000000)
#define KSEG2           ((uintptr_t)0xc0000000)
#define KSEG3           ((uintptr_t)0xe0000000)

static inline int is_low_512mb(uintptr_t addr)
{
    return !(addr & ~LOW_512MB_MASK);
}

static inline int is_kseg0(uintptr_t addr)
{
    return (addr >= KSEG0) && (addr < KSEG1);
}

static inline int is_kseg1(uintptr_t addr)
{
    return (addr >= KSEG1) && (addr < KSEG2);
}

static inline int is_kseg2(uintptr_t addr)
{
    return addr >= KSEG2;
}

static inline uintptr_t phys_to_kseg0(uintptr_t addr)
{
    return addr | KSEG0;
}

static inline uintptr_t kseg0_to_phys(uintptr_t addr)
{
    return addr - KSEG0;
}

static inline uintptr_t kseg1_to_phys(uintptr_t addr)
{
    return addr - KSEG1;
}

#endif // ASSEMBLY
