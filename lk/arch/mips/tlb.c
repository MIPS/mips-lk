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
#include <sys/types.h>
#include <mips/m32tlb.h>
#include <mips/m32c0.h>
#include <arch/mips.h>

void mips_invalidate_tlb_global(void)
{
    mips_tlbinvalall();
}

void mips_invalidate_tlb_asid(vaddr_t va, uint32_t asid)
{
    tlbhi_t entryhi = (va & ~0x1fffUL) | (asid & C0_ENTRYHI_ASID_MASK);
    mips_tlbinval(entryhi);
}

#define PG_RIE (1 << 31)
#define PG_XIE (1 << 30)
#define PG_IEC (1 << 27)

void mips_tlb_init(void)
{
#if (WITH_KERNEL_VM)
    mips_tlbinvalall();

    /* enable read and execute inhibit if implemented */
    if (mips_read_c0_config3() & CFG3_RXI)
    {
        mips_write_c0_entryhi(0);
        mips_write_c0_entrylo0(0);
        mips_write_c0_entrylo1(0);
        mips_write_c0_pagemask(3<<11);
        mips_write_c0_pagegrain(PG_RIE | PG_XIE | PG_IEC);
    }
#endif /* WITH_KERNEL_VM */
}
