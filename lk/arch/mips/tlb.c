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
#include <mips/m32tlb.h>
#include <mips/m32c0.h>
#include <arch/mips.h>
#include <arch/defines.h>

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

static void mips_setup_ftlb(void)
{
    // do we even have a FTLB?
    if (((mips_read_c0_config() >> 7) & 7) != 4)
      return;

    uint32_t cfg4 = mips_read_c0_config4();

#if __mips_isa_rev == 6
    unsigned mmudef = 3;
#else
    unsigned mmudef = (cfg4 >> 14) & 3;
#endif

    if (mmudef <= 1)
      return;

    unsigned new_ftlb_size;
    switch (PAGE_SIZE)
    {
    case 0x400:  new_ftlb_size = 0; break;
    case 0x1000: new_ftlb_size = 1; break;
    case 0x4000: new_ftlb_size = 2; break;
    case 0x10000: new_ftlb_size = 3; break;
    default: new_ftlb_size = 0; break;
    }

    cfg4 &= ~(0x1fUL << 8);
    cfg4 |= new_ftlb_size << 8;

    mips_write_c0_config4(cfg4);
}

void mips_tlb_init(void)
{
#if (WITH_KERNEL_VM)
    mips_tlbinvalall();
    mips_setup_ftlb();

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
