/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2015 Travis Geiselbrecht
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
#include <reg.h>
#include <sys/types.h>
#include <kernel/thread.h>
#include <kernel/vm.h>
#include <platform.h>
#include <platform/interrupts.h>
#include <platform/debug.h>
#include <platform/timer.h>
#include <platform/mips-malta.h>
#include <arch/mips.h>

extern void platform_init_interrupts(void);
extern void platform_init_uart(void);
extern void uart_init(void);

#if WITH_KERNEL_VM
struct mmu_initial_mapping mmu_initial_mappings[] = {
	{ .phys = MEMBASE,
	  .virt = KERNEL_BASE,
	  .size = MEMSIZE,
	  .flags = 0,
	  .name = "ram" },

	/* null entry to terminate the list */
	{ 0 }
};

static pmm_arena_t ram_arena = {
    .name  = "ram",
    .base  =  MEMBASE,
    .size  =  MEMSIZE,
    .flags =  PMM_ARENA_FLAG_KMAP
};
#endif

void platform_early_init(void)
{
    platform_init_interrupts();
    platform_init_uart();

    mips_init_timer(100000000);
    mips_enable_irq(2);

#if WITH_KERNEL_VM
    /* add the main memory arena */
    pmm_add_arena(&ram_arena);

    /* reserve the first page of ram, which should cover the vectab section */
    struct list_node list = LIST_INITIAL_VALUE(list);
    pmm_alloc_range(MEMBASE, 1, &list);
#endif
}

void platform_init(void)
{
    uart_init();
}
