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
#include <platform/mips-virt.h>
#include <platform/fdt.h>
#include <arch/mips.h>
#include <dev/virtio.h>
#include <libfdt.h>

extern void platform_init_interrupts(void);
extern void platform_init_uart(void);
extern void uart_init(void);

#if WITH_KERNEL_VM
struct mmu_initial_mapping mmu_initial_mappings[] = {
    {
        .phys = MEMBASE,
        .virt = KERNEL_BASE,
        .size = MEMSIZE,
        .flags = 0,
        .name = "ram"
    },
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

    mips_init_timer(100000000);
    mips_enable_irq(2);

    fdt_init();

#if WITH_KERNEL_VM
    /* look for a flattened device tree just before the kernel */
    void *fdt = fdt_get();
    if (fdt) {
        int node = fdt_path_offset(fdt, "/memory");

        if (node < 0) {
            printf("No RAM information found in device tree.\n");
        } else {
            uint64_t base, len;

            if (fdt_get_reg_val(fdt, node, 0, &base, &len) == 0) {
                ram_arena.base = base;
                ram_arena.size = len;
                printf("Setting RAM from DTB @0x%lx size: 0x%lx)\n",
                       ram_arena.base, ram_arena.size);
            } else {
                printf("Error reading memory entry from DTB.\n");
            }
        }
    }

    /* add the main memory arena */
    pmm_add_arena(&ram_arena);

    /* reserve the first page of ram, which should cover the vectab section */
    struct list_node list = LIST_INITIAL_VALUE(list);
    pmm_alloc_range(ram_arena.base, 1, &list);
#endif
}

static void platform_init_virtio_devices(void)
{
    void *fdt = fdt_get();

    if (!fdt)
        return;

    int devidx = 0;
    int offset = fdt_node_offset_by_compatible(fdt, -1, "virtio,mmio");

    while (offset >= 0) {
        if (fdt_is_enabled(fdt, offset))
            ++devidx;

        offset = fdt_node_offset_by_compatible(fdt, offset, "virtio,mmio");
    }

    if (devidx == 0 || virtio_mmio_alloc_devices(devidx) < 0)
        return;

    devidx = 0;
    offset = fdt_node_offset_by_compatible(fdt, -1, "virtio,mmio");
    while (offset >= 0) {
        uint64_t base, len;

        if (fdt_is_enabled(fdt, offset)
            && fdt_get_reg_val(fdt, offset, 0, &base, &len) == 0) {
            void *ptr = (void *) (uint) ((-1ULL << 31) + base);

            // XXX need to resolve IRQ number via interrupt parent
            int prop_size;
            fdt32_t const *prop =
                (fdt32_t const *) fdt_getprop(fdt, offset, "interrupts",
                                              &prop_size);

            if (prop && prop_size == 4) {
                uint irq = fdt32_to_cpu(*prop);

                if (virtio_mmio_setup_device(devidx, ptr, irq) >= 0)
                    ++devidx;
            }

        }

        offset = fdt_node_offset_by_compatible(fdt, offset, "virtio,mmio");
    }
}

void platform_init(void)
{
  platform_init_virtio_devices();
}
