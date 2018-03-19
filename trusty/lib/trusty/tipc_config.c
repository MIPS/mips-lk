/*
 * Copyright (c) 2014-2015, Google, Inc. All rights reserved
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
#include <assert.h>
#include <trace.h>

#include <lk/init.h>
#include <lib/trusty/tipc_dev.h>
#include <kernel/vm.h>
#include <platform/fdt.h>
#include <libfdt.h>

/* Default TIPC device (/dev/trusty-ipc-dev0) */
DECLARE_TIPC_DEVICE_DESCR(_descr0, 0, 32, 32, "dev0");

#define TIPC_DEV_NUM 1
static struct tipc_dev *tipc_devices[TIPC_DEV_NUM];

bool tipc_shm_paddr_within_range(paddr_t pa, size_t size)
{
	struct tipc_vdev_descr *desc = &_descr0;
	paddr_t pa_offset = (void *)pa - desc->shared_mem_base;

	if (!desc->shared_mem_base)
		return false;

	if (size > desc->shared_mem_size ||
			pa_offset > desc->shared_mem_size - size)
		return false;

	return true;
}

int tipc_dev_to_phys(paddr_t da, size_t size, paddr_t *pa)
{
	// XXX to support more than one tipc device, lookup the requested device
	// address translation in the correct tipc device address space.
	struct tipc_vdev_descr *desc = &_descr0;

	if (!desc->shared_mem_base)
		return ERR_NO_RESOURCES;

	if (size > desc->shared_mem_size || da > desc->shared_mem_size - size)
		return ERR_NO_RESOURCES;

	void *va = (void *)(desc->shared_mem_base + 0x80000000 + da);

	*pa = vaddr_to_paddr(va);
	if (*pa == (paddr_t)NULL)
		return ERR_NO_RESOURCES;

	return NO_ERROR;
}

static void tipc_init(uint level)
{
	status_t res;
	void *fdt = fdt_get();
	int offset;
	uint64_t base, len;
	int prop_size;
	fdt32_t const *prop;

	if (!fdt)
		return;

	offset = fdt_node_offset_by_compatible(fdt, -1, "trusty-virtio");

	if (offset < 0 || !fdt_is_enabled(fdt, offset))
		return;

	/* first set in reg contains address to config space */
	if (fdt_get_reg_val(fdt, offset, 0, &base, &len) < 0 || len < 0x200)
		return;

	_descr0.config_base = (void *) (uint) base;

	/* second set in reg contains specification of driver memory region */
	if (fdt_get_reg_val(fdt, offset, 1, &base, &len) < 0 || len == 0)
		return;

	_descr0.driver_mem_base = (void *) (uint) base;
	_descr0.driver_mem_size = (size_t) len;

	/* XXX need to resolve IRQ number via interrupt parent */
	prop = (fdt32_t const *) fdt_getprop(fdt, offset, "interrupts", &prop_size);

	if (!prop || prop_size < 4)
		return;

	_descr0.notify_irq = fdt32_to_cpu(prop[0]);

	/* look for  shared memory region */
	prop = (fdt32_t const *) fdt_getprop(fdt, offset, "trusty,shmem", 0);

	if (prop) {
		offset = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(prop[0]));

		if (offset >= 0 && fdt_is_enabled(fdt, offset)) {
			if (fdt_get_reg_val(fdt, offset, 0, &base, &len) >= 0) {
				_descr0.shared_mem_base = (void *) (uint) base;
				_descr0.shared_mem_size = (size_t) len;
			}
		}
	}

	if (!_descr0.shared_mem_size || !_descr0.shared_mem_base ||
			((uintptr_t)_descr0.shared_mem_base &
				(PAGE_SIZE - 1))) {
		_descr0.shared_mem_base = 0;
		_descr0.shared_mem_size = 0;
		res = ERR_NO_RESOURCES;
		panic("failed (%d) to register tee shmem\n", res);
	}

	res = create_tipc_device(&_descr0, sizeof(_descr0), &zero_uuid,
			&tipc_devices[0]);
	if (res != NO_ERROR) {
		panic("failed (%d) to register tipc device\n", res);
	}
}

LK_INIT_HOOK_FLAGS(tipc_init, tipc_init,
                   LK_INIT_LEVEL_APPS-2, LK_INIT_FLAG_PRIMARY_CPU);

