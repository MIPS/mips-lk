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
#include <libfdt.h>
#include <platform/fdt.h>

extern ulong lk_boot_args[4];

static void *boot_fdt;

void fdt_init(void)
{
    boot_fdt = (void *)lk_boot_args[3];

    if (!boot_fdt || fdt_check_header(boot_fdt) < 0) {
        boot_fdt = 0;
    }
}

void *fdt_get(void)
{
    return boot_fdt;
}

static size_t fdt_get_cells_attrib(void *fdt, int offset, const char *name,
                                   int default_cells)
{
    int parent = fdt_parent_offset(fdt, offset);

    int size;
    fdt32_t const *prop = (fdt32_t const *) fdt_getprop(fdt, parent,
                                                        name, &size);

    if (prop && size == 1) {
        int val = fdt32_to_cpu(*prop);

        if (val >= 0 && val < FDT_MAX_NCELLS)
            return val;
    }

    // Nothing? Check for a defintion in the root node.
    prop = (fdt32_t const *) fdt_getprop(fdt, 0, name, &size);

    if (prop && size == 1) {
        int val = fdt32_to_cpu(*prop);

        if (val >= 0 && val < FDT_MAX_NCELLS)
            return val;
    }

    return default_cells;
}

void fdt_get_cells(void *fdt, int offset,
                   size_t *addr_cells, size_t *size_cells)
{
  *addr_cells = fdt_get_cells_attrib(fdt, offset, "#address-cells", 1);
  *size_cells = fdt_get_cells_attrib(fdt, offset, "#size-cells", 1);
}

static uint64_t fdt_prop_val(fdt32_t const *prop, size_t cells)
{
    switch (cells)  {
    case 1: return fdt32_to_cpu(*prop);
    case 2:
        return (((uint64_t)fdt32_to_cpu(*prop)) << 32)
              + fdt32_to_cpu(*(prop + 1));
    }
    return 0;
}

static int fdt_translate_reg(void *fdt, int offset,
                             uint64_t *address, uint64_t *size)
{
    if (offset == 0)
        return 0;

    int parent = fdt_parent_offset(fdt, offset);

    if (parent == 0)
        return 0;

    int prop_sz;
    fdt32_t const *prop =
        (fdt32_t const *) fdt_getprop(fdt, parent, "ranges", &prop_sz);

    if (!prop)
        return -FDT_ERR_NOTFOUND;

    if (prop_sz == 0)
        return 0;

    size_t child_addr, child_sz, parent_addr, parent_sz;

    fdt_get_cells(fdt, offset, &child_addr, &child_sz);
    fdt_get_cells(fdt, parent, &parent_addr, &parent_sz);

    uint range_sz = child_addr + parent_addr + child_sz;

    if (prop_sz % range_sz != 0)
        return -FDT_ERR_BADSTATE;

    for (fdt32_t const *end = prop + prop_sz; prop < end; prop += range_sz) {
        uint64_t child_base = fdt_prop_val(prop, child_addr);
        uint64_t parent_base = fdt_prop_val(prop + child_addr, parent_addr);
        uint64_t sz = fdt_prop_val(prop + child_addr + parent_addr, child_sz);

        if (*address >= child_base && *address + *size <= child_base + sz) {
            *address = parent_base + (*address - child_base);
            return fdt_translate_reg(fdt, parent, address, size);
        }
    }

    return -FDT_ERR_NOTFOUND;
}

int fdt_get_reg_val(void *fdt, int offset, int index,
                    uint64_t *address, uint64_t *size)
{
    size_t addr_cells, size_cells;

    fdt_get_cells(fdt, offset, &addr_cells, &size_cells);

    /* only support up to 64bit addresses at the moment */
    if (addr_cells > 2 || size_cells > 2)
        return -FDT_ERR_BADSTATE;

    int rsize = addr_cells + size_cells;
    int prop_size;
    fdt32_t const *prop =
        (fdt32_t const *) fdt_getprop(fdt, offset, "reg", &prop_size);

    if (!prop && prop_size < 0)
        return prop_size;

    if (!prop)
        return -FDT_ERR_INTERNAL;

    if (prop_size < rsize * (index + 1))
        return -FDT_ERR_NOTFOUND;

    prop += rsize * index;

    *address = fdt_prop_val(prop, addr_cells);
    *size = fdt_prop_val(prop + addr_cells, size_cells);

    return fdt_translate_reg(fdt, offset, address, size);
}

bool fdt_is_enabled(void *fdt, int offset)
{
    int len;
    char const *p = (char const *) fdt_getprop(fdt, offset, "status", &len);

    if (!p)
      return true;

    return (len == 4 && !strncmp(p, "okay", 4))
           || (len == 2 && !strncmp(p, "ok", 2));
}

