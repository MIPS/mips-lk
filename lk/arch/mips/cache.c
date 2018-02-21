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
#include <mips/cpu.h>
#include <assert.h>

void arch_disable_cache(uint flags)
{
}

void arch_enable_cache(uint flags)
{
    mips_size_cache();
    mips_flush_cache();
}

/* clean (writeback) data in the data cache on the range */
void arch_clean_cache_range(addr_t start, size_t len)
{
    mips_clean_dcache(start, len);
}

/* clean (writeback) and then evict data from the data cache on the range */
void arch_clean_invalidate_cache_range(addr_t start, size_t len)
{
    mips_clean_dcache(start, len);
}

/* evict data from the data cache on the range */
void arch_invalidate_cache_range(addr_t start, size_t len)
{
    /*
     * Invalidate (but don't writeback) address range in data caches
     * XXX Only safe if region is totally cache-line aligned.
     */
    int cacheline_mask = mips_dcache_linesize - 1;
    (void)cacheline_mask;
    assert(!(start & cacheline_mask) && "Only safe if region is totally cache-line aligned");
    assert(!(len & cacheline_mask) && "Only safe if region is totally cache-line aligned");
    mips_clean_dcache_nowrite(start, len);
}

/*
 * clean (writeback) data on the range and then throw away the instruction cache,
 * ensuring that new instructions fetched from the range are not stale.
 */
void arch_sync_cache_range(addr_t start, size_t len)
{
    mips_sync_icache(start, len);
}
