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

#ifndef __MIPS_ARCH_UTHREAD_H
#define __MIPS_ARCH_UTHREAD_H

#include <kernel/vm.h>

struct uthread;

#define ASID_BITS 8
#define ASID_MASK ((1 << ASID_BITS) - 1)
#define ASID_GEN_MASK (~ASID_MASK)
#define ASID_GEN_FIRST (1 << ASID_BITS)
#define ASID_RESERVED 0
#define ASID_INITIAL_VERSION (ASID_GEN_MASK | ASID_RESERVED)

/*
 * The size of asid_t affects how often the ASID generation rolls over.  In
 * rare scenarios (i.e. extended sleep, cpu migration) where a thread comes
 * back online after a generation rollover it is unlikely but possible that
 * its ASID version could conflict with that of another thread.
 *
 * Choosing uint32_t is more efficient, choosing uint64_t make generation reuse
 * very rare.  Another solution is to traverse the uthread list and zero each
 * thread's ASID version when a generation rollover occurs.
 */
typedef uint64_t asid_t;

struct arch_uthread
{
	uint32_t kernel_stack;
	asid_t asid[SMP_MAX_CPUS];
};

uint32_t mips_cpu_asid(struct uthread *ut, uint cpu);

extern vaddr_t user_pgd[SMP_MAX_CPUS];

inline vaddr_t get_user_pgd(uint cpu)
{
	return user_pgd[cpu];
}
#endif
