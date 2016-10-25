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

#include <stdint.h>
#include <err.h>
#include <arch/mips.h>

extern long sys_undefined(int num);
extern const unsigned long syscall_table[];
extern unsigned long nr_syscalls;

__WEAK long syscall_privilege_check(unsigned long num)
{
	return NO_ERROR;
}

/* MIPS syscall ABI
 * ===============
 * Only syscalls with 4 args (max) are currently supported
 * v0    = syscall number, expected to be trashed.
 * a0-a3 = args
 * v0    = return value
 * syscalls run with interrupts enabled
 *
 * - caller must have already disabled interrupts
 */
void mips_syscall(struct mips_iframe *iframe)
{
	long ret;
	unsigned long syscall_num = iframe->v0;
	uint32_t (*fn)(uint32_t, uint32_t, uint32_t, uint32_t) = 0;

	if (syscall_num < nr_syscalls)
		fn = (void*)syscall_table[syscall_num];

	ret = syscall_privilege_check(syscall_num);
	if (ret)
		fn = 0;

	if (fn)
		ret = fn(iframe->a0, iframe->a1, iframe->a2, iframe->a3);
	else
		ret = sys_undefined(syscall_num);

	iframe->v0 = ret;
}
