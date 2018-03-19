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
 * syscalls with up to 8 parameters are currently supported
 *
 * v0    = syscall number, expected to be trashed.
 * a0-a3 = args 1-4
 * t0-t3 = args 5-8
 * v0    = return value
 *
 * syscalls run with interrupts enabled
 * - caller must have already disabled interrupts
 *
 * Syscall Limitations:
 *
 * - Syscalls may define combinations of 32-bit and 64-bit parameter sizes
 *   which do not exceed a total size of eight 4-byte words.
 * - Certain combinations of parameter sizes and alignments may reduce the
 *   total number of parameters which may be declared.
 *
 * WARNING: It is possible to define syscall prototypes which violate the
 * stated restrictions without causing compilation errors. Problems are then
 * only visible at runtime.
 *
 * - On 32-bit mips systems, 64-bit arguments are passed as pairs of 32-bit
 *   registers (a0:a1, a2:a3, t0:t1, t2:t3). They should be defined as
 *   odd-numbered syscall parameters (1, 3, 5, 7) to avoid having the compiler
 *   maintain alignment by reserving two 32-bit registers to pad a single
 *   odd-numbered 32-bit argument.
 *
 * - When an odd-numbered 32-bit argument is followed by a 64-bit argument the
 *   compiler reserves one register for padding and the total number of
 *   parameters for that syscall prototype is reduced by one.
 */
void mips_syscall(struct mips_iframe *iframe)
{
	long ret;
	unsigned long syscall_num = iframe->v0;
	uint32_t (*fn8)(uint32_t, uint32_t, uint32_t, uint32_t,
			uint32_t, uint32_t, uint32_t, uint32_t) = 0;

	if (syscall_num < nr_syscalls)
		fn8 = (void*)syscall_table[syscall_num];

	ret = syscall_privilege_check(syscall_num);
	if (ret)
		fn8 = 0;

	if (fn8)
		ret = fn8(iframe->a0, iframe->a1, iframe->a2, iframe->a3,
			  iframe->t0, iframe->t1, iframe->t2, iframe->t3);
	else
		ret = sys_undefined(syscall_num);

	iframe->v0 = ret;
}
