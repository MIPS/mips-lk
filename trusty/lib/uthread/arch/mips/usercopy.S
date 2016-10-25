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

#include <asm.h>
#include <arch/asm_macros.h>
#include <err.h>
#include <arch/uthread_mmu.h>

/* check for valid user address range; valid if ret == 0 */
.macro check_uaddr uaddr, len, ret, tmp
	.set push
	.set noat
	# valid if (mask & (uaddr | (uaddr + len) | len)) == 0
	addu	\tmp, \uaddr, \len
	or	\tmp, \tmp, \uaddr
	or	\tmp, \tmp, \len
	li	\ret, MAX_USR_VA_MASK
	and	\ret, \ret, \tmp
	.set pop
.endm

/* status_t arch_copy_to_user(user_addr_t udest, const void *ksrc, size_t len) */
FUNCTION(arch_copy_to_user)
	beqz	$a2, .Larch_copy_to_user_done
	check_uaddr $a0 /*uaddr*/, $a2 /*len*/, $t1, $t0
	bnez	$t1, .Larch_copy_to_user_fault
.Larch_copy_to_user_loop:
	lb	$t0, 0($a1)
	set_fault_handler	.Larch_copy_to_user_fault

	sb	$t0, 0($a0)
	addiu	$a0, $a0, 1
	addiu	$a1, $a1, 1
	addiu	$a2, $a2, -1
	bgtz	$a2, .Larch_copy_to_user_loop
.Larch_copy_to_user_done:
	move	$v0, $zero
	jr	$ra

/* status_t arch_copy_from_user(void *kdest, user_addr_t usrc, size_t len) */
FUNCTION(arch_copy_from_user)
	beqz	$a2, .Larch_copy_from_user_done
	check_uaddr $a1 /*uaddr*/, $a2 /*len*/, $t1, $t0
	bnez	$t1, .Larch_copy_from_user_fault
.Larch_copy_from_user_loop:
	set_fault_handler	.Larch_copy_from_user_fault
	lb	$t0, 0($a1)

	sb	$t0, 0($a0)
	addiu	$a0, $a0, 1
	addiu	$a1, $a1, 1
	addiu	$a2, $a2, -1
	bgtz	$a2, .Larch_copy_from_user_loop
.Larch_copy_from_user_done:
	move	$v0, $zero
	jr	$ra

/*
 * Copyright (c) 1998, 2015 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* MIPS assembly is derived from disassembled OpenBSD version of strlcpy.c */
/*	$OpenBSD: strlcpy.c,v 1.12 2015/01/15 03:54:12 millert Exp $	*/

/* ssize_t arch_strlcpy_from_user(char *kdst, user_addr_t usrc, size_t len) */
FUNCTION(arch_strlcpy_from_user)
	.set push
	beqz	$a2, .Larch_strlcpy_from_user_len_is_zero
	check_uaddr $a1 /*uaddr*/, $a2 /*len*/, $t1, $t0
	.set noreorder
	bnez	$t1, .Larch_strlcpy_from_user_fault
	  move	$v0, $a1
	addiu	$a2, $a2, -1
	b	.Larch_strlcpy_from_user_check_for_done
	  addu	$a2, $a2, $a1
.Larch_strlcpy_from_user_loop:
	set_fault_handler	.Larch_strlcpy_from_user_fault
	lbu	$v1, -1($v0)

	addiu	$a0, $a0, 1
	beqz	$v1, .Larch_strlcpy_from_user_done
	  sb	$v1, -1($a0)
.Larch_strlcpy_from_user_check_for_done:
	bne	$v0, $a2, .Larch_strlcpy_from_user_loop
	  addiu	$v0, $v0, 1
	addiu	$v0, $v0, -1
	sb	$zero, 0($a0)
.Larch_strlcpy_from_user_len_is_zero:
	addiu	$v0, $v0, 1
.Larch_strlcpy_from_user_get_src_len:
	lbu	$v1, -1($v0)
	bnez	$v1, .Larch_strlcpy_from_user_get_src_len
	  addiu	$v0, $v0, 1
	addiu	$v0, $v0, -1
.Larch_strlcpy_from_user_done:
	subu	$v0, $v0, $a1
	jr	$ra
	  addiu	$v0, $v0, -1
	.set pop

.Larch_strlcpy_from_user_fault:
	beqz	$a2, .Larch_copy_to_user_fault
.Larch_copy_from_user_fault:
	sb	$zero, 0($a0)
	addiu	$a0, $a0, 1
	addiu	$a2, $a2, -1
	bgtz	$a2, .Larch_copy_from_user_fault
.Larch_copy_to_user_fault:
	li	$v0, ERR_FAULT
	jr	$ra
