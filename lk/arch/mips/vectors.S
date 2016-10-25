/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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
#include <asm.h>
#include <arch/mips.h>

.macro iframe_save
    .set    push
    .set    noat
    addiu   $sp, -IFRAME_SIZE

    /* save all the non temporary registers */
    sw      $at, 0($sp)
    sw      $v0, 4($sp)
    sw      $v1, 8($sp)
    sw      $a0, 12($sp)
    sw      $a1, 16($sp)
    sw      $a2, 20($sp)
    sw      $a3, 24($sp)
    sw      $t0, 28($sp)
    sw      $t1, 32($sp)
    sw      $t2, 36($sp)
    sw      $t3, 40($sp)
    sw      $t4, 44($sp)
    sw      $t5, 48($sp)
    sw      $t6, 52($sp)
    sw      $t7, 56($sp)
    sw      $t8, 60($sp)
    sw      $t9, 64($sp)
    sw      $gp, 68($sp)
    /* sp is saved earlier */
    sw      $ra, 76($sp)
    mfhi    $at
    sw      $at, 80($sp)
    mflo    $at
    sw      $at, 84($sp)

    /* save the control registers */
    mfc0    $at, $12 /* status */
    sw      $at, 88($sp)
    mfc0    $at, $8 /* badvaddr */
    sw      $at, 92($sp)
    mfc0    $at, $13 /* cause */
    sw      $at, 96($sp)
    mfc0    $at, $14 /* epc */
    sw      $at, 100($sp)

    .set    pop
.endm

.macro iframe_restore
    .set    push
    .set    noat

    /* restore the temporary registers */
    lw      $at, 0($sp)
    lw      $v0, 4($sp)
    lw      $v1, 8($sp)
    lw      $a0, 12($sp)
    lw      $a1, 16($sp)
    lw      $a2, 20($sp)
    lw      $a3, 24($sp)
    lw      $t0, 28($sp)
    lw      $t1, 32($sp)
    lw      $t2, 36($sp)
    lw      $t3, 40($sp)
    lw      $t4, 44($sp)
    lw      $t5, 48($sp)
    lw      $t6, 52($sp)
    lw      $t7, 56($sp)
    lw      $t8, 60($sp)
    lw      $t9, 64($sp)
    lw      $gp, 68($sp)
    /* restore sp below */
    lw      $ra, 76($sp)
    lw      $k0, 80($sp)
    mthi    $k0
    lw      $k0, 84($sp)
    mtlo    $k0

    /* restore some control registers */
    lw      $k0, 88($sp)
    mtc0    $k0, $12 /* status */
    lw      $k0, 100($sp)
    mtc0    $k0, $14 /* epc */

    lw      $sp, IFRAME_SP($sp)
    .set    pop
.endm

#ifdef WITH_LIB_UTHREAD
#include <arch/mips/mmu.h>
#include <arch/uthread_mmu.h>

.macro get_kernel_sp ksp
    lui     \ksp, %hi(kernel_sp)
    lw      \ksp, %lo(kernel_sp)(\ksp)
.endm

.macro get_user_pgd pgd
    lui     \pgd, %hi(user_pgd)
    lw      \pgd, %lo(user_pgd)(\pgd)
.endm
#endif

.macro set_and_save_sp
#ifdef WITH_LIB_UTHREAD
    .set    push
    .set    noat
    mfc0    $k0, $12 /* status */
    ext     $k1, $k0, 3, 2
    .set    noreorder
    beqz    $k1, 1f /* 0 = kernel mode */
      move  $k0, $sp
    .set    reorder
    get_kernel_sp $k0
1:
    sw      $sp, (-IFRAME_SIZE+IFRAME_SP)($k0) /* save user sp in kernel_sp frame */
    move    $sp, $k0 /* switch to kernel_sp */
    .set    pop
#else
    sw      $sp, (-IFRAME_SIZE+IFRAME_SP)($sp)
#endif
.endm

.macro invalid_uaddr uaddr, ret
	.set push
	.set noat
	# invalid user address if (mask & uaddr) != 0
	li	\ret, MAX_USR_VA_MASK
	and	\ret, \ret, \uaddr
	.set pop
.endm

.section ".text.vectab"
FUNCTION(vectab)

.org 0
LOCAL_FUNCTION(_tlb_refill)
#ifdef WITH_LIB_UTHREAD
    .set    push
    .set    noreorder
    .set    noat
    mfc0    $k0, $8 /* badvaddr */
    invalid_uaddr $k0 $k1
    bnez    $k1, 1f
    srl     $k0, $k0, MMU_L1_INDEX
    andi    $k0, $k0, MMU_L1_INDEX_MASK
    sll     $k0, $k0, 2 /* size of L1 entry */
    get_user_pgd $k1
    addu    $k1, $k1, $k0
    lw      $k1, 0($k1) /* load pte pointer */
    beqz    $k1, 1f /* do slow path if NULL pte */
    mfc0    $k0, $4 /* context */
    srl     $k0, $k0, ((PAGE_SIZE_SHIFT - SHIFT_4K) + 1) /* scale context.badvpn2 alignment for 8 byte L2 entry pair */
    andi    $k0, $k0, ((MMU_L2_INDEX_MASK >> 1) << 3) /* context.badvpn2 field ignores low L2 index bit */
    addu    $k1, $k1, $k0
    lw      $k0, 0($k1)
    lw      $k1, 4($k1)
    rotr    $k0, $k0, TLB_ENTRYLO_RIXI_ROTR
    mtc0    $k0, $2 /* entrylo0 */
    rotr    $k1, $k1, TLB_ENTRYLO_RIXI_ROTR
    mtc0    $k1, $3 /* entrylo1 */
    .set    at=$k1
    li      $k0, ((PAGE_SIZE - PAGE_SIZE_4K) << 1) /* set ignored virtual addr bits */
    .set    noat
    mtc0    $k0, $5 /* pagemask */
    ehb
    tlbwr
    eret
     nop
1:
    b       _irq
    .set    pop
#else /* !WITH_LIB_UTHREAD */
    b       _irq
#endif

/* compatibility mode irq/syscall/general exception */
.org 0x180
LOCAL_FUNCTION(_irq)
    set_and_save_sp
    la      $k0, mips_gen_exception
    li      $k1, 0
    b       shared_irq_save_return

#if !WITH_MIPS_IRQCOMPAT_MODE
/* vectored base */
.macro vectored_irq, num
.org 0x200 + VECTORED_OFFSET_SHIFT * \num
_vectored_irq\num:
    set_and_save_sp
    la      $k0, mips_irq
    li      $k1, \num
    b       shared_irq_save_return
    b       .
.endm

vectored_irq 0
vectored_irq 1
vectored_irq 2
vectored_irq 3
vectored_irq 4
vectored_irq 5
vectored_irq 6
vectored_irq 7
vectored_irq 8
vectored_irq 9
#endif /* !WITH_MIPS_IRQCOMPAT_MODE */

/* branched to from above, k0 holds address to call, k1 holds arg to function */
shared_irq_save_return:
    iframe_save

    mfc0    $t0, $12 /* status */
    ins     $t0, $zero, 0, 5   # set kernel mode. clear IE, EXL, ERL, KSU
    mtc0    $t0, $12 /* status */
    ehb
    move    $a0, $sp
    move    $a1, $k1
    jal     $k0

    iframe_restore

    eret
