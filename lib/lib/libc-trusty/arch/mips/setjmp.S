#include <mips/asm.h>

.text
.weak setjmp
.type setjmp,function
setjmp:
LEAF(__setjmp)
    sw      $ra,0($a0)
    sw      $sp,4($a0)

    sw      $s0,8($a0)
    sw      $s1,12($a0)
    sw      $s2,16($a0)
    sw      $s3,20($a0)
    sw      $s4,24($a0)
    sw      $s5,28($a0)
    sw      $s6,32($a0)
    sw      $s7,36($a0)
    sw      $s8,40($a0)
    sw      $gp,44($a0)

    move    $v0,$zero
    j       $ra
END(__setjmp)

.text
LEAF(longjmp)
    lw      $ra,0($a0)
    lw      $sp,4($a0)

    lw      $s0,8($a0)
    lw      $s1,12($a0)
    lw      $s2,16($a0)
    lw      $s3,20($a0)
    lw      $s4,24($a0)
    lw      $s5,28($a0)
    lw      $s6,32($a0)
    lw      $s7,36($a0)
    lw      $s8,40($a0)
    lw      $gp,44($a0)

    bne     $a1,$zero,1f
    li      $a1,1
1:
    move    $v0,$a1
    lw      $t9,0($a0)
    jr      $t9
END(longjmp)
