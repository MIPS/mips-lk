/*
 * Copyright (c) 2013-2017 Google Inc. All rights reserved
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

/* This file is auto-generated. !!! DO NOT EDIT !!! */

#include <asm.h>
#include <generated_syscalls.h>

.section .text.gettime
FUNCTION(gettime)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_gettime
    syscall
    j       $ra
      nop

.section .text.test_syscall_0
FUNCTION(test_syscall_0)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_0
    syscall
    j       $ra
      nop

.section .text.test_syscall_1
FUNCTION(test_syscall_1)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_1
    syscall
    j       $ra
      nop

.section .text.test_syscall_2
FUNCTION(test_syscall_2)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_2
    syscall
    j       $ra
      nop

.section .text.test_syscall_3
FUNCTION(test_syscall_3)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_3
    syscall
    j       $ra
      nop

.section .text.test_syscall_4
FUNCTION(test_syscall_4)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_4
    syscall
    j       $ra
      nop

.section .text.test_syscall_5
FUNCTION(test_syscall_5)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_5
    syscall
    j       $ra
      nop

.section .text.test_syscall_6
FUNCTION(test_syscall_6)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_6
    syscall
    j       $ra
      nop

.section .text.test_syscall_7
FUNCTION(test_syscall_7)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_7
    syscall
    j       $ra
      nop

.section .text.test_syscall_8
FUNCTION(test_syscall_8)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_8
    syscall
    j       $ra
      nop

.section .text.test_syscall_4a
FUNCTION(test_syscall_4a)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_4a
    syscall
    j       $ra
      nop

.section .text.test_syscall_4b
FUNCTION(test_syscall_4b)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_4b
    syscall
    j       $ra
      nop

.section .text.test_syscall_4c
FUNCTION(test_syscall_4c)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_4c
    syscall
    j       $ra
      nop

.section .text.test_syscall_4d
FUNCTION(test_syscall_4d)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_4d
    syscall
    j       $ra
      nop

.section .text.test_syscall_5a
FUNCTION(test_syscall_5a)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_5a
    syscall
    j       $ra
      nop

.section .text.test_syscall_5b
FUNCTION(test_syscall_5b)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_5b
    syscall
    j       $ra
      nop

.section .text.test_syscall_5c
FUNCTION(test_syscall_5c)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_5c
    syscall
    j       $ra
      nop

.section .text.test_syscall_5d
FUNCTION(test_syscall_5d)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_test_syscall_5d
    syscall
    j       $ra
      nop
