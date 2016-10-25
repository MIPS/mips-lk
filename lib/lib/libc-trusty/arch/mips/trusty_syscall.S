/*
 * Copyright (c) 2013 Google Inc. All rights reserved
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
#include <trusty_syscalls.h>

.section .text.write
FUNCTION(write)
    li      $v0, __NR_write
    syscall
    j       $ra
      nop

.section .text.brk
FUNCTION(brk)
    li      $v0, __NR_brk
    syscall
    j       $ra
      nop

.section .text.exit_group
FUNCTION(exit_group)
    li      $v0, __NR_exit_group
    syscall
    j       $ra
      nop

.section .text.read
FUNCTION(read)
    li      $v0, __NR_read
    syscall
    j       $ra
      nop

.section .text.ioctl
FUNCTION(ioctl)
    li      $v0, __NR_ioctl
    syscall
    j       $ra
      nop

.section .text.nanosleep
FUNCTION(nanosleep)
    li      $v0, __NR_nanosleep
    syscall
    j       $ra
      nop

.section .text.gettime
FUNCTION(gettime)
    li      $v0, __NR_gettime
    syscall
    j       $ra
      nop

.section .text.mmap
FUNCTION(mmap)
    li      $v0, __NR_mmap
    syscall
    j       $ra
      nop

.section .text.munmap
FUNCTION(munmap)
    li      $v0, __NR_munmap
    syscall
    j       $ra
      nop

.section .text.prepare_dma
FUNCTION(prepare_dma)
    li      $v0, __NR_prepare_dma
    syscall
    j       $ra
      nop

.section .text.finish_dma
FUNCTION(finish_dma)
    li      $v0, __NR_finish_dma
    syscall
    j       $ra
      nop

.section .text.port_create
FUNCTION(port_create)
    li      $v0, __NR_port_create
    syscall
    j       $ra
      nop

.section .text.connect
FUNCTION(connect)
    li      $v0, __NR_connect
    syscall
    j       $ra
      nop

.section .text.accept
FUNCTION(accept)
    li      $v0, __NR_accept
    syscall
    j       $ra
      nop

.section .text.close
FUNCTION(close)
    li      $v0, __NR_close
    syscall
    j       $ra
      nop

.section .text.set_cookie
FUNCTION(set_cookie)
    li      $v0, __NR_set_cookie
    syscall
    j       $ra
      nop

.section .text.wait
FUNCTION(wait)
    li      $v0, __NR_wait
    syscall
    j       $ra
      nop

.section .text.wait_any
FUNCTION(wait_any)
    li      $v0, __NR_wait_any
    syscall
    j       $ra
      nop

.section .text.get_msg
FUNCTION(get_msg)
    li      $v0, __NR_get_msg
    syscall
    j       $ra
      nop

.section .text.read_msg
FUNCTION(read_msg)
    li      $v0, __NR_read_msg
    syscall
    j       $ra
      nop

.section .text.put_msg
FUNCTION(put_msg)
    li      $v0, __NR_put_msg
    syscall
    j       $ra
      nop

.section .text.send_msg
FUNCTION(send_msg)
    li      $v0, __NR_send_msg
    syscall
    j       $ra
      nop

.section .text.set_panic_handler
FUNCTION(set_panic_handler)
    li      $v0, __NR_set_panic_handler
    syscall
    j       $ra
      nop
