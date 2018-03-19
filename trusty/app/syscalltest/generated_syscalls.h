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

#define __NR_gettime                             	0x1
#define __NR_test_syscall_0                      	0x10
#define __NR_test_syscall_1                      	0x11
#define __NR_test_syscall_2                      	0x12
#define __NR_test_syscall_3                      	0x13
#define __NR_test_syscall_4                      	0x14
#define __NR_test_syscall_5                      	0x15
#define __NR_test_syscall_6                      	0x16
#define __NR_test_syscall_7                      	0x17
#define __NR_test_syscall_8                      	0x18
#define __NR_test_syscall_4a                     	0x40
#define __NR_test_syscall_4b                     	0x41
#define __NR_test_syscall_4c                     	0x42
#define __NR_test_syscall_4d                     	0x43
#define __NR_test_syscall_5a                     	0x50
#define __NR_test_syscall_5b                     	0x51
#define __NR_test_syscall_5c                     	0x52
#define __NR_test_syscall_5d                     	0x53

#ifndef ASSEMBLY

__BEGIN_CDECLS

long gettime(uint32_t clock_id, uint32_t flags, int64_t *time);
long test_syscall_0(void);
long test_syscall_1(uint32_t a);
long test_syscall_2(uint32_t a, uint32_t b);
long test_syscall_3(uint32_t a, uint32_t b, uint32_t c);
long test_syscall_4(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
long test_syscall_5(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e);
long test_syscall_6(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f);
long test_syscall_7(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g);
long test_syscall_8(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h);
long test_syscall_4a(uint64_t a, uint64_t b, uint64_t c, uint64_t d);
long test_syscall_4b(uint64_t a, uint64_t b, uint64_t c, uint32_t d);
long test_syscall_4c(uint32_t a, uint64_t b, uint64_t c, uint32_t d);
long test_syscall_4d(uint32_t a, uint64_t b, uint32_t c, uint64_t d);
long test_syscall_5a(uint64_t a, uint64_t b, uint64_t c, uint32_t d, uint32_t e);
long test_syscall_5b(uint32_t a, uint32_t b, uint64_t c, uint64_t d, uint64_t e);
long test_syscall_5c(uint64_t a, uint32_t b, uint32_t c, uint64_t d, uint32_t e);
long test_syscall_5d(uint32_t a, uint32_t b, uint32_t c, uint64_t d, uint64_t e);

__END_CDECLS

#endif
