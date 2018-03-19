/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
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

/* DEF_SYSCALL(syscall_nr, syscall_name, return type, nr_args, [argument list])
 *
 * Please keep this table sorted by syscall number
 */

DEF_SYSCALL(0x1, gettime, long, 3, uint32_t clock_id, uint32_t flags, int64_t *time)

/* unit test */
DEF_SYSCALL(0x10, test_syscall_0, long, 0)
DEF_SYSCALL(0x11, test_syscall_1, long, 1, uint32_t a)
DEF_SYSCALL(0x12, test_syscall_2, long, 2, uint32_t a, uint32_t b)
DEF_SYSCALL(0x13, test_syscall_3, long, 3, uint32_t a, uint32_t b, uint32_t c)
DEF_SYSCALL(0x14, test_syscall_4, long, 4, uint32_t a, uint32_t b, uint32_t c, uint32_t d)
DEF_SYSCALL(0x15, test_syscall_5, long, 5, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e)
DEF_SYSCALL(0x16, test_syscall_6, long, 6, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f)
DEF_SYSCALL(0x17, test_syscall_7, long, 7, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g)
DEF_SYSCALL(0x18, test_syscall_8, long, 8, uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t e, uint32_t f, uint32_t g, uint32_t h)

DEF_SYSCALL(0x40, test_syscall_4a, long, 4, uint64_t a, uint64_t b, uint64_t c, uint64_t d)
DEF_SYSCALL(0x41, test_syscall_4b, long, 4, uint64_t a, uint64_t b, uint64_t c, uint32_t d)
DEF_SYSCALL(0x42, test_syscall_4c, long, 4, uint32_t a, uint64_t b, uint64_t c, uint32_t d)
DEF_SYSCALL(0x43, test_syscall_4d, long, 4, uint32_t a, uint64_t b, uint32_t c, uint64_t d)

DEF_SYSCALL(0x50, test_syscall_5a, long, 5, uint64_t a, uint64_t b, uint64_t c, uint32_t d, uint32_t e)
DEF_SYSCALL(0x51, test_syscall_5b, long, 5, uint32_t a, uint32_t b, uint64_t c, uint64_t d, uint64_t e)
DEF_SYSCALL(0x52, test_syscall_5c, long, 5, uint64_t a, uint32_t b, uint32_t c, uint64_t d, uint32_t e)
DEF_SYSCALL(0x53, test_syscall_5d, long, 5, uint32_t a, uint32_t b, uint32_t c, uint64_t d, uint64_t e)
