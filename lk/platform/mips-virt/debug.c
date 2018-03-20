/*
 * Copyright (c) 2009 Corey Tabaka
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
#include <stdarg.h>
#include <err.h>
#include <trace.h>
#include <stdio.h>
#include <kernel/thread.h>
#include <lib/cbuf.h>
#include <dev/virtio/console.h>
#include <platform/interrupts.h>
#include <platform/mips-virt.h>

void platform_init_uart(void)
{
}

void platform_dputc(char c)
{
    register char creg asm ("a0") = c;
    asm volatile (
        ".set push; .set virt; hypcall 0x160; .set pop"
        : : "r" (creg)
    );
}

int platform_dgetc(char *c, bool wait)
{
    return ERR_NOT_CONFIGURED;
}
