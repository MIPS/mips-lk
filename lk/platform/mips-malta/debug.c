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
#include <reg.h>
#include <trace.h>
#include <stdio.h>
#include <kernel/thread.h>
#include <lib/cbuf.h>
#include <platform/interrupts.h>
#include <platform/mips-malta.h>

static int uart_baud_rate = 115200;
static int uart_io_port = 0x3f8;

static cbuf_t uart_rx_buf;

#define TRB (0) // read/write
#define BRL (0) // when LCR bit 7 is set.
#define IER (1) // read/write
#define BRH (1) // when LCR bit 7 is set.
#define IIR (2) // read only
#define FCR (2) // write only
#define LCR (3) // read/write
#define MCR (4) // read/write
#define LSR (5) // read only
#define MSR (6) // read only

// prevent extra echo of received character
#define WITH_UART_FLUSH_RXBUF

static enum handler_return uart_irq_handler(void *arg)
{
    unsigned char c;
    bool resched = false;

    while (isa_read_8(uart_io_port + LSR) & (1<<0)) {
        c = isa_read_8(uart_io_port + TRB);
#ifdef WITH_UART_FLUSH_RXBUF
        isa_write_8(uart_io_port + TRB, 0x0); // clear transmit/receive buffer
#endif
        cbuf_write_char(&uart_rx_buf, c, false);
        resched = true;
    }

    return resched ? INT_RESCHEDULE : INT_NO_RESCHEDULE;
}

void platform_init_uart(void)
{
    /* configure the uart */
    int divisor = 115200 / uart_baud_rate;

    /* get basic config done so that tx functions */
    isa_write_8(uart_io_port + LCR, 0x80); // set up to load divisor latch
    isa_write_8(uart_io_port + BRL, divisor & 0xff); // lsb
    isa_write_8(uart_io_port + BRH, divisor >> 8); // msb
    isa_write_8(uart_io_port + LCR, 3); // 8N1
    isa_write_8(uart_io_port + FCR, 0x07); // enable FIFO, clear, 14-byte threshold
}

void uart_init(void)
{
    /* finish uart init to get rx going */
    cbuf_initialize(&uart_rx_buf, 16);

    register_int_handler(0x4, uart_irq_handler, NULL);
    unmask_interrupt(0x4);

    isa_write_8(uart_io_port + IER, 0x1); // enable receive data available interrupt
}

void uart_putc(char c)
{
    while ((isa_read_8(uart_io_port + LSR) & (1<<6)) == 0)
        ;
    isa_write_8(uart_io_port + TRB, c);
}

int uart_getc(char *c, bool wait)
{
    return cbuf_read_char(&uart_rx_buf, c, wait);
}

void platform_dputc(char c)
{
    if (c == '\n')
        platform_dputc('\r');
#if WITH_CGA_CONSOLE
    cputc(c);
#else
    uart_putc(c);
#endif
}

int platform_dgetc(char *c, bool wait)
{
#if WITH_CGA_CONSOLE
    int ret =  platform_read_key(c);
    //if (ret < 0)
    //  arch_idle();
#else
    int ret = uart_getc(c, wait);
#endif

    return ret;
}
