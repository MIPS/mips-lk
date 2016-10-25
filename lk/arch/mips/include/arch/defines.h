/*
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
#pragma once

#define SHIFT_4K            (12)
#define PAGE_SIZE_4K        (1 << SHIFT_4K)

#define SHIFT_16K           (14)
#define PAGE_SIZE_16K       (1 << SHIFT_16K)

/* check if target has page_size override */
#if defined(ARCH_PAGE_SIZE)

#if (ARCH_PAGE_SIZE == PAGE_SIZE_4K)
# define PAGE_SIZE_SHIFT     SHIFT_4K
# define PAGE_SIZE           (1 << PAGE_SIZE_SHIFT)
#elif (ARCH_PAGE_SIZE == PAGE_SIZE_16K)
# define PAGE_SIZE_SHIFT     SHIFT_16K
# define PAGE_SIZE           (1 << PAGE_SIZE_SHIFT)
#else
# error Unsupported ARCH_PAGE_SIZE
#endif

#ifndef ASSEMBLY
#include <config.h>
#include <assert.h>
STATIC_ASSERT(ARCH_PAGE_SIZE == PAGE_SIZE);
#endif /* ASSEMBLY */

#else /* ARCH_PAGE_SIZE */

/* select default PAGE_SIZE */
#define PAGE_SIZE_SHIFT     SHIFT_4K
#define PAGE_SIZE           (1 << PAGE_SIZE_SHIFT)

#endif /* ARCH_PAGE_SIZE */

// XXX is this right?
#define CACHE_LINE 32

#define ARCH_DEFAULT_STACK_SIZE PAGE_SIZE
