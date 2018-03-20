/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
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

#ifndef TEE_API_PROPERTIES_H
#define TEE_API_PROPERTIES_H

#include <stdint.h>
#include <stdbool.h>

#define TA_PROP_TYPE_BOOL       0
#define TA_PROP_TYPE_BIN_BLOCK  1
#define TA_PROP_TYPE_ID         2
#define TA_PROP_TYPE_STR        3
#define TA_PROP_TYPE_U32        4
#define TA_PROP_TYPE_UUID       5

#define TA_FLAGS_SINGLE_INSTANCE (1 << 0)
#define TA_FLAGS_MULTI_SESSION   (1 << 1)
#define TA_FLAGS_KEEP_ALIVE      (1 << 2)

struct ta_property {
    const char *name;
    uint32_t type;
    const void *value;
};

struct result_property {
    uint32_t type;
    void *value;
    uint32_t value_buf_len;
};

typedef struct ta_property tee_api_properties_t[];

/* manifest section attributes */
#define TEE_API_PROP_ATTRS \
    __attribute((aligned(4))) __attribute((section(".tee_api.properties")))

#endif /* TEE_API_PROPERTIES_H */
