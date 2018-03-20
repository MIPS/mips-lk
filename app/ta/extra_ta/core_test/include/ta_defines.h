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

#ifndef TA_DEFINES_H
#define TA_DEFINES_H

/* Commands */
#define TA_CORE_TEST_CMD_SUCCESS                    0
#define TA_CORE_TEST_CMD_SESSION_LEAK               1
#define TA_CORE_TEST_CMD_WAIT_TIMEOUT               2
#define TA_CORE_TEST_CMD_SHARE_BUFFER_AND_PANIC     3
#define TA_CORE_TEST_CMD_CHECK_BUFFER_MAPPING       4
#define TA_CORE_TEST_CMD_OPEN_SIMS_SESSION          5
#define TA_CORE_TEST_CMD_SHARE_BUFFER               6
#define TA_CORE_TEST_CMD_INVOKE_TIMEOUT             7
#define TA_CORE_TEST_CMD_WAIT                       8
#define TA_CORE_TEST_CMD_INVOKE_OPENSESSION_TIMEOUT 9

#define TA_CORE_TEST_UUID { 0x5387ad61, 0xff1c, 0x43a0, \
    { 0xa7, 0xad, 0xd8, 0x5c, 0xda, 0x69, 0x9f, 0x51 } }

#endif /* TA_DEFINES_H */
