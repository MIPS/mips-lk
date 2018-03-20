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

#ifndef TA_DEFINES_H
#define TA_DEFINES_H

#define TRUSTED_APP_ERROR_BAD_PARAMETERS 0x00000002

/* Commands */
#define CMD_TEE_AllocatePropertyEnumerator 0x00000060
#define CMD_TEE_StartPropertyEnumerator    0x00000065
#define CMD_TEE_ResetPropertyEnumerator    0x00000070
#define CMD_TEE_GetPropertyNameAndAdvance  0x00000081
#define TA_KEEP_ALIVE_CMD_INC              0x000000F1
#define CMD_TEE_TestPrivilegedSyscalls     0x000000F2

#define TA_PROPS_UUID    { 0xacd1cbcc, 0x5fb2, 0x407b, \
                    { 0xb7, 0x55, 0x40, 0xe8, 0xbe, 0xbe, 0x33, 0x75 } }

#endif /* TA_DEFINES_H */
