/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TA_OS_TEST_H
#define TA_OS_TEST_H

#define TA_OS_TEST_CMD_INIT                 0
#define TA_OS_TEST_CMD_CLIENT_WITH_TIMEOUT  1
#define TA_OS_TEST_CMD_BASIC                5
#define TA_OS_TEST_CMD_PANIC                6
#define TA_OS_TEST_CMD_CLIENT               7
#define TA_OS_TEST_CMD_PARAMS_ACCESS        8
#define TA_OS_TEST_CMD_WAIT                 9
#define TA_OS_TEST_CMD_BAD_MEM_ACCESS       10

/* TA_MEM_FIREWALL commands TA_OS_TEST_MFW_CMD_BASE + TA_MEM_FIREWALL_CMD_* */
#define TA_OS_TEST_MFW_CMD_BASE         11
#define TA_OS_TEST_MFW_CMD_LAST         16

#endif /*TA_OS_TEST_H */
