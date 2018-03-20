/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _TEEUNITTEST_INCLUDE_TACOMMON_H_
#define _TEEUNITTEST_INCLUDE_TACOMMON_H_

#include <stdio.h>

#define TLOGI(fmt, ...) \
    fprintf(stderr, "%s: %d: " fmt, LOG_TAG, __LINE__,  ## __VA_ARGS__)

/* Trusted Applications command codes */
/* crypt TA CMD codes */
#define TA_CRYPT_CMD_SHA256                 2

/* SIMS TA CMD codes */
#define TA_SIMS_CMD_READ                    1
#define TA_SIMS_CMD_WRITE                   2
#define TA_SIMS_CMD_GET_MEMREF_UINT         4
#define TA_SIMS_CMD_CHECK_BUFFER            5

/* Multi instance memref TA CMD codes */
#define TA_MULTI_INSTANCE_MEMREF_CMD        11
#define TA_MULTI_INSTANCE_INVOKE_CMD        12
#define TA_MULTI_INSTANCE_WAIT_CMD          13
#define TA_MULTI_INSTANCE_RETURN_CMD        14

#endif
