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

#ifndef TA_CLIENT_TA_H
#define TA_CLIENT_TA_H

#define TA_CLIENT_CMD_OPENSESSION   0
#define TA_CLIENT_CMD_PANIC         1
#define TA_CLIENT_CMD_CLOSESESSION  2
#define TA_CLIENT_CMD_TEST_MALLOC_ALIGNEMENT    3
#define TA_CLIENT_CMD_TEST_MALLOC_SIZE_ZERO     4
#define TA_CLIENT_CMD_TEST_REALLOC_CONTENT      5
#define TA_CLIENT_CMD_TEST_REALLOC_ILLEGAL_PTR  6
#define TA_CLIENT_CMD_TEST_REALLOC_SIZE_ZERO    7
#define TA_CLIENT_CMD_DEFAULT_PANIC             8
#define TA_CLIENT_CMD_SUCCESS                   9

#endif // TA_CLIENT_TA_H
