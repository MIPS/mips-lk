/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
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
#ifndef _TEEUNITTEST_INCLUDE_TAUUIDS_H_
#define _TEEUNITTEST_INCLUDE_TAUUIDS_H_

#include <tee_internal_api.h>

/* UUID : {5b9e0e40-2636-11e1-ad9e-0002a5d5c51b} */
#define TA_OS_TEST_UUID                 { 0x5b9e0e40, 0x2636, 0x11e1, \
                    { 0xad, 0x9e, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

/* UUID : {cb3e5ba0-adf1-11e0-998b-0002a5d5c51b} */
#define TA_CRYPT_UUID                   { 0xcb3e5ba0, 0xadf1, 0x11e0, \
                    { 0x99, 0x8b, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

/* UUID : {c3f6e2c0-3548-11e1-b86c-0800200c9a66} */
#define TA_CREATE_FAIL_TEST_UUID        { 0xc3f6e2c0, 0x3548, 0x11e1, \
                    { 0xb8, 0x6c, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 } }

/* UUID : {e6a33ed4-562b-463a-bb7e-ff5e15a493c8} */
#define TA_SIMS_UUID                    { 0xe6a33ed4, 0x562b, 0x463a, \
                    { 0xbb, 0x7e, 0xff, 0x5e, 0x15, 0xa4, 0x93, 0xc8 } }

/* UUID : {e13010e0-2ae1-11e5-896a-0002a5d5c51b} */
#define TA_CONCURRENT_UUID              { 0xe13010e0, 0x2ae1, 0x11e5, \
                    { 0x89, 0x6a, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b } }

/* UUID : {634c11cf-1bf6-4938-b517-79a75ab43cf8} */
#define TA_MULTI_INSTANCE_MEMREF_UUID    { 0x634c11cf, 0x1bf6, 0x4938, \
                    { 0xb5, 0x17, 0x79, 0xa7, 0x5a, 0xb4, 0x3c, 0xf8 } }

/* UUID : {fce38bf2-ecbd-4ebd-99d8-6ffe8e7cd925} */
#define TA_BAD_MANIFEST_UUID    { 0xfce38bf2, 0xecbd, 0x4ebd, \
                    { 0x99, 0xd8, 0x6f, 0xfe, 0x8e, 0x7c, 0xd9, 0x25 } }

/* UUID : {c67430d3-9b8c-4df1-9df0-3c0aa0d1e8a9} */
#define TA_CLIENT_TA_UUID { 0xc67430d3, 0x9b8c, 0x4df1, \
                    { 0x9d, 0xf0, 0x3c, 0x0a, 0xa0, 0xd1, 0xe8, 0xa9 } }

/* UUID : {24922593-a36f-465f-816c-e8a297bd8ee8} */
#define TA_SISS_UUID     { 0x24922593, 0xa36f, 0x465f, \
                    { 0x81, 0x6c, 0xe8, 0xa2, 0x97, 0xbd, 0x8e, 0xe8 } }

#endif
