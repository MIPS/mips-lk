/*
 * Copyright (C) 2016 Imagination Technologies Ltd.
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

/* UUID : {534d4152-542d-4353-4c54-2d54412d5355} */
#define TA_ANSWERSUCCESSTOOPENSESSION_UUID  { 0x534d4152, 0x542d, 0x4353, \
                    { 0x4c, 0x54, 0x2d, 0x54, 0x41, 0x2d, 0x53, 0x55 } }

/* UUID : {534d4152-5443-534c-5445-5252544f4f53} */
#define TA_ANSWERERRORTOOPENSESSION_UUID    { 0x534d4152, 0x5443, 0x534c, \
                    { 0x54, 0x45, 0x52, 0x52, 0x54, 0x4f, 0x4f, 0x53 } }

/* UUID : {534d4152-542d-4353-4c54-2d54412d4552} */
#define TA_ANSWERERRORTOINVOKE_UUID     { 0x534d4152, 0x542d, 0x4353, \
                    { 0x4c, 0x54, 0x2d, 0x54, 0x41, 0x2d, 0x45, 0x52 } }

/* UUID : {534d4152-5443-534c-544f-53345041524d} */
#define TA_CHECKOPENSESSIONWITH4PARAMETERS_UUID {0x534d4152, 0x5443, 0x534c, \
                    { 0x54, 0x4f, 0x53, 0x34, 0x50, 0x41, 0x52, 0x4d } }

/* UUID : {534d4152-542d-4353-4c54-2d54412d5354} */
#define TA_TESTING_CLIENT_API_UUID      { 0x534d4152, 0x542d, 0x4353, \
                    { 0x4c, 0x54, 0x2d, 0x54, 0x41, 0x2d, 0x53, 0x54 } }

/* UUID : {534d4152-542d-4353-4c54-2d54412d3031} */
#define TA_TESTING_INTERNAL_API_TCF_UUID { 0x534d4152, 0x542d, 0x4353, \
                    { 0x4c, 0x54, 0x2d, 0x54, 0x41, 0x2d, 0x30, 0x31 } }

/* UUID : {534d4152-5443-534c-5441-544346494341} */
#define TA_TESTING_INTERNAL_API_TCF_ICA_UUID { 0x534d4152, 0x5443, 0x534c, \
                    { 0x54, 0x41, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41 } }

/* UUID : {534d4152-5443-534c-5454-434649434132} */
#define TA_TESTING_INTERNAL_API_TCF_ICA2_UUID { 0x534d4152, 0x5443, 0x534c, \
                    { 0x54, 0x54, 0x43, 0x46, 0x49, 0x43, 0x41, 0x32 } }

/* UUID : {534d4152-5443-534c-4d4c-54494e535443} */
#define TA_TESTING_INTERNAL_API_TCF_MULTI_UUID { 0x534d4152, 0x5443, 0x534c, \
                    { 0x4d, 0x4c, 0x54, 0x49, 0x4e, 0x53, 0x54, 0x43 } }

/* UUID : {534d4152-5443-534c-5347-4c494e535443} */
#define TA_TESTING_INTERNAL_API_TCF_SINGLE_UUID { 0x534d4152, 0x5443, 0x534c, \
                    { 0x53, 0x47, 0x4c, 0x49, 0x4e, 0x53, 0x54, 0x43 } }

/* UUID : {534d4152-5443-534c-5f54-494d45415049} */
#define TA_TESTING_INTERNAL_API_TIME_UUID    { 0x534d4152, 0x5443, 0x534c, \
                    { 0x5f, 0x54, 0x49, 0x4d, 0x45, 0x41, 0x50, 0x49 } }

#endif
