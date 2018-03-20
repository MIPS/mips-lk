/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#include <trusty_app_manifest.h>
#include <stddef.h>
#include <tee_api_properties.h>
#include <tee_api_types.h>
#include <ta_uuids.h>

tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties =
{
    { "gpd.ta.description", TA_PROP_TYPE_STR, "ta_os_test"},
    { "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){0}},
    { "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){1}},
    { "gpd.ta.instanceKeepAlive", TA_PROP_TYPE_BOOL, &(const bool){0}},
    { "gpd.ta.dataSize", TA_PROP_TYPE_U32, &(const uint32_t){900 * 1024}},
    { "gpd.ta.stackSize", TA_PROP_TYPE_U32, &(const uint32_t){8 * 1024}},
    { "gpd.ta.version", TA_PROP_TYPE_STR, "1.0"},
	{ "myprop.true", TA_PROP_TYPE_BOOL, &(const bool){ true } },
	{ "myprop.42",   TA_PROP_TYPE_U32,  &(const uint32_t){ 42 } },
    { "myprop.123",  TA_PROP_TYPE_UUID, &(const TEE_UUID) {1, 2, 3, {0} } },
	{ "myprop.1234", TA_PROP_TYPE_ID,
		&(const TEE_Identity) { 1, { 2, 3, 4, {0} } } },
	{ "myprop.hello", TA_PROP_TYPE_STR,
		"hello property, larger than 80 characters, so that it checks that it is not truncated by anything in the source code which may be wrong" },
    { "myprop.binaryblock", TA_PROP_TYPE_BIN_BLOCK, "SGVsbG8gd29ybGQh" },
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    TA_OS_TEST_UUID,

    /* optional configuration options here */
    {
        /* four pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4 * 4096),

        /* enable/disable auto start */
        TRUSTY_APP_CONFIG_AUTO_START(0),

        /* custom external config options */
        TRUSTY_APP_CONFIG_EXTERN((uint32_t)&tee_api_properties, (uint32_t)&ta_props_len),
    },
};
