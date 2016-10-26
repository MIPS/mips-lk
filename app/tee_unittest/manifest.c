/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
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
#include <stdio.h>
#include <tee_api_properties.h>

tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties =
{
    { "gpd.ta.description", TA_PROP_TYPE_STR, "tee_unittest"},
    { "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){1}},
    { "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){0}},
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    /* UUID : {f74df2bd-58b6-4503-9aa1-f68fa8f31aa9} */
    { 0xf74df2bd, 0x58b6, 0x4503,
    { 0x9a, 0xa1, 0xf6, 0x8f, 0xa8, 0xf3, 0x1a, 0xa9 } },

    /* optional configuration options here */
    {
        /* four pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4 * 4096),

        /* enable/disable auto start */
        TRUSTY_APP_CONFIG_AUTO_START(1),

        /* custom external config options */
        TRUSTY_APP_CONFIG_EXTERN((uint32_t)&tee_api_properties, (uint32_t)&ta_props_len),
    },
};
