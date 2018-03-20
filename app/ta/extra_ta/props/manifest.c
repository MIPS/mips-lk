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

#include <trusty_app_manifest.h>
#include <stddef.h>
#include <tee_api_properties.h>
#include <tee_api_types.h>

/* UUID : {acd1cbcc-5fb2-407b-b755-40e8bebe3375} */
#define TA_PROPS_UUID    { 0xacd1cbcc, 0x5fb2, 0x407b, \
                    { 0xb7, 0x55, 0x40, 0xe8, 0xbe, 0xbe, 0x33, 0x75 } }

tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties =
{
    { "gpd.ta.description", TA_PROP_TYPE_STR, "additional property tests"},
    { "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){1}},
    { "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){0}},
    { "gpd.ta.instanceKeepAlive", TA_PROP_TYPE_BOOL, &(const bool){1}},
    { "gpd.\t\n\r\0", TA_PROP_TYPE_BOOL, &(const uint32_t){1}},
    { "gpd.ta.instanceKeepAlive", TA_PROP_TYPE_BOOL, &(const bool){1}},
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    TA_PROPS_UUID,

    /* optional configuration options here */
    {
        /* four pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4 * 4096),

        /* enable/disable auto start */
        TRUSTY_APP_CONFIG_AUTO_START(0),

        /* custom external config options */
        TRUSTY_APP_CONFIG_EXTERN((uint32_t)&tee_api_properties, (uint32_t)&ta_props_len),

        /* give session manager extra privileges */
        TRUSTY_APP_CONFIG_PRIVILEGES(3),
    },
};
