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
#include <ta_uuids.h>

tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties =
{
    { "gpd.ta.description", TA_PROP_TYPE_STR, "sims_ta"},
    { "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){1}},
    { "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){1}},
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
    TA_SIMS_UUID,

    /* optional configuration options here */
    {
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(64 * 1024),
        TRUSTY_APP_CONFIG_MIN_STACK_SIZE(4 * 1024),

        /* enable/disable auto start */
        TRUSTY_APP_CONFIG_AUTO_START(0),

        /* custom external config options */
        TRUSTY_APP_CONFIG_EXTERN((uint32_t)&tee_api_properties, (uint32_t)&ta_props_len),
    },
};
