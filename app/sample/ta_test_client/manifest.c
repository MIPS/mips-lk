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
#include <stdio.h>
#include <tee_api_properties.h>

static tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties =
{
	{ "gpd.ta.description", TA_PROP_TYPE_STR, "ta_test_client"},
	{ "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){1}},
	{ "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){0}},
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
	/* UUID : {6c385b92-e514-11e5-9730-9a79f06e9478} */
	{ 0x6c385b92, 0xe514, 0x11e5,
	  { 0x97, 0x30, 0x9a, 0x79, 0xf0, 0x6e, 0x94, 0x78 } },

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
