/*
 * Copyright (c) 2016-218, MIPS Tech, LLC and/or its affiliated group companies
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
#include <stdio.h>
#include <arch.h>

/* App UUID:   {d26eb24f-858b-4049-b2c1-15668122c517} */
#define USERTEST_UUID \
	{ 0xd26eb24f, 0x858b, 0x4049, \
	  { 0xb2, 0xc1, 0x15, 0x66, 0x81, 0x22, 0xc5, 0x17 } }

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest =
{
	.uuid = USERTEST_UUID,

	/* optional configuration options here */
	{
		/* one page for heap */
		TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(PAGE_SIZE),

		/* one page for stack */
		TRUSTY_APP_CONFIG_MIN_STACK_SIZE(PAGE_SIZE),
	},
};
