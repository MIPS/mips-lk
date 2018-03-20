/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <trusty_app_manifest.h>
#include <tee_api_properties.h>
#include <tee_api_types.h>
#include <ta_rpc.h>

tee_api_properties_t TEE_API_PROP_ATTRS tee_api_properties = {
    { "gpd.ta.description", TA_PROP_TYPE_STR, "ta_rpc_test"},
    { "gpd.ta.singleInstance", TA_PROP_TYPE_BOOL, &(const bool){0} },
    { "gpd.ta.multiSession", TA_PROP_TYPE_BOOL, &(const bool){1} },
    { "gpd.ta.instanceKeepAlive", TA_PROP_TYPE_BOOL, &(const bool){0} },
    { "gpd.ta.dataSize", TA_PROP_TYPE_U32, &(const uint32_t){32 * 1024} },
    { "gpd.ta.stackSize", TA_PROP_TYPE_U32, &(const uint32_t){4 * 1024} },
};

static const size_t ta_props_len = sizeof(tee_api_properties) / sizeof(tee_api_properties[0]);

trusty_app_manifest_t TRUSTY_APP_MANIFEST_ATTRS trusty_app_manifest = {
    TA_RPC_TEST_UUID,

    /* optional configuration options here */
    {
        /* four pages for heap */
        TRUSTY_APP_CONFIG_MIN_HEAP_SIZE(4 * 4096),

        /* enable/disable auto start */
        TRUSTY_APP_CONFIG_AUTO_START(0),

        /* custom external config options */
        TRUSTY_APP_CONFIG_EXTERN((uint32_t)&tee_api_properties,
            (uint32_t)&ta_props_len),
    },
};
