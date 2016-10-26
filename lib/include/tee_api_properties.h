/*
 * Copyright (c) 2016 Imagination Technologies Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef TEE_API_PROPERTIES_H
#define TEE_API_PROPERTIES_H

#include <tee_api_types.h>
#include <sys/types.h>

#define TA_PROP_TYPE_BOOL       0
#define TA_PROP_TYPE_BIN_BLOCK  1
#define TA_PROP_TYPE_ID         2
#define TA_PROP_TYPE_STR        3
#define TA_PROP_TYPE_U32        4
#define TA_PROP_TYPE_UUID       5
#define TA_PROP_GET_NAME        6

#define MAX_STR 100

struct ta_property {
    const char *name;
    uint32_t type;
    const void *value;
};

struct result_property {
    char *name;
    union {
        uint32_t type;
        uint32_t prop_size;
    };
    void *value;
};

typedef struct ta_property tee_api_properties_t[];

/* manifest section attributes */
#define TEE_API_PROP_ATTRS \
    __attribute((aligned(4))) __attribute((section(".tee_api.properties")))

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator, const char* name, bool* value);
TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator, const char* name,
                                        void *valueBuffer, uint32_t *valueBufferLen);
TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator, const char* name, TEE_Identity *value);
TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator, const char* name,
                                    char *valueBuffer, uint32_t *valueBufferLen);
TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator, const char* name, uint32_t *value);
TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator, const char* name, TEE_UUID *value);
TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle* enumerator);
void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator);
void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator, TEE_PropSetHandle propSet);
void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator);
TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator, void *nameBuffer, uint32_t *nameBufferLen);
TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator);

#endif /* TEE_API_PROPERTIES_H */
