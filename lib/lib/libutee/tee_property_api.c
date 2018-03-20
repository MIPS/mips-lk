/*
 * Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
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
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <err.h>
#include <assert.h>
#include <tee_api_properties.h>
#include <tee_ta_interface.h>
#include <tee_internal_api.h>
#include <tee_api_defines.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "UTEE"

#define ALLOCATED_ENUMERATOR 0xffffffff
#define INVALID_BOOL (-1)

typedef long(*get_client_prop_t) (void *ret_val);

struct prop_enum {
    TEE_PropSetHandle propSet;
    uint32_t index;
};

static TEE_Result b64_dec(char *enc_val, void *value_buff,
                          uint32_t *val_buff_len)
{
    uint8_t enc_idx;
    uint8_t *buff = (uint8_t *)value_buff;
    uint32_t len = 0;
    uint32_t idx_count = 0;

    while (*enc_val != '\0') {
        /* Check if pad character is reached. */
        if (*enc_val == '=')
            break;

        if (len > *val_buff_len)
            return TEE_ERROR_SHORT_BUFFER;

        /* Find character index in accordance with the table from RFC 2045. */
        if (*enc_val >= 'A' && *enc_val <= 'Z')
            enc_idx = *enc_val - 'A';
        else if (*enc_val >= 'a' && *enc_val <= 'z')
            enc_idx = (*enc_val - 'a') + 26;
        else if (*enc_val >= '0' && *enc_val <= '9')
            enc_idx = *enc_val + 4;
        else if (*enc_val == '+')
            enc_idx = 62;
        else if (*enc_val == '\\')
            enc_idx = 63;
        else {
            enc_val++;
            continue;
        }

        enc_val++;
        switch (idx_count++ % 4) {
        case 0:
            buff[len++] = enc_idx << 2;
            break;
        case 1:
            buff[len - 1] |= enc_idx >> 4;
            buff[len++] = (enc_idx & 0xF) << 4;
            break;
        case 2:
            buff[len - 1] |= enc_idx >> 2;
            buff[len++] = (enc_idx & 0x3) << 6;
            break;
        case 3:
            buff[len - 1] |= enc_idx;
            break;
        }
    }

    *val_buff_len = len;
    return TEE_SUCCESS;
}

static void get_client_identity(void *client_id_val)
{
    tee_get_ta_client_id((TEE_Identity *)client_id_val);
}

static const struct ta_property propset_client[] = {
    /* Value pointer field is filled with address of a function that is used
     * to retrieve appropriate value
     */
    {"gpd.client.identity", TA_PROP_TYPE_ID, (void *)get_client_identity},
};

static const size_t propset_client_len = sizeof(propset_client) /
                                         sizeof(propset_client[0]);

static long handle_current_client(const char *name, size_t name_len,
                                  struct result_property *prop, uint32_t index)
{
    TEE_Identity client_id;
    const struct ta_property *property_ptr = propset_client;
    uint32_t prop_size = propset_client_len;

    if (name == NULL) {
        if (index >= prop_size)
            goto index_to_large;
        prop_size = 1;
        property_ptr += index;
    }

    do {
        if (name == NULL ||
                strncmp(name, property_ptr->name, name_len) == 0) {
            get_client_prop_t get_client =
                (get_client_prop_t)property_ptr->value;

            if (prop->value_buf_len < sizeof(TEE_Identity)) {
                prop->value_buf_len = sizeof(TEE_Identity);
                return TEE_ERROR_SHORT_BUFFER;
            }

            get_client(prop->value);

            prop->type = property_ptr->type;
            return TEE_SUCCESS;
        }
        property_ptr++;
    } while (--prop_size);

index_to_large:
    /* Get the client's UUID for the syscall */
    get_client_identity((void *)&client_id);

    /* If property is not in standard client properties and if login type
     * is TEE_LOGIN_TRUSTED_APP search in client TA properties.
     */
    if (client_id.login == TEE_LOGIN_TRUSTED_APP) {
        return get_ta_client_props((uuid_t *)&client_id.uuid, name, name_len,
                                      (void *)prop,
                                      index - propset_client_len);
    }
    return TEE_ERROR_ITEM_NOT_FOUND;
}

static TEE_Result ta_config_prop(const char *name,
        struct result_property *prop, uint32_t index, uint32_t prop_set_id)
{
    size_t name_len = 0;

    if (name != NULL)
        name_len = strlen(name) + 1;

    if (prop_set_id != TEE_PROPSET_CURRENT_CLIENT)
        return get_kprops(name, name_len, (void *)prop, index, prop_set_id);
    else if (prop_set_id == TEE_PROPSET_CURRENT_CLIENT)
        return handle_current_client(name, name_len, (void *)prop, index);

    TEE_DBG_MSG("ERROR: Invalid property set indentifier.\n");
    return TEE_ERROR_BAD_FORMAT;
}

static TEE_Result get_prop(TEE_PropSetHandle propset_or_enum, const char *name,
                           struct result_property *prop_val)
{
    TEE_Result res;
    struct prop_enum *enum_ptr;
    uint32_t set_or_enum;
    uint32_t enum_idx = ALLOCATED_ENUMERATOR;

    if ((uint32_t)propset_or_enum != TEE_PROPSET_CURRENT_TA &&
        (uint32_t)propset_or_enum != TEE_PROPSET_CURRENT_CLIENT &&
        (uint32_t)propset_or_enum != TEE_PROPSET_TEE_IMPLEMENTATION) {
        /* Ensure that name is set to NULL if access to properties
         * is not done through the property sets.
         */
        name = NULL;
        enum_ptr = (struct  prop_enum *)propset_or_enum;

        if (enum_ptr->index == ALLOCATED_ENUMERATOR)
            return TEE_ERROR_ITEM_NOT_FOUND;

        set_or_enum = (uint32_t)enum_ptr->propSet;
        enum_idx = enum_ptr->index;
    } else {
        /* Name must not be NULL. */
        if (name == NULL)
            TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        set_or_enum = (uint32_t)propset_or_enum;
    }

    res = ta_config_prop(name, prop_val, enum_idx, set_or_enum);

    return res;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
                                 const char *name, bool *value)
{
    TEE_Result res = 0;
    int prop_val = INVALID_BOOL;
    struct result_property property;

    if (value == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    property.value = (void *)(&prop_val);
    property.value_buf_len = sizeof(uint32_t);

    res = get_prop(propsetOrEnumerator, name, &property);

    if ((res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) &&
        property.type != TA_PROP_TYPE_BOOL) {
        res = TEE_ERROR_BAD_FORMAT;
        goto err_res;
    }

    if (res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        goto err_res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    assert(*(int *)property.value != INVALID_BOOL);
    *value = *(bool *)property.value;

    return TEE_SUCCESS;

err_res:
    *value = false;
    return res;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
                                        const char *name, void *valueBuffer,
                                        size_t *valueBufferLen)
{
    TEE_Result res;
    struct result_property property;

    if (valueBuffer == NULL || valueBufferLen == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    property.value = valueBuffer;
    property.value_buf_len = *valueBufferLen;

    res = get_prop(propsetOrEnumerator, name, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_BIN_BLOCK)
        return TEE_ERROR_BAD_FORMAT;

    if (res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;

    if (res != TEE_SUCCESS && res != TEE_ERROR_SHORT_BUFFER)
        TEE_Panic(res);

    if (property.value_buf_len > *valueBufferLen) {
        *valueBufferLen = property.value_buf_len;
        return TEE_ERROR_SHORT_BUFFER;
    }

    *valueBufferLen = property.value_buf_len;

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
                                     const char *name, TEE_Identity *value)
{
    TEE_Result res = 0;
    struct result_property property;

    if (value == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    property.value = (void *)value;
    property.value_buf_len = sizeof(TEE_Identity);

    res = get_prop(propsetOrEnumerator, name, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_ID)
        return TEE_ERROR_BAD_FORMAT;

    if (res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
                                   const char *name, char *valueBuffer,
                                   size_t *valueBufferLen)
{
    TEE_Result res = 0;
    uint32_t val_buff_len;
    struct result_property property;
    uint32_t buff_size;
    void *prop_val = NULL;
    TEE_Identity *id_to_string;
    TEE_UUID *uuid_to_string;
    uint32_t *u32_to_string;

    if (valueBuffer == NULL || valueBufferLen == NULL) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto err_ret;
    }

    val_buff_len = (uint32_t)*valueBufferLen;
    if (val_buff_len < sizeof(TEE_Identity))
        val_buff_len = sizeof(TEE_Identity);

    prop_val = TEE_Malloc(val_buff_len, TEE_MALLOC_FILL_ZERO);
    if (!prop_val) {
        TEE_DBG_MSG("TEE_Malloc failed\n");
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto err_ret;
    }

    property.value = prop_val;
    property.value_buf_len = val_buff_len;

    res = get_prop(propsetOrEnumerator, name, &property);

    if (res != TEE_SUCCESS) {
        if (res == TEE_ERROR_SHORT_BUFFER &&
            *valueBufferLen < property.value_buf_len)
            *valueBufferLen = property.value_buf_len;
        goto err_ret;
    }

    id_to_string = (TEE_Identity *)property.value;
    uuid_to_string = (TEE_UUID *)property.value;
    u32_to_string = (uint32_t *)property.value;

    switch (property.type) {
    case TA_PROP_TYPE_BOOL:
        if (((char *)property.value)[0])
            buff_size = strlcpy(valueBuffer, "true", *valueBufferLen);
        else
            buff_size = strlcpy(valueBuffer, "false", *valueBufferLen);
        break;
    case TA_PROP_TYPE_BIN_BLOCK:
    case TA_PROP_TYPE_STR:
        buff_size = strlcpy(valueBuffer, (char *)property.value,
            *valueBufferLen);
        break;
    case TA_PROP_TYPE_ID:
        buff_size = snprintf(valueBuffer, *valueBufferLen,
             "%08x:%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
             (unsigned int)id_to_string->login,
             (unsigned int)id_to_string->uuid.timeLow,
             id_to_string->uuid.timeMid,
             id_to_string->uuid.timeHiAndVersion,
             id_to_string->uuid.clockSeqAndNode[0],
             id_to_string->uuid.clockSeqAndNode[1],
             id_to_string->uuid.clockSeqAndNode[2],
             id_to_string->uuid.clockSeqAndNode[3],
             id_to_string->uuid.clockSeqAndNode[4],
             id_to_string->uuid.clockSeqAndNode[5],
             id_to_string->uuid.clockSeqAndNode[6],
             id_to_string->uuid.clockSeqAndNode[7]);
        break;
    case TA_PROP_TYPE_U32:
        buff_size = snprintf(valueBuffer, *valueBufferLen, "%u",
                             (uint32_t)(*u32_to_string));
        break;
    case TA_PROP_TYPE_UUID:
        buff_size = snprintf(valueBuffer, *valueBufferLen,
             "%08x-%04x-%04x-%02x%02x%02x%02x%02x%02x%02x%02x",
             (unsigned int)uuid_to_string->timeLow,
             uuid_to_string->timeMid,
             uuid_to_string->timeHiAndVersion,
             uuid_to_string->clockSeqAndNode[0],
             uuid_to_string->clockSeqAndNode[1],
             uuid_to_string->clockSeqAndNode[2],
             uuid_to_string->clockSeqAndNode[3],
             uuid_to_string->clockSeqAndNode[4],
             uuid_to_string->clockSeqAndNode[5],
             uuid_to_string->clockSeqAndNode[6],
             uuid_to_string->clockSeqAndNode[7]);
        break;
    default:
        res = TEE_ERROR_BAD_PARAMETERS;
        goto err_ret;
    }

    /* The returned sizes don't count trailing '\0' in length,
     * so it is added here.
     */
    if (++buff_size > *valueBufferLen)
        res = TEE_ERROR_SHORT_BUFFER;

    *valueBufferLen = buff_size;

err_ret:
    if (prop_val)
        TEE_Free(prop_val);

    if (res != TEE_SUCCESS &&
            res != TEE_ERROR_SHORT_BUFFER &&
            res != TEE_ERROR_ITEM_NOT_FOUND)
        TEE_Panic(res);

    return res;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
                                const char *name, uint32_t *value)
{
    TEE_Result res = 0;
    struct result_property property;

    if (value == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    property.value = (void *)value;
    property.value_buf_len = sizeof(uint32_t);

    res = get_prop(propsetOrEnumerator, name, &property);

    if ((res == TEE_SUCCESS || res == TEE_ERROR_SHORT_BUFFER) &&
        property.type != TA_PROP_TYPE_U32)
        res = TEE_ERROR_BAD_FORMAT;

    if (res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND) {
        *value = 0;
        return res;
    } else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
                                 const char *name, TEE_UUID *value)
{
    TEE_Result res = 0;
    struct result_property property;

    if (value == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    property.value = (void *)value;
    property.value_buf_len = sizeof(TEE_UUID);

    res = get_prop(propsetOrEnumerator, name, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_UUID)
        return TEE_ERROR_BAD_FORMAT;

    if (res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    return TEE_SUCCESS;
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
    struct prop_enum *enum_ptr;

    if (enumerator == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    enum_ptr = (struct prop_enum *)TEE_Malloc(sizeof(struct prop_enum), 0);

    if (enum_ptr == NULL) {
        *enumerator = (TEE_PropSetHandle)TEE_HANDLE_NULL;
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    enum_ptr->index = ALLOCATED_ENUMERATOR;

    *enumerator = (TEE_PropSetHandle) enum_ptr;

    return TEE_SUCCESS;
}

static void check_prop_set(uint32_t prop_set)
{
    if (prop_set != TEE_PROPSET_CURRENT_TA &&
        prop_set != TEE_PROPSET_CURRENT_CLIENT &&
        prop_set != TEE_PROPSET_TEE_IMPLEMENTATION)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
}

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator)
{
    struct prop_enum *enum_ptr = (struct prop_enum *)enumerator;

    if (enumerator == NULL || enumerator == TEE_HANDLE_NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
    TEE_Free((void *)enum_ptr);
}

void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator,
                                 TEE_PropSetHandle propSet)
{
    struct prop_enum *enum_ptr = (struct prop_enum *)enumerator;

    if (enumerator == NULL || enumerator == TEE_HANDLE_NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    check_prop_set((uint32_t)propSet);

    enum_ptr->index = 0;
    enum_ptr->propSet = propSet;
}

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator)
{
    struct prop_enum *enum_ptr = (struct prop_enum *)enumerator;

    if (enumerator == NULL || enumerator == TEE_HANDLE_NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
    check_prop_set((uint32_t)enum_ptr->propSet);
    enum_ptr->index = ALLOCATED_ENUMERATOR;
}

static TEE_Result handle_prop_name(uint32_t prop_set, uint32_t idx,
                                   char *prop_name, size_t *buffer_len)
{
    TEE_Result res;
    uuid_t *ta_uuid = NULL;
    size_t len;

    if (prop_set == TEE_PROPSET_CURRENT_CLIENT) {
        if (idx < propset_client_len) {
            len = strlcpy(prop_name, propset_client[idx].name, *buffer_len) + 1;
            if (len > *buffer_len) {
                *buffer_len = len;
                return TEE_ERROR_SHORT_BUFFER;
            }
            *buffer_len = len;
            return TEE_SUCCESS;
        } else {
            TEE_Identity client_id;

            idx -= propset_client_len;
            /* Get the client's UUID for the syscall */
            get_client_identity((void *)&client_id);
            if (client_id.login != TEE_LOGIN_TRUSTED_APP)
                return TEE_ERROR_ITEM_NOT_FOUND;
            ta_uuid = (uuid_t *)&client_id.uuid;
        }
    }

    res = get_prop_name(prop_set, idx, prop_name, ta_uuid, buffer_len);
    return res;
}

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator, void *nameBuffer,
                               size_t *nameBufferLen)
{
    TEE_Result res = 0;
    char *prop_name = (char *)nameBuffer;
    struct prop_enum *enum_ptr = (struct  prop_enum *)enumerator;

    if (!enum_ptr || !nameBuffer || !nameBufferLen) {
        res = TEE_ERROR_BAD_PARAMETERS;
        goto prop_name_err;
    }

    if (enum_ptr->index == ALLOCATED_ENUMERATOR) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        goto prop_name_err;
    }

    check_prop_set((uint32_t)enum_ptr->propSet);

    res = handle_prop_name((uint32_t)enum_ptr->propSet, enum_ptr->index,
                           prop_name, nameBufferLen);

prop_name_err:
    if (res != TEE_SUCCESS &&
            res != TEE_ERROR_SHORT_BUFFER &&
            res != TEE_ERROR_ITEM_NOT_FOUND)
        TEE_Panic(res);

    return res;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
    struct prop_enum *enum_ptr = (struct  prop_enum *)enumerator;
    uint32_t props_num = 0;
    uint32_t client_props_num = 0;
    TEE_Result res = TEE_SUCCESS;
    uuid_t *ta_uuid = NULL;
    TEE_Identity client_id = {0, {0} };

    if (enumerator == NULL || enumerator == TEE_HANDLE_NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    if (enum_ptr->index == ALLOCATED_ENUMERATOR) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        goto next_prop_err;
    } else
        enum_ptr->index++;

    check_prop_set((uint32_t)enum_ptr->propSet);

    if ((uint32_t) enum_ptr->propSet == TEE_PROPSET_CURRENT_CLIENT) {
        client_props_num = propset_client_len;
        if (enum_ptr->index >= client_props_num)
            res = TEE_ERROR_ITEM_NOT_FOUND;
    }

    if (((uint32_t) enum_ptr->propSet != TEE_PROPSET_CURRENT_CLIENT) ||
        client_id.login == TEE_LOGIN_TRUSTED_APP) {
        res = get_props_num(ta_uuid, (uint32_t) enum_ptr->propSet,
                                &props_num);
        if (res != TEE_SUCCESS)
            goto next_prop_err;
        if (enum_ptr->index >= props_num + client_props_num)
            res = TEE_ERROR_ITEM_NOT_FOUND;
    }

next_prop_err:
    if (res != TEE_ERROR_ITEM_NOT_FOUND &&
        res != TEE_SUCCESS)
        TEE_Panic(res);

    return res;
}
