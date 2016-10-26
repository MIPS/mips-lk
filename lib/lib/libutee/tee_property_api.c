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
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <err.h>
#include <tee_api_properties.h>
#include <tee_ta_interface.h>
#include <tee_internal_api.h>
#include <tee_api_defines.h>

#define ALLOCATED_ENUMERATOR 0xffffffff

typedef long(*get_client_prop_t) (void *ret_val);

struct prop_enum {
    TEE_PropSetHandle propSet;
    uint32_t index;
};

static TEE_Result b64_dec(char *enc_val, void *value_buff, uint32_t *val_buff_len) {
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
        switch(idx_count++ % 4) {
            case 0:
                buff[len++] = enc_idx << 2;
                break;
            case 1:
                buff[len -1] |= enc_idx >> 4;
                buff[len++] = (enc_idx & 0xF) << 4;
                break;
            case 2:
                buff[len -1] |= enc_idx >> 2;
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
    memcpy((void*)client_id_val, (void*)&ta_context->active_sess.client_id,
           sizeof(TEE_Identity));
}

static const struct ta_property propset_client[] = {
    /* Value pointer field is filled with address of a function that is used
     * to retrieve appropriate value
     */
    {"gpd.client.identity", TA_PROP_TYPE_ID, (void *)get_client_identity},
};

static const size_t propset_client_len = sizeof(propset_client) / sizeof(propset_client[0]);

static long ta_config_prop(const char *name, struct result_property *prop,
                           uint32_t index, uint32_t prop_set_id) {
    const struct ta_property *property_ptr = NULL;
    uint32_t prop_size = 1;

    if (prop_set_id == TEE_PROPSET_TEE_IMPLEMENTATION) {
        return get_implementation_props(name, (void *)prop, index);
    } else if (prop_set_id == TEE_PROPSET_CURRENT_TA) {
        property_ptr = ta_context->extern_props;
        prop_size = ta_context->extern_props_size;
    } else if (prop_set_id == TEE_PROPSET_CURRENT_CLIENT) {
        property_ptr = propset_client;
        prop_size = propset_client_len;
    }

    if (name == NULL) {
        if (index >= prop_size)
            return ERR_NOT_FOUND;
        prop_size = 1;
        property_ptr += index;
    }

    do {
        if (name == NULL || strcmp(name, property_ptr->name) == 0) {
            if (prop_set_id == TEE_PROPSET_CURRENT_TA) {
                memcpy((void *)prop->value, property_ptr->value, prop->prop_size);
            } else if (prop_set_id == TEE_PROPSET_CURRENT_CLIENT) {
                get_client_prop_t get_client = (get_client_prop_t)property_ptr->value;
                get_client(prop->value);
            } else
                return ERR_INVALID_ARGS;

            if(name == NULL) {
                if(prop->name && prop->prop_size <= strlen(property_ptr->name)) {
                    return ERR_NOT_ENOUGH_BUFFER;
                } else if (prop->name && prop->prop_size > strlen(property_ptr->name))
                    strlcpy(prop->name, property_ptr->name, prop->prop_size);
            }
            prop->type = property_ptr->type;
            return NO_ERROR;
        }
        property_ptr++;
    } while (--prop_size);

    return ERR_NOT_FOUND;
}

static TEE_Result get_prop(TEE_PropSetHandle propset_or_enum, const char *name,
                           uint32_t name_len, struct result_property *prop_val)
{
    TEE_Result res = TEE_ERROR_ITEM_NOT_FOUND;
    long sys_res = 0;
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

        if (enum_ptr->index == ALLOCATED_ENUMERATOR) {
            return TEE_ERROR_ITEM_NOT_FOUND;
        }

        set_or_enum = (uint32_t)enum_ptr->propSet;
        enum_idx = enum_ptr->index;
    } else {
        if (name == NULL)
            return TEE_ERROR_BAD_PARAMETERS;
        set_or_enum = (uint32_t)propset_or_enum;
    }

    switch (prop_val->type) {
        case TA_PROP_TYPE_BOOL:
            prop_val->prop_size = sizeof(bool);
            break;
        case TA_PROP_TYPE_BIN_BLOCK:
        case TA_PROP_TYPE_STR:
            prop_val->prop_size = MAX_STR;
            break;
        case TA_PROP_TYPE_ID:
            prop_val->prop_size = sizeof(TEE_Identity);
            break;
        case TA_PROP_TYPE_U32:
            prop_val->prop_size = sizeof(uint32_t);
            break;
        case TA_PROP_TYPE_UUID:
            prop_val->prop_size = sizeof(TEE_UUID);
            break;
        case TA_PROP_GET_NAME:
            prop_val->prop_size = name_len;
            break;
        default:
            return TEE_ERROR_BAD_PARAMETERS;
    }

    sys_res = ta_config_prop(name, prop_val, enum_idx, set_or_enum);

    /* If client property is not found in standard client properties.*/
    if (set_or_enum == TEE_PROPSET_CURRENT_CLIENT &&
        sys_res == ERR_NOT_FOUND) {
        TEE_Identity tmp_val;
        /* Get the client's UUID for the syscall */
        get_client_identity((void *)&tmp_val);

        /* If property is not in standard client properties and if login type
         * is TEE_LOGIN_TRUSTED_APP search in client TA properties.
         */
        if (tmp_val.login == TEE_LOGIN_TRUSTED_APP) {
            sys_res = get_ta_client_props((uuid_t *)&tmp_val.uuid, name,
                                          (void *)prop_val,
                                          enum_idx - propset_client_len);
        }
        else
            sys_res = ERR_INVALID_ARGS;
    }

    if (sys_res == ERR_INVALID_ARGS)
        res = TEE_ERROR_BAD_FORMAT;
    else if(sys_res == ERR_NOT_FOUND)
        res = TEE_ERROR_ITEM_NOT_FOUND;
    else if(sys_res == ERR_NOT_ENOUGH_BUFFER)
        res = TEE_ERROR_SHORT_BUFFER;
    else if (sys_res == NO_ERROR)
        res = TEE_SUCCESS;
    else
        res = TEE_ERROR_GENERIC;

    return res;
}

TEE_Result TEE_GetPropertyAsBool(TEE_PropSetHandle propsetOrEnumerator,
                                 const char *name, bool *value)
{
    TEE_Result res = 0;
    bool prop_val;
    struct result_property property = {NULL, {TA_PROP_TYPE_BOOL},
                                       (void *)&prop_val};

    if (value == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_prop(propsetOrEnumerator, name, 0, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_BOOL &&
        property.type != TA_PROP_TYPE_U32)
        return TEE_ERROR_BAD_FORMAT;

    if(res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    *value = *(bool *)property.value;

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsBinaryBlock(TEE_PropSetHandle propsetOrEnumerator,
                                        const char *name, void *valueBuffer,
                                        uint32_t *valueBufferLen)
{
    TEE_Result res;
    char prop_val[MAX_STR];
    struct result_property property = {NULL, {TA_PROP_TYPE_BIN_BLOCK},
                                       (void *)prop_val};

    if (valueBuffer == NULL || valueBufferLen == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_prop(propsetOrEnumerator, name, 0, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_BIN_BLOCK)
        return TEE_ERROR_BAD_FORMAT;

    if(res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;

    if (res != TEE_SUCCESS)
        TEE_Panic(res);

    return b64_dec(property.value, valueBuffer, valueBufferLen);
}

TEE_Result TEE_GetPropertyAsIdentity(TEE_PropSetHandle propsetOrEnumerator,
                                     const char *name, TEE_Identity *value)
{
    TEE_Result res = 0;
    TEE_Identity prop_val;
    struct result_property property = {NULL, {TA_PROP_TYPE_ID},
                                       (void *)&prop_val};

    if (value == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_prop(propsetOrEnumerator, name, 0, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_ID)
        return TEE_ERROR_BAD_FORMAT;

    if(res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    memcpy((void *)value, property.value, sizeof(TEE_Identity));

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsString(TEE_PropSetHandle propsetOrEnumerator,
                                   const char *name, char *valueBuffer,
                                   uint32_t *valueBufferLen)
{
    TEE_Result res = 0;
    /* Use string type for value as this will give large enough buffer for
     * all value types.
     */
    char prop_val[MAX_STR];
    struct result_property property = {NULL, {TA_PROP_TYPE_STR},
                                       (void *)prop_val};
    uint32_t buff_size;
    TEE_Identity *id_to_string = (TEE_Identity *)property.value;
    TEE_UUID *uuid_to_string = (TEE_UUID *)property.value;
    uint32_t *u32_to_string = (uint32_t *)property.value;

    if (valueBuffer == NULL || valueBufferLen == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_prop(propsetOrEnumerator, name, 0, &property);

    if (res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;

    switch(property.type) {
        case TA_PROP_TYPE_BOOL:
            if (((char *)property.value)[0])
                buff_size = strlcpy(valueBuffer, "True", MAX_STR);
            else
                buff_size = strlcpy(valueBuffer, "False", MAX_STR);
            break;
        case TA_PROP_TYPE_BIN_BLOCK:
        case TA_PROP_TYPE_STR:
            buff_size = strlcpy(valueBuffer, (char *)property.value, MAX_STR);
            break;
        case TA_PROP_TYPE_ID:
            buff_size = snprintf(valueBuffer, MAX_STR,
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
            buff_size = snprintf(valueBuffer, MAX_STR, "%u",
                                 (uint32_t)(*u32_to_string));
            break;
        case TA_PROP_TYPE_UUID:
            buff_size = snprintf(valueBuffer, MAX_STR,
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
            return TEE_ERROR_BAD_PARAMETERS;
    }

    /* The returned sizes don't count trailing '\0' in length,
     * so it is added here.
     */
    if (++buff_size > *valueBufferLen)
        return TEE_ERROR_SHORT_BUFFER;

    if (res != TEE_SUCCESS)
        TEE_Panic(res);

    *valueBufferLen = buff_size;

    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle propsetOrEnumerator,
                                const char *name, uint32_t *value)
{
    TEE_Result res = 0;
    uint32_t prop_val;
    struct result_property property = {NULL, {TA_PROP_TYPE_U32},
                                       (void *)&prop_val};

    if (value == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_prop(propsetOrEnumerator, name, 0, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_BOOL &&
        property.type != TA_PROP_TYPE_U32)
        return TEE_ERROR_BAD_FORMAT;

    if(res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    *value = *(uint32_t *)property.value;
    return TEE_SUCCESS;
}

TEE_Result TEE_GetPropertyAsUUID(TEE_PropSetHandle propsetOrEnumerator,
                                 const char *name, TEE_UUID *value)
{
    TEE_Result res = 0;
    TEE_UUID prop_val;
    struct result_property property = {NULL, {TA_PROP_TYPE_UUID},
                                       (void *)&prop_val};

    if (value == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = get_prop(propsetOrEnumerator, name, 0, &property);

    if (res == TEE_SUCCESS && property.type != TA_PROP_TYPE_UUID)
        return TEE_ERROR_BAD_FORMAT;

    if(res == TEE_ERROR_BAD_FORMAT || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    memcpy((void *)value, (void *)property.value, sizeof(TEE_UUID));

    return TEE_SUCCESS;
}

TEE_Result TEE_AllocatePropertyEnumerator(TEE_PropSetHandle *enumerator)
{
    struct prop_enum *enum_ptr;

    if (enumerator == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    enum_ptr = (struct prop_enum *)TEE_Malloc(sizeof(struct prop_enum), 0);

    if (enum_ptr == NULL) {
        enum_ptr = TEE_HANDLE_NULL;
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    enum_ptr->index = ALLOCATED_ENUMERATOR;

    *enumerator = (TEE_PropSetHandle) enum_ptr;

    return TEE_SUCCESS;
}

void TEE_FreePropertyEnumerator(TEE_PropSetHandle enumerator)
{
    struct prop_enum *enum_ptr = (struct prop_enum *)enumerator;
    TEE_Free((void *)enum_ptr);
}

void TEE_StartPropertyEnumerator(TEE_PropSetHandle enumerator,
                                 TEE_PropSetHandle propSet)
{
    struct prop_enum *enum_ptr = (struct prop_enum *)enumerator;

    if (enumerator == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    enum_ptr->index = 0;
    enum_ptr->propSet = propSet;
}

void TEE_ResetPropertyEnumerator(TEE_PropSetHandle enumerator)
{
    struct prop_enum *enum_ptr = (struct prop_enum *)enumerator;

    if (enumerator == NULL)
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);

    enum_ptr->index = ALLOCATED_ENUMERATOR;
}

TEE_Result TEE_GetPropertyName(TEE_PropSetHandle enumerator, void *nameBuffer,
                               uint32_t *nameBufferLen)
{
    TEE_Result res = 0;
    /* Use string type for value as this will give large enough buffer for
     * all value types
     */
    char prop_val[MAX_STR];
    char *prop_name = (char *)TEE_Malloc(*nameBufferLen, 0);
    struct result_property property = {NULL, {TA_PROP_GET_NAME},
                                       (void *)prop_val};
    struct prop_enum *enum_ptr = (struct  prop_enum *)enumerator;

    if (prop_name)
        property.name = prop_name;
    else {
        res = TEE_ERROR_OUT_OF_MEMORY;
        goto prop_name_err;
    }

    if (enum_ptr->index == ALLOCATED_ENUMERATOR) {
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    res = get_prop(enumerator, NULL, *nameBufferLen, &property);

prop_name_err:
    if (res == TEE_ERROR_SHORT_BUFFER || res == TEE_ERROR_ITEM_NOT_FOUND)
        return res;
    else if (res != TEE_SUCCESS)
        TEE_Panic(res);

    if (strlen(property.name) >= *nameBufferLen)
        return TEE_ERROR_SHORT_BUFFER;

    *nameBufferLen = strlen(property.name) + 1;
    strlcpy((char *)nameBuffer, property.name, *nameBufferLen);

    return TEE_SUCCESS;
}

TEE_Result TEE_GetNextProperty(TEE_PropSetHandle enumerator)
{
    struct prop_enum *enum_ptr = (struct  prop_enum *)enumerator;
    uint32_t props_num = 0;
    long sys_res = NO_ERROR;
    TEE_Result res = TEE_SUCCESS;

    if (enum_ptr->index == ALLOCATED_ENUMERATOR) {
                sys_res = ERR_NOT_FOUND;
                goto next_prop_err;
    } else
        enum_ptr->index++;

    switch((uint32_t) enum_ptr->propSet) {
        case TEE_PROPSET_CURRENT_TA:
            if (enum_ptr->index >= ta_context->extern_props_size)
                sys_res = ERR_NOT_FOUND;
            break;
        case TEE_PROPSET_CURRENT_CLIENT:
        {
            TEE_Identity tmp_val;
            /* Get the client's UUID for the syscall */
            get_client_identity((void *)&tmp_val);

            /* If login type is TEE_LOGIN_TRUSTED_APP get client TA
             * properties also.
             */
            if (tmp_val.login == TEE_LOGIN_TRUSTED_APP) {
                sys_res = get_props_num((uuid_t *)&tmp_val.uuid,
                                        TEE_PROPSET_CURRENT_CLIENT,
                                        &props_num);
                if (sys_res != NO_ERROR)
                    goto next_prop_err;
            }
            else
                /* If login type is not TEE_LOGIN_TRUSTED_APP, client's TA
                 * configuration properties cannot be accessed.
                 */
                props_num = 0;

            if (enum_ptr->index >= props_num + propset_client_len)
                sys_res = ERR_NOT_FOUND;
        }
            break;
        case TEE_PROPSET_TEE_IMPLEMENTATION:
            sys_res = get_props_num(NULL, TEE_PROPSET_TEE_IMPLEMENTATION,
                                    &props_num);
            if (sys_res != NO_ERROR)
                goto next_prop_err;
            if (enum_ptr->index >= props_num)
                sys_res = ERR_NOT_FOUND;
            break;
        default:
            sys_res = ERR_INVALID_ARGS;
    };

next_prop_err:
    if (sys_res == ERR_NOT_FOUND)
        res = TEE_ERROR_ITEM_NOT_FOUND;
    else if (sys_res == NO_ERROR)
        res = TEE_SUCCESS;
    else if (sys_res == ERR_INVALID_ARGS)
        res = TEE_ERROR_BAD_FORMAT;
    else if (sys_res == ERR_ACCESS_DENIED)
        res = TEE_ERROR_ACCESS_DENIED;

    if (res != TEE_ERROR_ITEM_NOT_FOUND &&
        res != TEE_SUCCESS)
        TEE_Panic(res);

    return res;
}
