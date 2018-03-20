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

#include <stdlib.h>
#include <string.h>
#include <lk/init.h>
#include <uthread.h>
#include <lib/syscall.h>
#include <lib/trusty/uuid.h>
#include <lib/trusty/uctx.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/trusty_app.h>
#include <tee_common_uapi.h>
#include <tee_arith_internal.h>
#include <tee_api_properties.h>
#include <lib/tee/tee_api.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "KTEE"

/* Masks for GP defined properties. */
#define GPD_TA_APPID        (1<<0)
#define GPD_TA_INSTANCE     (1<<1)
#define GPD_TA_SESSION      (1<<2)
#define GPD_TA_ALIVE        (1<<3)
#define GPD_TA_DATA         (1<<4)
#define GPD_TA_STACK        (1<<5)
#define GPD_TA_VERSION      (1<<6)
#define GPD_TA_DESC         (1<<7)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define SPACE " "
static const char description[] = APIVERSION SPACE DESCRIPTION;

static const struct ta_property tee_implementation[] = {
	{ "gpd.tee.apiversion", TA_PROP_TYPE_STR, APIVERSION },
	{ "gpd.tee.description", TA_PROP_TYPE_STR, description },
	{ "gpd.tee.deviceID", TA_PROP_TYPE_UUID, &(const uuid_t)TEE_DEVICE_UUID },
	{ "gpd.tee.systemTime.protectionLevel", TA_PROP_TYPE_U32,
	  &(const uint32_t){TEE_SYSTIME_PROTECT_LVL} },
	{ "gpd.tee.TAPersistentTime.protectionLevel", TA_PROP_TYPE_U32,
	  &(const uint32_t){TEE_PERSTIME_PROTECT_LVL} },
	{ "gpd.tee.trustedos.implementation.version", TA_PROP_TYPE_STR,
	  TEE_VERSION },
	{ "gpd.tee.trustedos.implementation.binaryversion", TA_PROP_TYPE_BIN_BLOCK,
	  TEE_BINVERSION },
	{ "gpd.tee.trustedos.manufacturer", TA_PROP_TYPE_STR, MANUFACTURER },
	{ "gpd.tee.arith.maxBigIntSize", TA_PROP_TYPE_U32,
	  &(const uint32_t){TEE_MAX_NUMBER_OF_SUPPORTED_BITS} },
	{ "gpd.tee.cryptography.ecc", TA_PROP_TYPE_BOOL, &(const bool){false} },
	{ "gpd.tee.trustedStorage.antiRollback.protectionLevel", TA_PROP_TYPE_U32,
	  &(const uint32_t){TEE_TS_ANTIRB_PROT_LVL} },
	{ "gpd.tee.firmware.implementation.version", TA_PROP_TYPE_STR,
	  TEE_FW_VERSION },
	{ "gpd.tee.firmware.implementation.binaryversion", TA_PROP_TYPE_BIN_BLOCK,
	  TEE_FW_BINVERSION },
	{ "gpd.tee.firmware.manufacturer", TA_PROP_TYPE_STR, TEE_FW_MANUFACTURER },
};

static const size_t tee_implementation_len = ARRAY_SIZE(tee_implementation);

struct trusty_ta_property {
	const char *name;
	uint32_t type;
	int struct_offset;
};

struct trusty_ta_property trusty_props[] = {
	{ "gpd.ta.appID", TA_PROP_TYPE_UUID,
		offsetof(trusty_app_props_t, uuid) },
	{ "trusty.ta.autostart", TA_PROP_TYPE_BOOL,
		offsetof(trusty_app_props_t, auto_start) },
	{ "trusty.ta.min_heap_size", TA_PROP_TYPE_U32,
		offsetof(trusty_app_props_t, min_heap_size) },
	{ "trusty.ta.map_io_mem_cnt", TA_PROP_TYPE_U32,
		offsetof(trusty_app_props_t, map_io_mem_cnt) },
	{ "trusty.ta.min_stack_size", TA_PROP_TYPE_U32,
		offsetof(trusty_app_props_t, min_stack_size) },
	{ "trusty.ta.privileges", TA_PROP_TYPE_U32,
		offsetof(trusty_app_props_t, privileges) },
};

#define TRUSTY_PROP_VALUE(trusty_prop_ptr, struct_base) \
	(void *)((char *)(struct_base) + (trusty_prop_ptr)->struct_offset)

static const size_t trusty_ta_props_len = ARRAY_SIZE(trusty_props);

static tee_api_properties_t *tee_api_properties(trusty_app_t *ta)
{
	return ta->props.custom_cfg_ptr;
}

static status_t tee_api_u_props_num(trusty_app_t *ta, uint32_t *ta_props_num)
{
	int res = NO_ERROR;
	void *u_props_num_kaddr;
	uint32_t *u_props_num_uaddr = ta->props.custom_cfg_size;

	res = uthread_virt_to_kvaddr(ta->ut, (vaddr_t)u_props_num_uaddr,
			&u_props_num_kaddr);
	if (res)
		return res;

	/* Set properties array size */
	*ta_props_num = *(uint32_t *)u_props_num_kaddr;

	return res;
}

static status_t tee_api_u_props_kaddr(trusty_app_t *ta,
				      struct ta_property **u_props_kaddr)
{
	int res = NO_ERROR;
	void *props_kaddr;
	uthread_t *ut = ta->ut;
	tee_api_properties_t *u_props_uaddr = tee_api_properties(ta);

	if (!u_props_uaddr) {
		*u_props_kaddr = NULL;
		return NO_ERROR;
	}

	res = uthread_virt_to_kvaddr(ut, (vaddr_t)u_props_uaddr, &props_kaddr);
	if (res)
		return res;

	/* Set kernel address of properties array */
	*u_props_kaddr = (struct ta_property *)props_kaddr;

	return res;
}

static status_t valid_props_to_karray(struct ta_property *kprops,
				      char *name, uint32_t type, void *value)
{
	uint32_t value_size = 0;

	kprops->type = type;
	switch (kprops->type) {
	case TA_PROP_TYPE_BOOL:
		value_size = sizeof(bool);
		break;
	case TA_PROP_TYPE_BIN_BLOCK:
	case TA_PROP_TYPE_STR:
		value_size = strlen((char *)value) + 1;
		break;
	case TA_PROP_TYPE_ID:
		value_size = sizeof(TEE_Identity);
		break;
	case TA_PROP_TYPE_U32:
		value_size = sizeof(uint32_t);
		break;
	case TA_PROP_TYPE_UUID:
		value_size = sizeof(TEE_UUID);
		break;
	default:
		TEE_DBG_MSG("WARNING: Invalid propery type!\n");
		return ERR_INVALID_ARGS;
	};

	kprops->name = (char *)malloc(strlen(name)+1);
	if (kprops->name == NULL)
		return ERR_NO_MEMORY;
	strlcpy((void *)kprops->name, (void *)name, strlen(name)+1);

	kprops->value = malloc(value_size);
	if (kprops->value == NULL)
		return ERR_NO_MEMORY;
	memcpy((void *)kprops->value, (void *)value, value_size);

	return NO_ERROR;
}

static status_t check_gpd_usage(char *prop_name)
{
	const char *pattern = "gpd.";
	char *substr = strstr(prop_name, pattern);

	if (substr && !strcmp(prop_name, substr)) {
		TEE_DBG_MSG("WARNING: Invalid property name: %s\n", prop_name);
		return ERR_INVALID_ARGS;
	}

	return NO_ERROR;
}

static status_t properties_copy_from_user_gpd_ta(
		trusty_app_t *ta,
		const struct ta_property *u_props_kaddr,
		struct ta_property *validating_props,
		tee_api_kprops_t *k_props,
		uint8_t *mask_gpd)
{
	status_t res = NO_ERROR;
	uthread_t *ut = ta->ut;
	char *name = NULL;
	void *value = NULL;

	res = uthread_virt_to_kvaddr(ut, (vaddr_t)u_props_kaddr->name,
			(void **)&name);
	if (res)
		return res;

	res = uthread_virt_to_kvaddr(ut, (vaddr_t)u_props_kaddr->value,
			&value);
	if (res)
		return res;

	if ((strcmp("gpd.ta.multiSession", name) == 0) &&
			!(*mask_gpd & GPD_TA_SESSION)) {

		k_props->multi_session = *(bool *)value;
		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_SESSION;
	} else if ((strcmp("gpd.ta.singleInstance", name) == 0) &&
			!(*mask_gpd & GPD_TA_INSTANCE)) {

		k_props->single_instance = *(bool *)value;
		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_INSTANCE;
	} else if ((strcmp("gpd.ta.instanceKeepAlive", name) == 0) &&
			!(*mask_gpd & GPD_TA_ALIVE)) {

		k_props->keep_alive = *(bool *)value;
		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_ALIVE;
	} else if ((strcmp("gpd.ta.dataSize", name) == 0) &&
			!(*mask_gpd & GPD_TA_DATA)) {

		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_DATA;
	} else if ((strcmp("gpd.ta.stackSize", name) == 0) &&
			!(*mask_gpd & GPD_TA_STACK)) {

		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_STACK;
	} else if ((strcmp("gpd.ta.version", name) == 0) &&
			!(*mask_gpd & GPD_TA_VERSION)) {

		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_VERSION;
	} else if ((strcmp("gpd.ta.description", name) == 0) &&
			!(*mask_gpd & GPD_TA_DESC)) {

		res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);
		*mask_gpd |= GPD_TA_DESC;
	} else if (strcmp("gpd.ta.appID", name) == 0) {
		/* "gpd.ta.appID" is already set from UUID field. */
		res = ERR_INVALID_ARGS;
	} else {
		/* Handle non GP defined properties. */
		/* There should be no properties starting with "gpd." here. */
		res = check_gpd_usage(name);
		if (res == NO_ERROR)
			res = valid_props_to_karray(validating_props, name,
				u_props_kaddr->type, value);

	}
	return res;
}

status_t properties_copy_from_user(trusty_app_t *ta)
{
	status_t res = NO_ERROR;
	tee_api_kprops_t *k_props = tee_api_kprops(ta);
	uint32_t props_num = 0, i;
	struct ta_property *u_props_kaddr = NULL;
	uint8_t mask_gpd = 0;
	struct ta_property *validating_props;
	struct trusty_ta_property *trusty_prop;

	/* The tee api ta_property structure and the .value field pointers
	 * within it are user space addresses mapped to each TA.  Translate
	 * these to kernel virtual addresses before copying.
	 */
	res = tee_api_u_props_kaddr(ta, &u_props_kaddr);
	if (res)
		return res;

	if (!u_props_kaddr)
		props_num = 0;
	else {
		res = tee_api_u_props_num(ta, &props_num);
		if (res)
			return res;
	}

	ta->props.valid_ta_props = malloc((props_num + trusty_ta_props_len) *
					sizeof(struct ta_property));
	if (ta->props.valid_ta_props == NULL)
		return ERR_NO_MEMORY;
	validating_props = (struct ta_property *)ta->props.valid_ta_props;
	ta->props.valid_ta_props_cnt = 0;

	/* Copy the UUID and the rest of the trusty defined properties to an
	 * array of verified properties.
	 */
	for (i = 0; i < trusty_ta_props_len; i++) {
		trusty_prop = &trusty_props[i];
		res = valid_props_to_karray(validating_props,
				(char *)trusty_prop->name, trusty_prop->type,
				TRUSTY_PROP_VALUE(trusty_prop, &ta->props));
		if (res != NO_ERROR)
			goto err_property;

		ta->props.valid_ta_props_cnt++;
		validating_props++;
	}

	/* Copy values from user space */
	for (i = 0; i < props_num; i++) {

		res = properties_copy_from_user_gpd_ta(ta, u_props_kaddr,
				validating_props, k_props, &mask_gpd);

		u_props_kaddr++;

		if (res == ERR_INVALID_ARGS) {
			TEE_DBG_MSG("If property is invalid, just skip it.\n");
			res = NO_ERROR;
			continue;
		} else if (res != NO_ERROR) {
			break;
		}

		validating_props++;
		ta->props.valid_ta_props_cnt++;
	}

err_property:
	if (res != NO_ERROR && res != ERR_INVALID_ARGS) {
		/* Free all name and value fields already allocated. */
		validating_props = ta->props.valid_ta_props;
		for (i = 0; i < ta->props.valid_ta_props_cnt; i++) {
			free((void *)validating_props->name);
			free((void *)validating_props->value);
			validating_props++;
		}
		free(ta->props.valid_ta_props);
		ta->props.valid_ta_props = NULL;
		ta->props.valid_ta_props_cnt = 0;
	} else {
		/* Shrink allocated memory to valid properties size. */
		ta->props.valid_ta_props = realloc(ta->props.valid_ta_props,
					       ta->props.valid_ta_props_cnt *
					       sizeof(struct ta_property));
	}

	return res;
}

static TEE_Result tee_props_get(const char *props_name, size_t name_len,
		void *prop, uint32_t index, uint32_t prop_set,
		const uuid_t *uuid)
{
	TEE_Result res;
	const struct ta_property *property_ptr;
	uint32_t prop_size;
	struct result_property *ret_prop = (struct result_property *)prop;
	size_t prop_len = 0;

	res = tee_check_user_param_rw((user_addr_t)ret_prop,
			sizeof(struct result_property));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_check_user_param_w((user_addr_t)ret_prop->value,
			ret_prop->value_buf_len);
	if (res != TEE_SUCCESS)
		return res;

	if (props_name) {
		res = tee_check_user_param_r((user_addr_t)props_name,
				name_len);
		if (res != TEE_SUCCESS)
			return res;
	}

	if (prop_set == TEE_PROPSET_TEE_IMPLEMENTATION) {
		property_ptr = tee_implementation;
		prop_size = tee_implementation_len;
	} else if (prop_set == TEE_PROPSET_CURRENT_TA) {
		trusty_app_t *ta = tee_get_current_ta();

		property_ptr = ta->props.valid_ta_props;
		prop_size = ta->props.valid_ta_props_cnt;
	} else if (prop_set == TEE_PROPSET_CURRENT_CLIENT) {
		trusty_app_t *ta = trusty_app_find_by_uuid((uuid_t *)uuid);

		if (!ta) {
			TEE_DBG_MSG("Cannot find TA\n");
			return TEE_ERROR_BAD_FORMAT;
		}
		property_ptr = ta->props.valid_ta_props;
		prop_size = ta->props.valid_ta_props_cnt;
	} else {
		TEE_DBG_MSG("ERROR: Invalid property set indentifier.\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (props_name == NULL) {
		if (index >= prop_size)
			return TEE_ERROR_ITEM_NOT_FOUND;
		property_ptr += index;
		prop_size = 1;
	};

	do {
		if (props_name == NULL ||
				strncmp(props_name,
					property_ptr->name, name_len) == 0) {
			ret_prop->type = property_ptr->type;

			switch(ret_prop->type) {
			case TA_PROP_TYPE_BOOL:
			case TA_PROP_TYPE_U32:
				prop_len = sizeof(uint32_t);
				break;
			case TA_PROP_TYPE_UUID:
				prop_len = sizeof(TEE_UUID);
				break;
			case TA_PROP_TYPE_ID:
				prop_len = sizeof(TEE_Identity);
				break;
			case TA_PROP_TYPE_STR:
			case TA_PROP_TYPE_BIN_BLOCK:
				prop_len = strlcpy(ret_prop->value, property_ptr->value,
					ret_prop->value_buf_len) + 1;
				if (ret_prop->value_buf_len < prop_len) {
					ret_prop->value_buf_len = prop_len;
					return TEE_ERROR_SHORT_BUFFER;
				}
				ret_prop->value_buf_len = prop_len;
				return TEE_SUCCESS;
			default:
				return TEE_ERROR_GENERIC;
			}

			if (ret_prop->value_buf_len < prop_len) {
				ret_prop->value_buf_len = prop_len;
				return TEE_ERROR_SHORT_BUFFER;
			}

			memcpy((void *)ret_prop->value, property_ptr->value, prop_len);

			return TEE_SUCCESS;
		}
		property_ptr++;
	} while (--prop_size);

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result __SYSCALL sys_get_ta_client_props(const uuid_t *uuid,
		const char *props_name, size_t name_len,
		void *prop, uint32_t index)
{
	TEE_Result res;
	uuid_t k_uuid;

	res = tee_copy_from_user(&k_uuid, (user_addr_t)uuid,
			sizeof(k_uuid));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_props_get(props_name, name_len, prop, index,
			    TEE_PROPSET_CURRENT_CLIENT, &k_uuid);
	return res;
}

TEE_Result __SYSCALL sys_get_kprops(const char *props_name, size_t name_len,
		void *prop, uint32_t index, uint32_t prop_set)
{
	TEE_Result res;

	res = tee_props_get(props_name, name_len, prop, index,
			    prop_set, NULL);

	return res;
}

TEE_Result __SYSCALL sys_get_props_num(const uuid_t *uuid, uint32_t prop_set,
				 uint32_t *prop_length)
{
	TEE_Result res;

	res = tee_check_user_param_w((user_addr_t)prop_length,
			sizeof(*prop_length));
	if (res != TEE_SUCCESS)
		return res;

	if (prop_set == TEE_PROPSET_TEE_IMPLEMENTATION) {
		*prop_length = tee_implementation_len;
	} else if (prop_set == TEE_PROPSET_CURRENT_CLIENT) {
		uuid_t k_uuid;

		res = tee_copy_from_user(&k_uuid, (user_addr_t)uuid,
				sizeof(k_uuid));
		if (res != TEE_SUCCESS)
			return res;

		trusty_app_t *ta = trusty_app_find_by_uuid((uuid_t *)&k_uuid);

		if (!ta) {
			TEE_DBG_MSG("Cannot find TA\n");
			return TEE_ERROR_BAD_FORMAT;
		}

		*prop_length = ta->props.valid_ta_props_cnt;
	} else if (prop_set == TEE_PROPSET_CURRENT_TA) {
		trusty_app_t *ta = tee_get_current_ta();
		*prop_length = ta->props.valid_ta_props_cnt;
	} else {
		TEE_DBG_MSG("Invalid prop_set\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	return TEE_SUCCESS;
}

TEE_Result __SYSCALL sys_get_prop_name(uint32_t prop_set, uint32_t idx,
				 char *prop_name, uuid_t *uuid, size_t *len)
{
	TEE_Result res;
	const struct ta_property *property_ptr;
	uint32_t prop_size;
	size_t buf_len;

	res = tee_check_user_param_rw((user_addr_t)len, sizeof(len));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_check_user_param_w((user_addr_t)prop_name, *len);
	if (res != TEE_SUCCESS)
		return res;

	if (prop_set == TEE_PROPSET_TEE_IMPLEMENTATION) {
		property_ptr = tee_implementation;
		prop_size = tee_implementation_len;
	} else if (prop_set == TEE_PROPSET_CURRENT_TA) {
		trusty_app_t *ta = tee_get_current_ta();

		property_ptr = ta->props.valid_ta_props;
		prop_size = ta->props.valid_ta_props_cnt;
	} else if (prop_set == TEE_PROPSET_CURRENT_CLIENT) {
		uuid_t k_uuid;

		res = tee_copy_from_user(&k_uuid, (user_addr_t)uuid,
				sizeof(k_uuid));
		if (res != TEE_SUCCESS)
			return res;

		trusty_app_t *ta = trusty_app_find_by_uuid((uuid_t *)&k_uuid);

		if (!ta) {
			TEE_DBG_MSG("Cannot find TA\n");
			return TEE_ERROR_BAD_FORMAT;
		}
		property_ptr = ta->props.valid_ta_props;
		prop_size = ta->props.valid_ta_props_cnt;
	} else {
		/* This should never be reached. */
		TEE_DBG_MSG("ERROR: Invalid property set indentifier.\n");
		return TEE_ERROR_BAD_FORMAT;
	}

	if (prop_size > idx) {
		property_ptr += idx;
	} else {
		TEE_DBG_MSG("Enumerator reached the end of the property set.\n");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	buf_len = strlcpy(prop_name, property_ptr->name, *len) + 1;
	if (buf_len > *len) {
		*len = buf_len;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*len = buf_len;

	return TEE_SUCCESS;
}
