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
#include <tee_api_properties.h>
#include <lib/tee/tee_api.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "KTEE"

static uint _tee_api_info_slot_id;
static uint _tee_api_nv_info_slot_id;

static const tee_api_kprops_t tee_api_default_kprops = {
	.single_instance = true,
	.multi_session = false,
	.keep_alive = false,
};

tee_api_info_t *tee_api_info(trusty_app_t *ta)
{
	return trusty_als_get(ta, _tee_api_info_slot_id);
}

tee_api_nv_info_t *tee_api_nv_info(trusty_app_t *ta)
{
	return trusty_als_get(ta, _tee_api_nv_info_slot_id);
}

tee_api_kprops_t *tee_api_kprops(trusty_app_t *ta)
{
	return &tee_api_nv_info(ta)->kprops;
}

static bool is_single_instance(trusty_app_t *ta)
{
	return tee_api_kprops(ta)->single_instance;
}

static bool is_multi_session(trusty_app_t *ta)
{
	return tee_api_kprops(ta)->multi_session;
}

static bool is_keep_alive(trusty_app_t *ta)
{
	return tee_api_kprops(ta)->keep_alive;
}

/*
 * Provide custom implementation to override default implementation.
 *
 * On success - copies a default ipc port name to buffer and
 *            - returns length of port name including trailing '\0'
 * On error   - returns negative error code
 */
int ipc_port_get_default_name(trusty_app_t *ta, char *buffer, ssize_t size)
{
	int len;
	uuid_t *uuid = &ta->props.uuid;
	uint32_t instance_id = (uint32_t)ta->ut;

	len = snprintf(buffer, size, UUID_STR_FORMAT "_id_%08x-%08x",
		   uuid->time_low, uuid->time_mid, uuid->time_hi_and_version,
		   uuid->clock_seq_and_node[0], uuid->clock_seq_and_node[1],
		   uuid->clock_seq_and_node[2], uuid->clock_seq_and_node[3],
		   uuid->clock_seq_and_node[4], uuid->clock_seq_and_node[5],
		   uuid->clock_seq_and_node[6], uuid->clock_seq_and_node[7],
		   instance_id, tee_api_nv_info(ta)->port_tag);
	if (len < 0 || len >= size)
		return ERR_INVALID_ARGS;
	/* snprintf returns length not including trailing '\0', add it here */
	return len + 1;
}

/*
 * Sets ta_instance only if ERR_ALREADY_STARTED or NO_ERROR,
 * returns ta_instance NULL for other !NO_ERROR codes.
 * ERR_ALREADY_STARTED is only expected for single_instance TAs,
 * multi_instance TAs start a new clone and return NO_ERROR on success.
 */
static int tee_api_create_ta_instance(uuid_t *uuid, trusty_app_t **ta_instance)
{
	int res = NO_ERROR;
	trusty_app_t *ta;
	trusty_app_t *ta_clone = NULL;

	*ta_instance = NULL;

	res = trusty_app_start_instance(uuid, &ta);
	if (res == ERR_NOT_FOUND)
		goto done;

	if (is_single_instance(ta)) {
		if ((res == NO_ERROR) || (res == ERR_ALREADY_STARTED))
			*ta_instance = ta;
	} else {
		/* Multi-instance app */
		if (res == NO_ERROR)
			*ta_instance = ta;
		else if (res == ERR_ALREADY_STARTED) {
			/* Clone new instance of parent app and start it */
			res = trusty_app_start_clone(uuid, &ta_clone);
			if (res == NO_ERROR)
				*ta_instance = ta_clone;
		}
	}

done:
	/* validate exit parameter logic */
	if (res == NO_ERROR)
		DEBUG_ASSERT(*ta_instance != NULL);
	else if (res == ERR_ALREADY_STARTED)
		DEBUG_ASSERT((*ta_instance != NULL) &&
				is_single_instance(*ta_instance));
	else
		DEBUG_ASSERT(*ta_instance == NULL);

	return res;
}

static status_t tee_api_connect_to_ta(trusty_app_t *dest_ta,
				      handle_id_t *channel)
{
	status_t res;
	char port_name[IPC_PORT_PATH_MAX];
	int len;

	len = ipc_port_get_default_name(dest_ta, port_name, sizeof(port_name));
	if (len < 0)
		return (status_t)len;

	res = k_sys_connect(port_name, IPC_CONNECT_ASYNC |
					IPC_CONNECT_WAIT_FOR_PORT);
	if (res < NO_ERROR) {
		/*
		 * ERR_NOT_FOUND here means problem in connecting to port.
		 * However, the only valid "error not found" while opening a
		 * session is if no Trusted Application matches the requested
		 * destination UUID. Set error code to indicate a communication
		 * error instead.
		 */
		if (res == ERR_NOT_FOUND)
			res = ERR_NOT_VALID;
		return res;
	}

	*channel = (handle_id_t)res;

	return NO_ERROR;
}

TEE_Result __SYSCALL sys_get_ta_flags(const uuid_t *dest_uuid, uint32_t *flags)
{
	trusty_app_t *trusty_app;
	uint32_t ta_flags = 0;
	bool value = false;

	trusty_app = trusty_app_find_by_uuid((uuid_t *)dest_uuid);
	if (!trusty_app) {
		TEE_DBG_MSG("Cannot find TA (in %s:%d)\n",
				__FUNCTION__, __LINE__);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	value = is_single_instance(trusty_app);
	ta_flags |= value ? TA_FLAGS_SINGLE_INSTANCE : 0;
	value = is_multi_session(trusty_app);
	ta_flags |= value ? TA_FLAGS_MULTI_SESSION : 0;
	value = is_keep_alive(trusty_app);
	ta_flags |= value ? TA_FLAGS_KEEP_ALIVE : 0;

	return tee_copy_to_user((user_addr_t)flags, &ta_flags,
			sizeof(uint32_t));
}

TEE_Result __SYSCALL sys_connect_to_ta(const uuid_t *dest_uuid,
		uint32_t *handle_id)
{
	status_t sys_res;
	TEE_Result tee_res;
	trusty_app_t *dest_ta = NULL;
	uuid_t uuid;
	handle_id_t channel = INVALID_HANDLE_ID;
	bool allow_instance_cleanup = true;
	bool err_cleanup_instance = false;

	/* Verify user uuid access rights and copy to kernel */
	tee_res = tee_copy_from_user(&uuid, (user_addr_t)dest_uuid,
			sizeof(uuid_t));
	if (tee_res != TEE_SUCCESS)
		return tee_res;

	/* set handle_id now to validate the pointer and to simplify error
	 * handling for TA instantiation; update it after connecting to TA.
	 */
	tee_res = tee_copy_to_user((user_addr_t)handle_id, &channel,
			sizeof(channel));
	if (tee_res != TEE_SUCCESS)
		return tee_res;

	sys_res = tee_api_create_ta_instance(&uuid, &dest_ta);
	if (sys_res == ERR_ALREADY_STARTED) {
		/* Only single_instance TA should return ERR_ALREADY_STARTED */

		/* Prevent error cleanup from destroying single_instance TA
		 * e.g. by calling open session with invalid parameters to
		 * force the instance to be cleaned up.
		 */
		if (dest_ta && is_single_instance(dest_ta))
			allow_instance_cleanup = false;
		else
			sys_res = ERR_NOT_VALID;

	} else if (sys_res)
		goto err_done;

	if (dest_ta == NULL) {
		sys_res = ERR_NOT_VALID;
		goto err_done;
	}

	err_cleanup_instance = true;

	sys_res = tee_api_connect_to_ta(dest_ta, &channel);

err_done:
	if (sys_res < NO_ERROR) {
		TEE_DBG_MSG("Error code = %d\n", sys_res);
		if (err_cleanup_instance && allow_instance_cleanup)
			trusty_app_exit(dest_ta);
	}

	*handle_id = channel;
	return err_to_tee_err(sys_res);
}

static status_t tee_api_load_properties(trusty_app_t *ta)
{
	status_t res = NO_ERROR;

	if (!ta->props.custom_cfg_ptr) {
		TEE_DBG_MSG("Tee API Properties do not exist\n");
		return ERR_INVALID_ARGS;
	}

	/* Set default values for kernel tee api properties */
	tee_api_kprops_t *kprops = tee_api_kprops(ta);
	memcpy(kprops, &tee_api_default_kprops, sizeof(*kprops));

	/* Copy user properties from user space into a kernel space
	 * structure to support querying ta properties from another ta context
	 */

	if (ta->is_parent)
		res = properties_copy_from_user(ta);

	if (!ta->is_parent) {
		trusty_app_t *ta_parent;
		ta_parent = trusty_app_find_by_uuid(&ta->props.uuid);

		if (!ta_parent)
			return ERR_NOT_FOUND;

		tee_api_kprops_t *k_props_parent = tee_api_kprops(ta_parent);
		memcpy(kprops, k_props_parent, sizeof(*kprops));
	}

	return res;
}

static void tee_api_info_free(trusty_app_t *ta)
{
	tee_api_info_t *ta_info = tee_api_info(ta);

	if (ta_info) {
		memset(ta_info, 0, sizeof(*ta_info));
		free(ta_info);
		trusty_als_set(ta, _tee_api_info_slot_id, NULL);
	}
}

static void tee_api_nv_info_free(trusty_app_t *ta)
{
	tee_api_nv_info_t *nv_info = tee_api_nv_info(ta);

	if (!ta->is_parent && nv_info) {
		memset(nv_info, 0, sizeof(*nv_info));
		free(nv_info);
		trusty_als_set(ta, _tee_api_nv_info_slot_id, NULL);
	}
}

static status_t tee_api_nv_info_init(trusty_app_t *ta)
{
	tee_api_nv_info_t *nv_info = calloc(1, sizeof(*nv_info));

	if (!nv_info)
		return ERR_NO_MEMORY;

	trusty_als_set(ta, _tee_api_nv_info_slot_id, nv_info);

	nv_info->port_tag = rand();

	return tee_api_load_properties(ta);
}

static status_t tee_api_info_init(trusty_app_t *ta)
{
	tee_api_info_t *ta_info = calloc(1, sizeof(*ta_info));

	if (!ta_info)
		return ERR_NO_MEMORY;

	trusty_als_set(ta, _tee_api_info_slot_id, ta_info);

	/* set non-zero defaults */
	ta_info->ta_port = INVALID_HANDLE_ID;
	ta_info->ta_channel = INVALID_HANDLE_ID;
	ta_info->cancel_masked = true;
	list_initialize(&ta_info->operation_list);
	list_initialize(&ta_info->cryp_states);
	list_initialize(&ta_info->objects);

	return NO_ERROR;
}

static status_t _tee_api_startup_notifier(trusty_app_t *ta)
{
	status_t res;

	res = tee_api_nv_info_init(ta);
	if (res)
		goto nv_info_err;

	res = tee_api_info_init(ta);
	if (res)
		goto ta_info_err;

	return NO_ERROR;

ta_info_err:
	tee_api_info_free(ta);
nv_info_err:
	tee_api_nv_info_free(ta);

	return res;
}

static status_t _tee_api_shutdown_notifier(trusty_app_t *ta)
{
	tee_api_info_free(ta);
	tee_api_nv_info_free(ta);
	return NO_ERROR;
}

static struct trusty_app_notifier _tee_api_notifier = {
	.startup = _tee_api_startup_notifier,
	.shutdown = _tee_api_shutdown_notifier,
};

static void tee_api_init(uint level)
{
	int res;

	/* Allocate als slot */
	res = trusty_als_alloc_slot();
	if (res < 0)
		panic("failed (%d) to alloc als slot\n", res);
	_tee_api_nv_info_slot_id = res;

	res = trusty_als_alloc_slot();
	if (res < 0)
		panic("failed (%d) to alloc als slot\n", res);
	_tee_api_info_slot_id = res;

	/* Register notifier */
	res = trusty_register_app_notifier(&_tee_api_notifier);
	if (res < 0)
		panic("failed (%d) to register tee_api notifier\n", res);
}

LK_INIT_HOOK(tee_api, tee_api_init, LK_INIT_LEVEL_APPS - 2);
