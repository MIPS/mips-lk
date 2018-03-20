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
#include <uthread.h>
#include <lib/syscall.h>
#include <lib/trusty/uuid.h>
#include <lib/trusty/uctx.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/trusty_app.h>
#include <tee_common_uapi.h>
#include <tee_api_properties.h>
#include <lib/tee/tee_api.h>
#include <platform.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "KTEE"
/* Maximal time needed for establishing connection with SM (TA)
 * or sending message to TA.
 */
#define TEE_CONNECT_SEND_MSG_TIMEOUT 2000
#define TEE_WAIT_INTERNAL_INTERVAL   50

#define TEE_LK_HANDLE_MAGIC (0x40000000u)
#define TEE_MASK_HANDLE_ID(handle_id) ((handle_id) | TEE_LK_HANDLE_MAGIC)
#define TEE_UNMASK_HANDLE_ID(handle_id) ((handle_id) ^ TEE_LK_HANDLE_MAGIC)

STATIC_ASSERT(sizeof(TEE_UUID) == sizeof(uuid_t));

/* Session manager ports */
static const char sm_comm[] = TEE_SESS_MANAGER_COMMAND_MSG;

static status_t poll_msg(uint32_t channel, uint8_t *buffer,
			 uint32_t timeout_msecs)
{
	status_t sys_res = NO_ERROR;
	uevent_t uev;

	/* Wait for parameters */
	sys_res = k_sys_wait(channel, &uev, timeout_msecs);
	if (sys_res != NO_ERROR)
		return sys_res;

	if (uev.event & IPC_HANDLE_POLL_MSG)
		sys_res = tee_get_msg_buffer(uev.handle, buffer);
	else if (uev.event & IPC_HANDLE_POLL_HUP)
		sys_res = ERR_CHANNEL_CLOSED;
	else
		sys_res = ERR_BAD_STATE;

	return sys_res;
}

static int32_t sync_connect(const char *path, uint32_t timeout)
{
	int32_t sys_res;
	uevent_t evt;
	uint32_t chan;

	sys_res = k_sys_connect(path, IPC_CONNECT_ASYNC |
					IPC_CONNECT_WAIT_FOR_PORT);
	if (sys_res >= 0) {
		chan = (uint32_t)sys_res;
		sys_res = k_sys_wait(chan, &evt, timeout);
		if (sys_res == 0) {
			sys_res = ERR_BAD_STATE;
			if (evt.handle == chan) {
				if (evt.event & IPC_HANDLE_POLL_READY)
					return chan;
				if (evt.event & IPC_HANDLE_POLL_HUP)
					sys_res = ERR_CHANNEL_CLOSED;
			}
		}
		k_sys_close(chan);
	}
	return sys_res;
}

static status_t tee_api_connect_to_sm(uint32_t timeout, const char *sm_port,
				      handle_id_t *channel)
{
	int32_t sys_res;

	/* Connect to SM port */
	assert(sm_port);
	sys_res = sync_connect(sm_port, timeout);
	if (sys_res < 0) {
		TEE_DBG_MSG("Cannot connect to SM port\n");
		return sys_res;
	}
	TEE_DBG_MSG("TA connected to SM port on channel: %d\n", sys_res);
	*channel = (uint32_t)sys_res;

	return NO_ERROR;
}

static void get_cancel_id(uint32_t *op_id, void *u_session)
{
	*op_id = vaddr_to_paddr(u_session);
}

static void uuid_to_octets(uint8_t oct[TEE_UUID_LEN], uuid_t *uuid)
{
	oct[0] = uuid->time_low >> 24;
	oct[1] = uuid->time_low >> 16;
	oct[2] = uuid->time_low >> 8;
	oct[3] = uuid->time_low;
	oct[4] = uuid->time_mid >> 8;
	oct[5] = uuid->time_mid;
	oct[6] = uuid->time_hi_and_version >> 8;
	oct[7] = uuid->time_hi_and_version;
	memcpy(oct + 8, uuid->clock_seq_and_node,
	       sizeof(uuid->clock_seq_and_node));
}

static TEE_Result prepare_open_session_msg_buffer(msg_map_t *msg_buffer,
		user_addr_t dest_uuid)
{
	trusty_app_t *ta = tee_get_current_ta();
	TEE_Result res;
	uuid_t ta_uuid;

	msg_buffer->client_ta = (uintptr_t)ta;
	msg_buffer->ret_origin = TEE_ORIGIN_TEE;
	msg_buffer->cmd = TEE_OPEN_SESSION_ID;
	msg_buffer->client_id_login = TEE_LOGIN_TRUSTED_APP;
	msg_buffer->parent_op_id = tee_api_info(ta)->parent_op_id;
	msg_buffer->parent_sess_id = tee_api_info(ta)->parent_sess_id;
	uuid_to_octets(msg_buffer->client_id_uuid, &ta->props.uuid);

	res = tee_copy_from_user(&ta_uuid, dest_uuid, sizeof(ta_uuid));
	uuid_to_octets(msg_buffer->ta_uuid, &ta_uuid);

	return res;
}

static TEE_Result prepare_invoke_command_msg_buffer(msg_map_t *msg_buffer,
		uint32_t cmd_id, uint32_t session_id)
{
	trusty_app_t *ta = tee_get_current_ta();

	msg_buffer->client_ta = (uintptr_t)ta;
	msg_buffer->ret_origin = TEE_ORIGIN_TEE;
	msg_buffer->cmd = TEE_INVOKE_COMMAND_ID;
	msg_buffer->session = session_id;
	msg_buffer->parent_op_id = tee_api_info(ta)->parent_op_id;
	msg_buffer->func = cmd_id;

	return TEE_SUCCESS;
}

static TEE_Result preprocess_sys_invoke_operation_args(user_addr_t u_uparams,
		user_addr_t u_uint_args,
		user_addr_t u_teec_session,
		uint32_t *timeout,
		uint32_t *open_sess,
		uint32_t *sm_channel,
		msg_map_t *msg_buffer)
{
	TEE_Result res;
	uint32_t user_arg_1;
	uint32_t uint_args[4];
	teec_session_t k_teec_session;

	memset(msg_buffer, 0, sizeof(*msg_buffer));

	res = tee_copy_from_user(&msg_buffer->utee_params, u_uparams,
			sizeof(msg_buffer->utee_params));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_copy_from_user(uint_args, u_uint_args, sizeof(uint_args));
	if (res != TEE_SUCCESS)
		return res;

	res = tee_copy_from_user(&k_teec_session, u_teec_session,
			sizeof(teec_session_t));
	if (res != TEE_SUCCESS)
		return res;

	*timeout = uint_args[0];
	user_arg_1 = uint_args[1];
	*open_sess = uint_args[2];
	(void)uint_args[3]; // unused

	*sm_channel = TEE_UNMASK_HANDLE_ID(k_teec_session.sm_channel);

	get_cancel_id(&msg_buffer->cancel_id, (void *)u_teec_session);

	if (*open_sess == TEEC_CMD_OPEN_SESSION) {
		user_addr_t dest_uuid = user_arg_1;
		res = prepare_open_session_msg_buffer(msg_buffer, dest_uuid);
	} else if (*open_sess == TEEC_CMD_INVOKE) {
		uint32_t cmd_id = user_arg_1;
		res = prepare_invoke_command_msg_buffer(msg_buffer, cmd_id,
			k_teec_session.session_id);
	} else
		return TEE_ERROR_BAD_PARAMETERS;

	return res;
}

static TEE_Result postprocess_sys_invoke_operation_args(user_addr_t u_uparams,
		user_addr_t u_teec_session,
		user_addr_t u_ret_orig,
		msg_map_t *sm_msg)
{
	TEE_Result res;
	utee_params_t utee_params;
	teec_session_t *teec_session;

	/* return only the parameters required by the specification to avoid
	 * leaking any state or updating fields which should not be changed.
	 */
	ta_set_return_utee_params(&utee_params, &sm_msg->utee_params);

	res = tee_copy_to_user(u_uparams, &utee_params,
			sizeof(utee_params_t));
	if (res != TEE_SUCCESS)
		return res;
	if (sm_msg->func == TEE_OPEN_SESSION_ID) {
		/* update session_id */
		teec_session = (teec_session_t *)u_teec_session;
		res = tee_copy_to_user((user_addr_t)&teec_session->session_id,
				&sm_msg->session, sizeof(uint32_t));
		if (res != TEE_SUCCESS)
			return res;
	}

	/* update return origin last if no other errors */
	res = tee_copy_to_user(u_ret_orig, &sm_msg->ret_origin,
			sizeof(uint32_t));
	if (res != TEE_SUCCESS)
		return res;

	/* success can only be generated by the trusty app itself */
	if ((sm_msg->ret_origin != TEE_ORIGIN_TRUSTED_APP) &&
			(sm_msg->ret == TEE_SUCCESS)) {
		sm_msg->ret = TEE_ERROR_GENERIC;
		TEE_DBG_MSG("Erroneous TEE_SUCCESS code changed to %x orig %x\n",
			sm_msg->ret, sm_msg->ret_origin);
	}

	return TEE_SUCCESS;
}

static status_t tee_api_request_cancellation(uint32_t channel, uint32_t op_id)
{
	status_t sys_res;
	msg_map_t cancel_msg;

	memset(&cancel_msg, 0, sizeof(cancel_msg));

	/* Prepare cancellation message. */
	cancel_msg.cmd = TEE_CANCEL_ID;
	cancel_msg.cancel_id = op_id;

	/* Send message to SM */
	TEE_DBG_MSG("Cancellation... channel %d ep %d op_id %u\n",
			channel, cancel_msg.cmd, op_id);
	sys_res = tee_send_msg(channel, &cancel_msg);
	if (sys_res)
		TEE_DBG_MSG("Cancellation failed...\n");

	return sys_res;
}

static TEE_Result process_sys_invoke_operation(msg_map_t *sm_msg,
		 uint32_t sm_channel, uint32_t timeout)
{
	status_t sys_res;
	uint32_t cancel_id = sm_msg->cancel_id;

	TEE_DBG_MSG("Operation... channel %d ep %d cmd %d\n",
			sm_channel, sm_msg->cmd, sm_msg->func);

	sys_res = tee_send_msg(sm_channel, sm_msg);
	if (sys_res) {
		TEE_DBG_MSG("Operation failed... channel %d\n", sm_channel);
		goto process_invoke_operation_end;
	}

	/* Get response from SM */
	sys_res = poll_msg(sm_channel, sm_msg->buffer, timeout);
	if (sys_res == ERR_TIMED_OUT) {
		/* Try cancelling then resume waiting for response */
		TEE_DBG_MSG("Operation timedout. Request cancellation.\n");
		tee_api_request_cancellation(sm_channel, cancel_id);
		poll_msg(sm_channel, sm_msg->buffer, TEE_TIMEOUT_INFINITE);
	} else if (sys_res < NO_ERROR)
		TEE_DBG_MSG("Error code = %d\n", sys_res);

process_invoke_operation_end:
	if (sys_res == ERR_TIMED_OUT)
		return TEE_SUCCESS;
	else if (sys_res == ERR_NO_MEMORY)
		return TEE_ERROR_OUT_OF_MEMORY;
	else if (sys_res < NO_ERROR)
		return TEE_ERROR_COMMUNICATION;
	else
		return TEE_SUCCESS;
}

TEE_Result __SYSCALL sys_invoke_operation(void *teec_session, void *uparams,
		uint32_t *ret_orig, uint32_t *uint_args)
{
	TEE_Result res;
	msg_map_t sm_msg;
	uint32_t timeout;
	uint32_t open_sess = TEEC_CMD_OPEN_SESSION;
	uint32_t sm_channel = TEE_HANDLE_NULL;
	uint32_t orig = TEE_ORIGIN_TEE;
	TEE_Result ret_code = TEE_SUCCESS;

	/* set return origin now; update it after completing the operation */
	res = tee_copy_to_user((user_addr_t)ret_orig, &orig,
			sizeof(uint32_t));
	if (res != TEE_SUCCESS) {
		ret_code = TEE_ERROR_ACCESS_DENIED;
		goto invoke_operation_end;
	}

	/* validate user space pointers; do not access them prior to this */
	res = preprocess_sys_invoke_operation_args((user_addr_t)uparams,
			(user_addr_t)uint_args, (user_addr_t)teec_session,
			&timeout, &open_sess, &sm_channel, &sm_msg);
	if (res != TEE_SUCCESS) {
		ret_code = TEE_ERROR_ACCESS_DENIED;
		goto invoke_operation_end;
	}

	res = process_sys_invoke_operation(&sm_msg, sm_channel, timeout);
	if (res != TEE_SUCCESS) {
		ret_code = res;
		goto invoke_operation_end;
	}

	res = postprocess_sys_invoke_operation_args((user_addr_t)uparams,
			(user_addr_t)teec_session, (user_addr_t)ret_orig,
			&sm_msg);
	if (res != TEE_SUCCESS) {
		ret_code = TEE_ERROR_ACCESS_DENIED;
		goto invoke_operation_end;
	}

	ret_code = sm_msg.ret;

invoke_operation_end:
	if (open_sess && (ret_code != TEE_SUCCESS) &&
		sm_channel != TEE_HANDLE_NULL) {
		/* If error occured, clean up the handle */
		k_sys_close(sm_channel);
	}

	return ret_code;
}

static void prepare_close_session_msg_buffer(msg_map_t *msg_buffer,
		uint32_t session_id)
{
	memset(msg_buffer, 0, sizeof(*msg_buffer));
	msg_buffer->ret_origin = TEE_ORIGIN_TEE;
	msg_buffer->cmd = TEE_CLOSE_SESSION_ID;
	msg_buffer->session = session_id;
}

TEE_Result __SYSCALL sys_close_session(void *teec_session)
{
	status_t sys_res;
	TEE_Result res;
	uevent_t ev;
	teec_session_t k_teec_session;
	uint32_t sm_channel = TEE_HANDLE_NULL;
	msg_map_t sm_msg;

	res = tee_copy_from_user(&k_teec_session, (user_addr_t)teec_session,
			sizeof(teec_session_t));
	if (res != TEE_SUCCESS)
		return res;

	sm_channel = TEE_UNMASK_HANDLE_ID(k_teec_session.sm_channel);

	prepare_close_session_msg_buffer(&sm_msg,
					 k_teec_session.session_id);

	TEE_DBG_MSG("Close session... channel %d ep %d\n",
			sm_channel, sm_msg.cmd);
	sys_res = tee_send_msg(sm_channel, &sm_msg);
	if (sys_res) {
		TEE_DBG_MSG("Close session failed... channel %d\n",
				sm_channel);
		goto close_session_end;
	}

	sys_res = k_sys_wait(sm_channel, &ev, -1);
	if (sys_res < NO_ERROR)
		goto close_session_end;

	sys_res = k_sys_close(sm_channel);
close_session_end:
	return err_to_tee_err(sys_res);
}

static int match_and_set_cancel(trusty_app_t *ta, void *data)
{
	uint32_t session_id = (uint32_t)data;

	if (tee_api_info(ta)->parent_sess_id == session_id) {
		tee_api_info(ta)->cancel = true;
		return 1;
	}
	return 0;
}

TEE_Result __SYSCALL sys_set_cancel_flag(uuid_t *ta_uuid, uint32_t *sess_id)
{
	uint32_t session_id;
	status_t sys_res = ERR_NOT_FOUND;
	TEE_Result res;
	int match = 0;

	res = tee_copy_from_user(&session_id, (user_addr_t)sess_id,
				 sizeof(session_id));
	if (res != TEE_SUCCESS)
		return res;

	/* Session ID cannot be 0. */
	assert(*sess_id);

	/* Search for trusted app with matching UUID. Parent and cloned apps
	 * with the same UUID are distinguished by the parent session ID
	 * of their currently active session.
	 */
	sys_res = trusty_app_find_instance_by_uuid(ta_uuid,
			&match_and_set_cancel, (void *)session_id, &match);
	if (sys_res == NO_ERROR) {
		if (!match)
			sys_res = ERR_NOT_FOUND;
	}
	return err_to_tee_err(sys_res);
}

bool __SYSCALL sys_get_cancel_flag(void)
{
	tee_api_info_t *ta_info = tee_current_ta_info();

	if (ta_info->cancel_masked)
		return false;
	else
		return ta_info->cancel;
}

bool __SYSCALL sys_mask_cancel_flag(void)
{
	bool prev_masked;
	tee_api_info_t *ta_info = tee_current_ta_info();

	prev_masked = ta_info->cancel_masked;
	ta_info->cancel_masked = true;

	return prev_masked;
}

bool __SYSCALL sys_unmask_cancel_flag(void)
{
	bool prev_masked;
	tee_api_info_t *ta_info = tee_current_ta_info();

	prev_masked = ta_info->cancel_masked;
	ta_info->cancel_masked = false;

	return prev_masked;
}

long syscall_privilege_check(unsigned long num)
{
	trusty_app_t *ta = tee_get_current_ta();
	uint32_t privileges = ta->props.privileges;

	switch (num) {
	case __NR_port_create:
	case __NR_connect:
	case __NR_accept:
	case __NR_connect_to_ta:
	case __NR_set_cancel_flag:
	case __NR_get_ta_flags:
		if (!privileges)
			return ERR_ACCESS_DENIED;
		break;
	default:
		break;
	}
	return NO_ERROR;
}

TEE_Result __SYSCALL sys_connect_to_sm(uint32_t *handle_id)
{
	long sys_res;
	handle_id_t channel = INVALID_HANDLE_ID;

	sys_res = tee_api_connect_to_sm(TEE_CONNECT_SEND_MSG_TIMEOUT, sm_comm,
					&channel);
	if (sys_res < NO_ERROR) {
		*handle_id = INVALID_HANDLE_ID;
		return TEE_ERROR_COMMUNICATION;
	}
	*handle_id = (uint32_t)TEE_MASK_HANDLE_ID(channel);
	return TEE_SUCCESS;
}

TEE_Result __SYSCALL sys_tee_wait(uint32_t timeout)
{
	lk_time_t start_time, curr_time;
	tee_api_info_t *ta_info = tee_current_ta_info();

	start_time = current_time();
	while (true) {
		if (ta_info->cancel && !ta_info->cancel_masked)
			return TEE_ERROR_CANCEL;
		curr_time = current_time();
		if (curr_time - start_time >= timeout &&
			timeout != TEE_TIMEOUT_INFINITE)
			return TEE_SUCCESS;
		thread_sleep(TEE_WAIT_INTERNAL_INTERVAL);
	}
}
