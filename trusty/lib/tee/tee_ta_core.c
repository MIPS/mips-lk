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
#include <lib/tee/tee_api.h>
#include <lib/tee/tee_obj.h>
#include <lib/tee/tee_svc_cryp.h>
#include <lib/tee/tee_svc_storage.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "KTEE"

#define TA_NUM_RX_BUF 1
#define TEE_SEND_MSG_RETRY 2
#define TEE_SEND_MSG_WAIT_MS 10

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void set_ta_dead(void);

static const char *id_str(unsigned int id)
{
	static const char * const id_str[] = {
		[TEE_OPEN_SESSION_ID] = "Open",
		[TEE_INVOKE_COMMAND_ID] = "Invoke",
		[TEE_CLOSE_SESSION_ID] = "Close",
		[TEE_CANCEL_ID] = "Cancel",
		[TEE_RETVAL_ID] = "RetVal",
		[TEE_DESTROY_ID] = "Destroy",
	};

	if ((id < ARRAY_SIZE(id_str)) && id_str[id])
		return id_str[id];

	return "Unknown";
}

static status_t tee_send_buffer(uint32_t channel, uint8_t *buffer,
		uint32_t buf_size)
{
	long length;
	status_t sys_res = NO_ERROR;
	ipc_msg_kern_t msg;
	iovec_kern_t iov;

	iov.base = buffer;
	iov.len = buf_size;

	msg.num_iov = 1;
	msg.iov = &iov;
	msg.num_handles = 0;
	msg.handles = NULL;

	length = k_sys_send_msg(channel, &msg);
	if (length < NO_ERROR)
		sys_res = (status_t)length;

	return sys_res;
}

status_t tee_send_msg(uint32_t channel, msg_map_t *msg)
{
	status_t res = NO_ERROR;
	status_t sys_res;
	int loop = TEE_SEND_MSG_RETRY + 1;
	unsigned long timeout_ms = TEE_SEND_MSG_WAIT_MS;
	uevent_t ev;

	while (loop--) {
		res = tee_send_buffer(channel, msg->buffer,
				sizeof(msg->buffer));
		if (res != ERR_NOT_ENOUGH_BUFFER || !loop)
			break;

		TEE_DBG_MSG("TA failed to send. Retrying\n");

		sys_res = k_sys_wait(channel, &ev, timeout_ms);
		if (sys_res == ERR_TIMED_OUT)
			continue;
		if (sys_res)
			break;

		if (ev.event & IPC_HANDLE_POLL_SEND_UNBLOCKED)
			continue;
		else if (ev.event & IPC_HANDLE_POLL_MSG) {
			// once a queued msg is available the thread won't
			// yield during wait anymore so yield manually
			thread_yield();
		} else
			break;
	};
	return res;
}

status_t tee_get_msg_buffer(uint32_t channel, uint8_t *buffer)
{
	long res;
	long put_res;
	ipc_msg_info_t msg_info;
	ipc_msg_kern_t msg;
	iovec_kern_t iov;

	iov.base = buffer;
	iov.len = TEE_MAX_BUFFER_SIZE;

	msg.num_iov = 1;
	msg.iov = &iov;
	msg.num_handles = 0;
	msg.handles = NULL;

	res = k_sys_get_msg(channel, &msg_info);
	if (res < 0)
		return res;

	res = k_sys_read_msg(channel, msg_info.id, 0, &msg);
	if (res < 0)
		goto err_put_fail;

	size_t read_len = (size_t)res;
	if (read_len != iov.len) {
		TEE_DBG_MSG("Error: invalid msg buffer length %zu != %zu\n",
				read_len, iov.len);
		res = ERR_IO;
		goto err_put_fail;
	}

err_put_fail:
	/* if put_msg succeeds don't overwrite error result */
	put_res = k_sys_put_msg(channel, msg_info.id);
	if (put_res < 0)
		res = put_res;

	return res;
}

static status_t ta_port_create(void)
{
	tee_api_info_t *ta_info = tee_current_ta_info();
	long sys_res;

	if (ta_info->ta_port != INVALID_HANDLE_ID)
		return NO_ERROR;

	sys_res = k_sys_port_create(0, TA_NUM_RX_BUF, TEE_MAX_BUFFER_SIZE,
				    IPC_PORT_ALLOW_TA_CONNECT);
	if (sys_res < 0) {
		TEE_DBG_MSG("Error: failed port create %ld\n", sys_res);
		return (status_t)sys_res;
	}

	ta_info->ta_port = (handle_id_t)sys_res;

	return NO_ERROR;
}

static status_t ta_accept_connection(uevent_t *ev)
{
	handle_id_t ta_port = ev->handle;
	uuid_t peer_uuid;
	long sys_res;

	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG) ||
	    (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
		TEE_DBG_MSG("Error: Bad event %x for port %d\n",
				ev->event, ta_port);
		return ERR_BAD_STATE;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		sys_res = k_sys_accept(ta_port, &peer_uuid);
		if (sys_res < 0) {
			TEE_DBG_MSG("Error: Failed to accept connection on port %d\n",
					ta_port);
			if (sys_res == ERR_CHANNEL_CLOSED)
				return NO_ERROR;
			else
				return ERR_BAD_STATE;
		}

		TEE_DBG_MSG("Connection accepted on port %d channel %d\n",
				ta_port, (handle_id_t)sys_res);
	}
	return NO_ERROR;
}

static status_t ta_get_msg(uevent_t *ev, msg_map_t *msg_buf)
{
	status_t res = NO_ERROR;
	handle_id_t channel = ev->handle;

	if (ev->event & IPC_HANDLE_POLL_MSG) {
		/* copy msg directly to user space using kernel addr */
		res = tee_get_msg_buffer(channel, (uint8_t *)msg_buf);
	} else if (ev->event & IPC_HANDLE_POLL_HUP) {
		TEE_DBG_MSG("HUP event on channel %d\n",
				channel);
		res = ERR_CHANNEL_CLOSED;
	} else {
		TEE_DBG_MSG("Error unexpected %x event on channel %d\n",
				ev->event, channel);
		res = ERR_BAD_STATE;
	}

	/* prevent processing of old or partial messages */
	if (res < 0)
		memset(msg_buf, 0, sizeof(*msg_buf));

	return res;
}

static status_t ta_poll_msg(msg_map_t *msg_buf)
{
	tee_api_info_t *ta_info = tee_current_ta_info();
	handle_id_t channel = INVALID_HANDLE_ID;
	uevent_t ev;
	status_t res = NO_ERROR;
	long sys_res;

	res = ta_port_create();
	if (res < 0)
		return res;

	do {
		sys_res = k_sys_wait_any(&ev, INFINITE_TIME);
		ta_info->cancel = false;
		if (sys_res < 0) {
			res = (int)sys_res;
			return res;
		}

		if (ev.handle == ta_info->ta_port) {
			res = ta_accept_connection(&ev);
			if (res < 0)
				return res;
		} else {
			channel = ev.handle;
			res = ta_get_msg(&ev, msg_buf);
			if (res < 0) {
				/*
				 * if application is dead wait until client
				 * closes session
				 */
				if (ta_info->ta_dead) {
					TEE_DBG_MSG("TA IS DEAD!\n");
					k_sys_close(channel);
					channel = INVALID_HANDLE_ID;
				} else {
					return res;
				}
			}
		}

	} while (channel == INVALID_HANDLE_ID);

	ta_info->ta_channel = channel;

	return res;
}

static status_t get_memref_buffer(uint64_t memref_param, user_addr_t *arg_p)
{
	*arg_p = (user_addr_t)memref_param;

	// check param for 64bit to 32bit overflow when casting
	if (sizeof(user_addr_t) != sizeof(uint64_t)) {
		if ((user_addr_t)memref_param != memref_param)
			return ERR_INVALID_ARGS;
	}
	return NO_ERROR;
}

static status_t get_memref_size(uint64_t memref_param, size_t *arg_p)
{
	*arg_p = (size_t)memref_param;

	// check param for 64bit to 32bit overflow when casting
	if (sizeof(size_t) != sizeof(uint64_t)) {
		if ((size_t)memref_param != memref_param)
			return ERR_INVALID_ARGS;
	}
	return NO_ERROR;
}

static status_t ta_munmap_memref(msg_map_t *msg_buf)
{
	uint64_t *params = msg_buf->utee_params.params;
	uint32_t param_types = msg_buf->utee_params.param_types;
	int i;
	status_t res;

	if (!param_types)
		return NO_ERROR;

	for (i = 0; i < TEE_NUM_PARAMS; i++) {
		user_addr_t memref_buffer;
		size_t size;

		switch (TEE_PARAM_TYPE_GET(param_types, i)) {
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:

			if (get_memref_buffer(params[2 * i], &memref_buffer))
				return ERR_INVALID_ARGS;
			if (get_memref_size(params[2 * i + 1], &size))
				return ERR_INVALID_ARGS;

			if (!memref_buffer)
				continue;

			res = uthread_revoke_pages(tee_get_current_ta()->ut,
					memref_buffer, size);
			if (res < NO_ERROR)
				return res;

			break;
		default:
			break;
		}
	}

	return NO_ERROR;
}

static uint32_t clear_remaining_paramtypes(uint32_t param_types, int n)
{
	int i;
	uint32_t p[TEE_NUM_PARAMS];

	for (i = 0; i < n; i++)
		p[i] = TEE_PARAM_TYPE_GET(param_types, i);
	for (i = n; i < TEE_NUM_PARAMS; i++)
		p[i] = TEE_PARAM_TYPE_GET(TEE_PARAM_TYPE_NONE, i);

	return TEE_PARAM_TYPES(p[0], p[1], p[2], p[3]);
}

static uint32_t get_memref_param_flags(uint32_t param_types, int i)
{
	uint32_t flags = 0;
	int paramtype = TEE_PARAM_TYPE_GET(param_types, i);

	if (paramtype == TEE_PARAM_TYPE_MEMREF_INPUT)
		flags = UTM_R;
	else if (paramtype == TEE_PARAM_TYPE_MEMREF_OUTPUT)
		flags = UTM_R | UTM_W;
	else if (paramtype == TEE_PARAM_TYPE_MEMREF_INOUT)
		flags = UTM_R | UTM_W;

	return flags;
}

static bool has_memref_paramtype(uint32_t param_types)
{
	// isolate the MEMREF bit using XOR
	const uint32_t mr = TEE_PARAM_TYPE_MEMREF_INOUT ^
				TEE_PARAM_TYPE_VALUE_INOUT;

	if (!param_types)
		return false;

	return param_types & TEE_PARAM_TYPES(mr, mr, mr, mr);
}

static void uuid_from_octets(uuid_t *uuid, uint8_t oct[TEE_UUID_LEN])
{
	uuid->time_low = (oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) |
			 oct[3];
	uuid->time_mid = (oct[4] << 8) | oct[5];
	uuid->time_hi_and_version = (oct[6] << 8) | oct[7];
	memcpy(uuid->clock_seq_and_node, oct + 8,
		sizeof(uuid->clock_seq_and_node));
}

static int match_client_ta(trusty_app_t *ta, void *data)
{
	trusty_app_t *client_ta = (trusty_app_t *)data;

	return (ta == client_ta);
}

static bool valid_client_ta(trusty_app_t *client_ta,
		uint8_t client_uuid[TEE_UUID_LEN])
{
	uuid_t uuid;
	status_t ret;
	int match = 0;

	uuid_from_octets(&uuid, client_uuid);
	ret = trusty_app_find_instance_by_uuid(&uuid,
			&match_client_ta, client_ta, &match);
	if (ret != NO_ERROR)
		return false;
	else
		return (bool)match;
}

static status_t ta_mmap_memref(msg_map_t *msg_buf)
{
	uint32_t ep_id = msg_buf->cmd;
	uint64_t *params = msg_buf->utee_params.params;
	uint32_t param_types = msg_buf->utee_params.param_types;
	trusty_app_t *client_ta = (trusty_app_t *)msg_buf->client_ta;
	uthread_t *ut_src = NULL;
	uthread_t *ut_target;
	bool ns_src = false;
	int i;
	status_t res;

	if (ep_id != TEE_OPEN_SESSION_ID && ep_id != TEE_INVOKE_COMMAND_ID)
		return NO_ERROR;

	if (!has_memref_paramtype(param_types))
		return NO_ERROR;

	if (client_ta) {
		if (!valid_client_ta(client_ta, msg_buf->client_id_uuid)) {
			TEE_DBG_MSG("Cannot find client TA\n");
			return ERR_NOT_FOUND;
		}
		ut_src = client_ta->ut;
	} else
		ns_src = true;

	assert(ut_src || ns_src);
	ut_target = tee_get_current_ta()->ut;

	for (i = 0; i < TEE_NUM_PARAMS; i++) {
		uint32_t uflags = 0;
		user_addr_t memref_buffer;
		vaddr_t uaddr_mapped = 0;
		size_t size;

		uflags = get_memref_param_flags(param_types, i);
		if (!uflags)
			continue;

		if (get_memref_buffer(params[2 * i], &memref_buffer))
			return ERR_INVALID_ARGS;
		if (get_memref_size(params[2 * i + 1], &size))
			return ERR_INVALID_ARGS;

		if (!memref_buffer)
			continue;

		// TODO add TEE support for mapping a chain of multiple memrefs
		// TEE mapping of fragmented memrefs is not implemented; REE
		// must enforce contiguous memref regions from its user space.
		if (ns_src)
			uflags |= UTM_PHYS_CONTIG;

		if (ut_src)
			uflags |= UTM_NS_MEM;

		res = uthread_grant_pages(ut_target, ut_src, memref_buffer,
			size, uflags, &uaddr_mapped, ns_src);
		if (res < NO_ERROR) {
			/*
			 * mapping 'i' failed, zero paramtype for remaining
			 * memrefs to skip memory unmap cleanup
			 */
			TEE_DBG_MSG("memref mapping failed %d\n", res);
			msg_buf->utee_params.param_types =
				clear_remaining_paramtypes(param_types, i);
			return res;
		}

		/* update memref buffer with TA mapping */
		params[2 * i] = (uint64_t)uaddr_mapped;
	}

	return NO_ERROR;
}

static void ta_set_ta_msg(msg_map_t *sm_msg, msg_map_t *ta_msg)
{
	/* zero out any previous buffer content */
	memset(ta_msg, 0, sizeof(*ta_msg));

	memcpy(&ta_msg->utee_params, &sm_msg->utee_params,
		sizeof(utee_params_t));
	ta_msg->cmd = sm_msg->cmd;
	ta_msg->func = sm_msg->func;
	ta_msg->client_id_login = sm_msg->client_id_login;
	memcpy(ta_msg->client_id_uuid, sm_msg->client_id_uuid, TEE_UUID_LEN);
	ta_msg->session_ctx = sm_msg->session_ctx;
}

static status_t ta_preprocess_msg(msg_map_t *sm_msg, msg_map_t *ta_msg)
{
	tee_api_info_t *ta_info = tee_current_ta_info();
	status_t res = NO_ERROR;

	res = ta_mmap_memref(sm_msg);
	if (res < 0)
		goto preprocess_err;

	ta_set_ta_msg(sm_msg, ta_msg);

	ta_info->parent_op_id = sm_msg->parent_op_id;
	ta_info->parent_sess_id = sm_msg->parent_sess_id;

preprocess_err:
	return res;
}

static status_t ta_validate_ta_reply(msg_map_t *sm_msg, msg_map_t *ta_msg)
{
	status_t res = NO_ERROR;
	uint32_t ep_id_saved = sm_msg->cmd;
	uint32_t ep_id_reply = ta_msg->cmd;

	if (ep_id_reply == TEE_RETVAL_ID) {
		/* default panic handler exit */
		if (ta_msg->ret != TEE_ERROR_TARGET_DEAD)
			return ERR_INVALID_ARGS;
		else
			return NO_ERROR;
	}

	/* verify that entrypoint function id makes sense */
	if (ep_id_reply != ep_id_saved ||
		ta_msg->utee_params.param_types !=
		sm_msg->utee_params.param_types)
		res = ERR_INVALID_ARGS;

	return res;
}

void ta_set_return_utee_params(utee_params_t *utee_params_ret,
		const utee_params_t *utee_params_src)
{
	uint64_t *params_r = utee_params_ret->params;
	const uint64_t *params_s = utee_params_src->params;
	uint32_t param_types = utee_params_src->param_types;
	int i;

	memset(utee_params_ret, 0, sizeof(utee_params_t));
	utee_params_ret->param_types = utee_params_src->param_types;

	for (i = 0; i < TEE_NUM_PARAMS; i++) {
		switch (TEE_PARAM_TYPE_GET(param_types, i)) {
		case TEE_PARAM_TYPE_VALUE_OUTPUT:
		case TEE_PARAM_TYPE_VALUE_INOUT:
			params_r[2 * i] = params_s[2 * i];
			params_r[2 * i + 1] = params_s[2 * i + 1];
			break;
		case TEE_PARAM_TYPE_MEMREF_OUTPUT:
		case TEE_PARAM_TYPE_MEMREF_INOUT:
			params_r[2 * i + 1] = params_s[2 * i + 1];
			break;
		case TEE_PARAM_TYPE_NONE:
		case TEE_PARAM_TYPE_VALUE_INPUT:
		case TEE_PARAM_TYPE_MEMREF_INPUT:
		default:
			break;
		}
	}
}

static void ta_set_reply_msg(msg_map_t *sm_msg, msg_map_t *ta_msg)
{
	uint32_t ep_id = ta_msg->cmd;

	/* move cmd to func to make way for TEE_RETVAL_ID */
	sm_msg->cmd = TEE_RETVAL_ID;
	sm_msg->func = ep_id;
	sm_msg->ret_origin = ta_msg->ret_origin;
	sm_msg->ret = ta_msg->ret;

	if ((ep_id == TEE_OPEN_SESSION_ID) && (ta_msg->ret == TEE_SUCCESS)) {
		tee_api_info_t *ta_info = tee_current_ta_info();

		/* save the TA's opaque session context */
		sm_msg->session_ctx = ta_msg->session_ctx;
		ta_info->ta_channel_refcnt++;
	}

	/* update output parameters in saved msg buffer */
	ta_set_return_utee_params(&sm_msg->utee_params, &ta_msg->utee_params);
}

static status_t ta_send_reply(msg_map_t *sm_msg, msg_map_t *ta_msg)
{
	tee_api_info_t *ta_info = tee_current_ta_info();
	handle_id_t channel = ta_info->ta_channel;
	status_t res;

	res = ta_validate_ta_reply(sm_msg, ta_msg);
	if (res < 0)
		return res;

	ta_set_reply_msg(sm_msg, ta_msg);

	assert(channel != INVALID_HANDLE_ID);

	res = tee_send_msg(channel, sm_msg);
	if (res)
		TEE_DBG_MSG("TA failed to send func %s:%u on channel %d\n",
				id_str(sm_msg->func), sm_msg->func, channel);
	return res;
}

static status_t ta_close_channel(msg_map_t *sm_msg, status_t res)
{
	tee_api_info_t *ta_info = tee_current_ta_info();
	tee_api_kprops_t *ta_kprops = tee_api_kprops(tee_get_current_ta());
	uint32_t ep_id;
	bool close_channel_and_exit = false;
	bool close_channel = false;

	if (res != NO_ERROR) {
		close_channel_and_exit = true;
		goto close_channel_end;
	}

	/* ta_set_reply_msg moves cmd to func */
	assert(sm_msg->cmd == TEE_RETVAL_ID);
	ep_id = sm_msg->func;

	/* close channel depending on TA state */
	if (ta_info->ta_dead) {
		close_channel_and_exit = true;
		goto close_channel_end;
	}

	switch (ep_id) {
	case TEE_OPEN_SESSION_ID:
		if (sm_msg->ret != TEE_SUCCESS) {
			if (!ta_info->ta_channel_refcnt &&
				!ta_kprops->keep_alive)
				close_channel_and_exit = true;
			else
				close_channel = true;
		}
		break;
	case TEE_CLOSE_SESSION_ID:
		close_channel = true;
		break;
	case TEE_INVOKE_COMMAND_ID:
		break;
	case TEE_RETVAL_ID: /* default panic handler exit */
		break;
	case TEE_DESTROY_ID:
	default:
		close_channel_and_exit = true;
		break;
	}

close_channel_end:
	if (close_channel || close_channel_and_exit) {
		if (close_channel_and_exit) {
			TEE_DBG_MSG("close_channel_and_exit\n");
			/* Set TA dead to prevent accepting new connections */
			set_ta_dead();
			ta_info->ta_channel_refcnt = 0;
			if (res == NO_ERROR)
				res = ERR_GENERIC;
		} else {
			TEE_DBG_MSG("close_channel\n");
			if (ta_info->ta_channel_refcnt)
				ta_info->ta_channel_refcnt--;
			/* Prevent TA instance closing. */
			res = NO_ERROR;
		}
		k_sys_close(ta_info->ta_channel);
	}

	/* zero the channel, a new channel handle will be polled */
	ta_info->ta_channel = INVALID_HANDLE_ID;

	return res;
}

static bool ta_first_pass(void)
{
	return (tee_current_ta_info()->ta_port == INVALID_HANDLE_ID);
}

static status_t ta_postprocess_msg(msg_map_t *sm_msg, msg_map_t *ta_msg)
{
	status_t res;

	if (ta_first_pass())
		return NO_ERROR;

	/* unmap memory references using saved mappings in sm_msg */
	res = ta_munmap_memref(sm_msg);
	if (res < 0)
		goto postprocess_err;

	res = ta_send_reply(sm_msg, ta_msg);
	if (res < 0)
		goto postprocess_err;

postprocess_err:
	res = ta_close_channel(sm_msg, res);

	/*
	 * indicate to ta_exit_cleanup ==> ta_munmap_memref that there are no
	 * memrefs to unmap in case of error
	 */
	sm_msg->utee_params.param_types = 0;

	return res;
}

static status_t ta_init_msg_buf(user_addr_t user_msg_buf, msg_map_t **sm_msg,
				msg_map_t **ta_msg_kaddr)
{
	tee_api_info_t *ta_info = tee_current_ta_info();
	uthread_t *ut = uthread_get_current();
	status_t res;
	void *msg_buf_kaddr;

	*sm_msg = &ta_info->sm_msg;

	if (ta_info->ta_msg_uaddr && (user_msg_buf == ta_info->ta_msg_uaddr)) {
		*ta_msg_kaddr = ta_info->ta_msg_kaddr;
		return NO_ERROR;
	}

	/*
	 * don't set TEE_MEMORY_ACCESS_ANY_OWNER, the user_msg_buf must be in
	 * private TA memory
	 */
	res = mmu_check_access_rights(ut,
				      TEE_MEMORY_ACCESS_READ |
				      TEE_MEMORY_ACCESS_WRITE,
				      user_msg_buf,
				      sizeof(msg_map_t));
	if (res < NO_ERROR)
		return res;

	/* get kernel address of user space message buffer */
	res = uthread_virt_to_kvaddr(ut, (vaddr_t)user_msg_buf,
			&msg_buf_kaddr);
	if (res < NO_ERROR)
		return res;

	*ta_msg_kaddr = (msg_map_t *)msg_buf_kaddr;

	ta_info->ta_msg_kaddr = (msg_map_t *)msg_buf_kaddr;
	ta_info->ta_msg_uaddr = (uintptr_t)user_msg_buf;

	return NO_ERROR;
}

static void ta_exit_cleanup(msg_map_t *sm_msg)
{
	tee_api_info_t *ta_info = tee_current_ta_info();

	ta_munmap_memref(sm_msg);

	if (ta_info->ta_channel != INVALID_HANDLE_ID)
		k_sys_close(ta_info->ta_channel);

	if (ta_info->ta_port != INVALID_HANDLE_ID)
		k_sys_close(ta_info->ta_port);

	/* Free cryp states created by this TA */
	tee_svc_cryp_free_states(ta_info);

	/* Close cryp objects opened by this TA */
	tee_obj_close_all(ta_info);

	/* Free emums created by this TA */
	//tee_svc_storage_close_all_enum(ta_info);
}

long __SYSCALL sys_ta_next_msg(user_addr_t user_msg_buf)
{
	status_t res;
	msg_map_t *ta_msg = NULL;
	msg_map_t *sm_msg = NULL;

	res = ta_init_msg_buf(user_msg_buf, &sm_msg, &ta_msg);
	if (res < 0)
		goto err_cleanup;

	res = ta_postprocess_msg(sm_msg, ta_msg);
	if (res < 0)
		goto err_cleanup;

	/* main TA loop */
	res = ta_poll_msg(sm_msg);
	if (res < 0)
		goto err_cleanup;

	res = ta_preprocess_msg(sm_msg, ta_msg);
	if (res < 0)
		goto err_cleanup;

	/* return to TA to call TA entrypoint */
	return 0;

err_cleanup:
	TEE_DBG_MSG("TA exit with code = %x\n", res);
	ta_exit_cleanup(sm_msg);

	return res;
}

static void set_ta_dead(void)
{
	trusty_app_t *ta = tee_get_current_ta();
	tee_api_info_t *ta_info = tee_api_info(ta);

	trusty_app_dead(ta);
	ta_info->ta_dead = true;
}

void __SYSCALL sys_ta_dead(void)
{
	set_ta_dead();
}
