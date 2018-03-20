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

#ifndef TEE_API_H
#define TEE_API_H

#include <lib/trusty/uctx.h>
#include <lib/trusty/trusty_app.h>
#include <tee_common_uapi.h>
#include <tee_api_properties.h>

#define copy_from_user(x...) _Pragma("GCC error \"Do not use copy_from_user directly\"")
#define copy_to_user(x...) _Pragma("GCC error \"Do not use copy_to_user directly\"")

typedef struct tee_api_kprops {
	bool single_instance;
	bool multi_session;
	bool keep_alive;
} tee_api_kprops_t;

typedef struct tee_api_nv_info {
	uint32_t port_tag;
	tee_api_kprops_t kprops;
} tee_api_nv_info_t;

typedef struct tee_api_info {
	handle_id_t ta_port;
	handle_id_t ta_channel;
	uint32_t ta_channel_refcnt;
	bool cancel;			// cancellation flag
	bool cancel_masked;		// cancellation flag masked?
	bool ta_dead;
	uint32_t parent_sess_id;	// ID of a session that initialized the TA
	uint32_t parent_op_id;          // used for cancelling operations in child sessions
	uintptr_t ta_msg_uaddr;
	msg_map_t *ta_msg_kaddr;
	msg_map_t sm_msg;
	struct list_node operation_list;
	struct list_node cryp_states;
	struct list_node objects;
} tee_api_info_t;

status_t mmu_check_access_rights(const struct uthread *ut, uint32_t flags,
		user_addr_t uaddr, size_t len);
TEE_Result tee_mmu_check_access_rights(const struct uthread *ut,
		uint32_t flags, user_addr_t uaddr, size_t len);
TEE_Result tee_check_user_param_r(user_addr_t usrc, size_t len);
TEE_Result tee_check_user_param_w(user_addr_t usrc, size_t len);
TEE_Result tee_check_user_param_rw(user_addr_t usrc, size_t len);
TEE_Result tee_copy_from_user(void *kdest, user_addr_t usrc, size_t len);
TEE_Result tee_copy_to_user(user_addr_t udest, const void *ksrc, size_t len);
tee_api_info_t *tee_api_info(trusty_app_t *ta);
status_t tee_send_msg(uint32_t channel, msg_map_t *msg);
int32_t tee_get_msg_buffer(uint32_t channel, uint8_t *buffer);
void ta_set_return_utee_params(utee_params_t *utee_params_ret,
		const utee_params_t *utee_params_src);
status_t properties_copy_from_user(trusty_app_t *ta);
tee_api_kprops_t *tee_api_kprops(trusty_app_t *ta);

static inline trusty_app_t *tee_get_current_ta(void)
{
	return uthread_get_current()->private_data;
}

static inline tee_api_info_t *tee_current_ta_info(void)
{
	return tee_api_info(tee_get_current_ta());
}

#endif /* TEE_API_H */
