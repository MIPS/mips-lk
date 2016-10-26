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

#if WITH_GP_API

#include <stdlib.h>
#include <string.h>
#include <lk/init.h>
#include <uthread.h>
#include <lib/syscall.h>
#include <lib/trusty/uuid.h>
#include <lib/trusty/uctx.h>
#include <lib/trusty/ipc.h>
#include <lib/trusty/trusty_app.h>
#include <tee_api_types.h>
#include <tee_api_properties.h>
#include <tee_common_uapi.h>
#include <mm.h>
#include <lib/tee/tee_api.h>

#define TEE_LOCAL_TRACE 0
#define TEE_TAG "KTEE"

STATIC_ASSERT(sizeof(TEE_UUID) == sizeof(uuid_t));

typedef iovec_kern_t iovec_t;
typedef ipc_msg_kern_t ipc_msg_t;

typedef struct tee_api_kprops {
	bool single_instance;
	bool multi_session;
	bool keep_alive;
} tee_api_kprops_t;

static const tee_api_kprops_t tee_api_default_kprops = {
	.single_instance = true,
	.multi_session = false,
	.keep_alive = false,
};

typedef struct tee_api_info {
	handle_id_t ta_port;
	uint32_t port_tag;
	tee_api_kprops_t kprops;
} tee_api_info_t;

extern long __SYSCALL sys_port_create(user_addr_t path, uint num_recv_bufs,
		size_t recv_buf_size, uint32_t flags);
extern long __SYSCALL sys_accept(uint32_t handle_id, user_addr_t user_uuid);
extern long __SYSCALL sys_wait(uint32_t handle_id, user_addr_t user_event, unsigned long timeout_msecs);
extern long __SYSCALL sys_wait_any(user_addr_t user_event, unsigned long timeout_msecs);
extern long __SYSCALL sys_close(uint32_t handle_id);
extern long __SYSCALL sys_put_msg (uint32_t handle, uint32_t msg_id);
extern long k_sys_connect(const char *path, uint flags);
extern long k_sys_wait (uint32_t handle_id, uevent_t *event, unsigned long timeout_msecs);
extern long k_sys_get_msg (uint32_t handle, ipc_msg_info_t *msg_info);
extern long k_sys_read_msg (uint32_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg);
extern long k_sys_send_msg (uint32_t handle, ipc_msg_t *msg);

static tee_api_properties_t *tee_api_properties(trusty_app_t *ta);
static tee_api_info_t *tee_api_info(trusty_app_t *ta);
static tee_api_kprops_t *tee_api_kprops(trusty_app_t *ta);
static void tee_api_properties_dump(trusty_app_t *ta);

#define SPACE " "
static const char description[] = APIVERSION SPACE DESCRIPTION;

static const struct ta_property tee_implementation[] = {
	{"gpd.tee.apiversion", TA_PROP_TYPE_STR, APIVERSION},
	{"gpd.tee.description", TA_PROP_TYPE_STR, description},
	{"gpd.tee.trustedos.implementation.version", TA_PROP_TYPE_STR, TEE_VERSION},
	{"gpd.tee.trustedos.manufacturer", TA_PROP_TYPE_STR, MANUFACTURER},
	{"gpd.tee.arith.maxBigIntSize", TA_PROP_TYPE_U32, &(const uint32_t){BIGINTSIZE}},
};

static const size_t tee_implementation_len =
	sizeof(tee_implementation) / sizeof(tee_implementation[0]);

static uint _tee_api_slot_id;

/* Session manager ports */
static const char sm_priority[] = TEE_SESS_MANAGER_PRIORITY_MSG;
static const char sm_comm[] = TEE_SESS_MANAGER_COMMAND_MSG;


/*
 * Provide custom implementation to override default implementation.
 *
 * On success - copies a default ipc port name to buffer and
 *            - returns length of port name including trailing '\0'
 * On error   - returns negative error code
 */
int ipc_port_get_default_name(trusty_app_t *tapp, char* buffer, ssize_t size)
{
	int len;
	uuid_t *uuid = &tapp->props.uuid;
	uint32_t instance_id = (uint32_t)tapp->ut;

	len = snprintf(buffer, size, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x_id_%08x-%08x",
		   uuid->time_low, uuid->time_mid, uuid->time_hi_and_version,
		   uuid->clock_seq_and_node[0], uuid->clock_seq_and_node[1],
		   uuid->clock_seq_and_node[2], uuid->clock_seq_and_node[3],
		   uuid->clock_seq_and_node[4], uuid->clock_seq_and_node[5],
		   uuid->clock_seq_and_node[6], uuid->clock_seq_and_node[7],
		   instance_id, tee_api_info(tapp)->port_tag);
	if (len < 0 || len >= size) {
		return ERR_INVALID_ARGS;
	}
	/* snprintf returns length not including trailing '\0', add it here */
	return len + 1;
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
		return res;

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

	/* Ensure ERR_ALREADY_STARTED is only set when ta_instance is valid */
	if ((res == ERR_ALREADY_STARTED) && (ta_instance == NULL)) {
		assert(!((res == ERR_ALREADY_STARTED) && (ta_instance == NULL)) &&
			"invalid return values");
		res = ERR_NOT_ALLOWED;
	}

	return res;
}

static status_t tee_api_connect_to_ta(trusty_app_t *dest_ta, handle_id_t *channel)
{
	status_t res;
	char port_name[IPC_PORT_PATH_MAX];
	int len;

	len = ipc_port_get_default_name(dest_ta, port_name, sizeof(port_name));
	if (len < 0)
		return (status_t)len;

	res = k_sys_connect(port_name, IPC_CONNECT_ASYNC | IPC_CONNECT_WAIT_FOR_PORT);
	if (res < NO_ERROR) {
		/* ERR_NOT_FOUND here means problem in connecting to port.
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

long __SYSCALL sys_connect_to_ta(const uuid_t *dest_uuid)
{
	status_t res;
	trusty_app_t *dest_ta = NULL;
	uuid_t uuid;
	handle_id_t channel = INVALID_HANDLE_ID;
	bool allow_instance_cleanup = true;
	bool err_cleanup_instance = false;

	/* Verify user uuid access rights and copy to kernel */
	res = tee_copy_from_user(&uuid, (user_addr_t)dest_uuid, sizeof(uuid_t));
	if (res < 0) {
		res = ERR_ACCESS_DENIED;
		goto err_done;
	}

	res = tee_api_create_ta_instance(&uuid, &dest_ta);
	if (res == ERR_ALREADY_STARTED) {
		assert(dest_ta != NULL);

		/* Instance is already started, check if multi_session is
		 * supported. Only single_instance TA types should have
		 * returned ERR_ALREADY_STARTED.
		 */
		assert(is_single_instance(dest_ta));

		/* Prevent error cleanup from destroying single_instance TA
		 * e.g. by calling open session and passing invalid path or
		 * size parameters to force the instance to be cleaned up.
		 */
		allow_instance_cleanup = false;

		if (is_keep_alive(dest_ta)) {
			/* TODO we should actually be returning ERR_BUSY if the
			 * keep_alive instance is not multi_session. We need a
			 * new mechanism to determine when the TA is ready to
			 * accept another session.
			 */
		} else if (!is_multi_session(dest_ta)) {
			TEE_DBG_MSG("Single_instance, multi_session property "
					"is not enabled\n");
			res = ERR_BUSY;
			goto err_done;
		}

		/* Single_instance already started; allow multi_session. */

	} else if (res)
		goto err_done;

	if (dest_ta == NULL) {
		assert(dest_ta != NULL);
		res = ERR_NOT_VALID;
		goto err_done;
	}

	err_cleanup_instance = true;

	res = tee_api_connect_to_ta(dest_ta, &channel);

err_done:
	if (res < NO_ERROR) {
		TEE_DBG_MSG("Error code = %d\n", res);
		if (err_cleanup_instance && allow_instance_cleanup)
			trusty_app_exit(dest_ta);

		return res;
	}

	return channel;
}

long __SYSCALL sys_ta_dead(void)
{
	trusty_app_t *ta = uthread_get_current()->private_data;
	trusty_app_dead(ta);
	return NO_ERROR;
}

static status_t ta_get_port(handle_id_t *port)
{
	trusty_app_t *ta = uthread_get_current()->private_data;
	tee_api_info_t *ta_info = tee_api_info(ta);
	long sys_res;

	if (ta_info->ta_port != INVALID_HANDLE_ID) {
		*port = ta_info->ta_port;
		return NO_ERROR;
	}

	sys_res = sys_port_create(0, 1, TEE_MAX_BUFFER_SIZE, IPC_PORT_ALLOW_TA_CONNECT);
	if (sys_res < 0) {
		TEE_DBG_MSG("Error: failed port create %ld\n", sys_res);
		return (status_t)sys_res;
	}

	ta_info->ta_port = (handle_id_t)sys_res;
	*port = ta_info->ta_port;

	return NO_ERROR;
}

static status_t accept_connection(uevent_t *ev, handle_id_t *channel, user_addr_t peer_uuid)
{
	handle_id_t ta_port = ev->handle;
	status_t res = NO_ERROR;
	long sys_res;

	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_HUP) ||
	    (ev->event & IPC_HANDLE_POLL_MSG) ||
	    (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
		TEE_DBG_MSG("Error: Bad event %x for port %d\n", ev->event, ta_port);
		return ERR_BAD_STATE;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		sys_res = sys_accept(ta_port, peer_uuid);
		if (sys_res < 0) {
			TEE_DBG_MSG("Error: Failed to accept connection on port %d\n", ta_port);
			return ERR_BAD_STATE;
		}

		*channel = (handle_id_t)sys_res;
	}
	return res;
}

static status_t ta_poll_msg(handle_id_t ta_port, user_addr_t user_event, user_addr_t peer_uuid)
{
	uevent_t _uev;
	uevent_t *ev = &_uev;
	handle_id_t channel = INVALID_HANDLE_ID;
	status_t res = NO_ERROR;
	long sys_res;

	res = tee_copy_from_user(ev, user_event, sizeof(*ev));
	if (res < 0)
		return res;

	if (ev->handle == ta_port) {
		res = accept_connection(ev, &channel, peer_uuid);
		if (res < 0)
			return res;
	} else {
		channel = (handle_id_t)ev->handle;
	}

	if (ev->event & IPC_HANDLE_POLL_READY) {
		sys_res = sys_wait(channel, user_event, INFINITE_TIME);
		if (sys_res < 0)
			return (status_t)sys_res;

		/* Update channel event */
		res = tee_copy_from_user(ev, user_event, sizeof(*ev));
		if (res < 0)
			return res;

		assert(channel == (handle_id_t)ev->handle);
	}

	if ((ev->event & IPC_HANDLE_POLL_ERROR) ||
	    (ev->event & IPC_HANDLE_POLL_SEND_UNBLOCKED)) {
		TEE_DBG_MSG("Error: Bad event %x for channel %d\n", ev->event, channel);
		return ERR_BAD_STATE;
	}

	/* Return to user space to handle channel event */
	return res;
}

long __SYSCALL sys_ta_next_msg(user_addr_t user_event, user_addr_t peer_uuid)
{
	handle_id_t ta_port = INVALID_HANDLE_ID;
	status_t res;
	long sys_res;

	res = ta_get_port(&ta_port);
	if (res < 0)
		goto err_cleanup;

	sys_res = sys_wait_any(user_event, INFINITE_TIME);
	if (sys_res < 0) {
		res = (int)sys_res;
		goto err_cleanup;
	}

	res = ta_poll_msg(ta_port, user_event, peer_uuid);
	if (res < 0)
		goto err_cleanup;

	return (long)ta_port;

err_cleanup:
	TEE_DBG_MSG("Error code = %d\n", res);
	if (ta_port != INVALID_HANDLE_ID)
		sys_close(ta_port);

	return res;
}

long __SYSCALL sys_get_ta_props_cnt(const uuid_t *dest_uuid, uint32_t *config_entry_cnt)
{
	int res = NO_ERROR;
	trusty_app_t *trusty_app;

	trusty_app = trusty_app_find_by_uuid((uuid_t *)dest_uuid);
	if (!trusty_app) {
		TEE_DBG_MSG("Cannot find TA\n");
		return ERR_NOT_FOUND;
	}

	*config_entry_cnt = trusty_app->props.config_entry_cnt;

	return res;
}

long __SYSCALL sys_get_ta_client_props(const uuid_t *uuid, const char* prop_name, void *prop, uint32_t index)
{
	int res = NO_ERROR;
	char *name;
	trusty_app_t *ta;
	paddr_t pa;
	struct ta_property *u_props;
	struct ta_property *u_props_kaddr;
	uint32_t *props_num;
	uint32_t k_props_size = 1;
	struct result_property *ret_prop = (struct result_property *)prop;

	/* Find client ta */
	ta = trusty_app_find_by_uuid((uuid_t *)uuid);

	if (!ta) {
		TEE_DBG_MSG("Cannot find TA\n");
		return ERR_NOT_FOUND;
	}

	props_num = ta->props.custom_cfg_size;
	res = uthread_virt_to_phys(ta->ut, (vaddr_t)props_num, &pa);
	if (res)
		return res;

	k_props_size = *(uint32_t *)paddr_to_kvaddr(pa);

	u_props = ta->props.custom_cfg_ptr;

	res = uthread_virt_to_phys(ta->ut, (vaddr_t)u_props, &pa);
	if (res)
		return res;

	/* Set kernel address of properties array */
	u_props_kaddr = (struct ta_property *)paddr_to_kvaddr(pa);

	if (prop_name == NULL) {
		if (index >= k_props_size)
			return ERR_NOT_FOUND;
		k_props_size = 1;
		u_props_kaddr += index;
	}

	do {

		res = uthread_virt_to_phys(ta->ut,
				(vaddr_t)u_props_kaddr->name,
				&pa);
		if (res)
			return res;
		name = paddr_to_kvaddr(pa);

		if (prop_name == NULL || strcmp(prop_name, name) == 0) {
			res = uthread_virt_to_phys(ta->ut,
					(vaddr_t)u_props_kaddr->value,
					&pa);
			if (res)
				return res;
			memcpy((void *)ret_prop->value, paddr_to_kvaddr(pa), ret_prop->prop_size);

			if (prop_name == NULL) {
				/* Size of buffer for property name is in prop->type if this function
				 * is called for obtaining property name.
				 */
				if (ret_prop->name && ret_prop->prop_size <= strlen(name)) {
					TEE_DBG_MSG("Property name too long\n");
					return ERR_NOT_ENOUGH_BUFFER;
				} else if (ret_prop->name && ret_prop->prop_size > strlen(name))
					strlcpy(ret_prop->name, name, ret_prop->prop_size);
			}

			ret_prop->type = u_props_kaddr->type;
			return NO_ERROR;
		}
		u_props_kaddr++;
	} while (--k_props_size);

	return ERR_NOT_FOUND;
}

long __SYSCALL sys_get_implementation_props(const char *props_name, void *prop, uint32_t index)
{
    const struct ta_property *property_ptr = tee_implementation;
	struct result_property *ret_prop = (struct result_property *)prop;
    uint32_t prop_size = 1;

	if (props_name == NULL) {
		if (index >= tee_implementation_len)
			return ERR_NOT_FOUND;
		property_ptr += index;
	} else prop_size = tee_implementation_len;

	do{
		if(props_name == NULL || strcmp(props_name, property_ptr->name) == 0) {
			memcpy((void *)ret_prop->value, property_ptr->value, ret_prop->prop_size);
			/* Get the property name. */
			if (props_name == NULL) {
				if(ret_prop->name  && ret_prop->prop_size < strlen(property_ptr->name))
					return ERR_NOT_ENOUGH_BUFFER;
				else if (ret_prop->name && ret_prop->prop_size >= strlen(property_ptr->name))
					strlcpy(ret_prop->name, property_ptr->name, ret_prop->prop_size);
			}
			ret_prop->type = property_ptr->type;
			return NO_ERROR;
		}
		property_ptr++;
	} while (--prop_size);

	return ERR_NOT_FOUND;
}

long __SYSCALL sys_get_props_num(const uuid_t *uuid, uint32_t prop_set, uint32_t *prop_length)
{
	if (prop_set == TEE_PROPSET_TEE_IMPLEMENTATION) {
		*prop_length = tee_implementation_len;
	} else if (prop_set == TEE_PROPSET_CURRENT_CLIENT) {
		int res = NO_ERROR;
		trusty_app_t *ta;
		paddr_t pa;
		uint32_t *props_num;

		/* Find client ta */
		ta = trusty_app_find_by_uuid((uuid_t *)uuid);

		if (!ta) {
			TEE_DBG_MSG("Cannot find TA\n");
			return ERR_INVALID_ARGS;
		}

		props_num = ta->props.custom_cfg_size;
		res = uthread_virt_to_phys(ta->ut, (vaddr_t)props_num, &pa);
		if (res)
			return res;

		*prop_length = *(uint32_t *)paddr_to_kvaddr(pa);
	} else {
		TEE_DBG_MSG("Invalid prop_set\n");
		return ERR_INVALID_ARGS;
	}

	return NO_ERROR;
}

static tee_api_properties_t *tee_api_properties(trusty_app_t *ta)
{
	return ta->props.custom_cfg_ptr;
}

static bool valid_ta_user_context(trusty_app_t *ta)
{
	return ta->ut->page_table == (void*)get_user_pgd(arch_curr_cpu_num());
}

static tee_api_info_t *tee_api_info(trusty_app_t *ta)
{
	return trusty_als_get(ta, _tee_api_slot_id);
}

static tee_api_kprops_t *tee_api_kprops(trusty_app_t *ta)
{
	tee_api_info_t *ta_info = trusty_als_get(ta, _tee_api_slot_id);
	return &ta_info->kprops;
}

static status_t properties_copy_from_user(trusty_app_t *ta)
{
	int res = NO_ERROR;
	uthread_t *ut = ta->ut;
	tee_api_kprops_t *k_props = tee_api_kprops(ta);
	uint32_t *k_props_size = 0, i;
	tee_api_properties_t *u_props = tee_api_properties(ta);
	uint32_t *u_props_size = ta->props.custom_cfg_size;
	paddr_t pa;
	struct ta_property *u_props_kaddr;
	char *name;
	void *value;

	if (!u_props)
		return NO_ERROR;

	/* The tee api ta_property structure and the .value field pointers
	 * within it are user space addresses mapped to each TA.  Translate
	 * these to kernel virtual addresses before copying.
	 */
	res = uthread_virt_to_phys(ut, (vaddr_t)u_props, &pa);
	if (res)
		return res;

	/* Set kernel address of properties array */
	u_props_kaddr = (struct ta_property *)paddr_to_kvaddr(pa);

	res = uthread_virt_to_phys(ut, (vaddr_t)u_props_size, &pa);
	if (res)
		return res;

	/* Set kernel address of properties array size */
	k_props_size = (uint32_t *)paddr_to_kvaddr(pa);

	/* Copy necessary values from user space */
	for(i = 0; i < *k_props_size; i++) {
		res = uthread_virt_to_phys(ut, (vaddr_t)u_props_kaddr->name,
				&pa);
		if (res)
			return res;

		name = paddr_to_kvaddr(pa);

		res = uthread_virt_to_phys(ut, (vaddr_t)u_props_kaddr->value,
				&pa);
		if (res)
			return res;

		value = paddr_to_kvaddr(pa);

		if (strcmp("gpd.ta.multiSession", name) == 0)
			k_props->multi_session = *(bool *)value;
		else if (strcmp("gpd.ta.singleInstance", name) == 0)
			k_props->single_instance = *(bool *)value;
		else if (strcmp("gpd.ta.instanceKeepAlive", name) == 0)
			k_props->keep_alive = *(bool *)value;

		u_props_kaddr++;
	}

	return res;
}

static status_t tee_api_load_properties(trusty_app_t *ta)
{
	status_t res = NO_ERROR;

	if (!ta->props.custom_cfg_ptr) {
		TEE_DBG_MSG("Tee API Properties do not exist\n");
		return ERR_INVALID_ARGS;
	}

	/* Set default values for kernel tee api properties */
	tee_api_kprops_t *k_props = tee_api_kprops(ta);
	memcpy(k_props, &tee_api_default_kprops, sizeof(*k_props));

	/* Copy user properties from user space into a kernel space
	 * structure to support querying ta properties from another ta context
	 */

	if (ta->is_parent) {
		res = properties_copy_from_user(ta);
	}

	if (!ta->is_parent) {
		trusty_app_t *ta_parent;
		ta_parent = trusty_app_find_by_uuid(&ta->props.uuid);
		if (!ta_parent)
			return ERR_NOT_FOUND;

		tee_api_kprops_t *k_props_parent = tee_api_kprops(ta_parent);
		memcpy(k_props, &k_props_parent, sizeof(*k_props));
	}

	return res;
}

static status_t tee_api_als_init(trusty_app_t *ta)
{
	status_t res = NO_ERROR;

	tee_api_info_t *ta_info = (tee_api_info_t*)calloc(1, sizeof(*ta_info));
	if (!ta_info)
		return ERR_NO_MEMORY;

	trusty_als_set(ta, _tee_api_slot_id, ta_info);

	ta_info->ta_port = INVALID_HANDLE_ID;
	ta_info->port_tag = rand();

	res = tee_api_load_properties(ta);
	if (res < 0)
		return res;

	return res;
}

static status_t tee_api_als_free(trusty_app_t *ta)
{
	if (!ta->is_parent) {
		tee_api_info_t *ta_info = tee_api_info(ta);
		if (ta_info) {
			memset(ta_info, 0, sizeof(*ta_info));
			free(ta_info);
		}
	}

	return NO_ERROR;
}

static status_t _tee_api_startup_notifier(trusty_app_t *ta)
{
	return tee_api_als_init(ta);
}

static status_t _tee_api_shutdown_notifier(trusty_app_t *ta)
{
	return tee_api_als_free(ta);
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
	_tee_api_slot_id = res;

	/* Register notifier */
	res = trusty_register_app_notifier(&_tee_api_notifier);
	if (res < 0)
		panic("failed (%d) to register tee_api notifier\n", res);
}

LK_INIT_HOOK(tee_api, tee_api_init, LK_INIT_LEVEL_APPS - 2);

static long lookup_uaddr_by_uuid(uuid_t *handle_uuid, user_addr_t uaddr,
		paddr_t *paddr)
{
	uuid_t uuid;
	status_t res;

	/* Verify user uuid access rights and copy to kernel */
	res = tee_copy_from_user(&uuid, (user_addr_t)handle_uuid, sizeof(uuid_t));
	if (res < 0)
		return ERR_ACCESS_DENIED;

	trusty_app_t *ta = trusty_app_find_by_uuid(&uuid);
	if (!ta)
		return ERR_NOT_FOUND;

	res = uthread_virt_to_phys(ta->ut, uaddr, paddr);
	return res;
}

long __SYSCALL sys_mmap_memref(user_addr_t uaddr, uint32_t size, uint32_t flags, uint32_t handle)
{
	vaddr_t vaddr;
	paddr_t paddr;
	uintptr_t uaddr_offset;
	user_addr_t uaddr_aligned;
	long res;

	if (flags & MMAP_FLAG_IO_HANDLE)
		return ERR_NOT_SUPPORTED;

	u_int align = UT_MAP_ALIGN_DEFAULT;
	u_int uflags = 0;

	if (flags & MMAP_FLAG_PROT_READ)
		uflags |= UTM_R;
	if (flags & MMAP_FLAG_PROT_WRITE)
		uflags |= UTM_W;

	/* TODO enforce maximum size, avoid uaddr+size roll-over
	 * fixup size in case uaddr is not page-aligned
	 */
	uaddr_aligned = ROUNDDOWN(uaddr, align);
	uaddr_offset = uaddr - uaddr_aligned;
	size += uaddr_offset;
	uaddr = uaddr_aligned;

	/* Size is allowed to be zero and must return a non-NULL ptr */
	if (size == 0)
		size = 1;

	size = ROUNDUP(size, align);

	if (handle) {
		/* TODO re-consider security and efficiency of using uuid as handle */
		res = lookup_uaddr_by_uuid((uuid_t *)handle, uaddr, &paddr);
		if (res) {
			TEE_DBG_MSG("Error code = %ld\n", res);
			return res;
		}
	} else {
		/* TODO miniheap will waste 2 pages when 1 page is allocated (header info etc) */
		/* TODO alloc a bigger chunk and manage it ourselves */
		/* TODO or maybe prealloc N pages per TA that it can use for shared mem? */
		paddr = (paddr_t)memalign(align, size);
	}
	res = uthread_map_contig(uthread_get_current(), &vaddr, paddr, size,
			uflags, align);
	if (res != NO_ERROR) {
		TEE_DBG_MSG("Error code = %ld\n", res);
		return -1;
	}

	return vaddr + uaddr_offset;
}

long __SYSCALL sys_munmap_memref(user_addr_t uaddr, uint32_t size)
{
	trusty_app_t *trusty_app = uthread_get_current()->private_data;

	/*
	 * uthread_unmap always unmaps whole region.
	 * TBD: Add support to unmap partial region when there's use case.
	 */
	return uthread_unmap(trusty_app->ut, uaddr, size);
}

long syscall_privilege_check(unsigned long num)
{
	trusty_app_t *trusty_app = uthread_get_current()->private_data;
	uint32_t privileges = trusty_app->props.privileges;

	switch(num) {
	case __NR_port_create:
	case __NR_connect:
	case __NR_accept:
	case __NR_connect_to_ta:
		if (!privileges)
			return ERR_ACCESS_DENIED;
		break;
	default:
		break;
	}
	return NO_ERROR;
}

static int32_t utee_send_params(uint32_t *channel, uint8_t *buffer)
{
	int32_t length;
	ipc_msg_t msg;
	iovec_t iov;

	iov.base = buffer;
	iov.len = TEE_MAX_BUFFER_SIZE;

	msg.num_iov = 1;
	msg.iov= &iov;
	msg.num_handles = 0;
	msg.handles = NULL;

	length = k_sys_send_msg(*channel, &msg);

	return length;
}

static int32_t utee_get_msg(uint32_t *channel, uint8_t *buffer)
{
	int32_t res;
	ipc_msg_info_t msg_info;
	ipc_msg_t msg;
	iovec_t iov;

	iov.base = buffer;
	iov.len = TEE_MAX_BUFFER_SIZE;

	msg.num_iov = 1;
	msg.iov= &iov;
	msg.num_handles = 0;
	msg.handles = NULL;

	res = k_sys_get_msg(*channel, &msg_info);
	if (res < 0)
		return res;

	res = k_sys_read_msg(*channel, msg_info.id, 0, &msg);
	if (res < 0)
		return res;
	/* TODO: Handle incomplete reads */

	/* Retire message */
	res = sys_put_msg(*channel, msg_info.id);
	if (res < 0)
		return res;

	return res;
}

/* TODO add timeout */
static int32_t poll_msg(uint32_t channel, uint8_t *buffer)
{
	int32_t res = NO_ERROR;
	uevent_t uev;

	/* Wait for parameters */
	res = k_sys_wait(channel, &uev, -1);
	if (res != NO_ERROR)
		return res;

	if (uev.event & IPC_HANDLE_POLL_MSG) {
		res = utee_get_msg(&uev.handle, buffer);
	} else if (uev.event & IPC_HANDLE_POLL_HUP) {
		res = ERR_CHANNEL_CLOSED;
	} else
		res = ERR_BAD_STATE;

	return res;
}

static int32_t sync_connect(const char *path, uint32_t timeout)
{
	int32_t res;
	uevent_t evt;
	uint32_t chan;

	res = k_sys_connect(path, IPC_CONNECT_ASYNC | IPC_CONNECT_WAIT_FOR_PORT);
	if (res >= 0) {
		chan = (uint32_t)res;
		res = k_sys_wait(chan, &evt, timeout);
		if (res == 0) {
			res = ERR_BAD_STATE;
			if (evt.handle == chan) {
				if (evt.event & IPC_HANDLE_POLL_READY)
					return chan;
				if (evt.event & IPC_HANDLE_POLL_HUP)
					res = ERR_CHANNEL_CLOSED;
			}
		}
		sys_close(chan);
	}
	return res;
}

static int32_t connect_to_sm(uint32_t timeout)
{
	int32_t res;
	uint32_t handle;

	/* Connect to SM command port */
	res = sync_connect(sm_comm, timeout);
	if (res < 0) {
		TEE_DBG_MSG("Cannot connect to SM command channel\n");
		return res;
	}
	TEE_DBG_MSG("TA connected to SM command port on channel: %d\n", res);
	handle = (uint32_t)res;

	return handle;
}

static status_t prepare_open_session_msg_buffer(msg_map_t *msg_buffer, void *uparams, void *dest_uuid)
{
	trusty_app_t *ta = uthread_get_current()->private_data;
	status_t res;

	memset(msg_buffer, 0, sizeof(*msg_buffer));

	msg_buffer->return_origin = TEE_ORIGIN_TEE;
	msg_buffer->operation_id = TEE_OPEN_SESSION_ID;
	msg_buffer->client_id.login = TEE_LOGIN_TRUSTED_APP;

	memcpy(&msg_buffer->client_id.uuid, &ta->props.uuid, sizeof(msg_buffer->client_id.uuid));

	res = tee_copy_from_user(&msg_buffer->ta_uuid, (user_addr_t)dest_uuid, sizeof(msg_buffer->ta_uuid));
	if (res < NO_ERROR)
		return res;

	res = tee_copy_from_user(&msg_buffer->utee_params, (user_addr_t)uparams, sizeof(msg_buffer->utee_params));
	if (res < NO_ERROR)
		return res;

	return NO_ERROR;
}

long __SYSCALL sys_open_session(uint32_t *session, void *uparams, uint32_t *ret_orig, uint32_t *uint_args)
{
	int32_t res;
	uint32_t ret_code;
	uint32_t timeout, channel;
	void *dest_uuid;
	msg_map_t sm_msg;
	uint32_t orig = TEE_ORIGIN_TEE;

	res = tee_copy_to_user((user_addr_t)ret_orig, &orig, sizeof(uint32_t));
	if (res < NO_ERROR)
		return TEE_ERROR_GENERIC;

	res = tee_copy_from_user(&timeout, (user_addr_t)&uint_args[0], sizeof(uint32_t));
	if (res < NO_ERROR)
		return TEE_ERROR_GENERIC;

	dest_uuid = (void*)uint_args[1];

	res = prepare_open_session_msg_buffer(&sm_msg, uparams, dest_uuid);
	if (res < NO_ERROR)
		return TEE_ERROR_GENERIC;

	res = connect_to_sm(timeout);
	if (res < NO_ERROR)
		return TEE_ERROR_COMMUNICATION;
	channel = (uint32_t)res;

	/* Send message to SM */
	TEE_DBG_MSG("Open session... channel %d ep %d\n", channel, sm_msg.operation_id);
	res = utee_send_params(&channel, sm_msg.buffer);
	if (res < NO_ERROR) {
		TEE_DBG_MSG("Open session failed... channel %d\n", channel);
		return TEE_ERROR_COMMUNICATION;
	}

	/* Get response from SM */
	res = poll_msg(channel, sm_msg.buffer);
	if (res < NO_ERROR) {
		TEE_DBG_MSG("Error code = %d\n", res);
		return TEE_ERROR_COMMUNICATION;
	}

	ret_code = sm_msg.return_code;
	/* If error occured, clean up the handle */
	if (ret_code != TEE_SUCCESS)
		sys_close(channel);

	res = tee_copy_to_user((user_addr_t)uparams, &sm_msg.utee_params, sizeof(utee_params_t));
	if (res < NO_ERROR)
		return TEE_ERROR_GENERIC;

	channel = TEE_MASK_HANDLE_ID(channel);
	res = tee_copy_to_user((user_addr_t)session, &channel, sizeof(uint32_t));
	if (res < NO_ERROR)
		return TEE_ERROR_GENERIC;

	res = tee_copy_to_user((user_addr_t)ret_orig, &sm_msg.return_origin, sizeof(uint32_t));
	if (res < NO_ERROR) {
		tee_copy_to_user((user_addr_t)ret_orig, &orig, sizeof(uint32_t));
		return TEE_ERROR_GENERIC;
	}

	return ret_code;
}

static status_t prepare_invoke_command_msg_buffer(msg_map_t *msg_buffer, void *uparams, uint32_t cmd_id)
{
	status_t res;

	memset(msg_buffer, 0, sizeof(*msg_buffer));

	msg_buffer->return_origin = TEE_ORIGIN_TEE;
	msg_buffer->operation_id = TEE_INVOKE_COMMAND_ID;
	msg_buffer->command_id = cmd_id;

	res = tee_copy_from_user(&msg_buffer->utee_params, (user_addr_t)uparams, sizeof(msg_buffer->utee_params));
	if (res < NO_ERROR)
		return res;

	return NO_ERROR;
}

long __SYSCALL sys_invoke_command(uint32_t session, void *uparams, uint32_t *ret_orig, uint32_t *uint_args)
{
	int32_t res;
	msg_map_t sm_msg;
	uint32_t timeout, channel;
	uint32_t cmd_id;
	uint32_t orig = TEE_ORIGIN_TEE;

	res = tee_copy_to_user((user_addr_t)ret_orig, &orig, sizeof(uint32_t));
	if (res < NO_ERROR)
	return TEE_ERROR_ACCESS_DENIED;

	res = tee_copy_from_user(&timeout, (user_addr_t)&uint_args[0], sizeof(uint32_t));
	if (res < NO_ERROR)
		return TEE_ERROR_ACCESS_DENIED;

	res = tee_copy_from_user(&cmd_id, (user_addr_t)&uint_args[1], sizeof(cmd_id));
	if (res < NO_ERROR)
		return TEE_ERROR_ACCESS_DENIED;

	res = prepare_invoke_command_msg_buffer(&sm_msg, uparams, cmd_id);
	if (res < NO_ERROR)
		return TEE_ERROR_ACCESS_DENIED;

	channel = TEE_UNMASK_HANDLE_ID(session);
	TEE_DBG_MSG("Invoke... channel %d ep %d cmd %d\n", channel, sm_msg.operation_id, sm_msg.command_id);
	res = utee_send_params(&channel, sm_msg.buffer);
	if (res < NO_ERROR) {
		TEE_DBG_MSG("Invoke failed... channel %d\n", channel);
		tee_copy_to_user((user_addr_t)ret_orig, &orig, sizeof(uint32_t));
		return TEE_ERROR_COMMUNICATION;
	}

	/* Get response from SM */
	res = poll_msg(channel, sm_msg.buffer);
	if (res < NO_ERROR) {
		TEE_DBG_MSG("Error code = %d\n", res);
		tee_copy_to_user((user_addr_t)ret_orig, &orig, sizeof(uint32_t));
		return TEE_ERROR_COMMUNICATION;
	}

	res = tee_copy_to_user((user_addr_t)uparams, &sm_msg.utee_params, sizeof(utee_params_t));
	if (res < NO_ERROR)
		return TEE_ERROR_ACCESS_DENIED;

	res = tee_copy_to_user((user_addr_t)ret_orig, &sm_msg.return_origin, sizeof(uint32_t));
	if (res < NO_ERROR) {
		tee_copy_to_user((user_addr_t)ret_orig, &orig, sizeof(uint32_t));
		return TEE_ERROR_ACCESS_DENIED;
	}

	return sm_msg.return_code;
}

static status_t prepare_close_session_msg_buffer(msg_map_t *msg_buffer)
{
	memset(msg_buffer, 0, sizeof(*msg_buffer));

	msg_buffer->return_origin = TEE_ORIGIN_TEE;
	msg_buffer->operation_id = TEE_CLOSE_SESSION_ID;

	return NO_ERROR;
}

long __SYSCALL sys_close_session(uint32_t session)
{
	int32_t res;
	uevent_t ev;
	uint32_t channel = TEE_UNMASK_HANDLE_ID(session);
	msg_map_t sm_msg;

	prepare_close_session_msg_buffer(&sm_msg);

	TEE_DBG_MSG("Close session... channel %d ep %d\n", channel, sm_msg.operation_id);
	res = utee_send_params(&channel, sm_msg.buffer);
	if (res < NO_ERROR) {
		TEE_DBG_MSG("Close session failed... channel %d\n", channel);
		return err_to_tee_err(res);
	}

	res = k_sys_wait(channel, &ev, -1);
	if (res < NO_ERROR)
		return res;

	res = sys_close(channel);
	return res;
}

#endif /* WITH_GP_API */
