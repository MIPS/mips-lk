/*
 * Copyright (c) 2012-2013, NVIDIA CORPORATION. All rights reserved
 * Copyright (c) 2013, Google, Inc. All rights reserved
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

#ifndef __LIB_TRUSTY_APP_H
#define __LIB_TRUSTY_APP_H

#include <assert.h>
#include <list.h>
#include <sys/types.h>
#include <uthread.h>

#include <lib/trusty/uuid.h>

#define PF_TO_UTM_FLAGS(x) ((((x) & PF_R) ? UTM_R : 0) | \
			    (((x) & PF_W) ? UTM_W : 0) | \
			    (((x) & PF_X) ? UTM_X : 0))

typedef struct
{
	uuid_t		uuid;
	uint32_t	min_stack_size;
	uint32_t	min_heap_size;
	uint32_t	map_io_mem_cnt;
	bool		auto_start;
	uint32_t	privileges;
	uint32_t	config_entry_cnt;
	uint32_t	*config_blob;
	void		*custom_cfg_ptr;
	uint32_t	*custom_cfg_size;
	void		*valid_ta_props;
	uint32_t	valid_ta_props_cnt;
} trusty_app_props_t;

struct free_map_node {
	struct list_node node;
	void* ptr;
};

typedef struct trusty_app
{
	vaddr_t end_bss;

	vaddr_t start_brk;
	vaddr_t cur_brk;
	vaddr_t end_brk;

	trusty_app_props_t props;

	void *app_img;

	uthread_t *ut;
	thread_t *kt;

	/* app local storage */
	void **als;

	struct list_node free_map_list;   // list of mapped pages to free
	struct list_node started_node;    // node in started_app_list
	struct list_node trusty_app_node; // node in trusty_app_list
	struct list_node cloned_child_list; // list of cloned children
	struct list_node cloned_node;     // node in cloned_child_list

	/* state info */
	u_int trusty_app_index;           // app index for log messages
	bool is_parent;			  // parent app or clone?
	bool started;                     // has app been started?
	bool dead;                        // has app exited?
} trusty_app_t;

status_t trusty_app_start_instance(uuid_t *uuid, trusty_app_t **trusty_app);
status_t trusty_app_start_clone(uuid_t *uuid, trusty_app_t **trusty_app);
status_t trusty_app_exit(trusty_app_t *trusty_app);
void trusty_app_dead(trusty_app_t *trusty_app);

void trusty_app_init(void);
status_t trusty_app_setup_mmio(trusty_app_t *trusty_app,
		u_int mmio_id, vaddr_t *vaddr, uint32_t size);
trusty_app_t *trusty_app_find_by_uuid(uuid_t *uuid);
status_t trusty_app_find_instance_by_uuid(uuid_t *uuid,
		int (*fn)(trusty_app_t *ta, void *data),
		void *data, int *fn_ret);
void trusty_app_forall(void (*fn)(trusty_app_t *ta, void *data), void *data);

typedef struct trusty_app_notifier
{
	struct list_node node;
	status_t (*startup)(trusty_app_t *app);
	status_t (*shutdown)(trusty_app_t *app);
} trusty_app_notifier_t;


/*
 * All app notifiers registration has to be complete before
 * libtrusty is initialized which is happening at LK_INIT_LEVEL_APPS-1
 * init level.
 */
status_t trusty_register_app_notifier(trusty_app_notifier_t *n);

/*
 * All als slots must be allocated before libtrusty is initialized
 * which is happening at LK_INIT_LEVEL_APPS-1 init level.
 */
int trusty_als_alloc_slot(void);

extern uint als_slot_cnt;

static inline void *trusty_als_get(struct trusty_app *app, int slot_id)
{
	uint slot = slot_id - 1;
	ASSERT(slot < als_slot_cnt);
	return app->als[slot];
}

static inline void trusty_als_set(struct trusty_app *app, int slot_id, void *ptr)
{
	uint slot = slot_id - 1;
	ASSERT(slot < als_slot_cnt);
	app->als[slot] = ptr;
}

#endif
