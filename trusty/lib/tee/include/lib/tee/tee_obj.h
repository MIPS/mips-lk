/*
 * Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
 * (“MIPS”).
 * Copyright (c) 2014, STMicroelectronics International N.V.
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

#ifndef TEE_OBJ_H
#define TEE_OBJ_H

#include <stdbool.h>
#include <tee_api_types.h>
#include <list.h>
#include <lib/tee/tee_api.h>

#define TEE_USAGE_DEFAULT   0xffffffff

struct tee_obj {
	struct list_node node;
	TEE_ObjectInfo info;
	bool busy;		/* true if used by an operation */
	uint32_t have_attrs;	/* bitfield identifying set properties */
	void *attr;
	size_t ds_pos;
	struct tee_pobj *pobj;	/* ptr to persistant object */
	struct tee_file_handle *fh;
	uint32_t flags;		/* permission flags for persistent objects */
};

void tee_obj_add(tee_api_info_t *ta_info, struct tee_obj *o);

TEE_Result tee_obj_get(tee_api_info_t *ta_info, uint32_t obj_id,
		       struct tee_obj **obj);

void tee_obj_close(struct tee_obj *o);

void tee_obj_close_all(tee_api_info_t *ta_info);

struct tee_obj *tee_obj_alloc(void);
void tee_obj_free(struct tee_obj *o);

#endif
