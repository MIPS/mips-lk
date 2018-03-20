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

#include <lib/tee/tee_obj.h>

#include <stdlib.h>
#include <tee_api_defines.h>
#include <lib/tee/tee_api.h>
#include <lib/tee/tee_fs.h>
#include <lib/tee/tee_pobj.h>
#include <trace.h>
#include <lib/tee/tee_svc_cryp.h>

void tee_obj_add(tee_api_info_t *ta_info, struct tee_obj *o)
{
	list_add_tail(&ta_info->objects, &o->node);
}

TEE_Result tee_obj_get(tee_api_info_t *ta_info, uint32_t obj_id,
		       struct tee_obj **obj)
{
	struct tee_obj *o;

	list_for_every_entry(&ta_info->objects, o, struct tee_obj, node) {
		if (obj_id == (vaddr_t)o) {
			*obj = o;
			return TEE_SUCCESS;
		}
	}
	return TEE_ERROR_BAD_PARAMETERS;
}

void tee_obj_close(struct tee_obj *o)
{
	list_delete(&o->node);

	if ((o->info.handleFlags & TEE_HANDLE_FLAG_PERSISTENT)) {
		o->pobj->fops->close(&o->fh);
		tee_pobj_release(o->pobj);
	}

	tee_obj_free(o);
}

void tee_obj_close_all(tee_api_info_t *ta_info)
{
	struct tee_obj *obj, *next_obj;

	list_for_every_entry_safe(&ta_info->objects, obj, next_obj,
			struct tee_obj, node) {
		tee_obj_close(obj);
	}
}

struct tee_obj *tee_obj_alloc(void)
{
	return calloc(1, sizeof(struct tee_obj));
}

void tee_obj_free(struct tee_obj *o)
{
	if (o) {
		tee_obj_attr_free(o);
		free(o->attr);
		free(o);
	}
}
