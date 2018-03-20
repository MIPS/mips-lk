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

#include <kernel/mutex.h>
#include <stdlib.h>
#include <string.h>
#include <lib/tee/tee_pobj.h>
#include <trace.h>

static struct list_node tee_pobjs = LIST_INITIAL_VALUE(tee_pobjs);
static mutex_t pobjs_mutex = MUTEX_INITIAL_VALUE(pobjs_mutex);

static TEE_Result tee_pobj_check_access(uint32_t oflags, uint32_t nflags)
{
	/* meta is exclusive */
	if ((oflags & TEE_DATA_FLAG_ACCESS_WRITE_META) ||
	    (nflags & TEE_DATA_FLAG_ACCESS_WRITE_META))
		return TEE_ERROR_ACCESS_CONFLICT;

	/*
	 * Excerpt of TEE Internal Core API Specification v1.1:
	 * If more than one handle is opened on the same  object, and if any
	 * of these object handles was opened with the flag
	 * TEE_DATA_FLAG_ACCESS_READ, then all the object handles MUST have been
	 * opened with the flag TEE_DATA_FLAG_SHARE_READ
	 */
	if (((oflags & TEE_DATA_FLAG_ACCESS_READ) ||
	     (nflags & TEE_DATA_FLAG_ACCESS_READ)) &&
	    !((nflags & TEE_DATA_FLAG_SHARE_READ) &&
	      (oflags & TEE_DATA_FLAG_SHARE_READ)))
		return TEE_ERROR_ACCESS_CONFLICT;

	/*
	 * Excerpt of TEE Internal Core API Specification v1.1:
	 * An object can be opened with only share flags, which locks the access
	 * to an object against a given mode.
	 * An object can be opened with no flag set, which completely locks all
	 * subsequent attempts to access the object
	 */
	if ((nflags & TEE_DATA_FLAG_SHARE_READ) !=
	    (oflags & TEE_DATA_FLAG_SHARE_READ))
		return TEE_ERROR_ACCESS_CONFLICT;

	/* Same on WRITE access */
	if (((oflags & TEE_DATA_FLAG_ACCESS_WRITE) ||
	     (nflags & TEE_DATA_FLAG_ACCESS_WRITE)) &&
	    !((nflags & TEE_DATA_FLAG_SHARE_WRITE) &&
	      (oflags & TEE_DATA_FLAG_SHARE_WRITE)))
		return TEE_ERROR_ACCESS_CONFLICT;
	if ((nflags & TEE_DATA_FLAG_SHARE_WRITE) !=
	    (oflags & TEE_DATA_FLAG_SHARE_WRITE))
		return TEE_ERROR_ACCESS_CONFLICT;

	return TEE_SUCCESS;
}

TEE_Result tee_pobj_get(TEE_UUID *uuid, void *obj_id, uint32_t obj_id_len,
			uint32_t flags, bool temporary,
			const struct tee_file_operations *fops,
			struct tee_pobj **obj)
{
	struct tee_pobj *o;
	TEE_Result res;

	*obj = NULL;

	mutex_acquire(&pobjs_mutex);
	/* Check if file is open */
	list_for_every_entry(&tee_pobjs, o, struct tee_pobj, node) {
		if ((obj_id_len == o->obj_id_len) &&
		    (memcmp(obj_id, o->obj_id, obj_id_len) == 0) &&
		    (memcmp(uuid, &o->uuid, sizeof(TEE_UUID)) == 0) &&
		    (fops == o->fops)) {
			*obj = o;
		}
	}

	if (*obj) {
		if (temporary != (*obj)->temporary) {
			res = TEE_ERROR_ACCESS_CONFLICT;
			goto out;
		}
		res = tee_pobj_check_access((*obj)->flags, flags);
		if (res == TEE_SUCCESS)
			(*obj)->refcnt++;
		goto out;
	}

	/* new file */
	o = calloc(sizeof(struct tee_pobj), 1);
	if (!o) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	o->refcnt = 1;
	memcpy(&o->uuid, uuid, sizeof(TEE_UUID));
	o->flags = flags;
	o->fops = fops;
	o->temporary = temporary;

	o->obj_id = malloc(obj_id_len);
	if (o->obj_id == NULL) {
		free(o);
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}
	memcpy(o->obj_id, obj_id, obj_id_len);
	o->obj_id_len = obj_id_len;

	list_add_tail(&tee_pobjs, &o->node);
	*obj = o;

	res = TEE_SUCCESS;
out:
	if (res != TEE_SUCCESS)
		*obj = NULL;
	mutex_release(&pobjs_mutex);
	return res;
}

TEE_Result tee_pobj_release(struct tee_pobj *obj)
{
	if (obj == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_acquire(&pobjs_mutex);
	obj->refcnt--;
	if (obj->refcnt == 0) {
		list_delete(&obj->node);
		free(obj->obj_id);
		free(obj);
	}
	mutex_release(&pobjs_mutex);

	return TEE_SUCCESS;
}

TEE_Result tee_pobj_rename(struct tee_pobj *obj, void *obj_id,
			   uint32_t obj_id_len)
{
	TEE_Result res = TEE_SUCCESS;
	void *new_obj_id = NULL;

	if (obj == NULL || obj_id == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_acquire(&pobjs_mutex);
	if (obj->refcnt != 1) {
		res = TEE_ERROR_BAD_STATE;
		goto exit;
	}

	new_obj_id = malloc(obj_id_len);
	if (new_obj_id == NULL) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto exit;
	}
	memcpy(new_obj_id, obj_id, obj_id_len);

	/* update internal data */
	free(obj->obj_id);
	obj->obj_id = new_obj_id;
	obj->obj_id_len = obj_id_len;
	new_obj_id = NULL;

exit:
	mutex_release(&pobjs_mutex);
	free(new_obj_id);
	return res;
}
