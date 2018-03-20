/*
 * Copyright (c) 2015, Linaro Limited
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
#ifndef UTEE_SYSCALLS_H
#define UTEE_SYSCALLS_H

#include <compiler.h>
#include <stddef.h>
#include <stdint.h>

#include <tee_common_uapi.h>
#include <tee_api_types.h>
#include <trace.h>

/*
 * Arguments must use the native register width, unless it's a signed
 * argument then it must be a 32-bit value instead to avoid problems with
 * sign extension. To keep it simple, only use pointers, int32_t, unsigned
 * long and size_t. Pointers may only point structures or types based on
 * fixed width integer types. Only exception are buffers with opaque data.
 *
 * Return values should not use a fixed width larger than 32 bits, unsigned
 * long and pointers are OK though.
 *
 * Members in structs on the other hand should only use fixed width integer
 * types; uint32_t, uint64_t etc. To keep it simple, use uint64_t for all
 * length fields.
 */

TEE_Result utee_cryp_state_alloc(unsigned long algo, unsigned long op_mode,
				 unsigned long key1, unsigned long key2,
				 uint32_t *state);
TEE_Result utee_cryp_state_copy(unsigned long dst, unsigned long src);
TEE_Result utee_cryp_state_free(unsigned long state);

/* iv and iv_len are ignored for some algorithms */
TEE_Result utee_hash_init(unsigned long state, const void *iv, size_t iv_len);
TEE_Result utee_hash_update(unsigned long state, const void *chunk,
			    size_t chunk_size);
TEE_Result utee_hash_final(unsigned long state, const void *chunk,
			   size_t chunk_size, void *hash, uint64_t *hash_len);

TEE_Result utee_cipher_init(unsigned long state, const void *iv, size_t iv_len);
TEE_Result utee_cipher_update(unsigned long state, const void *src,
			size_t src_len, void *dest, uint64_t *dest_len);
TEE_Result utee_cipher_final(unsigned long state, const void *src,
			size_t src_len, void *dest, uint64_t *dest_len);

/* Generic Object Functions */
TEE_Result utee_cryp_obj_get_info(unsigned long obj, TEE_ObjectInfo *info);
TEE_Result utee_cryp_obj_restrict_usage(unsigned long obj, unsigned long usage);
TEE_Result utee_cryp_obj_get_attr(unsigned long obj, unsigned long attr_id,
			void *buffer, uint64_t *size);

/* Transient Object Functions */
/* type has type TEE_ObjectType */
TEE_Result utee_cryp_obj_alloc(unsigned long type, unsigned long max_size,
			uint32_t *obj);
TEE_Result utee_cryp_obj_close(unsigned long obj);
TEE_Result utee_cryp_obj_reset(unsigned long obj);
TEE_Result utee_cryp_obj_populate(unsigned long obj,
			struct utee_attribute *attrs, unsigned long attr_count);
TEE_Result utee_cryp_obj_copy(unsigned long dst_obj, unsigned long src_obj);

TEE_Result utee_cryp_obj_generate_key(unsigned long obj, unsigned long key_size,
			const struct utee_attribute *params,
			unsigned long param_count);

TEE_Result utee_cryp_derive_key(unsigned long state,
			const struct utee_attribute *params,
			unsigned long param_count, unsigned long derived_key);

TEE_Result utee_cryp_random_number_generate(void *buf, size_t blen);

TEE_Result utee_authenc_init(unsigned long state, const void *nonce,
			size_t nonce_len, size_t tag_len, size_t aad_len,
			size_t payload_len);
TEE_Result utee_authenc_update_aad(unsigned long state, const void *aad_data,
			size_t aad_data_len);
TEE_Result utee_authenc_update_payload(unsigned long state,
			const void *src_data, size_t src_len, void *dest_data,
			uint64_t *dest_len);
TEE_Result utee_authenc_enc_final(unsigned long state, const void *src_data,
			size_t src_len, void *dest_data, uint64_t *dest_len,
			void *tag, uint64_t *tag_len);
TEE_Result utee_authenc_dec_final(unsigned long state, const void *src_data,
			size_t src_len, void *dest_data, uint64_t *dest_len,
			const void *tag, size_t tag_len);

TEE_Result utee_asymm_operate(unsigned long state,
			const struct utee_attribute *params,
			unsigned long num_params, const void *src_data,
			size_t src_len, void *dest_data, uint64_t *dest_len);

TEE_Result utee_asymm_verify(unsigned long state,
			const struct utee_attribute *params,
			unsigned long num_params, const void *data,
			size_t data_len, const void *sig, size_t sig_len);

/* Persistant Object Functions */
/* obj is of type TEE_ObjectHandle */
TEE_Result utee_storage_obj_open(unsigned long storage_id,
				 const void *object_id,
				 size_t object_id_len, unsigned long flags,
				 uint32_t *obj);

/*
 * attr is of type TEE_ObjectHandle
 * obj is of type TEE_ObjectHandle
 */
TEE_Result utee_storage_obj_create(unsigned long storage_id,
				   const void *object_id,
				   size_t object_id_len, unsigned long flags,
				   unsigned long attr, const void *data,
				   size_t len, uint32_t *obj);

/* obj is of type TEE_ObjectHandle */
TEE_Result utee_storage_obj_del(unsigned long obj);

/* obj is of type TEE_ObjectHandle */
TEE_Result utee_storage_obj_rename(unsigned long obj, const void *new_obj_id,
				size_t new_obj_id_len);

/* Persistent Object Enumeration Functions */
/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result utee_storage_alloc_enum(uint32_t *obj_enum);


/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result utee_storage_free_enum(unsigned long obj_enum);

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result utee_storage_reset_enum(unsigned long obj_enum);

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result utee_storage_start_enum(unsigned long obj_enum,
			unsigned long storage_id);

/* obj_enum is of type TEE_ObjectEnumHandle */
TEE_Result utee_storage_next_enum(unsigned long obj_enum, TEE_ObjectInfo *info,
			void *obj_id, uint64_t *len);

/* Data Stream Access Functions */
/* obj is of type TEE_ObjectHandle */
TEE_Result utee_storage_obj_read(unsigned long obj, void *data, size_t len,
			uint64_t *count);

/* obj is of type TEE_ObjectHandle */
TEE_Result utee_storage_obj_write(unsigned long obj, const void *data,
			size_t len);

/* obj is of type TEE_ObjectHandle */
TEE_Result utee_storage_obj_trunc(unsigned long obj, size_t len);

/* obj is of type TEE_ObjectHandle */
/* whence is of type TEE_Whence */
TEE_Result utee_storage_obj_seek(unsigned long obj, int32_t offset,
				 unsigned long whence);

#endif /* UTEE_SYSCALLS_H */
