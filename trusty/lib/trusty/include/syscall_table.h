/*
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

/* DEF_SYSCALL(syscall_nr, syscall_name, return type, nr_args, [argument list])
 *
 * Please keep this table sorted by syscall number
 */

DEF_SYSCALL(0x1, write, long, 3, uint32_t fd, void *msg, uint32_t size)
DEF_SYSCALL(0x2, brk, long, 1, uint32_t brk)
DEF_SYSCALL(0x3, exit_group, long, 0)
DEF_SYSCALL(0x4, read, long, 3, uint32_t fd, void *msg, uint32_t size)
DEF_SYSCALL(0x5, ioctl, long, 3, uint32_t fd, uint32_t req, void *buf)
DEF_SYSCALL(0x6, nanosleep, long, 3, uint32_t clock_id, uint32_t flags, uint64_t sleep_time)
DEF_SYSCALL(0x7, gettime, long, 3, uint32_t clock_id, uint32_t flags, int64_t *time)
DEF_SYSCALL(0x8, mmap, long, 4, void *uaddr, uint32_t size, uint32_t flags, uint32_t handle)
DEF_SYSCALL(0x9, munmap, long, 2, void *uaddr, uint32_t size)
DEF_SYSCALL(0xa, prepare_dma, long, 4, void *uaddr, uint32_t size, uint32_t flags, struct dma_pmem *pmem)
DEF_SYSCALL(0xb, finish_dma, long, 3, void *uaddr, uint32_t size, uint32_t flags)

/* IPC connection establishement syscalls */
DEF_SYSCALL(0x10, port_create, long, 4, const char *path, uint32_t num_recv_bufs, uint32_t recv_buf_size, uint32_t flags)
DEF_SYSCALL(0x11, connect, long, 2, const char *path, uint32_t flags)
DEF_SYSCALL(0x12, accept, long, 2, uint32_t handle_id, uuid_t *peer_uuid)
DEF_SYSCALL(0x13, close, long, 1, uint32_t handle_id)
DEF_SYSCALL(0x14, set_cookie, long, 2, uint32_t handle, void *cookie)

/* handle polling related syscalls */
DEF_SYSCALL(0x18, wait, long, 3, uint32_t handle_id, uevent_t *event, uint32_t timeout_msecs)
DEF_SYSCALL(0x19, wait_any, long, 2, uevent_t *event, uint32_t timeout_msecs)

/* message send/recv syscalls */
DEF_SYSCALL(0x20, get_msg, long, 2, uint32_t handle, ipc_msg_info_t *msg_info)
DEF_SYSCALL(0x21, read_msg, long, 4, uint32_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg)
DEF_SYSCALL(0x22, put_msg, long, 2, uint32_t handle, uint32_t msg_id)
DEF_SYSCALL(0x23, send_msg, long, 2, uint32_t handle, ipc_msg_t *msg)

DEF_SYSCALL(0x24, set_panic_handler, long, 2, void (*pa_handler)(void *), void *args)

/* Trusted Execution Environment API syscalls */
DEF_SYSCALL(0x30, check_access_rights, TEE_Result, 3, unsigned long flags, const void *buf, uint32_t len)
DEF_SYSCALL(0x31, connect_to_ta, TEE_Result, 2, const uuid_t *dest_uuid, uint32_t *handle_id)
DEF_SYSCALL(0x32, get_kprops, TEE_Result, 5, const char *prop_name, size_t name_len, void *prop, uint32_t index, uint32_t prop_set)
DEF_SYSCALL(0x33, get_ta_client_props, TEE_Result, 5, const uuid_t *uuid, const char *prop_name, size_t name_len, void *prop, uint32_t index)
DEF_SYSCALL(0x34, get_props_num, TEE_Result, 3, const uuid_t *uuid, uint32_t prop_set, uint32_t *prop_length)
DEF_SYSCALL(0x35, get_prop_name, TEE_Result, 5, uint32_t prop_set, uint32_t index, char *prop_name, uuid_t *uuid, size_t *len)
DEF_SYSCALL(0x36, ta_dead, void, 0)
DEF_SYSCALL(0x37, ta_next_msg, long, 1, void *msg_buf)
DEF_SYSCALL(0x38, invoke_operation, TEE_Result, 4, void *teec_session, void *utee_params, uint32_t *ret_orig, uint32_t *uint_args)
DEF_SYSCALL(0x39, close_session, TEE_Result, 1, void *teec_session)
DEF_SYSCALL(0x3a, set_cancel_flag, TEE_Result, 2, uuid_t *ta_uuid, uint32_t *sess_id)
DEF_SYSCALL(0x3b, get_cancel_flag, bool, 0)
DEF_SYSCALL(0x3c, mask_cancel_flag, bool, 0)
DEF_SYSCALL(0x3d, unmask_cancel_flag, bool, 0)
DEF_SYSCALL(0x3e, connect_to_sm, TEE_Result, 1, uint32_t *handle_id)
DEF_SYSCALL(0x3f, get_ta_flags, TEE_Result, 2, const uuid_t *dest_uuid, uint32_t *flags)
DEF_SYSCALL(0x40, tee_wait, TEE_Result, 1, uint32_t timeout)

/* TEE Crypto API syscalls */
DEF_SYSCALL(0x50, utee_cryp_state_alloc, TEE_Result, 5, unsigned long algo, unsigned long op_mode, unsigned long key1, unsigned long key2, uint32_t *state)
DEF_SYSCALL(0x51, utee_cryp_state_copy, TEE_Result, 2, unsigned long dst, unsigned long src)
DEF_SYSCALL(0x52, utee_cryp_state_free, TEE_Result, 1, unsigned long state)

/* iv and iv_len are ignored for some algorithms */
DEF_SYSCALL(0x53, utee_hash_init, TEE_Result, 3, unsigned long state, const void *iv, size_t iv_len)
DEF_SYSCALL(0x54, utee_hash_update, TEE_Result, 3, unsigned long state, const void *chunk, size_t chunk_size)
DEF_SYSCALL(0x55, utee_hash_final, TEE_Result, 5, unsigned long state, const void *chunk, size_t chunk_size, void *hash, uint64_t *hash_len)

DEF_SYSCALL(0x56, utee_cipher_init, TEE_Result, 3, unsigned long state, const void *iv, size_t iv_len)
DEF_SYSCALL(0x57, utee_cipher_update, TEE_Result, 5, unsigned long state, const void *src, size_t src_len, void *dest, uint64_t *dest_len)
DEF_SYSCALL(0x58, utee_cipher_final, TEE_Result, 5, unsigned long state, const void *src, size_t src_len, void *dest, uint64_t *dest_len)

/* Generic Object Functions */
DEF_SYSCALL(0x59, utee_cryp_obj_get_info, TEE_Result, 2, unsigned long obj, TEE_ObjectInfo *info)
DEF_SYSCALL(0x5a, utee_cryp_obj_restrict_usage, TEE_Result, 2, unsigned long obj, unsigned long usage)
DEF_SYSCALL(0x5b, utee_cryp_obj_get_attr, TEE_Result, 4, unsigned long obj, unsigned long attr_id, void *buffer, uint64_t *size)

/* Transient Object Functions */
/* type has type TEE_ObjectType */
DEF_SYSCALL(0x5c, utee_cryp_obj_alloc, TEE_Result, 3, unsigned long type, unsigned long max_size, uint32_t *obj)
DEF_SYSCALL(0x5d, utee_cryp_obj_close, TEE_Result, 1, unsigned long obj)
DEF_SYSCALL(0x5e, utee_cryp_obj_reset, TEE_Result, 1, unsigned long obj)
DEF_SYSCALL(0x5f, utee_cryp_obj_populate, TEE_Result, 3, unsigned long obj, struct utee_attribute *attrs, unsigned long attr_count)
DEF_SYSCALL(0x60, utee_cryp_obj_copy, TEE_Result, 2, unsigned long dst_obj, unsigned long src_obj)

DEF_SYSCALL(0x61, utee_cryp_obj_generate_key, TEE_Result, 4, unsigned long obj, unsigned long key_size, const struct utee_attribute *params, unsigned long param_count)

DEF_SYSCALL(0x62, utee_cryp_derive_key, TEE_Result, 4, unsigned long state, const struct utee_attribute *params, unsigned long param_count, unsigned long derived_key)

DEF_SYSCALL(0x63, utee_cryp_random_number_generate, TEE_Result, 2, void *buf, size_t blen)
DEF_SYSCALL(0x64, utee_authenc_init, TEE_Result, 6, unsigned long state, const void *nonce, size_t nonce_len, size_t tag_len, size_t aad_len, size_t payload_len)
DEF_SYSCALL(0x65, utee_authenc_update_aad, TEE_Result, 3, unsigned long state, const void *aad_data, size_t aad_data_len)
DEF_SYSCALL(0x66, utee_authenc_update_payload, TEE_Result, 5, unsigned long state, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len)
DEF_SYSCALL(0x67, utee_authenc_enc_final, TEE_Result, 7, unsigned long state, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len, void *tag, uint64_t *tag_len)
DEF_SYSCALL(0x68, utee_authenc_dec_final, TEE_Result, 7, unsigned long state, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len, const void *tag, size_t tag_len)

DEF_SYSCALL(0x69, utee_asymm_operate, TEE_Result, 7, unsigned long state, const struct utee_attribute *params, unsigned long num_params, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len)

DEF_SYSCALL(0x6a, utee_asymm_verify, TEE_Result, 7, unsigned long state, const struct utee_attribute *params, unsigned long num_params, const void *data, size_t data_len, const void *sig, size_t sig_len)

/* Persistant Object Functions */
/* obj is of type TEE_ObjectHandle */
DEF_SYSCALL(0x6b, utee_storage_obj_open, TEE_Result, 5, unsigned long storage_id, const void *object_id, size_t object_id_len, unsigned long flags, uint32_t *obj)

/*
 * attr is of type TEE_ObjectHandle
 * obj is of type TEE_ObjectHandle
 */
DEF_SYSCALL(0x6c, utee_storage_obj_create, TEE_Result, 8, unsigned long storage_id, const void *object_id, size_t object_id_len, unsigned long flags, unsigned long attr, const void *data, size_t len, uint32_t *obj)

/* obj is of type TEE_ObjectHandle */
DEF_SYSCALL(0x6d, utee_storage_obj_del, TEE_Result, 1, unsigned long obj)

/* obj is of type TEE_ObjectHandle */
DEF_SYSCALL(0x6e, utee_storage_obj_rename, TEE_Result, 3, unsigned long obj, const void *new_obj_id, size_t new_obj_id_len)

/* Persistent Object Enumeration Functions */
/* obj_enum is of type TEE_ObjectEnumHandle */
DEF_SYSCALL(0x6f, utee_storage_alloc_enum, TEE_Result, 1, uint32_t *obj_enum)


/* obj_enum is of type TEE_ObjectEnumHandle */
DEF_SYSCALL(0x70, utee_storage_free_enum, TEE_Result, 1, unsigned long obj_enum)

/* obj_enum is of type TEE_ObjectEnumHandle */
DEF_SYSCALL(0x71, utee_storage_reset_enum, TEE_Result, 1, unsigned long obj_enum)

/* obj_enum is of type TEE_ObjectEnumHandle */
DEF_SYSCALL(0x72, utee_storage_start_enum, TEE_Result, 2, unsigned long obj_enum, unsigned long storage_id)

/* obj_enum is of type TEE_ObjectEnumHandle */
DEF_SYSCALL(0x73, utee_storage_next_enum, TEE_Result, 4, unsigned long obj_enum, TEE_ObjectInfo *info, void *obj_id, uint64_t *len)

/* Data Stream Access Functions */
/* obj is of type TEE_ObjectHandle */
DEF_SYSCALL(0x74, utee_storage_obj_read, TEE_Result, 4, unsigned long obj, void *data, size_t len, uint64_t *count)

/* obj is of type TEE_ObjectHandle */
DEF_SYSCALL(0x75, utee_storage_obj_write, TEE_Result, 3, unsigned long obj, const void *data, size_t len)

/* obj is of type TEE_ObjectHandle */
DEF_SYSCALL(0x76, utee_storage_obj_trunc, TEE_Result, 2, unsigned long obj, size_t len)

/* obj is of type TEE_ObjectHandle */
/* whence is of type TEE_Whence */
DEF_SYSCALL(0x77, utee_storage_obj_seek, TEE_Result, 3, unsigned long obj, int32_t offset, unsigned long whence)
