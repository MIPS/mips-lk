/*
 * Copyright (c) 2013-2017 Google Inc. All rights reserved
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

/* This file is auto-generated. !!! DO NOT EDIT !!! */

#define __NR_write                               	0x1
#define __NR_brk                                 	0x2
#define __NR_exit_group                          	0x3
#define __NR_read                                	0x4
#define __NR_ioctl                               	0x5
#define __NR_nanosleep                           	0x6
#define __NR_gettime                             	0x7
#define __NR_mmap                                	0x8
#define __NR_munmap                              	0x9
#define __NR_prepare_dma                         	0xa
#define __NR_finish_dma                          	0xb
#define __NR_port_create                         	0x10
#define __NR_connect                             	0x11
#define __NR_accept                              	0x12
#define __NR_close                               	0x13
#define __NR_set_cookie                          	0x14
#define __NR_wait                                	0x18
#define __NR_wait_any                            	0x19
#define __NR_get_msg                             	0x20
#define __NR_read_msg                            	0x21
#define __NR_put_msg                             	0x22
#define __NR_send_msg                            	0x23
#define __NR_set_panic_handler                   	0x24
#define __NR_check_access_rights                 	0x30
#define __NR_connect_to_ta                       	0x31
#define __NR_get_kprops                          	0x32
#define __NR_get_ta_client_props                 	0x33
#define __NR_get_props_num                       	0x34
#define __NR_get_prop_name                       	0x35
#define __NR_ta_dead                             	0x36
#define __NR_ta_next_msg                         	0x37
#define __NR_invoke_operation                    	0x38
#define __NR_close_session                       	0x39
#define __NR_set_cancel_flag                     	0x3a
#define __NR_get_cancel_flag                     	0x3b
#define __NR_mask_cancel_flag                    	0x3c
#define __NR_unmask_cancel_flag                  	0x3d
#define __NR_connect_to_sm                       	0x3e
#define __NR_get_ta_flags                        	0x3f
#define __NR_tee_wait                            	0x40
#define __NR_utee_cryp_state_alloc               	0x50
#define __NR_utee_cryp_state_copy                	0x51
#define __NR_utee_cryp_state_free                	0x52
#define __NR_utee_hash_init                      	0x53
#define __NR_utee_hash_update                    	0x54
#define __NR_utee_hash_final                     	0x55
#define __NR_utee_cipher_init                    	0x56
#define __NR_utee_cipher_update                  	0x57
#define __NR_utee_cipher_final                   	0x58
#define __NR_utee_cryp_obj_get_info              	0x59
#define __NR_utee_cryp_obj_restrict_usage        	0x5a
#define __NR_utee_cryp_obj_get_attr              	0x5b
#define __NR_utee_cryp_obj_alloc                 	0x5c
#define __NR_utee_cryp_obj_close                 	0x5d
#define __NR_utee_cryp_obj_reset                 	0x5e
#define __NR_utee_cryp_obj_populate              	0x5f
#define __NR_utee_cryp_obj_copy                  	0x60
#define __NR_utee_cryp_obj_generate_key          	0x61
#define __NR_utee_cryp_derive_key                	0x62
#define __NR_utee_cryp_random_number_generate    	0x63
#define __NR_utee_authenc_init                   	0x64
#define __NR_utee_authenc_update_aad             	0x65
#define __NR_utee_authenc_update_payload         	0x66
#define __NR_utee_authenc_enc_final              	0x67
#define __NR_utee_authenc_dec_final              	0x68
#define __NR_utee_asymm_operate                  	0x69
#define __NR_utee_asymm_verify                   	0x6a
#define __NR_utee_storage_obj_open               	0x6b
#define __NR_utee_storage_obj_create             	0x6c
#define __NR_utee_storage_obj_del                	0x6d
#define __NR_utee_storage_obj_rename             	0x6e
#define __NR_utee_storage_alloc_enum             	0x6f
#define __NR_utee_storage_free_enum              	0x70
#define __NR_utee_storage_reset_enum             	0x71
#define __NR_utee_storage_start_enum             	0x72
#define __NR_utee_storage_next_enum              	0x73
#define __NR_utee_storage_obj_read               	0x74
#define __NR_utee_storage_obj_write              	0x75
#define __NR_utee_storage_obj_trunc              	0x76
#define __NR_utee_storage_obj_seek               	0x77

#ifndef ASSEMBLY

__BEGIN_CDECLS

long write(uint32_t fd, void *msg, uint32_t size);
long brk(uint32_t brk);
long exit_group(void);
long read(uint32_t fd, void *msg, uint32_t size);
long ioctl(uint32_t fd, uint32_t req, void *buf);
long nanosleep(uint32_t clock_id, uint32_t flags, uint64_t sleep_time);
long gettime(uint32_t clock_id, uint32_t flags, int64_t *time);
long mmap(void *uaddr, uint32_t size, uint32_t flags, uint32_t handle);
long munmap(void *uaddr, uint32_t size);
long prepare_dma(void *uaddr, uint32_t size, uint32_t flags, struct dma_pmem *pmem);
long finish_dma(void *uaddr, uint32_t size, uint32_t flags);
long port_create(const char *path, uint32_t num_recv_bufs, uint32_t recv_buf_size, uint32_t flags);
long connect(const char *path, uint32_t flags);
long accept(uint32_t handle_id, uuid_t *peer_uuid);
long close(uint32_t handle_id);
long set_cookie(uint32_t handle, void *cookie);
long wait(uint32_t handle_id, uevent_t *event, uint32_t timeout_msecs);
long wait_any(uevent_t *event, uint32_t timeout_msecs);
long get_msg(uint32_t handle, ipc_msg_info_t *msg_info);
long read_msg(uint32_t handle, uint32_t msg_id, uint32_t offset, ipc_msg_t *msg);
long put_msg(uint32_t handle, uint32_t msg_id);
long send_msg(uint32_t handle, ipc_msg_t *msg);
long set_panic_handler(void (*pa_handler)(void *), void *args);
TEE_Result check_access_rights(unsigned long flags, const void *buf, uint32_t len);
TEE_Result connect_to_ta(const uuid_t *dest_uuid, uint32_t *handle_id);
TEE_Result get_kprops(const char *prop_name, size_t name_len, void *prop, uint32_t index, uint32_t prop_set);
TEE_Result get_ta_client_props(const uuid_t *uuid, const char *prop_name, size_t name_len, void *prop, uint32_t index);
TEE_Result get_props_num(const uuid_t *uuid, uint32_t prop_set, uint32_t *prop_length);
TEE_Result get_prop_name(uint32_t prop_set, uint32_t index, char *prop_name, uuid_t *uuid, size_t *len);
void ta_dead(void);
long ta_next_msg(void *msg_buf);
TEE_Result invoke_operation(void *teec_session, void *utee_params, uint32_t *ret_orig, uint32_t *uint_args);
TEE_Result close_session(void *teec_session);
TEE_Result set_cancel_flag(uuid_t *ta_uuid, uint32_t *sess_id);
bool get_cancel_flag(void);
bool mask_cancel_flag(void);
bool unmask_cancel_flag(void);
TEE_Result connect_to_sm(uint32_t *handle_id);
TEE_Result get_ta_flags(const uuid_t *dest_uuid, uint32_t *flags);
TEE_Result tee_wait(uint32_t timeout);
TEE_Result utee_cryp_state_alloc(unsigned long algo, unsigned long op_mode, unsigned long key1, unsigned long key2, uint32_t *state);
TEE_Result utee_cryp_state_copy(unsigned long dst, unsigned long src);
TEE_Result utee_cryp_state_free(unsigned long state);
TEE_Result utee_hash_init(unsigned long state, const void *iv, size_t iv_len);
TEE_Result utee_hash_update(unsigned long state, const void *chunk, size_t chunk_size);
TEE_Result utee_hash_final(unsigned long state, const void *chunk, size_t chunk_size, void *hash, uint64_t *hash_len);
TEE_Result utee_cipher_init(unsigned long state, const void *iv, size_t iv_len);
TEE_Result utee_cipher_update(unsigned long state, const void *src, size_t src_len, void *dest, uint64_t *dest_len);
TEE_Result utee_cipher_final(unsigned long state, const void *src, size_t src_len, void *dest, uint64_t *dest_len);
TEE_Result utee_cryp_obj_get_info(unsigned long obj, TEE_ObjectInfo *info);
TEE_Result utee_cryp_obj_restrict_usage(unsigned long obj, unsigned long usage);
TEE_Result utee_cryp_obj_get_attr(unsigned long obj, unsigned long attr_id, void *buffer, uint64_t *size);
TEE_Result utee_cryp_obj_alloc(unsigned long type, unsigned long max_size, uint32_t *obj);
TEE_Result utee_cryp_obj_close(unsigned long obj);
TEE_Result utee_cryp_obj_reset(unsigned long obj);
TEE_Result utee_cryp_obj_populate(unsigned long obj, struct utee_attribute *attrs, unsigned long attr_count);
TEE_Result utee_cryp_obj_copy(unsigned long dst_obj, unsigned long src_obj);
TEE_Result utee_cryp_obj_generate_key(unsigned long obj, unsigned long key_size, const struct utee_attribute *params, unsigned long param_count);
TEE_Result utee_cryp_derive_key(unsigned long state, const struct utee_attribute *params, unsigned long param_count, unsigned long derived_key);
TEE_Result utee_cryp_random_number_generate(void *buf, size_t blen);
TEE_Result utee_authenc_init(unsigned long state, const void *nonce, size_t nonce_len, size_t tag_len, size_t aad_len, size_t payload_len);
TEE_Result utee_authenc_update_aad(unsigned long state, const void *aad_data, size_t aad_data_len);
TEE_Result utee_authenc_update_payload(unsigned long state, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len);
TEE_Result utee_authenc_enc_final(unsigned long state, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len, void *tag, uint64_t *tag_len);
TEE_Result utee_authenc_dec_final(unsigned long state, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len, const void *tag, size_t tag_len);
TEE_Result utee_asymm_operate(unsigned long state, const struct utee_attribute *params, unsigned long num_params, const void *src_data, size_t src_len, void *dest_data, uint64_t *dest_len);
TEE_Result utee_asymm_verify(unsigned long state, const struct utee_attribute *params, unsigned long num_params, const void *data, size_t data_len, const void *sig, size_t sig_len);
TEE_Result utee_storage_obj_open(unsigned long storage_id, const void *object_id, size_t object_id_len, unsigned long flags, uint32_t *obj);
TEE_Result utee_storage_obj_create(unsigned long storage_id, const void *object_id, size_t object_id_len, unsigned long flags, unsigned long attr, const void *data, size_t len, uint32_t *obj);
TEE_Result utee_storage_obj_del(unsigned long obj);
TEE_Result utee_storage_obj_rename(unsigned long obj, const void *new_obj_id, size_t new_obj_id_len);
TEE_Result utee_storage_alloc_enum(uint32_t *obj_enum);
TEE_Result utee_storage_free_enum(unsigned long obj_enum);
TEE_Result utee_storage_reset_enum(unsigned long obj_enum);
TEE_Result utee_storage_start_enum(unsigned long obj_enum, unsigned long storage_id);
TEE_Result utee_storage_next_enum(unsigned long obj_enum, TEE_ObjectInfo *info, void *obj_id, uint64_t *len);
TEE_Result utee_storage_obj_read(unsigned long obj, void *data, size_t len, uint64_t *count);
TEE_Result utee_storage_obj_write(unsigned long obj, const void *data, size_t len);
TEE_Result utee_storage_obj_trunc(unsigned long obj, size_t len);
TEE_Result utee_storage_obj_seek(unsigned long obj, int32_t offset, unsigned long whence);

__END_CDECLS

#endif
