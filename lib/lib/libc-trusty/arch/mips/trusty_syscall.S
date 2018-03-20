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

#include <asm.h>
#include <trusty_syscalls.h>

.section .text.write
FUNCTION(write)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_write
    syscall
    j       $ra
      nop

.section .text.brk
FUNCTION(brk)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_brk
    syscall
    j       $ra
      nop

.section .text.exit_group
FUNCTION(exit_group)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_exit_group
    syscall
    j       $ra
      nop

.section .text.read
FUNCTION(read)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_read
    syscall
    j       $ra
      nop

.section .text.ioctl
FUNCTION(ioctl)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_ioctl
    syscall
    j       $ra
      nop

.section .text.nanosleep
FUNCTION(nanosleep)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_nanosleep
    syscall
    j       $ra
      nop

.section .text.gettime
FUNCTION(gettime)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_gettime
    syscall
    j       $ra
      nop

.section .text.mmap
FUNCTION(mmap)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_mmap
    syscall
    j       $ra
      nop

.section .text.munmap
FUNCTION(munmap)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_munmap
    syscall
    j       $ra
      nop

.section .text.prepare_dma
FUNCTION(prepare_dma)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_prepare_dma
    syscall
    j       $ra
      nop

.section .text.finish_dma
FUNCTION(finish_dma)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_finish_dma
    syscall
    j       $ra
      nop

.section .text.port_create
FUNCTION(port_create)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_port_create
    syscall
    j       $ra
      nop

.section .text.connect
FUNCTION(connect)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_connect
    syscall
    j       $ra
      nop

.section .text.accept
FUNCTION(accept)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_accept
    syscall
    j       $ra
      nop

.section .text.close
FUNCTION(close)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_close
    syscall
    j       $ra
      nop

.section .text.set_cookie
FUNCTION(set_cookie)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_set_cookie
    syscall
    j       $ra
      nop

.section .text.wait
FUNCTION(wait)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_wait
    syscall
    j       $ra
      nop

.section .text.wait_any
FUNCTION(wait_any)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_wait_any
    syscall
    j       $ra
      nop

.section .text.get_msg
FUNCTION(get_msg)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_msg
    syscall
    j       $ra
      nop

.section .text.read_msg
FUNCTION(read_msg)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_read_msg
    syscall
    j       $ra
      nop

.section .text.put_msg
FUNCTION(put_msg)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_put_msg
    syscall
    j       $ra
      nop

.section .text.send_msg
FUNCTION(send_msg)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_send_msg
    syscall
    j       $ra
      nop

.section .text.set_panic_handler
FUNCTION(set_panic_handler)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_set_panic_handler
    syscall
    j       $ra
      nop

.section .text.check_access_rights
FUNCTION(check_access_rights)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_check_access_rights
    syscall
    j       $ra
      nop

.section .text.connect_to_ta
FUNCTION(connect_to_ta)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_connect_to_ta
    syscall
    j       $ra
      nop

.section .text.get_kprops
FUNCTION(get_kprops)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_kprops
    syscall
    j       $ra
      nop

.section .text.get_ta_client_props
FUNCTION(get_ta_client_props)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_ta_client_props
    syscall
    j       $ra
      nop

.section .text.get_props_num
FUNCTION(get_props_num)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_props_num
    syscall
    j       $ra
      nop

.section .text.get_prop_name
FUNCTION(get_prop_name)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_prop_name
    syscall
    j       $ra
      nop

.section .text.ta_dead
FUNCTION(ta_dead)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_ta_dead
    syscall
    j       $ra
      nop

.section .text.ta_next_msg
FUNCTION(ta_next_msg)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_ta_next_msg
    syscall
    j       $ra
      nop

.section .text.invoke_operation
FUNCTION(invoke_operation)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_invoke_operation
    syscall
    j       $ra
      nop

.section .text.close_session
FUNCTION(close_session)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_close_session
    syscall
    j       $ra
      nop

.section .text.set_cancel_flag
FUNCTION(set_cancel_flag)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_set_cancel_flag
    syscall
    j       $ra
      nop

.section .text.get_cancel_flag
FUNCTION(get_cancel_flag)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_cancel_flag
    syscall
    j       $ra
      nop

.section .text.mask_cancel_flag
FUNCTION(mask_cancel_flag)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_mask_cancel_flag
    syscall
    j       $ra
      nop

.section .text.unmask_cancel_flag
FUNCTION(unmask_cancel_flag)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_unmask_cancel_flag
    syscall
    j       $ra
      nop

.section .text.connect_to_sm
FUNCTION(connect_to_sm)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_connect_to_sm
    syscall
    j       $ra
      nop

.section .text.get_ta_flags
FUNCTION(get_ta_flags)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_get_ta_flags
    syscall
    j       $ra
      nop

.section .text.tee_wait
FUNCTION(tee_wait)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_tee_wait
    syscall
    j       $ra
      nop

.section .text.utee_cryp_state_alloc
FUNCTION(utee_cryp_state_alloc)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_state_alloc
    syscall
    j       $ra
      nop

.section .text.utee_cryp_state_copy
FUNCTION(utee_cryp_state_copy)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_state_copy
    syscall
    j       $ra
      nop

.section .text.utee_cryp_state_free
FUNCTION(utee_cryp_state_free)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_state_free
    syscall
    j       $ra
      nop

.section .text.utee_hash_init
FUNCTION(utee_hash_init)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_hash_init
    syscall
    j       $ra
      nop

.section .text.utee_hash_update
FUNCTION(utee_hash_update)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_hash_update
    syscall
    j       $ra
      nop

.section .text.utee_hash_final
FUNCTION(utee_hash_final)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_hash_final
    syscall
    j       $ra
      nop

.section .text.utee_cipher_init
FUNCTION(utee_cipher_init)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cipher_init
    syscall
    j       $ra
      nop

.section .text.utee_cipher_update
FUNCTION(utee_cipher_update)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cipher_update
    syscall
    j       $ra
      nop

.section .text.utee_cipher_final
FUNCTION(utee_cipher_final)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cipher_final
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_get_info
FUNCTION(utee_cryp_obj_get_info)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_get_info
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_restrict_usage
FUNCTION(utee_cryp_obj_restrict_usage)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_restrict_usage
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_get_attr
FUNCTION(utee_cryp_obj_get_attr)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_get_attr
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_alloc
FUNCTION(utee_cryp_obj_alloc)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_alloc
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_close
FUNCTION(utee_cryp_obj_close)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_close
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_reset
FUNCTION(utee_cryp_obj_reset)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_reset
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_populate
FUNCTION(utee_cryp_obj_populate)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_populate
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_copy
FUNCTION(utee_cryp_obj_copy)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_copy
    syscall
    j       $ra
      nop

.section .text.utee_cryp_obj_generate_key
FUNCTION(utee_cryp_obj_generate_key)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_obj_generate_key
    syscall
    j       $ra
      nop

.section .text.utee_cryp_derive_key
FUNCTION(utee_cryp_derive_key)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_derive_key
    syscall
    j       $ra
      nop

.section .text.utee_cryp_random_number_generate
FUNCTION(utee_cryp_random_number_generate)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_cryp_random_number_generate
    syscall
    j       $ra
      nop

.section .text.utee_authenc_init
FUNCTION(utee_authenc_init)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_authenc_init
    syscall
    j       $ra
      nop

.section .text.utee_authenc_update_aad
FUNCTION(utee_authenc_update_aad)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_authenc_update_aad
    syscall
    j       $ra
      nop

.section .text.utee_authenc_update_payload
FUNCTION(utee_authenc_update_payload)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_authenc_update_payload
    syscall
    j       $ra
      nop

.section .text.utee_authenc_enc_final
FUNCTION(utee_authenc_enc_final)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_authenc_enc_final
    syscall
    j       $ra
      nop

.section .text.utee_authenc_dec_final
FUNCTION(utee_authenc_dec_final)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_authenc_dec_final
    syscall
    j       $ra
      nop

.section .text.utee_asymm_operate
FUNCTION(utee_asymm_operate)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_asymm_operate
    syscall
    j       $ra
      nop

.section .text.utee_asymm_verify
FUNCTION(utee_asymm_verify)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_asymm_verify
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_open
FUNCTION(utee_storage_obj_open)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_open
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_create
FUNCTION(utee_storage_obj_create)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_create
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_del
FUNCTION(utee_storage_obj_del)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_del
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_rename
FUNCTION(utee_storage_obj_rename)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_rename
    syscall
    j       $ra
      nop

.section .text.utee_storage_alloc_enum
FUNCTION(utee_storage_alloc_enum)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_alloc_enum
    syscall
    j       $ra
      nop

.section .text.utee_storage_free_enum
FUNCTION(utee_storage_free_enum)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_free_enum
    syscall
    j       $ra
      nop

.section .text.utee_storage_reset_enum
FUNCTION(utee_storage_reset_enum)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_reset_enum
    syscall
    j       $ra
      nop

.section .text.utee_storage_start_enum
FUNCTION(utee_storage_start_enum)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_start_enum
    syscall
    j       $ra
      nop

.section .text.utee_storage_next_enum
FUNCTION(utee_storage_next_enum)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_next_enum
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_read
FUNCTION(utee_storage_obj_read)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_read
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_write
FUNCTION(utee_storage_obj_write)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_write
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_trunc
FUNCTION(utee_storage_obj_trunc)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_trunc
    syscall
    j       $ra
      nop

.section .text.utee_storage_obj_seek
FUNCTION(utee_storage_obj_seek)
    lw      $t0, 16($sp)
    lw      $t1, 20($sp)
    lw      $t2, 24($sp)
    lw      $t3, 28($sp)
    li      $v0, __NR_utee_storage_obj_seek
    syscall
    j       $ra
      nop
