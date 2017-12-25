#
# Copyright (c) 2017-2018, MIPS Tech, LLC and/or its affiliated group companies
# (“MIPS”).
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/ciphers/aes/aes.c \
	$(LOCAL_DIR)/ciphers/des.c \
	$(LOCAL_DIR)/encauth/ccm/ccm_reset.c \
	$(LOCAL_DIR)/encauth/ccm/ccm_add_aad.c \
	$(LOCAL_DIR)/encauth/ccm/ccm_add_nonce.c \
	$(LOCAL_DIR)/encauth/ccm/ccm_done.c \
	$(LOCAL_DIR)/encauth/ccm/ccm_init.c \
	$(LOCAL_DIR)/encauth/ccm/ccm_process.c \
	$(LOCAL_DIR)/encauth/eax/eax_addheader.c \
	$(LOCAL_DIR)/encauth/eax/eax_decrypt.c \
	$(LOCAL_DIR)/encauth/eax/eax_decrypt_verify_memory.c \
	$(LOCAL_DIR)/encauth/eax/eax_done.c \
	$(LOCAL_DIR)/encauth/eax/eax_encrypt.c \
	$(LOCAL_DIR)/encauth/eax/eax_encrypt_authenticate_memory.c \
	$(LOCAL_DIR)/encauth/eax/eax_init.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_add_aad.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_add_iv.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_reset.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_done.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_init.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_memory.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_process.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_gf_mult.c \
	$(LOCAL_DIR)/encauth/gcm/gcm_mult_h.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_decrypt.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_decrypt_verify_memory.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_done_decrypt.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_done_encrypt.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_encrypt.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_encrypt_authenticate_memory.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_ntz.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_shift_xor.c \
	$(LOCAL_DIR)/encauth/ocb/s_ocb_done.c \
	$(LOCAL_DIR)/encauth/ocb/ocb_init.c \
	$(LOCAL_DIR)/hashes/helper/hash_memory.c \
	$(LOCAL_DIR)/hashes/helper/hash_memory_multi.c \
	$(LOCAL_DIR)/hashes/md5.c \
	$(LOCAL_DIR)/hashes/sha1.c \
	$(LOCAL_DIR)/hashes/sha2/sha256.c \
	$(LOCAL_DIR)/hashes/sha2/sha512_224.c \
	$(LOCAL_DIR)/hashes/sha2/sha512_256.c \
	$(LOCAL_DIR)/hashes/sha2/sha512.c \
	$(LOCAL_DIR)/hashes/sha2/sha224.c \
	$(LOCAL_DIR)/hashes/sha2/sha384.c \
	$(LOCAL_DIR)/mac/hmac/hmac_memory_multi.c \
	$(LOCAL_DIR)/mac/hmac/hmac_done.c \
	$(LOCAL_DIR)/mac/hmac/hmac_memory.c \
	$(LOCAL_DIR)/mac/hmac/hmac_process.c \
	$(LOCAL_DIR)/mac/hmac/hmac_init.c \
	$(LOCAL_DIR)/mac/omac/omac_memory_multi.c \
	$(LOCAL_DIR)/mac/omac/omac_done.c \
	$(LOCAL_DIR)/mac/omac/omac_init.c \
	$(LOCAL_DIR)/mac/omac/omac_memory.c \
	$(LOCAL_DIR)/mac/omac/omac_process.c \
	$(LOCAL_DIR)/mac/pmac/pmac_done.c \
	$(LOCAL_DIR)/mac/pmac/pmac_file.c \
	$(LOCAL_DIR)/mac/pmac/pmac_memory.c \
	$(LOCAL_DIR)/mac/pmac/pmac_memory_multi.c \
	$(LOCAL_DIR)/mac/pmac/pmac_ntz.c \
	$(LOCAL_DIR)/mac/pmac/pmac_process.c \
	$(LOCAL_DIR)/mac/pmac/pmac_shift_xor.c \
	$(LOCAL_DIR)/mac/pmac/pmac_init.c \
	$(LOCAL_DIR)/mac/xcbc/xcbc_done.c \
	$(LOCAL_DIR)/mac/xcbc/xcbc_file.c \
	$(LOCAL_DIR)/mac/xcbc/xcbc_init.c \
	$(LOCAL_DIR)/mac/xcbc/xcbc_memory.c \
	$(LOCAL_DIR)/mac/xcbc/xcbc_memory_multi.c \
	$(LOCAL_DIR)/mac/xcbc/xcbc_process.c \
	$(LOCAL_DIR)/math/fp/ltc_ecc_fp_mulmod.c \
	$(LOCAL_DIR)/math/multi.c \
	$(LOCAL_DIR)/math/gmp_desc.c \
	$(LOCAL_DIR)/math/ltm_desc.c \
	$(LOCAL_DIR)/math/rand_bn.c \
	$(LOCAL_DIR)/math/radix_to_bin.c \
	$(LOCAL_DIR)/math/rand_prime.c \
	$(LOCAL_DIR)/math/tfm_desc.c \
	$(LOCAL_DIR)/misc/base64/base64_decode.c \
	$(LOCAL_DIR)/misc/base64/base64_encode.c \
	$(LOCAL_DIR)/misc/crypt/crypt_cipher_descriptor.c \
	$(LOCAL_DIR)/misc/crypt/crypt_cipher_is_valid.c \
	$(LOCAL_DIR)/misc/crypt/crypt_constants.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_cipher.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_cipher_any.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_cipher_id.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_hash.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_hash_any.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_hash_id.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_hash_oid.c \
	$(LOCAL_DIR)/misc/crypt/crypt_hash_descriptor.c \
	$(LOCAL_DIR)/misc/crypt/crypt_hash_is_valid.c \
	$(LOCAL_DIR)/misc/crypt/crypt_inits.c \
	$(LOCAL_DIR)/misc/crypt/crypt_ltc_mp_descriptor.c \
	$(LOCAL_DIR)/misc/crypt/crypt_prng_descriptor.c \
	$(LOCAL_DIR)/misc/crypt/crypt_prng_is_valid.c \
	$(LOCAL_DIR)/misc/crypt/crypt_prng_rng_descriptor.c \
	$(LOCAL_DIR)/misc/crypt/crypt_register_all_ciphers.c \
	$(LOCAL_DIR)/misc/crypt/crypt_register_all_hashes.c \
	$(LOCAL_DIR)/misc/crypt/crypt_register_all_prngs.c \
	$(LOCAL_DIR)/misc/crypt/crypt_register_cipher.c \
	$(LOCAL_DIR)/misc/crypt/crypt_register_hash.c \
	$(LOCAL_DIR)/misc/crypt/crypt_register_prng.c \
	$(LOCAL_DIR)/misc/crypt/crypt_sizes.c \
	$(LOCAL_DIR)/misc/crypt/crypt_unregister_cipher.c \
	$(LOCAL_DIR)/misc/crypt/crypt_unregister_hash.c \
	$(LOCAL_DIR)/misc/crypt/crypt_unregister_prng.c \
	$(LOCAL_DIR)/misc/crypt/crypt.c \
	$(LOCAL_DIR)/misc/crypt/crypt_argchk.c \
	$(LOCAL_DIR)/misc/crypt/crypt_find_prng.c \
	$(LOCAL_DIR)/misc/crypt/crypt_fsa.c \
	$(LOCAL_DIR)/misc/mem_neq.c \
	$(LOCAL_DIR)/misc/burn_stack.c \
	$(LOCAL_DIR)/misc/compare_testvector.c \
	$(LOCAL_DIR)/misc/crc32.c \
	$(LOCAL_DIR)/misc/pkcs5/pkcs_5_1.c \
	$(LOCAL_DIR)/misc/pkcs5/pkcs_5_2.c \
	$(LOCAL_DIR)/misc/error_to_string.c \
	$(LOCAL_DIR)/misc/pk_get_oid.c \
	$(LOCAL_DIR)/misc/zeromem.c \
	$(LOCAL_DIR)/modes/cbc/cbc_getiv.c \
	$(LOCAL_DIR)/modes/cbc/cbc_setiv.c \
	$(LOCAL_DIR)/modes/cbc/cbc_decrypt.c \
	$(LOCAL_DIR)/modes/cbc/cbc_done.c \
	$(LOCAL_DIR)/modes/cbc/cbc_encrypt.c \
	$(LOCAL_DIR)/modes/cbc/cbc_start.c \
	$(LOCAL_DIR)/modes/cfb/cfb_decrypt.c \
	$(LOCAL_DIR)/modes/cfb/cfb_done.c \
	$(LOCAL_DIR)/modes/cfb/cfb_encrypt.c \
	$(LOCAL_DIR)/modes/cfb/cfb_getiv.c \
	$(LOCAL_DIR)/modes/cfb/cfb_setiv.c \
	$(LOCAL_DIR)/modes/cfb/cfb_start.c \
	$(LOCAL_DIR)/modes/ctr/ctr_decrypt.c \
	$(LOCAL_DIR)/modes/ctr/ctr_getiv.c \
	$(LOCAL_DIR)/modes/ctr/ctr_done.c \
	$(LOCAL_DIR)/modes/ctr/ctr_encrypt.c \
	$(LOCAL_DIR)/modes/ctr/ctr_setiv.c \
	$(LOCAL_DIR)/modes/ctr/ctr_start.c \
	$(LOCAL_DIR)/modes/ecb/ecb_decrypt.c \
	$(LOCAL_DIR)/modes/ecb/ecb_done.c \
	$(LOCAL_DIR)/modes/ecb/ecb_encrypt.c \
	$(LOCAL_DIR)/modes/ecb/ecb_start.c \
	$(LOCAL_DIR)/modes/f8/f8_decrypt.c \
	$(LOCAL_DIR)/modes/f8/f8_done.c \
	$(LOCAL_DIR)/modes/f8/f8_encrypt.c \
	$(LOCAL_DIR)/modes/f8/f8_getiv.c \
	$(LOCAL_DIR)/modes/f8/f8_setiv.c \
	$(LOCAL_DIR)/modes/f8/f8_start.c \
	$(LOCAL_DIR)/modes/lrw/lrw_decrypt.c \
	$(LOCAL_DIR)/modes/lrw/lrw_done.c \
	$(LOCAL_DIR)/modes/lrw/lrw_encrypt.c \
	$(LOCAL_DIR)/modes/lrw/lrw_getiv.c \
	$(LOCAL_DIR)/modes/lrw/lrw_process.c \
	$(LOCAL_DIR)/modes/lrw/lrw_setiv.c \
	$(LOCAL_DIR)/modes/lrw/lrw_start.c \
	$(LOCAL_DIR)/modes/ofb/ofb_decrypt.c \
	$(LOCAL_DIR)/modes/ofb/ofb_done.c \
	$(LOCAL_DIR)/modes/ofb/ofb_encrypt.c \
	$(LOCAL_DIR)/modes/ofb/ofb_getiv.c \
	$(LOCAL_DIR)/modes/ofb/ofb_setiv.c \
	$(LOCAL_DIR)/modes/ofb/ofb_start.c \
	$(LOCAL_DIR)/modes/xts/xts_mult_x.c \
	$(LOCAL_DIR)/modes/xts/xts_done.c \
	$(LOCAL_DIR)/modes/xts/xts_init.c \
	$(LOCAL_DIR)/modes/xts/xts_decrypt.c \
	$(LOCAL_DIR)/modes/xts/xts_encrypt.c \
	$(LOCAL_DIR)/pk/asn1/der/bit/der_decode_bit_string.c \
	$(LOCAL_DIR)/pk/asn1/der/bit/der_encode_bit_string.c \
	$(LOCAL_DIR)/pk/asn1/der/bit/der_length_bit_string.c \
	$(LOCAL_DIR)/pk/asn1/der/bit/der_decode_raw_bit_string.c \
	$(LOCAL_DIR)/pk/asn1/der/bit/der_encode_raw_bit_string.c \
	$(LOCAL_DIR)/pk/asn1/der/boolean/der_encode_boolean.c \
	$(LOCAL_DIR)/pk/asn1/der/boolean/der_length_boolean.c \
	$(LOCAL_DIR)/pk/asn1/der/boolean/der_decode_boolean.c \
	$(LOCAL_DIR)/pk/asn1/der/choice/der_decode_choice.c \
	$(LOCAL_DIR)/pk/asn1/der/generalizedtime/der_decode_generalizedtime.c \
	$(LOCAL_DIR)/pk/asn1/der/generalizedtime/der_encode_generalizedtime.c \
	$(LOCAL_DIR)/pk/asn1/der/generalizedtime/der_length_generalizedtime.c \
	$(LOCAL_DIR)/pk/asn1/der/ia5/der_decode_ia5_string.c \
	$(LOCAL_DIR)/pk/asn1/der/ia5/der_encode_ia5_string.c \
	$(LOCAL_DIR)/pk/asn1/der/ia5/der_length_ia5_string.c \
	$(LOCAL_DIR)/pk/asn1/der/integer/der_decode_integer.c \
	$(LOCAL_DIR)/pk/asn1/der/integer/der_encode_integer.c \
	$(LOCAL_DIR)/pk/asn1/der/integer/der_length_integer.c \
	$(LOCAL_DIR)/pk/asn1/der/object_identifier/der_decode_object_identifier.c \
	$(LOCAL_DIR)/pk/asn1/der/object_identifier/der_encode_object_identifier.c \
	$(LOCAL_DIR)/pk/asn1/der/object_identifier/der_length_object_identifier.c \
	$(LOCAL_DIR)/pk/asn1/der/octet/der_decode_octet_string.c \
	$(LOCAL_DIR)/pk/asn1/der/octet/der_encode_octet_string.c \
	$(LOCAL_DIR)/pk/asn1/der/octet/der_length_octet_string.c \
	$(LOCAL_DIR)/pk/asn1/der/printable_string/der_decode_printable_string.c \
	$(LOCAL_DIR)/pk/asn1/der/printable_string/der_encode_printable_string.c \
	$(LOCAL_DIR)/pk/asn1/der/printable_string/der_length_printable_string.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_decode_sequence_ex.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_decode_sequence_flexi.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_decode_sequence_multi.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_decode_subject_public_key_info.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_encode_sequence_ex.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_encode_sequence_multi.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_encode_subject_public_key_info.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_length_sequence.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_sequence_free.c \
	$(LOCAL_DIR)/pk/asn1/der/sequence/der_sequence_shrink.c \
	$(LOCAL_DIR)/pk/asn1/der/set/der_encode_set.c \
	$(LOCAL_DIR)/pk/asn1/der/set/der_encode_setof.c \
	$(LOCAL_DIR)/pk/asn1/der/short_integer/der_decode_short_integer.c \
	$(LOCAL_DIR)/pk/asn1/der/short_integer/der_encode_short_integer.c \
	$(LOCAL_DIR)/pk/asn1/der/short_integer/der_length_short_integer.c \
	$(LOCAL_DIR)/pk/asn1/der/utctime/der_decode_utctime.c \
	$(LOCAL_DIR)/pk/asn1/der/utctime/der_encode_utctime.c \
	$(LOCAL_DIR)/pk/asn1/der/utctime/der_length_utctime.c \
	$(LOCAL_DIR)/pk/asn1/der/utf8/der_decode_utf8_string.c \
	$(LOCAL_DIR)/pk/asn1/der/utf8/der_length_utf8_string.c \
	$(LOCAL_DIR)/pk/asn1/der/utf8/der_encode_utf8_string.c \
	$(LOCAL_DIR)/pk/asn1/der/teletex_string/der_decode_teletex_string.c \
	$(LOCAL_DIR)/pk/asn1/der/teletex_string/der_length_teletex_string.c \
	$(LOCAL_DIR)/pk/dh/dh.c \
	$(LOCAL_DIR)/pk/dh/dh_check_pubkey.c \
	$(LOCAL_DIR)/pk/dh/dh_export.c \
	$(LOCAL_DIR)/pk/dh/dh_export_key.c \
	$(LOCAL_DIR)/pk/dh/dh_free.c \
	$(LOCAL_DIR)/pk/dh/dh_generate_key.c \
	$(LOCAL_DIR)/pk/dh/dh_import.c \
	$(LOCAL_DIR)/pk/dh/dh_set.c \
	$(LOCAL_DIR)/pk/dh/dh_set_pg_dhparam.c \
	$(LOCAL_DIR)/pk/dh/dh_shared_secret.c \
	$(LOCAL_DIR)/pk/dsa/dsa_decrypt_key.c \
	$(LOCAL_DIR)/pk/dsa/dsa_encrypt_key.c \
	$(LOCAL_DIR)/pk/dsa/dsa_export.c \
	$(LOCAL_DIR)/pk/dsa/dsa_free.c \
	$(LOCAL_DIR)/pk/dsa/dsa_generate_key.c \
	$(LOCAL_DIR)/pk/dsa/dsa_generate_pqg.c \
	$(LOCAL_DIR)/pk/dsa/dsa_import.c \
	$(LOCAL_DIR)/pk/dsa/dsa_make_key.c \
	$(LOCAL_DIR)/pk/dsa/dsa_set.c \
	$(LOCAL_DIR)/pk/dsa/dsa_set_pqg_dsaparam.c \
	$(LOCAL_DIR)/pk/dsa/dsa_shared_secret.c \
	$(LOCAL_DIR)/pk/dsa/dsa_sign_hash.c \
	$(LOCAL_DIR)/pk/dsa/dsa_verify_hash.c \
	$(LOCAL_DIR)/pk/dsa/dsa_verify_key.c \
	$(LOCAL_DIR)/pk/ecc/ecc.c \
	$(LOCAL_DIR)/pk/ecc/ecc_free.c \
	$(LOCAL_DIR)/pk/ecc/ecc_shared_secret.c \
	$(LOCAL_DIR)/pk/ecc/ecc_sign_hash.c \
	$(LOCAL_DIR)/pk/ecc/ecc_verify_hash.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_is_valid_idx.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_map.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_mul2add.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_points.c \
	$(LOCAL_DIR)/pk/ecc/ecc_make_key.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_mulmod.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_mulmod_timing.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_projective_add_point.c \
	$(LOCAL_DIR)/pk/ecc/ltc_ecc_projective_dbl_point.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_i2osp.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_os2ip.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_mgf1.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_oaep_decode.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_oaep_encode.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_pss_decode.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_pss_encode.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_v1_5_decode.c \
	$(LOCAL_DIR)/pk/pkcs1/pkcs_1_v1_5_encode.c \
	$(LOCAL_DIR)/pk/rsa/rsa_free.c \
	$(LOCAL_DIR)/pk/rsa/rsa_decrypt_key.c \
	$(LOCAL_DIR)/pk/rsa/rsa_encrypt_key.c \
	$(LOCAL_DIR)/pk/rsa/rsa_export.c \
	$(LOCAL_DIR)/pk/rsa/rsa_import.c \
	$(LOCAL_DIR)/pk/rsa/rsa_make_key.c \
	$(LOCAL_DIR)/pk/rsa/rsa_sign_hash.c \
	$(LOCAL_DIR)/pk/rsa/rsa_verify_hash.c \
	$(LOCAL_DIR)/pk/rsa/rsa_exptmod.c \
	$(LOCAL_DIR)/prngs/fortuna.c \
	$(LOCAL_DIR)/prngs/rc4.c \
	$(LOCAL_DIR)/prngs/rng_make_prng.c \
	$(LOCAL_DIR)/prngs/rng_get_bytes.c \
	$(LOCAL_DIR)/prngs/sprng.c \
	$(LOCAL_DIR)/prngs/yarrow.c \

# excluded files
#	$(LOCAL_DIR)/encauth/ccm/ccm_memory.c \
#	$(LOCAL_DIR)/hashes/helper/hash_file.c \
#	$(LOCAL_DIR)/hashes/helper/hash_filehandle.c \
#	$(LOCAL_DIR)/mac/hmac/hmac_file.c \
#	$(LOCAL_DIR)/mac/omac/omac_file.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_ansi_x963_import.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_decrypt_key.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_encrypt_key.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_export.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_get_size.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_import.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_sizes.c \
#	$(LOCAL_DIR)/pk/ecc/ecc_ansi_x963_export.c \

LOCAL_DIR :=
