#
# Copyright (c) 2016-2018, MIPS Tech, LLC and/or its affiliated group companies
# (“MIPS”).
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

MODULE_SRCS += \
	$(LOCAL_DIR)/tee_ta_properties.c \
	$(LOCAL_DIR)/tee_ta_manager.c \
	$(LOCAL_DIR)/tee_ta_core.c \
	$(LOCAL_DIR)/tee_api.c \
	$(LOCAL_DIR)/tee_mmu.c \
	$(LOCAL_DIR)/tee_obj.c \
	$(LOCAL_DIR)/tee_pobj.c \
	$(LOCAL_DIR)/tee_svc.c \
	$(LOCAL_DIR)/tee_svc_cryp.c \
	$(LOCAL_DIR)/tee_cryp_concat_kdf.c \
	$(LOCAL_DIR)/tee_cryp_hkdf.c \
	$(LOCAL_DIR)/tee_cryp_pbkdf2.c \
	$(LOCAL_DIR)/tee_cryp_utl.c \

	# TODO NOT_YET
	#$(LOCAL_DIR)/tee_svc_storage.c \

MODULE_DEPS += \
	lib/trusty \
	lib/syscall \
	lib/uthread \
	lib/libutils \
	lib/libtomcrypt \

include make/module.mk
