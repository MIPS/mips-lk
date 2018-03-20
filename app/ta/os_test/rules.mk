#
# Copyright (C) 2014 The Android Open Source Project
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/manifest.c \
	$(LOCAL_DIR)/init.c \
	$(LOCAL_DIR)/os_test.c \
	$(LOCAL_DIR)/ta_entry.c \
	$(LOCAL_DIR)/tb_addsub.c \
	$(LOCAL_DIR)/tb_cmp.c \
	$(LOCAL_DIR)/tb_conv.c \
	$(LOCAL_DIR)/tb_div.c \
	$(LOCAL_DIR)/tb_fmm.c \
	$(LOCAL_DIR)/tb_gcd.c \
	$(LOCAL_DIR)/tb_io.c \
	$(LOCAL_DIR)/tb_modulus.c \
	$(LOCAL_DIR)/tb_mul.c \
	$(LOCAL_DIR)/tb_prime.c \
	$(LOCAL_DIR)/tb_shift.c \
	$(LOCAL_DIR)/tb_var.c \
	$(LOCAL_DIR)/test_float_subj.c \
	$(LOCAL_DIR)/testframework.c \

MODULE_DEPS += \
	app/trusty \
	lib/libc-trusty \
	lib/libutee \

include make/module.mk
