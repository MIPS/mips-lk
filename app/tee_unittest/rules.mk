#
# Copyright (C) 2016 Imagination Technologies Ltd.
#
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

GLOBAL_INCLUDES += $(LOCAL_DIR)/include

MODULE := $(LOCAL_DIR)

MODULE_DEFINES += WITH_RICH_OS=0

MODULE_SRCS += \
	$(LOCAL_DIR)/manifest.c \
	$(LOCAL_DIR)/tee_unittest.c \
	$(LOCAL_DIR)/teec_api.c \
	$(LOCAL_DIR)/test_helpers.c \
	$(LOCAL_DIR)/tests/tee_test_extra.c \
	$(LOCAL_DIR)/tests/tee_test_1000.c \

MODULE_DEPS += \
	app/trusty \
	lib/libc-trusty \
	lib/libutee \

include make/module.mk
