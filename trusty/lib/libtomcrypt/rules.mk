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

MODULE_INCLUDES := $(LOCAL_DIR)/include

MODULE_CFLAGS += -DLTC_SOURCE

MODULE_SRCS += \
	$(LOCAL_DIR)/src/mpa_desc.c \
	$(LOCAL_DIR)/src/tee_ltc_provider.c \

MODULE_DEPS += lib/libmpa

# PRNG configuration
# If CFG_WITH_SOFTWARE_PRNG is enabled, crypto provider provided
# software PRNG implementation is used.
# Otherwise, you need to implement hw_get_random_byte() for your platform
CFG_WITH_SOFTWARE_PRNG ?= y

# use checkconf.mk to evaluate CFG_CRYPTO_* dependencies
# and enable select crypto src/ subsystems
include $(LOCAL_DIR)/checkconf.mk
include $(LOCAL_DIR)/sub.mk

# convert CFG_* makefile variables set by sub.mk into GLOBAL_DEFINES
include $(LOCAL_DIR)/setconf.mk
GLOBAL_DEFINES += $(call set-defines-mk, CFG_ _CFG_)

# make crypto src/ subsystems
include $(LOCAL_DIR)/src/rules.mk

include make/module.mk
