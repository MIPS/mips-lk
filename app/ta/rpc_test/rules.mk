LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES += $(LOCAL_DIR)/../crypt/include \
MODULE_INCLUDES += $(LOCAL_DIR)/../sims/include \

MODULE_SRCS += \
	$(LOCAL_DIR)/manifest.c \
	$(LOCAL_DIR)/ta_entry.c \
	$(LOCAL_DIR)/ta_rpc.c \

MODULE_DEPS += \
	app/trusty \
	lib/libc-trusty \
	lib/libutee \

include make/module.mk
