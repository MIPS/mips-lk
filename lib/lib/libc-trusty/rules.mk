LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES := $(LOCAL_DIR)/include $(LKROOT)/include $(GLOBAL_INCLUDES)

MODULE_SRCS := \
	$(LOCAL_DIR)/abort.c \
	$(LOCAL_DIR)/assert.c \
	$(LOCAL_DIR)/atexit.c \
	$(LOCAL_DIR)/exit.c \
	$(LOCAL_DIR)/malloc.c \
	$(LOCAL_DIR)/libc_init.c \
	$(LOCAL_DIR)/libc_fatal.c \

ifeq (true,$(call TOBOOL,$(WITH_UPSTREAM_LK)))
WITH_LIBC_CUSTOM_MALLOC := 1
GLOBAL_DEFINES += WITH_LIBC_CUSTOM_MALLOC=$(WITH_LIBC_CUSTOM_MALLOC)

WITH_LIBC_CUSTOM_STDIO := 1
GLOBAL_DEFINES += WITH_LIBC_CUSTOM_STDIO=$(WITH_LIBC_CUSTOM_STDIO)
MODULE_SRCS += \
	$(LOCAL_DIR)/io.c \
	$(LOCAL_DIR)/stdio_upstream.c
else
WITH_CUSTOM_MALLOC := true

MODULE_SRCS += \
	$(LOCAL_DIR)/stdio.c
endif

include $(LOCAL_DIR)/arch/$(ARCH)/rules.mk

MODULE_DEPS := \
	lib/libc

include make/module.mk
