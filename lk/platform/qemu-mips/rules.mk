LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

ARCH := mips
MIPS_CPU := m14k
WITH_KERNEL_VM := 0

MODULE_DEPS += \
    lib/cbuf

MODULE_SRCS += \
	$(LOCAL_DIR)/debug.c \
	$(LOCAL_DIR)/intc.c \
	$(LOCAL_DIR)/platform.c

MEMSIZE ?= 0x01000000 # 16MB

MODULE_DEPS += \

LINKER_SCRIPT += \
	$(BUILDDIR)/linker.ld

include make/module.mk
