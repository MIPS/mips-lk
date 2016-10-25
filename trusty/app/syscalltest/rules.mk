LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES += \
	$(LOCAL_DIR)/. \

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/. \

MODULE_SRCS += \
	$(LOCAL_DIR)/syscalltest.c \
	$(LOCAL_DIR)/generated_syscalls.S \

MODULE_DEPS += \
	lib/uthread \
	lib/syscall \

GLOBAL_DEFINES += \
	WITH_SYSCALL_TABLE=1 \

# to generate syscall header and assembly stubs:
# ../../lib/syscall/stubgen/stubgen.py -d generated_syscalls.h -s generated_syscalls.S -a <ARCH> syscall_table.h

include make/module.mk
