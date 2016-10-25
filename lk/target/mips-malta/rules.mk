LOCAL_DIR := $(GET_LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

GLOBAL_DEFINES += \
	WITH_MIPS_IRQCOMPAT_MODE=1

# optionally override default page size
ARCH_PAGE_SIZE := 0x4000 # 16K

PLATFORM := mips-malta

#include make/module.mk
