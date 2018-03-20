LOCAL_DIR := $(GET_LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include

GLOBAL_DEFINES += \
	WITH_MIPS_IRQCOMPAT_MODE=1 \
	WITH_VIRTIO_ROOT_CONSOLE

# optionally override default page size
ARCH_PAGE_SIZE := 0x4000 # 16K

PLATFORM := mips-virt

#include make/module.mk
