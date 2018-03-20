LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

ARCH := mips
MIPS_CPU := mips32r2
TOOLCHAIN_PREFIX := mips-mti-elf-
LITTLE_ENDIAN := 1

MODULE_DEPS += \
    lib/cbuf \
    lib/fdt \
    dev/virtio/console

MODULE_SRCS += \
	$(LOCAL_DIR)/debug.c \
	$(LOCAL_DIR)/gic.c \
	$(LOCAL_DIR)/fdt.c \
	$(LOCAL_DIR)/platform.c

MEMSIZE ?= 0x01000000 # 16MB
KERNEL_LOAD_OFFSET ?= 0x10000 # skip QEMU malta bootloader ENVP @ 0x2000, boot-cps SMP cpu_launch @0xf00

GLOBAL_COMPILEFLAGS += -DWITH_DEV_VIRTIO_CONSOLE -DVIRTIO_MMIO_SPACING=0x4000

LINKER_SCRIPT += \
	$(BUILDDIR)/linker-malta.ld

include make/module.mk
