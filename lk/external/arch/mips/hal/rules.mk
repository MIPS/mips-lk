LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/cache.S \
	$(LOCAL_DIR)/cache_ops.S \
	$(LOCAL_DIR)/m32cache.S \
	$(LOCAL_DIR)/m32cache_ops.S \
	$(LOCAL_DIR)/mips_l2size.S \
	$(LOCAL_DIR)/mips_cm3_l2size.S \
	$(LOCAL_DIR)/m32tlb_ops.S \
	$(LOCAL_DIR)/mxxtlb_ops.S

# provide default values normally provided by linker script
MODULE_SRCS += $(LOCAL_DIR)/../lk_defaults.c

# disable gp relative sdata accesses when hal built as a module
MODULE_COMPILEFLAGS += -G0

include make/module.mk
