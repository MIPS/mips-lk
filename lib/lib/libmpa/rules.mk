LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_INCLUDES += $(LOCAL_DIR)/include

MODULE_CFLAGS := -Wno-sign-compare

MODULE_SRCS := \
	$(LOCAL_DIR)/mpa_addsub.c \
	$(LOCAL_DIR)/mpa_cmp.c \
	$(LOCAL_DIR)/mpa_conv.c \
	$(LOCAL_DIR)/mpa_div.c \
	$(LOCAL_DIR)/mpa_expmod.c \
	$(LOCAL_DIR)/mpa_gcd.c \
	$(LOCAL_DIR)/mpa_init.c \
	$(LOCAL_DIR)/mpa_io.c \
	$(LOCAL_DIR)/mpa_mem_static.c \
	$(LOCAL_DIR)/mpa_misc.c \
	$(LOCAL_DIR)/mpa_modulus.c \
	$(LOCAL_DIR)/mpa_montgomery.c \
	$(LOCAL_DIR)/mpa_mul.c \
	$(LOCAL_DIR)/mpa_primetable.h \
	$(LOCAL_DIR)/mpa_primetest.c \
	$(LOCAL_DIR)/mpa_random.c \
	$(LOCAL_DIR)/mpa_shift.c \

include $(LOCAL_DIR)/arch/$(ARCH)/rules.mk

include make/module.mk
