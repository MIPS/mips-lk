LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/virtio-console.c \

MODULE_DEPS += \
	dev/virtio \
	lib/bio


include make/module.mk
