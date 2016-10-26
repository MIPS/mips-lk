LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

GLOBAL_INCLUDES := $(LOCAL_DIR)/include $(LKROOT)/include $(GLOBAL_INCLUDES)

MODULE_SRCS := \
	$(LOCAL_DIR)/tee_ta_interface.c \
	$(LOCAL_DIR)/tee_call_entrypoint.c \
	$(LOCAL_DIR)/tee_cancellations.c \
	$(LOCAL_DIR)/tee_internal_client_api.c \
	$(LOCAL_DIR)/tee_memory_api.c \
	$(LOCAL_DIR)/tee_panic_api.c \
	$(LOCAL_DIR)/tee_property_api.c \
	$(LOCAL_DIR)/tee_storage_api.c \
	$(LOCAL_DIR)/tee_crypto_api.c \
	$(LOCAL_DIR)/tee_time_api.c \
	$(LOCAL_DIR)/tee_arithmetic_api.c \

include make/module.mk
