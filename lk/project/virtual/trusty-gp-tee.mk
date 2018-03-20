LOCAL_DIR := $(GET_LOCAL_DIR)

include project/virtual/trusty.mk

WITH_TRUSTY_IPC := 1
WITH_KERNEL_VM := 1

ifeq (true,$(call TOBOOL,$(WITH_VIRTIO_VIODEV_SUPPORT)))
# enable tipc virtio device connection to REE
WITH_TRUSTY_TIPC_DEV := 1
endif

GLOBAL_DEFINES += APIVERSION=\"1.1\"
GLOBAL_DEFINES += DESCRIPTION=\"123\"
GLOBAL_DEFINES += MANUFACTURER=\"IMGTec\"
GLOBAL_DEFINES += TEE_SYSTIME_PROTECT_LVL=1000
GLOBAL_DEFINES += TEE_PERSTIME_PROTECT_LVL=1000
GLOBAL_DEFINES += TEE_DEVICE_UUID=ZERO_UUID
GLOBAL_DEFINES += TEE_TS_ANTIRB_PROT_LVL=0
GLOBAL_DEFINES += TEE_FW_VERSION=\"0.0\"
GLOBAL_DEFINES += TEE_FW_BINVERSION=\"0000\"
GLOBAL_DEFINES += TEE_FW_MANUFACTURER=\"MIPS\"

# Generate gpd.tee.trustedos.implementation.version and
# gpd.tee.trustedos.implementation.binaryversion
TEE_VERSION=$(shell git describe --always --dirty=-dev 2>/dev/null || echo Unknown)
TEE_BINVERSION=$(shell echo ${TEE_VERSION} | base64)
GLOBAL_DEFINES += TEE_VERSION=\"${TEE_VERSION}\"
GLOBAL_DEFINES += TEE_BINVERSION=\"${TEE_BINVERSION}\"

UTHREAD_WITH_MEMORY_MAPPING_SUPPORT := 1
GLOBAL_DEFINES += \
    UTHREAD_WITH_MEMORY_MAPPING_SUPPORT=$(UTHREAD_WITH_MEMORY_MAPPING_SUPPORT)

#
# Modules to be compiled into lk.bin
#
MODULES += \
	lib/tee \

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS +=

# compiled from source
TRUSTY_ALL_USER_TASKS += \
	tee/sess_mngr \
