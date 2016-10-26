LOCAL_DIR := $(GET_LOCAL_DIR)

include project/target/mips-malta.mk
include project/virtual/trusty.mk

DEBUG ?= 2

# This project requires trusty IPC which in turn requires kernel VM
WITH_TRUSTY_IPC := 1
WITH_KERNEL_VM := 1

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS +=

# compiled from source
TRUSTY_ALL_USER_TASKS += \
	sample/ipc-unittest/main \
	sample/ipc-unittest/srv \
	sample/ipc-unittest/starter \
