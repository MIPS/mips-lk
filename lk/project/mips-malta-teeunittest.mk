LOCAL_DIR := $(GET_LOCAL_DIR)

include project/target/mips-malta.mk
include project/virtual/trusty-gp-tee.mk

GLOBAL_INCLUDES += app/tee_unittest/include

# set LK_DEBUGLEVEL
DEBUG = 1

GLOBAL_DEFINES += WITH_TEE_MPA=0

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS +=

# compiled from source
TRUSTY_ALL_USER_TASKS += \
	tee_unittest \
	tee_unittest/ta/os_test \
	tee_unittest/ta/create_fail_test \
	tee_unittest/ta/sims \
	tee_unittest/ta/concurrent \

#
# Modules to be compiled into lk.bin
#
MODULES += app/shell \
