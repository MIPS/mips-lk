LOCAL_DIR := $(GET_LOCAL_DIR)

include project/target/mips-malta.mk
include project/virtual/trusty-gp-tee.mk

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS +=

# compiled from source
TRUSTY_ALL_USER_TASKS += \
	sample/ta_test_server \
	sample/ta_test_client \
	sample/ta_test_client2 \

#
# Modules to be compiled into lk.bin
#
MODULES += app/shell \
