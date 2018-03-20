include project/target/mips-virt.mk
include project/virtual/trusty-gp-tee.mk

DEBUG ?= 2

TRUSTY_PREBUILT_USER_TASKS +=

TRUSTY_ALL_USER_TASKS += \
	ta/sample/ta_test_server \
	ta/sample/ta_test_client \
	ta/sample/ta_test_client2

#
# Modules to be compiled into lk.bin
#
MODULES += app/shell
