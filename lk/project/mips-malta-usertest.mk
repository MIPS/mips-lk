LOCAL_DIR := $(GET_LOCAL_DIR)

include project/target/mips-malta.mk
include project/virtual/trusty.mk

DEBUG ?= 2

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS +=

# compiled from source
TRUSTY_ALL_USER_TASKS += \
	sample/usertest/fatal_mips_001 \
	sample/usertest/fatal_mips_002 \
	sample/usertest/fatal_mips_003 \
	sample/usertest/fatal_mips_004 \
	sample/usertest/fatal_mips_005 \
	sample/usertest/fatal_mips_006 \
	sample/usertest/fatal_mips_007 \
	sample/usertest \

MODULES += app/shell \
           app/tests
