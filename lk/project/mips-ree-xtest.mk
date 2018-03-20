LOCAL_DIR := $(GET_LOCAL_DIR)

include project/mips-trusty-svr.mk

GLOBAL_INCLUDES += app/ta/include

# set LK_DEBUGLEVEL
DEBUG = 1

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS +=

# compiled from source
TRUSTY_ALL_USER_TASKS += \
	ta/extra_ta/props \
	ta/extra_ta/core_test \
	ta/os_test \
	ta/create_fail_test \
	ta/sims \
	ta/concurrent \
	ta/multi_instance_memref \
	ta/bad_manifest \
	ta/client_ta \
	ta/siss \
	ta/crypt \
	ta/rpc_test \

# include addition xtest user tasks if they have been generated
-include app/xtest/xtest-user-tasks.generated.mk

#
# Modules to be compiled into lk.bin
#
