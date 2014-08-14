# top level project rules for the zybo-test project
#
LOCAL_DIR := $(GET_LOCAL_DIR)

MODULES += \
	app/zybo-common \
	app/inetsrv \
	app/tests \
	app/stringtests \
	app/shell \
	app/lkboot \
	lib/cksum \
	lib/debugcommands \
	lib/libm \

GLOBAL_DEFINES += \
	SYSPARAM_ALLOW_WRITE=1

include $(LOCAL_DIR)/zybo.mk

