LOCAL_DIR := $(GET_LOCAL_DIR)

include project/virtual/userlib.mk

DEBUG ?= 2

TARGET := mips-malta

#
# user tasks to be compiled into lk.bin
#

# prebuilt
TRUSTY_PREBUILT_USER_TASKS :=

# compiled from source
TRUSTY_ALL_USER_TASKS := \
	sample/skel \
	sample/skel2\
	sample/timer\
	sample/usertest\

MODULES += app/shell \
		   app/clonetest \
