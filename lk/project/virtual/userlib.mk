# common defines for building apps running in user space

#
# GLOBAL definitions
#

# requires linker GC
WITH_LINKER_GC := 1
GLOBAL_DEFINES += WITH_LINKER_GC=$(WITH_LINKER_GC)

# use LK from upstream rather than trusty's external/lk
WITH_UPSTREAM_LK := 1
GLOBAL_DEFINES += WITH_UPSTREAM_LK=$(WITH_UPSTREAM_LK)

# limit heap grows
GLOBAL_DEFINES += HEAP_GROW_SIZE=65536

#
# Modules to be compiled into lk.bin
#
MODULES += \
	lib/trusty \

TRUSTY_USER_ARCH := mips

EXTRA_BUILDRULES += app/trusty/user-tasks.mk
