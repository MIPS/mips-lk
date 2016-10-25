ifndef ARCH_mips_TOOLCHAIN_INCLUDED
ARCH_mips_TOOLCHAIN_INCLUDED := 1

# try to find the toolchain
ifndef ARCH_mips_TOOLCHAIN_PREFIX

# if TOOLCHAIN_PREFIX is not empty, try to use it first
ifneq ($(TOOLCHAIN_PREFIX),)
ARCH_mips_TOOLCHAIN_PREFIX := $(TOOLCHAIN_PREFIX)
FOUNDTOOL=$(shell which $(ARCH_mips_TOOLCHAIN_PREFIX)gcc)
endif

else
FOUNDTOOL=$(shell which $(ARCH_mips_TOOLCHAIN_PREFIX)gcc)
endif # ARCH_mips_TOOLCHAIN_PREFIX

ifeq ($(FOUNDTOOL),)
$(error cannot find toolchain, please set ARCH_mips_TOOLCHAIN_PREFIX or add it to your path)
endif

endif
