LOCAL_DIR := $(GET_LOCAL_DIR)

MODULE := $(LOCAL_DIR)

MODULE_SRCS += \
	$(LOCAL_DIR)/arch.c \
	$(LOCAL_DIR)/asm.S \
	$(LOCAL_DIR)/exceptions.c \
	$(LOCAL_DIR)/start.S \
	$(LOCAL_DIR)/thread.c \
	$(LOCAL_DIR)/timer.c \
	$(LOCAL_DIR)/vectors.S \
	$(LOCAL_DIR)/cache.c \
	$(LOCAL_DIR)/mmu.c \
	$(LOCAL_DIR)/tlb.c \

MODULE_DEPS += \
	arch/mips/hal

GLOBAL_DEFINES += \
	SMP_MAX_CPUS=1

# set the default toolchain to microblaze elf and set a #define
ifndef TOOLCHAIN_PREFIX
TOOLCHAIN_PREFIX := mips-elf-
endif

WITH_LINKER_GC ?= 0
LITTLE_ENDIAN ?= 0

ifneq ($(LITTLE_ENDIAN),0)
GLOBAL_COMPILEFLAGS += -EL
GLOBAL_ASFLAGS += -EL
GLOBAL_LDFLAGS += -EL
GLOBAL_MODULE_LDFLAGS += -EL
endif

ARCH_COMPILEFLAGS := -mno-gpopt
ARCH_OPTFLAGS := -O2

ifeq ($(MIPS_CPU),m14k)
ARCH_COMPILEFLAGS += -march=m14k
endif
ifeq ($(MIPS_CPU),microaptiv-uc)
ARCH_COMPILEFLAGS += -march=m14k
endif
ifeq ($(MIPS_CPU),mips32r2)
ARCH_COMPILEFLAGS += -march=mips32r2
endif

LIBGCC := $(shell $(TOOLCHAIN_PREFIX)gcc $(GLOBAL_COMPILEFLAGS) $(ARCH_COMPILEFLAGS) $(GLOBAL_CFLAGS) -print-libgcc-file-name)
$(info LIBGCC = $(LIBGCC))

cc-option = $(shell if test -z "`$(1) $(2) -S -o /dev/null -xc /dev/null 2>&1`"; \
	then echo "$(2)"; else echo "$(3)"; fi ;)

# we have a mmu and want the vmm/pmm
WITH_KERNEL_VM ?= 1

ifeq ($(WITH_KERNEL_VM),1)
GLOBAL_DEFINES += \
    KERNEL_ASPACE_BASE=0x80000000 \
    KERNEL_ASPACE_SIZE=0x80000000 \
    USER_ASPACE_BASE=0 \
    USER_ASPACE_SIZE=0x80000000
endif

MEMBASE ?= 0
KERNEL_BASE ?= 0x80000000
KERNEL_LOAD_OFFSET ?= 0
VECTOR_BASE_PHYS ?= 0

GLOBAL_DEFINES += \
    MEMBASE=$(MEMBASE) \
    MEMSIZE=$(MEMSIZE) \
    KERNEL_BASE=$(KERNEL_BASE) \
    KERNEL_LOAD_OFFSET=$(KERNEL_LOAD_OFFSET)

ifneq ($(ARCH_PAGE_SIZE),)
GLOBAL_DEFINES += \
    ARCH_PAGE_SIZE=$(ARCH_PAGE_SIZE)
endif

# potentially generated files that should be cleaned out with clean make rule
GENERATED += \
	$(BUILDDIR)/linker.ld \
	$(BUILDDIR)/linker-malta.ld

# rules for generating the linker
$(BUILDDIR)/linker.ld: $(LOCAL_DIR)/linker.ld $(wildcard arch/*.ld) linkerscript.phony
	@echo generating $@
	@$(MKDIR)
	$(NOECHO)sed "s/%MEMBASE%/$(MEMBASE)/;s/%MEMSIZE%/$(MEMSIZE)/;s/%KERNEL_BASE%/$(KERNEL_BASE)/;s/%KERNEL_LOAD_OFFSET%/$(KERNEL_LOAD_OFFSET)/;s/%VECTOR_BASE_PHYS%/$(VECTOR_BASE_PHYS)/" < $< > $@.tmp
	@$(call TESTANDREPLACEFILE,$@.tmp,$@)

$(BUILDDIR)/linker-malta.ld: $(LOCAL_DIR)/linker-malta.ld $(wildcard arch/*.ld) linkerscript.phony
	@echo generating $@
	@$(MKDIR)
	$(NOECHO)sed "s/%MEMBASE%/$(MEMBASE)/;s/%MEMSIZE%/$(MEMSIZE)/;s/%KERNEL_BASE%/$(KERNEL_BASE)/;s/%KERNEL_LOAD_OFFSET%/$(KERNEL_LOAD_OFFSET)/;s/%VECTOR_BASE_PHYS%/$(VECTOR_BASE_PHYS)/" < $< > $@.tmp
	@$(call TESTANDREPLACEFILE,$@.tmp,$@)

linkerscript.phony:
.PHONY: linkerscript.phony

include make/module.mk
