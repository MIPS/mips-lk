LOCAL_DIR := $(GET_LOCAL_DIR)

GLOBAL_INCLUDES += \
	$(LOCAL_DIR)/include \

MODULE_SRCS += \
	$(LOCAL_DIR)/trusty_syscall.S \
	$(LOCAL_DIR)/setjmp.S

FIRST_OBJ := $(BUILDDIR)/crtbegin.o
LAST_OBJ  := $(BUILDDIR)/crtend.o

$(FIRST_OBJ): $(LOCAL_DIR)/crtbegin.c $(CONFIGHEADER)
	@$(MKDIR)
	@echo compiling $<
	$(NOECHO)$(CC) $(GLOBAL_COMPILEFLAGS) $(GLOBAL_CFLAGS) $(GLOBAL_INCLUDES) $(ARCH_COMPILEFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

$(LAST_OBJ): $(LOCAL_DIR)/crtend.S $(CONFIGHEADER)
	@$(MKDIR)
	@echo compiling $<
	$(NOECHO)$(CC) $(GLOBAL_COMPILEFLAGS) $(GLOBAL_ASMFLAGS) $(GLOBAL_INCLUDES) $(ARCH_COMPILEFLAGS) -c $< -MD -MT $@ -MF $(@:%o=%d) -o $@

ALLMODULE_OBJS += $(FIRST_OBJ) $(LAST_OBJ)

FIRST_OBJ :=
LAST_OBJ  :=
