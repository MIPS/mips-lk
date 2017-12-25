# Convert Makefile variables into .h preprocessor style definitions
# Requires checkconf.mk for cfg-vars-by-prefix()
#
# Example usage (by default the script will consider all CFG_*
# and _CFG_* variables plus PLATFORM_*):
#
# CFG_VARS := $(call set-defines-mk, CFG_CUSTOM _CUSTOM)
define set-defines-mk
	$(strip $(foreach var,				\
	$(call cfg-vars-by-prefix,$1),			\
	$(call cfg-make-define-macro,$(var))))
endef

# Convert a makefile variable to a preprocessor define
# <undefined>, n => <undefined>
# y              => 1
# <other value>  => <other value>
define cfg-make-define-macro
	$(strip $(if $(filter y,$($1)), $1=1,
			$(if $(filter xn x,x$($1)),
				"", $1=$($1))))
endef
