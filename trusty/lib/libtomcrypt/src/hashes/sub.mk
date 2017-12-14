srcs-$(CFG_CRYPTO_MD5) += md5.c

ifeq ($(CFG_CRYPTO_SHA1),y)
srcs-y += sha1.c
endif

subdirs-y += helper
subdirs-y += sha2
