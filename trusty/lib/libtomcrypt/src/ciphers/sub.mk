cflags-y += -Wno-unused-parameter

subdirs-$(CFG_CRYPTO_AES) += aes
srcs-$(CFG_CRYPTO_DES) += des.c
