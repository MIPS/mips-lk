srcs-$(CFG_CRYPTO_SHA224) += sha224.c

# SHA-224 needs SHA-256
SHA256 := $(call cfg-one-enabled, CFG_CRYPTO_SHA224 CFG_CRYPTO_SHA256)
ifeq ($(SHA256),y)
srcs-y += sha256.c
endif

srcs-$(CFG_CRYPTO_SHA384) += sha384.c
srcs-$(CFG_CRYPTO_SHA512) += sha512_224.c
srcs-$(CFG_CRYPTO_SHA512) += sha512_256.c
srcs-$(CFG_CRYPTO_SHA512) += sha512.c
