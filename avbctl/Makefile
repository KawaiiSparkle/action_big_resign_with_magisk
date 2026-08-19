# avbctl — static pie-avbtool-compatible AVB signer (fork of avb_mini_signer)
#
# Usage (from the repository root):   make -C avbctl
# Requirements: gcc + make + git (mbedtls-3.6 is fetched once into ./mbedtls;
# pre-vendor that directory to build fully offline).

CC      ?= gcc
CFLAGS  ?= -O2 -std=c99

MBEDTLS_DIR := mbedtls
MBEDTLS_SRC := aes.c asn1parse.c asn1write.c base64.c bignum.c bignum_core.c \
               bignum_mod.c bignum_mod_raw.c cipher.c cipher_wrap.c \
               constant_time.c md.c oid.c pem.c pk.c pkparse.c pk_wrap.c \
               platform.c platform_util.c rsa.c rsa_alt_helpers.c sha256.c \
               sha512.c

CONFIG_FLAGS := -Imbedtls-config \
                -DMBEDTLS_CONFIG_FILE='"avb_config.h"' \
                -DMBEDTLS_SHA512_C

all: avbctl

$(MBEDTLS_DIR)/library/sha512.c:
	git clone --depth 1 --branch mbedtls-3.6 \
		https://github.com/Mbed-TLS/mbedtls.git $(MBEDTLS_DIR)

libmbedcrypto.a: $(MBEDTLS_DIR)/library/sha512.c avbctl.c
	@set -e; mkdir -p .objs; \
	cd $(MBEDTLS_DIR)/library; \
	for f in $(MBEDTLS_SRC); do \
		echo "  CC mbedtls $$f"; \
		$(CC) -c -std=c99 -O2 -fPIC -fvisibility=hidden \
			-fdata-sections -ffunction-sections \
			-I../../$(MBEDTLS_DIR)/include \
			-I../../mbedtls-config \
			-DMBEDTLS_CONFIG_FILE='"avb_config.h"' \
			-DMBEDTLS_SHA512_C \
			"$$f" -o "../../.objs/$$f.o" || exit 1; \
	done; \
	ar rcs ../../libmbedcrypto.a ../../.objs/*.o; \
	echo "  AR libmbedcrypto.a"

avbctl: avbctl.c libmbedcrypto.a
	$(CC) $(CFLAGS) $(CONFIG_FLAGS) -I$(MBEDTLS_DIR)/include \
		avbctl.c libmbedcrypto.a -o avbctl
	@echo "built: avbctl/avbctl"

clean:
	rm -rf avbctl libmbedcrypto.a .objs

distclean: clean
	rm -rf $(MBEDTLS_DIR)

.PHONY: all clean distclean
