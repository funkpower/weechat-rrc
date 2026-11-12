# weechat-rrc - Reticulum Relay Chat for WeeChat

PKG_CONFIG ?= pkg-config
CC ?= cc
VERSION := 0.1.0

WEECHAT_CFLAGS := $(shell $(PKG_CONFIG) --cflags weechat 2>/dev/null)
CRYPTO_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto)
CRYPTO_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto)

CFLAGS ?= -O2 -g
override CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -fPIC \
	-Wall -Wextra -Wno-unused-parameter -DRRC_CLIENT_VERSION=\"$(VERSION)\"

CORE := src/crypto.c src/cbor.c src/hdlc.c src/rns.c src/rrc.c src/micron.c
CORE_OBJ := $(CORE:.c=.o)

PLUGIN_DIR ?= $(HOME)/.local/share/weechat/plugins

all: rrc.so

src/plugin.o: src/plugin.c
	$(CC) $(CFLAGS) $(WEECHAT_CFLAGS) $(CRYPTO_CFLAGS) -c $< -o $@

src/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -c $< -o $@

rrc.so: $(CORE_OBJ) src/plugin.o
	$(CC) -shared -o $@ $^ $(LDFLAGS) $(CRYPTO_LIBS)

tests/test_unit: tests/test_unit.c tests/vectors.h $(CORE)
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -o $@ tests/test_unit.c $(CORE) $(CRYPTO_LIBS)

tests/rrc-cli: tests/rrc-cli.c $(CORE)
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -o $@ tests/rrc-cli.c $(CORE) $(CRYPTO_LIBS)

check: tests/test_unit
	./tests/test_unit

# Same tests under AddressSanitizer and UBSan.
check-asan:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
		LDFLAGS="-fsanitize=address,undefined" check
	$(MAKE) clean

install: rrc.so
	install -d $(PLUGIN_DIR)
	install -m 0644 rrc.so $(PLUGIN_DIR)/rrc.so

clean:
	rm -f src/*.o rrc.so tests/test_unit tests/rrc-cli tests/fuzz

.PHONY: all check check-asan install clean

tests/fuzz: tests/fuzz.c tests/vectors.h $(CORE)
	$(CC) $(CFLAGS) $(CRYPTO_CFLAGS) -o $@ tests/fuzz.c $(CORE) $(CRYPTO_LIBS)

fuzz:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" tests/fuzz
	./tests/fuzz 300000
	$(MAKE) clean

.PHONY: fuzz
