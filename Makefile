# weechat-rrc - Reticulum Relay Chat for WeeChat

PKG_CONFIG ?= pkg-config
CC ?= cc
VERSION := 0.1.0

WEECHAT_CFLAGS := $(shell $(PKG_CONFIG) --cflags weechat 2>/dev/null)
# WeeChat only loads a plugin built against its own plugin API, so a new
# weechat-plugin.h (a WeeChat upgrade) has to rebuild the plugin
WEECHAT_HEADER := $(firstword $(wildcard $(patsubst -I%,%/weechat-plugin.h,$(filter -I%,$(WEECHAT_CFLAGS))) /usr/include/weechat/weechat-plugin.h))
CRYPTO_CFLAGS := $(shell $(PKG_CONFIG) --cflags libcrypto)
CRYPTO_LIBS := $(shell $(PKG_CONFIG) --libs libcrypto)
# libbz2 ships a .pc file on some distributions only
BZ2_CFLAGS := $(shell $(PKG_CONFIG) --cflags bzip2 2>/dev/null)
BZ2_LIBS := $(shell $(PKG_CONFIG) --libs bzip2 2>/dev/null || echo -lbz2)
DEP_CFLAGS := $(CRYPTO_CFLAGS) $(BZ2_CFLAGS)
DEP_LIBS := $(CRYPTO_LIBS) $(BZ2_LIBS)

CFLAGS ?= -O2 -g
override CFLAGS += -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -fPIC \
	-Wall -Wextra -Wno-unused-parameter -DRRC_CLIENT_VERSION=\"$(VERSION)\"

CORE := src/crypto.c src/cbor.c src/hdlc.c src/rns.c src/resource.c src/rrc.c src/rrc_resource.c src/micron.c
CORE_OBJ := $(CORE:.c=.o)

PLUGIN_DIR ?= $(HOME)/.local/share/weechat/plugins
SCRIPT_DIR ?= $(PLUGIN_DIR)/../python

all: rrc.so

src/plugin.o: src/plugin.c src/*.h $(WEECHAT_HEADER)
	$(CC) $(CFLAGS) $(WEECHAT_CFLAGS) $(DEP_CFLAGS) -c $< -o $@

src/%.o: src/%.c src/*.h
	$(CC) $(CFLAGS) $(DEP_CFLAGS) -c $< -o $@

rrc.so: $(CORE_OBJ) src/plugin.o
	$(CC) -shared -o $@ $^ $(LDFLAGS) $(DEP_LIBS)

tests/test_unit: tests/test_unit.c tests/vectors.h $(CORE)
	$(CC) $(CFLAGS) $(DEP_CFLAGS) -o $@ tests/test_unit.c $(CORE) $(DEP_LIBS)

tests/rrc-cli: tests/rrc-cli.c $(CORE)
	$(CC) $(CFLAGS) $(DEP_CFLAGS) -o $@ tests/rrc-cli.c $(CORE) $(DEP_LIBS)

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
	install -d $(SCRIPT_DIR)/autoload
	sed 's|@SOURCE_DIR@|$(CURDIR)|' scripts/rrc_autobuild.py > $(SCRIPT_DIR)/rrc_autobuild.py
	ln -sf ../rrc_autobuild.py $(SCRIPT_DIR)/autoload/rrc_autobuild.py

clean:
	rm -f src/*.o rrc.so tests/test_unit tests/rrc-cli tests/fuzz

.PHONY: all check check-asan install clean

tests/fuzz: tests/fuzz.c tests/vectors.h $(CORE)
	$(CC) $(CFLAGS) $(DEP_CFLAGS) -o $@ tests/fuzz.c $(CORE) $(DEP_LIBS)

fuzz:
	$(MAKE) clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" tests/fuzz
	./tests/fuzz 300000
	$(MAKE) clean

.PHONY: fuzz
