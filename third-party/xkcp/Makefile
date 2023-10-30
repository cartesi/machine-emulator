XKCP_CFLAGS=-O2 -g0 -fPIC -fomit-frame-pointer -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0
XKCP_DIR=XKCP-3dcb0dd952213b25828a5fe81ef7d31736ee3b2e
XKCP_LIBS=$(XKCP_DIR)/bin/libXKCP_generic64.a

TARGET_ARCH=$(shell uname -m)

ifeq ($(TARGET_ARCH),x86_64)
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_SSSE3.a
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_AVX.a
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_AVX2.a
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_AVX512.a
endif

all: $(XKCP_LIBS)

$(XKCP_DIR)/bin: xkcp-build.xml
	cp xkcp-build.xml $(XKCP_DIR)/doc/HOWTO-customize.build
	$(MAKE) -C $(XKCP_DIR)

$(XKCP_DIR)/bin/libXKCP_generic64.a: $(XKCP_DIR)/bin
	$(MAKE) -C $(XKCP_DIR) libXKCP_generic64.a CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) $(XKCP_CFLAGS)"

$(XKCP_DIR)/bin/libXKCP_SSSE3.a: ARCHFLAGS=-mssse3
$(XKCP_DIR)/bin/libXKCP_AVX.a: ARCHFLAGS=-mavx
$(XKCP_DIR)/bin/libXKCP_AVX2.a: ARCHFLAGS=-mavx2
$(XKCP_DIR)/bin/libXKCP_AVX512.a: ARCHFLAGS=-mavx512f -mavx512vl
$(XKCP_DIR)/bin/libXKCP_%.a: $(XKCP_DIR)/bin
	$(MAKE) -C $(XKCP_DIR) libXKCP_$*.a CC="$(CC)" AR="$(AR)" CFLAGS="$(CFLAGS) $(ARCHFLAGS) $(XKCP_CFLAGS)"
	objcopy --prefix-symbols $*_ $@ $@
	objcopy --redefine-sym $*_memset=memset \
			--redefine-sym $*_memcpy=memcpy \
			$@ $@

clean depclean:
	if [ -d "$(XKCP_DIR)" ]; then $(MAKE) -C $(XKCP_DIR) clean; fi
