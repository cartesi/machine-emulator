LIB_CFLAGS+=-O2 -g0 -fvisibility=hidden -fPIC
LIB_CFLAGS+=-fno-stack-protector -D_FORTIFY_SOURCE=0
XKCP_DIR=XKCP-f7fe32a80f0c6600d1c5db50392a43265d3bba9a
XKCP_LIBS=$(XKCP_DIR)/bin/libXKCP.a

TARGET_OS?=$(shell uname)
TARGET_ARCH?=$(shell uname -m)

ifeq ($(TARGET_ARCH),x86_64)
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_generic64.a
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_SSSE3.a
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_AVX.a
XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_AVX2.a
#XKCP_LIBS+=$(XKCP_DIR)/bin/libXKCP_AVX512.a
endif

all: $(XKCP_LIBS)

$(XKCP_DIR)/bin:
	$(MAKE) -C $(XKCP_DIR)

$(XKCP_DIR)/bin/generic64/libXKCP.a: $(XKCP_DIR)/bin
	$(MAKE) -C $(XKCP_DIR) generic64/libXKCP.a CC=$(CC) AR=$(AR) CFLAGS="$(CFLAGS) $(LIB_CFLAGS)"

$(XKCP_DIR)/bin/libXKCP.a: $(XKCP_DIR)/bin/generic64/libXKCP.a
	cp $< $@

$(XKCP_DIR)/bin/libXKCP_SSSE3.a: ARCHFLAGS=-mssse3
$(XKCP_DIR)/bin/libXKCP_AVX.a: ARCHFLAGS=-mavx
$(XKCP_DIR)/bin/libXKCP_AVX2.a: ARCHFLAGS=-mavx2
$(XKCP_DIR)/bin/libXKCP_AVX512.a: ARCHFLAGS=-march=skylake-avx512
$(XKCP_DIR)/bin/libXKCP_%.a: $(XKCP_DIR)/bin/libXKCP.a
	$(MAKE) -C $(XKCP_DIR) $*/libXKCP.a CC=$(CC) AR=$(AR) CFLAGS="$(CFLAGS) $(ARCHFLAGS) $(LIB_CFLAGS)"
	# prefix all library symbols with the target extension
	objcopy --prefix-symbols $*_ \
			$(XKCP_DIR)/bin/$*/libXKCP.a $@
	# rename back symbols that should be linked later
	objcopy --redefine-sym $*_memset=memset \
			--redefine-sym $*_memcpy=memcpy \
			--redefine-sym $*_fputc=fputc \
			--redefine-sym $*_fprintf=fprintf \
			$@ $@

depclean:
	if [ -d "$(XKCP_DIR)" ]; then $(MAKE) -C $(XKCP_DIR) clean; fi
