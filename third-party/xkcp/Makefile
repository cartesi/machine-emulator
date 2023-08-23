LIB_CFLAGS=-O2 -g0 -fvisibility=hidden -fno-stack-protector -fPIC
XKCP_COMMIT=f7fe32a80f0c6600d1c5db50392a43265d3bba9a
XKCP_LIBS=XKCP/bin/libXKCP_generic64.a

UNAME_ARCH=$(shell uname -m)

ifeq ($(UNAME_ARCH),x86_64)
XKCP_LIBS+=XKCP/bin/libXKCP_AVX.a XKCP/bin/libXKCP_AVX2.a XKCP/bin/libXKCP_AVX512.a XKCP/bin/libXKCP_SSSE3.a
endif

all: $(XKCP_LIBS)

XKCP:
	rm -rf XKCP-$(XKCP_COMMIT)
	tar -xzvf ../downloads/$(XKCP_COMMIT).tar.gz
	mv XKCP-$(XKCP_COMMIT) XKCP
	$(MAKE) -C XKCP

XKCP/bin/libXKCP_SSSE3.a: ARCHFLAGS=-mssse3
XKCP/bin/libXKCP_AVX.a: ARCHFLAGS=-mavx
XKCP/bin/libXKCP_AVX2.a: ARCHFLAGS=-mavx2
XKCP/bin/libXKCP_AVX512.a: ARCHFLAGS=-march=skylake-avx512
XKCP/bin/libXKCP_%.a: XKCP
	$(MAKE) -C XKCP $*/libXKCP.a CFLAGS="$(ARCHFLAGS) $(LIB_CFLAGS)"
	# prefix all library symbols with the target extension
	objcopy --prefix-symbols $*_ \
			XKCP/bin/$*/libXKCP.a $@
	# rename back symbols that should be linked later
	objcopy --redefine-sym $*_memset=memset \
			--redefine-sym $*_memcpy=memcpy \
			--redefine-sym $*_fputc=fputc \
			--redefine-sym $*_fprintf=fprintf \
			$@ $@

clean:
	if [ -d "XKCP" ]; then $(MAKE) -C XKCP clean; fi

depclean:
	rm -rf XKCP-$(XKCP_COMMIT) XKCP
