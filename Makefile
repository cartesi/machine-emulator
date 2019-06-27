UNAME:=$(shell uname)

DEPDIR := third-party
SRCDIR := src
BUILDBASE := build
BUILDDIR := $(BUILDBASE)/$(UNAME)_$(shell uname -m)
PREFIX=$(abspath $(BUILDDIR))
DOWNLOADDIR := $(DEPDIR)/downloads
SUBCLEAN := $(addsuffix .clean,$(SRCDIR))
DEPDIRS := $(addprefix $(DEPDIR)/,cryptopp-CRYPTOPP_7_0_0 grpc lua-5.3.5)
DEPCLEAN := $(addsuffix .clean,$(DEPDIRS))

ifeq ($(UNAME),Darwin)
LUA_PLAT ?= macosx
LIBRARY_PATH := "export DYLD_LIBRARY_PATH=\"$(PREFIX)/lib\""
else ifeq ($(UNAME),Linux)
LUA_PLAT ?= linux
LIBRARY_PATH := "export LD_LIBRARY_PATH=\"$(PREFIX)/lib\""
else
LUA_PLAT ?= none
endif


all: luacartesi grpc

clean: $(SUBCLEAN)

depclean: $(DEPCLEAN) clean
	rm -rf $(BUILDDIR)

distclean: clean
	rm -rf $(BUILDBASE) $(DOWNLOADDIR) $(filter-out %grpc,$(DEPDIRS))

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

downloads:
	mkdir -p $(DOWNLOADDIR)
	wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	cd $(DEPDIR) && shasum -c shasumfile

library_path:
	@echo $(LIBRARY_PATH)

dep: downloads $(BUILDDIR) $(DEPDIRS)

luacartesi grpc test:
	$(MAKE) -C $(SRCDIR) $@

$(SRCDIR):
	$(MAKE) -C $@ $(TARGET)

$(DEPDIR)/lua-5.3.5:
	tar -xzf $(DOWNLOADDIR)/lua-5.3.5.tar.gz -C $(DEPDIR)
	cd $@ && patch -p1 < ../luapp.patch
	$(MAKE) -C $@ $(LUA_PLAT)
	$(MAKE) -C $@ INSTALL_TOP=$(abspath $(BUILDDIR)) install


$(DEPDIR)/cryptopp-CRYPTOPP_7_0_0:
	tar -xzf $(DOWNLOADDIR)/CRYPTOPP_7_0_0.tar.gz -C $(DEPDIR)
	$(MAKE) -C $@ shared
	$(MAKE) -C $@ static
	$(MAKE) -C $@ libcryptopp.pc
	$(MAKE) -C $@ PREFIX=$(PREFIX) install


$(DEPDIR)/grpc:
	if [ ! -d $@ ]; then git clone --branch v1.16.0 --depth 1 https://github.com/grpc/grpc.git $@; fi
	cd $@ && git checkout v1.16.0 && git submodule update --init --recursive
	cd $@/third_party/protobuf && ./autogen.sh && ./configure --prefix=$(PREFIX)
	$(MAKE) -C $@/third_party/protobuf
	$(MAKE) -C $@/third_party/protobuf install
	$(MAKE) -C $@ HAS_SYSTEM_PROTOBUF=false prefix=$(PREFIX)
	$(MAKE) -C $@ HAS_SYSTEM_PROTOBUF=false prefix=$(PREFIX) install
	# There is a bug in grpc install on Linux (!@$)...
	[ -f $(PREFIX)/lib/libgrpc++.so.6 ] && mv -f $(PREFIX)/lib/libgrpc++.so.6 $(PREFIX)/lib/libgrpc++.so.1 || true

$(SUBCLEAN) $(DEPCLEAN): %.clean:
	$(MAKE) -C $* clean

linux-env:
	docker run -it --rm -v `pwd`:/opt/emulator -w /opt/emulator cartesi/linux-env:v1

build-linux-env:
	docker build -t cartesi/linux-env:v1 tools/docker


.PHONY: all clean distclean downloads src test luacartesi library_path grpc\
	$(DEPDIRS) $(SUBDIRS) $(SUBCLEAN) $(DEPCLEAN) $(DEPDIR)/lua.clean
