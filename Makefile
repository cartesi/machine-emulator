UNAME:=$(shell uname)

DEPDIR := third-party
SRCDIR := $(abspath src)
BUILDBASE := $(abspath build)
BUILDDIR = $(BUILDBASE)/$(UNAME)_$(shell uname -m)
DOWNLOADDIR := $(DEPDIR)/downloads
SUBCLEAN := $(addsuffix .clean,$(SRCDIR))
DEPDIRS := $(addprefix $(DEPDIR)/,cryptopp-CRYPTOPP_7_0_0 grpc lua-5.3.5)
DEPCLEAN := $(addsuffix .clean,$(DEPDIRS))

ifeq ($(UNAME),Darwin)
LUA_PLAT ?= macosx
LIBRARY_PATH := "export DYLD_LIBRARY_PATH=$(BUILDDIR)/lib"
LUACC = "CC=clang++ -std=c++17 -fopenmp"
else ifeq ($(UNAME),Linux)
LUA_PLAT ?= linux
LIBRARY_PATH := "export LD_LIBRARY_PATH=$(BUILDDIR)/lib"
else
LUA_PLAT ?= none
endif

all: luacartesi grpc

clean: $(SUBCLEAN)

depclean: $(DEPCLEAN) clean
	rm -rf $(BUILDDIR)

distclean: clean
	rm -rf $(BUILDBASE) $(DOWNLOADDIR) $(DEPDIRS)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

downloads:
	mkdir -p $(DOWNLOADDIR)
	wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	cd $(DEPDIR) && shasum -c shasumfile

env:
	@echo $(LIBRARY_PATH)
	@echo export PATH=$(SRCDIR):$(BUILDDIR)/bin:$${PATH}

$(DEPDIRS): downloads

dep: submodules $(BUILDDIR) $(DEPDIRS)

submodules:
	git submodule update --init --recursive

luacartesi grpc test:
	$(MAKE) -C $(SRCDIR) $@

$(SRCDIR):
	$(MAKE) -C $@ $(TARGET)

$(DEPDIR)/lua-5.3.5:
	tar -xzf $(DOWNLOADDIR)/lua-5.3.5.tar.gz -C $(DEPDIR)
	cd $@ && patch -p1 < ../luapp.patch
	$(MAKE) -C $@ $(LUA_PLAT) $(LUACC)
	$(MAKE) -C $@ INSTALL_TOP=$(BUILDDIR) install

$(DEPDIR)/cryptopp-CRYPTOPP_7_0_0:
	tar -xzf $(DOWNLOADDIR)/CRYPTOPP_7_0_0.tar.gz -C $(DEPDIR)
	$(MAKE) -C $@ shared
	$(MAKE) -C $@ static
	$(MAKE) -C $@ libcryptopp.pc
	$(MAKE) -C $@ PREFIX=$(BUILDDIR) install

$(DEPDIR)/grpc:
	if [ ! -d $@ ]; then git clone --branch v1.16.0 --depth 1 https://github.com/grpc/grpc.git $@; fi
	cd $@ && git checkout v1.16.0 && git submodule update --init --recursive
	cd $@/third_party/protobuf && ./autogen.sh && ./configure --prefix=$(BUILDDIR)
	$(MAKE) -C $@/third_party/protobuf
	$(MAKE) -C $@/third_party/protobuf install
	$(MAKE) -C $@ HAS_SYSTEM_PROTOBUF=false prefix=$(BUILDDIR)
	$(MAKE) -C $@ HAS_SYSTEM_PROTOBUF=false prefix=$(BUILDDIR) install
	# There is a bug in grpc install on Linux (!@$)...
	[ -f $(BUILDDIR)/lib/libgrpc++.so.6 ] && mv -f $(BUILDDIR)/lib/libgrpc++.so.6 $(BUILDDIR)/lib/libgrpc++.so.1 || true

$(SUBCLEAN) $(DEPCLEAN): %.clean:
	$(MAKE) -C $* clean

linux-env:
	docker run -it --rm -v `pwd`:/opt/emulator -w /opt/emulator cartesi/linux-env:v1

build-linux-env:
	docker build -t cartesi/linux-env:v1 tools/docker


.PHONY: all submodules clean distclean downloads src test luacartesi library_path grpc\
	$(DEPDIRS) $(SUBDIRS) $(SUBCLEAN) $(DEPCLEAN) $(DEPDIR)/lua.clean
