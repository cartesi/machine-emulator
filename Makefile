UNAME:=$(shell uname)

DEPDIR := third-party
SRCDIR := src
BUILDBASE := build
BUILDDIR := $(BUILDBASE)/$(UNAME)_$(shell uname -m)
DOWNLOADDIR := $(DEPDIR)/downloads
SUBCLEAN := $(addsuffix .clean,$(SRCDIR))
DEPDIRS := $(addprefix $(DEPDIR)/,cryptopp-CRYPTOPP_7_0_0 grpc lua-5.3.5)
DEPCLEAN := $(addsuffix .clean,$(DEPDIRS))

ifeq ($(UNAME),Darwin)
LUA_PLAT ?= macosx
NPROC ?= $(shell sysctl -n hw.physicalcpu)
else ifeq ($(UNAME),Linux)
LUA_PLAT ?= linux
NPROC ?= $(shell nproc)
else
LUA_PLAT ?= none
NPROC ?= 1
endif

all: $(SRCDIR) grpc

clean: $(SUBCLEAN)

depclean: $(DEPCLEAN) clean
	rm -rf $(BUILDDIR)

distclean: clean
	rm -rf $(BUILDBASE) $(DOWNLOADDIR) $(filter-out %grpc,$(DEPDIRS))

$(BUILDDIR):
	mkdir -p $(BUILDDIR)
	echo $(abspath $(BUILDDIR))

downloads:
	mkdir -p $(DOWNLOADDIR)
	wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	cd $(DEPDIR) && shasum -c shasumfile

dep: downloads $(BUILDDIR) $(DEPDIRS)

grpc test:
	$(MAKE) -C $(SRCDIR) -j$(NPROC) $@

$(SRCDIR):
	$(MAKE) -C $@ -j$(NPROC) $(TARGET)

$(DEPDIR)/lua-5.3.5:
	tar -xzf $(DOWNLOADDIR)/lua-5.3.5.tar.gz -C $(DEPDIR)
	cd $@ && patch -p1 < ../luapp.patch
	$(MAKE) -C $@ -j$(NPROC) $(LUA_PLAT)
	$(MAKE) -C $@ INSTALL_TOP=$(abspath $(BUILDDIR)) install

$(DEPDIR)/cryptopp-CRYPTOPP_7_0_0:
	tar -xzf $(DOWNLOADDIR)/CRYPTOPP_7_0_0.tar.gz -C $(DEPDIR)
	$(MAKE) -C $@ -j$(NPROC)
	$(MAKE) -C $@ PREFIX=$(abspath $(BUILDDIR)) install

$(DEPDIR)/grpc:
	git submodule update --init --recursive $@
	$(MAKE) -C $@
	$(MAKE) -C $@ prefix=$(abspath $(BUILDDIR)) install
	$(MAKE) -C $@/third_party/protobuf
	$(MAKE) -C $@/third_party/protobuf prefix=$(abspath $(BUILDDIR)) install

$(SUBCLEAN) $(DEPCLEAN): %.clean:
	$(MAKE) -C $* clean

linux-env:
	docker run -it --rm -v `pwd`:/opt/emulator -w /opt/emulator cartesi/linux-env:v1

build-linux-env:
	docker build -t cartesi/linux-env:v1 tools/docker


.PHONY: all clean distclean downloads src test grpc\
	$(DEPDIRS) $(SUBDIRS) $(SUBCLEAN) $(DEPCLEAN) $(DEPDIR)/lua.clean
