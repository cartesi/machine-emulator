UNAME:=$(shell uname)

# Install settings
PREFIX= /opt/cartesi
BIN_INSTALL_PATH= $(PREFIX)/bin
LIB_INSTALL_PATH= $(PREFIX)/lib
LUA_INSTALL_PATH= $(LIB_INSTALL_PATH)/lua/5.3
INSTALL_PLAT = install-$(UNAME)

INSTALL= cp -RP
CHMOD_EXEC= chmod 0755
CHMOD_DATA= chmod 0644

DEP_TO_BIN= luapp5.3 luacpp5.3
DEP_TO_LIB=
EMU_TO_BIN= cartesi-machine-server cartesi-machine-client
EMU_TO_LUA= cartesi-machine-tests.lua cartesi-machine.lua cartesi.so

# Build settings
DEPDIR := third-party
SRCDIR := $(abspath src)
BUILDBASE := $(abspath build)
BUILDDIR = $(BUILDBASE)/$(UNAME)_$(shell uname -m)
DOWNLOADDIR := $(DEPDIR)/downloads
SUBCLEAN := $(addsuffix .clean,$(SRCDIR))
DEPDIRS := $(addprefix $(DEPDIR)/,cryptopp-CRYPTOPP_7_0_0 grpc lua-5.3.5)
DEPCLEAN := $(addsuffix .clean,$(DEPDIRS))

# Mac OS X specific settings
ifeq ($(UNAME),Darwin)
LUA_PLAT ?= macosx
LUACC = "CC=clang++ -std=c++17 -fopenmp"
LIBRARY_PATH := "export DYLD_LIBRARY_PATH=$(BUILDDIR)/lib"
DEP_TO_LIB += *.dylib

# Linux specific settings
else ifeq ($(UNAME),Linux)
LUA_PLAT ?= linux
LIBRARY_PATH := "export LD_LIBRARY_PATH=$(BUILDDIR)/lib"
DEP_TO_LIB += *.so*

# Unknown platform
else
LUA_PLAT ?= none
INSTALL_PLAT=
endif

all: luacartesi grpc

clean: $(SUBCLEAN)

depclean: $(DEPCLEAN) clean
	rm -rf $(BUILDDIR)

distclean: clean
	rm -rf $(BUILDBASE) $(DOWNLOADDIR) $(DEPDIRS)

$(BUILDDIR) $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH):
	mkdir -p $@

downloads:
	mkdir -p $(DOWNLOADDIR)
	wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	cd $(DEPDIR) && shasum -c shasumfile

env:
	@echo $(LIBRARY_PATH)
	@echo export PATH=$(SRCDIR):$(BUILDDIR)/bin:$${PATH}
	@echo export LUA_CPATH='$(SRCDIR)/?.so;'$${LUA_CPATH}

doc:
	cd doc && doxygen Doxyfile

dep: $(BUILDDIR) $(DEPDIRS)

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

install-Darwin:
	install_name_tool -add_rpath $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH)/cartesi.so
	install_name_tool -change $(BUILDDIR)/lib/libcryptopp.dylib @rpath/libcryptopp.dylib $(LUA_INSTALL_PATH)/cartesi.so
	cd $(BIN_INSTALL_PATH) && \
		for x in $(DEP_TO_BIN) $(EMU_TO_BIN); do \
			install_name_tool -add_rpath $(LIB_INSTALL_PATH) $$x ;\
			install_name_tool -change $(BUILDDIR)/lib/libcryptopp.dylib @rpath/libcryptopp.dylib $$x; \
			install_name_tool -change $(BUILDDIR)/lib/libprotobuf.17.dylib @rpath/libprotobuf.17.dylib $$x; \
			install_name_tool -change libgrpc.dylib @rpath/libgrpc.dylib $$x; \
			install_name_tool -change libgrpc++.dylib @rpath/libgrpc++.dylib $$x; \
		done
	cd $(LIB_INSTALL_PATH) && \
		for x in `find . -maxdepth 1 -type f -name "*.dylib" | cut -d "/" -f 2`; do \
			install_name_tool -add_rpath $(LIB_INSTALL_PATH) $$x ; \
			install_name_tool -id @rpath/$$x $$x ; \
			install_name_tool -change $(BUILDDIR)/lib/libprotobuf.17.dylib @rpath/libprotobuf.17.dylib $$x; \
			install_name_tool -change libgrpc.dylib @rpath/libgrpc.dylib $$x; \
			install_name_tool -change libgrpc++.dylib @rpath/libgrpc++.dylib $$x; \
			install_name_tool -change libgpr.dylib @rpath/libgpr.dylib $$x; \
			install_name_tool -change libgrpc_unsecure.dylib @rpath/libgrpc_unsecure.dylib $$x; \
			install_name_tool -change libgrpc_cronet.dylib @rpath/libgrpc_cronet.dylib $$x; \
		done

install-Linux:
	cd $(BIN_INSTALL_PATH) && for x in $(DEP_TO_BIN) $(EMU_TO_BIN); do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done
	cd $(LIB_INSTALL_PATH) && for x in `find . -maxdepth 1 -type f -name "*.so*"`; do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done
	cd $(LUA_INSTALL_PATH) && for x in `find . -maxdepth 1 -type f -name "*.so"`; do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done

install-dep: $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH)
	cd $(BUILDDIR)/bin && $(INSTALL) $(DEP_TO_BIN) $(BIN_INSTALL_PATH)
	cd $(BUILDDIR)/lib && $(INSTALL) $(DEP_TO_LIB) $(LIB_INSTALL_PATH)
	cd $(BIN_INSTALL_PATH) && $(CHMOD_EXEC) $(DEP_TO_BIN)
	cd $(LIB_INSTALL_PATH) && $(CHMOD_EXEC) $(DEP_TO_LIB)

install-emulator: $(BIN_INSTALL_PATH) $(LUA_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_BIN) $(BIN_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_LUA) $(LUA_INSTALL_PATH)
	echo "#!/bin/bash\nLUA_CPATH=$(LUA_INSTALL_PATH)/?.so $(BIN_INSTALL_PATH)/luapp5.3 $(LUA_INSTALL_PATH)/cartesi-machine.lua \$$@" > $(BIN_INSTALL_PATH)/cartesi-machine
	echo "#!/bin/bash\nLUA_CPATH=$(LUA_INSTALL_PATH)/?.so $(BIN_INSTALL_PATH)/luapp5.3 $(LUA_INSTALL_PATH)/cartesi-machine-tests.lua \$$@" > $(BIN_INSTALL_PATH)/cartesi-machine-tests
	cd $(BIN_INSTALL_PATH) && $(CHMOD_EXEC) $(EMU_TO_BIN) cartesi-machine cartesi-machine-tests
	cd $(LUA_INSTALL_PATH) && $(CHMOD_DATA) $(EMU_TO_LUA)

install: install-dep install-emulator $(INSTALL_PLAT)


.PHONY: all submodules doc clean distclean downloads src test luacartesi grpc\
	$(DEPDIRS) $(SUBDIRS) $(SUBCLEAN) $(DEPCLEAN) $(DEPDIR)/lua.clean
