UNAME:=$(shell uname)

# Install settings
PREFIX= /opt/cartesi
BIN_INSTALL_PATH= $(PREFIX)/bin
LIB_INSTALL_PATH= $(PREFIX)/lib
SHARE_INSTALL_PATH= $(PREFIX)/share
IMAGES_INSTALL_PATH= $(SHARE_INSTALL_PATH)/images
CDIR=lib/luapp/5.3
LDIR=share/luapp/5.3
LUA_INSTALL_CPATH= $(PREFIX)/$(CDIR)
LUA_INSTALL_PATH= $(PREFIX)/$(LDIR)
INC_INSTALL_PATH= $(PREFIX)/include/machine-emulator
INSTALL_PLAT = install-$(UNAME)

INSTALL= cp -RP
CHMOD_EXEC= chmod 0755
CHMOD_DATA= chmod 0644
STRIP_EXEC= strip -x

DEP_TO_BIN= luapp5.3 luacpp5.3
DEP_TO_LIB=
EMU_TO_BIN= cartesi-machine-server cartesi-machine-proxy merkle-tree-hash
EMU_TO_LIB= libcartesi.so
EMU_LUA_TO_BIN= cartesi-machine-tests.lua cartesi-machine.lua cartesi-machine-stored-hash.lua
EMU_TO_LUA_PATH= cartesi/util.lua cartesi/proof.lua
EMU_TO_LUA_CPATH= cartesi.so
EMU_TO_LUA_CARTESI_CPATH= cartesi/grpc.so
EMU_TO_INC= pma-defines.h rtc-defines.h

# Build settings
DEPDIR := third-party
SRCDIR := $(abspath src)
BUILDBASE := $(abspath build)
BUILDDIR = $(BUILDBASE)/$(UNAME)_$(shell uname -m)
DOWNLOADDIR := $(DEPDIR)/downloads
SUBCLEAN := $(addsuffix .clean,$(SRCDIR))
DEPDIRS := $(addprefix $(DEPDIR)/,cryptopp-CRYPTOPP_7_0_0 grpc lua-5.3.5 luasocket)
DEPCLEAN := $(addsuffix .clean,$(DEPDIRS))
COREPROTO := lib/grpc-interfaces/core.proto
GRPC_VERSION ?= v1.38.0
LUASOCKET_VERSION ?= 5b18e475f38fcf28429b1cc4b17baee3b9793a62

LUAMYCFLAGS = "MYCFLAGS=-std=c++17 -x c++ -fopenmp -DLUA_ROOT=\\\"$(PREFIX)/\\\""
LUASOCKETCFLAGS = "MYCFLAGS=-std=c++17 -x c++ -DLUASOCKET_API=\"extern \\\"C\\\" __attribute__ ((visibility (\\\"default\\\")))\""

# Docker image tag
TAG ?= devel

# Mac OS X specific settings
ifeq ($(UNAME),Darwin)
LUA_PLAT ?= macosx
export CC = clang
export CXX = clang++
LUACC = "CC=$(CXX)"
LIBRARY_PATH := "export DYLD_LIBRARY_PATH=$(BUILDDIR)/lib"
LIB_EXTENSION = dylib
DEP_TO_LIB += *.$(LIB_EXTENSION)
LUAMYLIBS = "MYLIBS=-L/opt/local/lib/libomp -L/usr/local/opt/llvm/lib -lomp"

# Linux specific settings
else ifeq ($(UNAME),Linux)
LUA_PLAT ?= linux
LIBRARY_PATH := "export LD_LIBRARY_PATH=$(BUILDDIR)/lib"
LIB_EXTENSION := so
DEP_TO_LIB += *.$(LIB_EXTENSION)*
LUACC = "CC=g++"
LUAMYLIBS = "MYLIBS=\"-lgomp\""
# Unknown platform
else
LUA_PLAT ?= none
INSTALL_PLAT=
LIB_EXTENSION := dll
DEP_TO_LIB += *.$(LIB_EXTENSION)
endif


# Check if some binary dependencies already exists on build directory to skip
# downloading and building them.
DEPBINS := $(addprefix $(BUILDDIR)/,bin/luapp5.3 lib/libcryptopp.$(LIB_EXTENSION) lib/libgrpc.$(LIB_EXTENSION) $(CDIR)/socket/core.so)

all: source-default

clean: $(SUBCLEAN)

depclean: $(DEPCLEAN) clean
	rm -rf $(BUILDDIR)

distclean: clean profile-clean
	rm -rf $(BUILDBASE) $(DOWNLOADDIR) $(DEPDIRS)

profile-clean:
	$(MAKE) -C $(SRCDIR) $@

$(BUILDDIR) $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH) $(LUA_INSTALL_CPATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(INC_INSTALL_PATH) $(IMAGES_INSTALL_PATH):
	mkdir -m 0755 -p $@

env:
	@echo $(LIBRARY_PATH)
	@echo "export PATH='$(SRCDIR):$(BUILDDIR)/bin:${PATH}'"
	@echo "export LUAPP_CPATH='./?.so;$(SRCDIR)/?.so;$(BUILDDIR)/$(CDIR)/?.so'"
	@echo "export LUAPP_PATH='./?.lua;$(SRCDIR)/?.lua;$(BUILDDIR)/$(LDIR)/?.lua'"

doc:
	cd doc && doxygen Doxyfile

$(DOWNLOADDIR):
	@mkdir -p $(DOWNLOADDIR)
	@wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	@cd $(DEPDIR) && shasum -c shasumfile

downloads: $(DOWNLOADDIR)

dep: $(DEPBINS)
	@rm -f $(BUILDDIR)/lib/*.a
	@$(STRIP_EXEC) \
		$(BUILDDIR)/bin/lua* \
		$(BUILDDIR)/bin/grpc* \
		$(BUILDDIR)/bin/protoc* \
		$(BUILDDIR)/lib/*.$(LIB_EXTENSION)*

submodules:
	git submodule update --init --recursive

$(COREPROTO):
	$(info gprc-interfaces submodule not initialized!)
	@exit 1

grpc: | $(COREPROTO)
hash luacartesi grpc test lint:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

source-default:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR)

$(DEPDIR)/lua-5.3.5 $(BUILDDIR)/bin/luapp5.3: | $(BUILDDIR) $(DOWNLOADDIR)
	if [ ! -d $(DEPDIR)/lua-5.3.5 ]; then \
		tar -xzf $(DOWNLOADDIR)/lua-5.3.5.tar.gz -C $(DEPDIR); \
		cd $(DEPDIR)/lua-5.3.5 && patch -p1 < ../luapp.patch; \
	fi
	$(MAKE) -C $(DEPDIR)/lua-5.3.5 $(LUA_PLAT) $(LUACC) $(LUAMYCFLAGS) $(LUAMYLIBS)
	$(MAKE) -C $(DEPDIR)/lua-5.3.5 INSTALL_TOP=$(BUILDDIR) install

$(DEPDIR)/luasocket $(BUILDDIR)/$(CDIR)/socket/core.so: $(BUILDDIR)/bin/luapp5.3 | $(BUILDDIR) $(DOWNLOADDIR)
	if [ ! -d $(DEPDIR)/luasocket ]; then \
		git clone https://github.com/diegonehab/luasocket.git $(DEPDIR)/luasocket; \
		cd $(DEPDIR)/luasocket; \
		git reset --hard $(LUASOCKET_VERSION); \
	fi
	$(MAKE) -C $(DEPDIR)/luasocket PLAT=$(LUA_PLAT) $(LUACC) $(LUASOCKETCFLAGS) LUAINC=$(BUILDDIR)/include/luapp/5.3
	$(MAKE) -C $(DEPDIR)/luasocket PLAT=$(LUA_PLAT) CDIR=$(CDIR) LDIR=$(LDIR) prefix=$(BUILDDIR) install


$(DEPDIR)/cryptopp-CRYPTOPP_7_0_0 $(BUILDDIR)/lib/libcryptopp.$(LIB_EXTENSION): | $(BUILDDIR) $(DOWNLOADDIR)
	if [ ! -d $(DEPDIR)/cryptopp-CRYPTOPP_7_0_0 ]; then tar -xzf $(DOWNLOADDIR)/CRYPTOPP_7_0_0.tar.gz -C $(DEPDIR); fi
	$(MAKE) -C $(DEPDIR)/cryptopp-CRYPTOPP_7_0_0 shared
	$(MAKE) -C $(DEPDIR)/cryptopp-CRYPTOPP_7_0_0 static
	$(MAKE) -C $(DEPDIR)/cryptopp-CRYPTOPP_7_0_0 libcryptopp.pc
	$(MAKE) -C $(DEPDIR)/cryptopp-CRYPTOPP_7_0_0 PREFIX=$(BUILDDIR) install
	if [ "$(UNAME)" = "Darwin" ]; then install_name_tool -id @rpath/libcryptopp.$(LIB_EXTENSION) $(BUILDDIR)/lib/libcryptopp.$(LIB_EXTENSION); fi

$(DEPDIR)/grpc $(BUILDDIR)/lib/libgrpc.$(LIB_EXTENSION): | $(BUILDDIR)
	if [ ! -d $(DEPDIR)/grpc ]; then git clone --branch $(GRPC_VERSION) --depth 1 https://github.com/grpc/grpc.git $(DEPDIR)/grpc; fi
	cd $(DEPDIR)/grpc && git submodule update --init --recursive --depth 1
	mkdir -p $(DEPDIR)/grpc/cmake/build && cd $(DEPDIR)/grpc/cmake/build && cmake -C $(abspath $(DEPDIR))/grpc.cmake -DCMAKE_INSTALL_PREFIX=$(BUILDDIR) ../..
	$(MAKE) -C $(DEPDIR)/grpc/cmake/build all install

$(SUBCLEAN) $(DEPCLEAN): %.clean:
	$(MAKE) -C $* clean

linux-env:
	docker run -it --rm -v `pwd`:/opt/emulator -w /opt/emulator cartesi/linux-env:v2

build-linux-env:
	docker build -t cartesi/linux-env:v2 tools/docker

build-ubuntu-image:
	docker build -t cartesi/machine-emulator:$(TAG) -f .github/workflows/Dockerfile .

build-alpine-image:
	docker build -t cartesi/machine-emulator:$(TAG)-alpine -f .github/workflows/Dockerfile.alpine .

install-Darwin:
	install_name_tool -add_rpath $(LIB_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi.so
	install_name_tool -add_rpath $(LIB_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi/grpc.so
	cd $(BIN_INSTALL_PATH) && \
		for x in $(DEP_TO_BIN) $(EMU_TO_BIN); do \
			install_name_tool -add_rpath $(LIB_INSTALL_PATH) $$x ;\
		done
	cd $(LIB_INSTALL_PATH) && \
		for x in `find . -maxdepth 1 -type f -name "*.dylib" | cut -d "/" -f 2`; do \
			install_name_tool -add_rpath $(LIB_INSTALL_PATH) $$x ; \
		done

install-Linux:
	cd $(BIN_INSTALL_PATH) && for x in $(DEP_TO_BIN) $(EMU_TO_BIN); do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done
	cd $(LIB_INSTALL_PATH) && for x in `find . -maxdepth 1 -type f -name "*.so*"`; do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done
	cd $(LUA_INSTALL_CPATH) && for x in `find . -maxdepth 2 -type f -name "*.so"`; do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done

install-dep: $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH) $(LUA_INSTALL_CPATH)
	cd $(BUILDDIR)/bin && $(INSTALL) $(DEP_TO_BIN) $(BIN_INSTALL_PATH)
	cd $(BUILDDIR)/lib && $(INSTALL) $(DEP_TO_LIB) $(LIB_INSTALL_PATH)
	$(INSTALL) $(BUILDDIR)/$(CDIR)/* $(LUA_INSTALL_CPATH)
	$(INSTALL) $(BUILDDIR)/$(LDIR)/* $(LUA_INSTALL_PATH)
	cd $(BIN_INSTALL_PATH) && $(CHMOD_EXEC) $(DEP_TO_BIN)
	cd $(LIB_INSTALL_PATH) && $(CHMOD_EXEC) $(DEP_TO_LIB)

install-emulator: $(BIN_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(INC_INSTALL_PATH) $(IMAGES_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_BIN) $(BIN_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_LIB) $(LIB_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_LUA_TO_BIN) $(BIN_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_LUA_CPATH) $(LUA_INSTALL_CPATH)
	cd src && $(INSTALL) $(EMU_TO_LUA_CARTESI_CPATH) $(LUA_INSTALL_CPATH)/cartesi
	cd src && $(INSTALL) $(EMU_TO_LUA_PATH) $(LUA_INSTALL_PATH)/cartesi
	echo "#!/bin/sh\nCARTESI_IMAGES_PATH=$(IMAGES_INSTALL_PATH) $(BIN_INSTALL_PATH)/luapp5.3 $(BIN_INSTALL_PATH)/cartesi-machine.lua \"\$$@\"" > $(BIN_INSTALL_PATH)/cartesi-machine
	echo "#!/bin/sh\n$(BIN_INSTALL_PATH)/luapp5.3 $(BIN_INSTALL_PATH)/cartesi-machine-tests.lua \"\$$@"\" > $(BIN_INSTALL_PATH)/cartesi-machine-tests
	echo "#!/bin/sh\n$(BIN_INSTALL_PATH)/luapp5.3 $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash.lua \"\$$@"\" > $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash
	cd $(BIN_INSTALL_PATH) && $(CHMOD_EXEC) $(EMU_TO_BIN) cartesi-machine cartesi-machine-tests cartesi-machine-stored-hash
	cd $(BIN_INSTALL_PATH) && $(CHMOD_DATA) $(EMU_LUA_TO_BIN)
	cd lib/machine-emulator-defines && $(INSTALL) $(EMU_TO_INC) $(INC_INSTALL_PATH)
	cd $(LUA_INSTALL_CPATH) && $(CHMOD_EXEC) $(EMU_TO_LUA_CPATH)

install-strip:
	cd $(BIN_INSTALL_PATH) && $(STRIP_EXEC) $(EMU_TO_BIN) $(DEP_TO_BIN)
	cd $(LIB_INSTALL_PATH) && $(STRIP_EXEC) $(DEP_TO_LIB)
	cd $(LUA_INSTALL_CPATH) && $(STRIP_EXEC) *.so

install: install-dep install-emulator install-strip $(INSTALL_PLAT)

.SECONDARY: $(DOWNLOADDIR) $(DEPDIRS) $(COREPROTO)

.PHONY: all submodules doc clean distclean downloads src test luacartesi grpc hash\
	$(SUBDIRS) $(SUBCLEAN) $(DEPCLEAN) $(DEPDIR)/lua.clean
