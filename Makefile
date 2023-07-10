# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
#

UNAME:=$(shell uname)

# Install settings
PREFIX= /opt/cartesi
BIN_INSTALL_PATH= $(PREFIX)/bin
LIB_INSTALL_PATH= $(PREFIX)/lib
SHARE_INSTALL_PATH= $(PREFIX)/share
IMAGES_INSTALL_PATH= $(SHARE_INSTALL_PATH)/images
UARCH_INSTALL_PATH= $(SHARE_INSTALL_PATH)/uarch
LUA_INSTALL_CPATH= $(PREFIX)/lib/lua/5.4
LUA_INSTALL_PATH= $(PREFIX)/share/lua/5.4
INC_INSTALL_PATH= $(PREFIX)/include/machine-emulator
INSTALL_PLAT = install-$(UNAME)
LIBCARTESI_Darwin=libcartesi.dylib
LIBCARTESI_Linux=libcartesi.so
LIBCARTESI_PROTOBUF_Darwin=libcartesi_protobuf.dylib
LIBCARTESI_PROTOBUF_Linux=libcartesi_protobuf.so
LIBCARTESI_GRPC_Darwin=libcartesi_grpc.dylib
LIBCARTESI_GRPC_Linux=libcartesi_grpc.so

INSTALL= cp -RP
CHMOD_EXEC= chmod 0755
CHMOD_DATA= chmod 0644
STRIP_EXEC= strip -x

DEP_TO_BIN=
DEP_TO_LIB=
EMU_TO_BIN= jsonrpc-remote-cartesi-machine remote-cartesi-machine remote-cartesi-machine-proxy merkle-tree-hash
EMU_TO_LIB= $(LIBCARTESI_$(UNAME)) $(LIBCARTESI_PROTOBUF_$(UNAME)) $(LIBCARTESI_GRPC_$(UNAME))
EMU_LUA_TO_BIN= cartesi-machine-tests.lua cartesi-machine.lua cartesi-machine-stored-hash.lua rollup-memory-range.lua uarch-riscv-tests.lua
EMU_TO_LUA_PATH= cartesi/util.lua cartesi/proof.lua
EMU_TO_LUA_CPATH= cartesi.so
EMU_TO_LUA_CARTESI_CPATH= cartesi/grpc.so cartesi/jsonrpc.so
EMU_TO_INC= pma-defines.h rtc-defines.h
UARCH_TO_SHARE= uarch-ram.bin

# Build settings
DEPDIR := third-party
SRCDIR := $(abspath src)
BUILDBASE := $(abspath build)
BUILDDIR = $(BUILDBASE)/$(UNAME)_$(shell uname -m)
DOWNLOADDIR := $(DEPDIR)/downloads
SUBCLEAN := $(addsuffix .clean,$(SRCDIR) uarch third-party/riscv-arch-tests)
DEPDIRS := $(addprefix $(DEPDIR)/,mongoose-7.9)
DEPCLEAN := $(addsuffix .clean,$(DEPDIRS))
COREPROTO := lib/grpc-interfaces/core.proto
LUASOCKET_VERSION ?= 5b18e475f38fcf28429b1cc4b17baee3b9793a62
LUA_DEFAULT_PATHS = $(LUA_INSTALL_PATH)/?.lua
LUA_DEFAULT_C_PATHS = $(LUA_INSTALL_CPATH)/?.so

# Docker image tag
TAG ?= devel
# Docker image platform
BUILD_PLATFORM ?=

ifneq ($(BUILD_PLATFORM),)
DOCKER_PLATFORM=--platform $(BUILD_PLATFORM)
endif

# Code instrumentation
release?=no
sanitize?=no
coverage?=no
export sanitize
export release
export coverage

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
LIBRARY_PATH := "export LD_LIBRARY_PATH=$(BUILDDIR)/lib:$(SRCDIR)"
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
DEPBINS := $(addprefix $(BUILDDIR)/,include/mongoose.h)

all: source-default

clean: $(SUBCLEAN)

depclean: $(DEPCLEAN) clean
	rm -rf $(BUILDDIR)
	$(MAKE) -C third-party/riscv-arch-tests depclean

distclean:
	rm -rf $(BUILDBASE) $(DOWNLOADDIR) $(DEPDIRS)
	$(MAKE) -C third-party/riscv-arch-tests depclean
	$(MAKE) clean

$(BUILDDIR) $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH) $(LUA_INSTALL_CPATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(INC_INSTALL_PATH) $(IMAGES_INSTALL_PATH) $(UARCH_INSTALL_PATH):
	mkdir -m 0755 -p $@

env:
	@echo $(LIBRARY_PATH)
	@echo "export PATH='$(SRCDIR):$(BUILDDIR)/bin:${PATH}'"
	@echo "export LUA_PATH_5_4='$(SRCDIR)/?.lua;$${LUA_PATH_5_4:-;}'"
	@echo "export LUA_CPATH_5_4='$(SRCDIR)/?.so;$${LUA_CPATH_5_4:-;}'"

doc:
	cd doc && doxygen Doxyfile

help:
	@echo 'Cleaning targets:'
	@echo '  clean                      - clean the src/ artifacts'
	@echo '  depclean                   - clean + dependencies'
	@echo '  distclean                  - depclean + profile information and downloads'
	@echo 'Docker targets:'
	@echo '  build-debian-image         - Build the machine-emulator debian based docker image'
	@echo 'Generic targets:'
	@echo '* all                        - build the src/ code. To build from a clean clone, run: make submodules downloads dep all'
	@echo '  doc                        - build the doxygen documentation (requires doxygen to be installed)'
	@echo '  uarch                      - build microarchitecture'
	@echo '  uarch-with-linux-env       - build microarchitecture using the linux-env docker image'
	@echo '  uarch-tests                - build and run microarchitecture rv64i instruction tests'
	@echo '  uarch-tests-with-linux-env - build and run microarchitecture rv64i instruction tests using the linux-env docker image'

$(DOWNLOADDIR):
	@mkdir -p $(DOWNLOADDIR)
	@wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	@cd $(DEPDIR) && shasum -c shasumfile

downloads: $(DOWNLOADDIR)

dep: $(DEPBINS)
	@rm -f $(BUILDDIR)/lib/*.a

submodules:
	git submodule update --init --recursive

$(COREPROTO):
	$(info grpc-interfaces submodule not initialized!)
	@exit 1

grpc: | $(COREPROTO)

hash luacartesi grpc test lint coverage-report check-format format check-format-lua check-lua format-lua:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

test-%:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

uarch-tests:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C third-party/riscv-arch-tests

run-uarch-tests:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C third-party/riscv-arch-tests run

source-default:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR)

uarch: $(SRCDIR)/machine-c-version.h
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C uarch

$(BUILDDIR)/include/mongoose.h $(BUILDDIR)/lib/libmongoose.a: | $(BUILDDIR) $(DOWNLOADDIR)
	mkdir -p $(BUILDDIR)/include $(BUILDDIR)/lib
	if [ ! -d $(DEPDIR)/mongoose-7.9 ]; then tar -xzf $(DOWNLOADDIR)/7.9.tar.gz -C /tmp/; mv /tmp/mongoose-7.9 $(DEPDIR)/; fi
	cp $(DEPDIR)/mongoose-7.9/mongoose.c $(BUILDDIR)/lib
	cp $(DEPDIR)/mongoose-7.9/mongoose.h $(BUILDDIR)/include

$(SRCDIR)/machine-c-version.h:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) machine-c-version.h

$(SUBCLEAN) $(DEPCLEAN): %.clean:
	$(MAKE) -C $* clean

build-linux-env:
	docker build $(DOCKER_PLATFORM) --target linux-env -t cartesi/linux-env:$(TAG) -f Dockerfile .

build-debian-image:
	docker build $(DOCKER_PLATFORM) --build-arg RELEASE=$(release) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) -t cartesi/machine-emulator:$(TAG) -f Dockerfile .

check-linux-env:
	@if docker images $(DOCKER_PLATFORM) -q cartesi/linux-env:$(TAG)$(image_name) 2>/dev/null | grep -q .; then \
		echo "Docker image cartesi/linux-env:$(TAG) exists"; \
	else \
		echo "Docker image cartesi/linux-env:$(TAG) does not exist. Creating:"; \
		$(MAKE) build-linux-env; \
	fi

linux-env: check-linux-env
	@docker run $(DOCKER_PLATFORM) --hostname linux-env -it --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`:/opt/cartesi/machine-emulator \
		-w /opt/cartesi/machine-emulator \
		cartesi/linux-env:$(TAG) /bin/bash

linux-env-exec: check-linux-env
	@docker run --hostname linux-env --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`:/opt/cartesi/machine-emulator \
		-w /opt/cartesi/machine-emulator \
		cartesi/linux-env:$(TAG) /bin/bash -c "$(CONTAINER_COMMAND)"

uarch-with-linux-env:
	@$(MAKE) linux-env-exec CONTAINER_COMMAND="make uarch"

uarch-tests-with-linux-env:
	@$(MAKE) linux-env-exec CONTAINER_COMMAND="make uarch-tests"

install-Darwin:
	install_name_tool -delete_rpath $(BUILDDIR)/lib -delete_rpath $(SRCDIR) -add_rpath $(LIB_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi.so
	install_name_tool -delete_rpath $(BUILDDIR)/lib -delete_rpath $(SRCDIR) -add_rpath $(LIB_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi/grpc.so
	install_name_tool -delete_rpath $(BUILDDIR)/lib -delete_rpath $(SRCDIR) -add_rpath $(LIB_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi/jsonrpc.so
	cd $(BIN_INSTALL_PATH) && \
		for x in $(DEP_TO_BIN) $(EMU_TO_BIN); do \
			install_name_tool -delete_rpath $(BUILDDIR)/lib -delete_rpath $(SRCDIR) -add_rpath $(LIB_INSTALL_PATH) $$x ;\
		done

install-Linux:
	cd $(BIN_INSTALL_PATH) && for x in $(DEP_TO_BIN) $(EMU_TO_BIN); do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done
	cd $(LIB_INSTALL_PATH) && for x in `find . -maxdepth 1 -type f -name "*.so*"`; do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done
	cd $(LUA_INSTALL_CPATH) && for x in `find . -maxdepth 2 -type f -name "*.so"`; do patchelf --set-rpath $(LIB_INSTALL_PATH) $$x ; done

install-emulator: $(BIN_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(INC_INSTALL_PATH) $(IMAGES_INSTALL_PATH) $(UARCH_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_BIN) $(BIN_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_LIB) $(LIB_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_LUA_TO_BIN) $(BIN_INSTALL_PATH)
	cd src && $(INSTALL) $(EMU_TO_LUA_CPATH) $(LUA_INSTALL_CPATH)
	cd src && $(INSTALL) $(EMU_TO_LUA_CARTESI_CPATH) $(LUA_INSTALL_CPATH)/cartesi
	cd src && $(INSTALL) $(EMU_TO_LUA_PATH) $(LUA_INSTALL_PATH)/cartesi
	cd uarch && $(INSTALL) $(UARCH_TO_SHARE) $(UARCH_INSTALL_PATH)
	cat tools/template/cartesi-machine.template | sed 's|ARG_LUA_PATH|${LUA_DEFAULT_PATHS}|g;s|ARG_LUA_CPATH|${LUA_DEFAULT_C_PATHS}|g;s|ARG_INSTALL_PATH|${IMAGES_INSTALL_PATH}|g;s|ARG_BIN_INSTALL_PATH|${BIN_INSTALL_PATH}|g' > $(BIN_INSTALL_PATH)/cartesi-machine
	cat tools/template/cartesi-machine-tests.template | sed 's|ARG_LUA_PATH|${LUA_DEFAULT_PATHS}|g;s|ARG_LUA_CPATH|${LUA_DEFAULT_C_PATHS}|g;s|ARG_BIN_INSTALL_PATH|${BIN_INSTALL_PATH}|g' > $(BIN_INSTALL_PATH)/cartesi-machine-tests
	cat tools/template/cartesi-machine-stored-hash.template | sed 's|ARG_LUA_PATH|${LUA_DEFAULT_PATHS}|g;s|ARG_LUA_CPATH|${LUA_DEFAULT_C_PATHS}|g;s|ARG_BIN_INSTALL_PATH|${BIN_INSTALL_PATH}|g' > $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash
	cat tools/template/rollup-memory-range.template | sed 's|ARG_LUA_PATH|${LUA_DEFAULT_PATHS}|g;s|ARG_LUA_CPATH|${LUA_DEFAULT_C_PATHS}|g;s|ARG_BIN_INSTALL_PATH|${BIN_INSTALL_PATH}|g' > $(BIN_INSTALL_PATH)/rollup-memory-range
	cat tools/template/uarch-riscv-tests.template | sed 's|ARG_LUA_PATH|${LUA_DEFAULT_PATHS}|g;s|ARG_LUA_CPATH|${LUA_DEFAULT_C_PATHS}|g;s|ARG_BIN_INSTALL_PATH|${BIN_INSTALL_PATH}|g' > $(BIN_INSTALL_PATH)/uarch-riscv-tests
	cd $(BIN_INSTALL_PATH) && $(CHMOD_EXEC) $(EMU_TO_BIN) cartesi-machine cartesi-machine-tests cartesi-machine-stored-hash rollup-memory-range uarch-riscv-tests
	cd $(BIN_INSTALL_PATH) && $(CHMOD_DATA) $(EMU_LUA_TO_BIN)
	cd lib/machine-emulator-defines && $(INSTALL) $(EMU_TO_INC) $(INC_INSTALL_PATH)
	cd $(LUA_INSTALL_CPATH) && $(CHMOD_EXEC) $(EMU_TO_LUA_CPATH)

install-strip:
	cd $(BIN_INSTALL_PATH) && $(STRIP_EXEC) $(EMU_TO_BIN) $(DEP_TO_BIN)
	cd $(LIB_INSTALL_PATH) && $(STRIP_EXEC) $(DEP_TO_LIB)
	cd $(LUA_INSTALL_CPATH) && $(STRIP_EXEC) *.so

install: install-emulator install-strip $(INSTALL_PLAT)

.SECONDARY: $(DOWNLOADDIR) $(DEPDIRS) $(COREPROTO)

.PHONY: help all submodules doc clean distclean downloads src test luacartesi grpc hash uarch \
	$(SUBDIRS) $(SUBCLEAN) $(DEPCLEAN)
