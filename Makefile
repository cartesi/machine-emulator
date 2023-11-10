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

TARGET_OS?=$(shell uname)
export TARGET_OS

# Install settings
DEB_ARCH:= $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
PREFIX= /usr
MACHINE_EMULATOR_VERSION:= $(shell make -sC src version)
MACHINE_EMULATOR_SO_VERSION:= $(shell make -sC src so-version)
DEB_FILENAME= cartesi-machine-v$(MACHINE_EMULATOR_VERSION)_$(DEB_ARCH).deb
BIN_RUNTIME_PATH= $(PREFIX)/bin
LIB_RUNTIME_PATH= $(PREFIX)/lib
DOC_RUNTIME_PATH= $(PREFIX)/doc/cartesi-machine
SHARE_RUNTIME_PATH= $(PREFIX)/share/cartesi-machine
IMAGES_RUNTIME_PATH= $(SHARE_RUNTIME_PATH)/images
LUA_RUNTIME_CPATH= $(PREFIX)/lib/lua/5.4
LUA_RUNTIME_PATH= $(PREFIX)/share/lua/5.4

LIBCARTESI_Darwin=libcartesi.dylib
LIBCARTESI_Linux=libcartesi.so
LIBCARTESI_GRPC_Darwin=libcartesi_grpc.dylib
LIBCARTESI_GRPC_Linux=libcartesi_grpc.so
LIBCARTESI_JSONRPC_Darwin=libcartesi_jsonrpc.dylib
LIBCARTESI_JSONRPC_Linux=libcartesi_jsonrpc.so

LIBCARTESI_SO_Darwin:=libcartesi-$(MACHINE_EMULATOR_SO_VERSION).dylib
LIBCARTESI_SO_Linux:=libcartesi-$(MACHINE_EMULATOR_SO_VERSION).so
LIBCARTESI_SO_GRPC_Darwin:=libcartesi_grpc-$(MACHINE_EMULATOR_SO_VERSION).dylib
LIBCARTESI_SO_GRPC_Linux:=libcartesi_grpc-$(MACHINE_EMULATOR_SO_VERSION).so
LIBCARTESI_SO_JSONRPC_Darwin:=libcartesi_jsonrpc-$(MACHINE_EMULATOR_SO_VERSION).dylib
LIBCARTESI_SO_JSONRPC_Linux:=libcartesi_jsonrpc-$(MACHINE_EMULATOR_SO_VERSION).so

BIN_INSTALL_PATH:=    $(abspath $(DESTDIR)$(BIN_RUNTIME_PATH))
LIB_INSTALL_PATH:=    $(abspath $(DESTDIR)$(LIB_RUNTIME_PATH))
DOC_INSTALL_PATH:=    $(abspath $(DESTDIR)$(DOC_RUNTIME_PATH))
SHARE_INSTALL_PATH:=  $(abspath $(DESTDIR)$(SHARE_RUNTIME_PATH))
IMAGES_INSTALL_PATH:= $(abspath $(DESTDIR)$(IMAGES_RUNTIME_PATH))
UARCH_INSTALL_PATH:=  $(abspath $(SHARE_INSTALL_PATH)/uarch)
LUA_INSTALL_CPATH:=   $(abspath $(DESTDIR)$(LUA_RUNTIME_CPATH))
LUA_INSTALL_PATH:=    $(abspath $(DESTDIR)$(LUA_RUNTIME_PATH))
INC_INSTALL_PATH:=    $(abspath $(DESTDIR)$(PREFIX)/include/cartesi-machine)

INSTALL_FILE= install -m0644
INSTALL_EXEC= install -m0755
INSTALL_DIR= cp -RP
SYMLINK= ln -sf
CHMOD_EXEC= chmod 0755
STRIP= strip
STRIP_BINARY= $(STRIP)
STRIP_SHARED= $(STRIP) -S -x
STRIP_STATIC= $(STRIP) -S

EMU_TO_BIN= src/jsonrpc-remote-cartesi-machine src/remote-cartesi-machine src/merkle-tree-hash
EMU_TEST_TO_BIN= src/tests/test-merkle-tree-hash src/tests/test-machine-c-api
EMU_TO_LIB= src/$(LIBCARTESI_SO_$(TARGET_OS)) src/$(LIBCARTESI_SO_GRPC_$(TARGET_OS)) src/$(LIBCARTESI_SO_JSONRPC_$(TARGET_OS))
EMU_TO_LIB_A= src/libcartesi.a src/libcartesi_jsonrpc.a
EMU_LUA_TO_BIN= src/cartesi-machine.lua src/cartesi-machine-stored-hash.lua src/rollup-memory-range.lua
EMU_LUA_TEST_TO_BIN= src/cartesi-machine-tests.lua src/uarch-riscv-tests.lua
EMU_TO_LUA_PATH= src/cartesi/util.lua src/cartesi/proof.lua src/cartesi/gdbstub.lua
EMU_TO_LUA_CPATH= src/cartesi.so
EMU_TO_LUA_CARTESI_CPATH= src/cartesi/grpc.so src/cartesi/jsonrpc.so
EMU_TO_INC= $(addprefix src/,jsonrpc-machine-c-api.h grpc-machine-c-api.h machine-c-api.h \
	    machine-c-defines.h machine-c-version.h pma-defines.h rtc-defines.h htif-defines.h uarch-defines.h)
UARCH_TO_SHARE= uarch-ram.bin

MONGOOSE_VERSION=7.12

# Build settings
DEPDIR := third-party
SRCDIR := $(abspath src)
DOWNLOADDIR := $(DEPDIR)/downloads
DEPDIRS := third-party/mongoose-$(MONGOOSE_VERSION)
SUBCLEAN := $(addsuffix .clean,$(SRCDIR) uarch third-party/riscv-arch-tests)
COREPROTO := lib/grpc-interfaces/core.proto

# Docker image tag
TAG ?= devel
DEBIAN_IMG ?= cartesi/machine-emulator:$(TAG).deb

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
ifeq ($(TARGET_OS),Darwin)
export CC = clang
export CXX = clang++
LIBRARY_PATH := "export DYLD_LIBRARY_PATH="

# Linux specific settings
else ifeq ($(TARGET_OS),Linux)
export CC=gcc
export CXX=g++
LIBRARY_PATH := "export LD_LIBRARY_PATH=$(SRCDIR)"
endif

all: source-default

clean: $(SUBCLEAN)

depclean: clean
	$(MAKE) -C third-party/riscv-arch-tests depclean

distclean:
	rm -rf $(DOWNLOADDIR) $(DEPDIRS)
	$(MAKE) -C third-party/riscv-arch-tests depclean
	$(MAKE) clean

$(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH) $(LUA_INSTALL_CPATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(INC_INSTALL_PATH) $(IMAGES_INSTALL_PATH) $(UARCH_INSTALL_PATH):
	mkdir -m 0755 -p $@

env:
	@echo $(LIBRARY_PATH)
	@echo "export PATH='$(SRCDIR):${PATH}'"
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
	@echo '  build-debian-package       - BUild the cartesi-machine.deb package from image'
	@echo 'Generic targets:'
	@echo '* all                        - build the src/ code. To build from a clean clone, run: make submodules downloads dep all'
	@echo '  doc                        - build the doxygen documentation (requires doxygen to be installed)'
	@echo '  copy                       - copy generated artifacts out of a docker image'
	@echo '  uarch                      - build microarchitecture'
	@echo '  uarch-with-linux-env       - build microarchitecture using the linux-env docker image'
	@echo '  uarch-tests                - build and run microarchitecture rv64i instruction tests'
	@echo '  uarch-tests-with-linux-env - build and run microarchitecture rv64i instruction tests using the linux-env docker image'

checksum:
	@cd $(DEPDIR) && shasum -c shasumfile

$(DOWNLOADDIR):
	@mkdir -p $(DOWNLOADDIR)
	@wget -nc -i $(DEPDIR)/dependencies -P $(DOWNLOADDIR)
	$(MAKE) checksum

downloads: $(DOWNLOADDIR)

third-party/downloads/$(MONGOOSE_VERSION).tar.gz: | downloads
third-party/mongoose-$(MONGOOSE_VERSION): third-party/downloads/$(MONGOOSE_VERSION).tar.gz
	tar -C third-party -xzf $< mongoose-$(MONGOOSE_VERSION)/mongoose.c mongoose-$(MONGOOSE_VERSION)/mongoose.h

dep: $(DEPDIRS)

submodules:
	git submodule update --init --recursive

$(COREPROTO):
	$(info grpc-interfaces submodule not initialized!)
	@exit 1

grpc: | $(COREPROTO)

hash luacartesi grpc test lint coverage-report check-format format check-format-lua check-lua format-lua:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

libcartesi libcartesi_grpc libcartesi_jsonrpc:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

version:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -sC $(SRCDIR) $@

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

$(SRCDIR)/machine-c-version.h:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) machine-c-version.h

$(SUBCLEAN): %.clean:
	$(MAKE) -C $* clean

build-linux-env:
	docker build $(DOCKER_PLATFORM) --target linux-env -t cartesi/linux-env:$(TAG) -f Dockerfile .

build-debian-image:
	docker build $(DOCKER_PLATFORM) --build-arg RELEASE=$(release) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION) -t cartesi/machine-emulator:$(TAG) -f Dockerfile .

build-debian-package:
	docker build $(DOCKER_PLATFORM) --target debian-packager --build-arg RELEASE=$(release) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION=) -t $(DEBIAN_IMG) -f Dockerfile .

copy:
	ID=`docker create $(DOCKER_PLATFORM) $(DEBIAN_IMG)` && \
	   docker cp $$ID:/usr/src/emulator/$(DEB_FILENAME) . && \
	   docker cp $$ID:/usr/src/emulator/uarch/uarch-ram.bin . && \
	   docker rm $$ID

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

install-headers: $(INC_INSTALL_PATH)
	$(INSTALL_FILE) $(EMU_TO_INC) $(INC_INSTALL_PATH)

install-emulator: $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(IMAGES_INSTALL_PATH)
	$(INSTALL_EXEC) $(EMU_TO_BIN) $(BIN_INSTALL_PATH)
	$(INSTALL_EXEC) $(EMU_TO_LIB) $(LIB_INSTALL_PATH)
	$(INSTALL_FILE) $(EMU_TO_LIB_A) $(LIB_INSTALL_PATH)
	$(INSTALL_FILE) $(EMU_LUA_TO_BIN) $(LUA_INSTALL_PATH)
	$(INSTALL_EXEC) $(EMU_TO_LUA_CPATH) $(LUA_INSTALL_CPATH)
	$(INSTALL_EXEC) $(EMU_TO_LUA_CARTESI_CPATH) $(LUA_INSTALL_CPATH)/cartesi
	$(INSTALL_FILE) $(EMU_TO_LUA_PATH) $(LUA_INSTALL_PATH)/cartesi
	cat tools/template/cartesi-machine.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_INSTALL_PATH|$(IMAGES_RUNTIME_PATH)|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/cartesi-machine
	cat tools/template/cartesi-machine-stored-hash.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash
	cat tools/template/rollup-memory-range.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/rollup-memory-range
	$(CHMOD_EXEC) $(BIN_INSTALL_PATH)/cartesi-machine $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash $(BIN_INSTALL_PATH)/rollup-memory-range
	$(SYMLINK) $(LIBCARTESI_SO_$(TARGET_OS)) $(LIB_INSTALL_PATH)/$(LIBCARTESI_$(TARGET_OS))
	$(SYMLINK) $(LIBCARTESI_SO_GRPC_$(TARGET_OS)) $(LIB_INSTALL_PATH)/$(LIBCARTESI_GRPC_$(TARGET_OS))
	$(SYMLINK) $(LIBCARTESI_SO_JSONRPC_$(TARGET_OS)) $(LIB_INSTALL_PATH)/$(LIBCARTESI_JSONRPC_$(TARGET_OS))
	$(INSTALL_DIR) tools/gdb $(SHARE_INSTALL_PATH)/gdb

install-strip: install-emulator
	$(STRIP_BINARY) $(subst src/,$(BIN_INSTALL_PATH)/,$(EMU_TO_BIN))
	$(STRIP_SHARED) $(subst src/,$(LUA_INSTALL_CPATH)/,$(EMU_TO_LUA_CPATH))
	$(STRIP_SHARED) $(subst src/,$(LIB_INSTALL_PATH)/,$(EMU_TO_LIB))
	$(STRIP_STATIC) $(subst src/,$(LIB_INSTALL_PATH)/,$(EMU_TO_LIB_A))

install: install-strip install-headers

install-tests: install
	$(INSTALL_FILE) $(EMU_LUA_TEST_TO_BIN) $(LUA_INSTALL_PATH)
	$(INSTALL_EXEC) $(EMU_TEST_TO_BIN) $(BIN_INSTALL_PATH)
	cat tools/template/cartesi-machine-tests.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/cartesi-machine-tests
	cat tools/template/uarch-riscv-tests.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/uarch-riscv-tests
	$(CHMOD_EXEC) $(BIN_INSTALL_PATH)/cartesi-machine-tests $(BIN_INSTALL_PATH)/uarch-riscv-tests

install-uarch: install $(UARCH_INSTALL_PATH)
	$(INSTALL_FILE) uarch/$(UARCH_TO_SHARE) $(UARCH_INSTALL_PATH)

debian-package: install
	mkdir -p $(DESTDIR)/DEBIAN $(DOC_INSTALL_PATH)
	$(INSTALL_FILE) COPYING $(DOC_INSTALL_PATH)/copyright
	cat tools/template/control.template | sed 's|ARG_VERSION|$(MACHINE_EMULATOR_VERSION)|g;s|ARG_ARCH|$(DEB_ARCH)|g' > $(DESTDIR)/DEBIAN/control
	dpkg-deb -Zxz --root-owner-group --build $(DESTDIR) $(DEB_FILENAME)

.SECONDARY: $(DOWNLOADDIR) $(DEPDIRS) $(COREPROTO)

.PHONY: help all submodules doc clean distclean downloads checksum src test luacartesi grpc hash uarch \
	$(SUBDIRS) $(SUBCLEAN)
