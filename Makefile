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
DEB_ARCH?= $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
PREFIX= /usr
MACHINE_EMULATOR_VERSION= $(shell make -sC src version)
MACHINE_EMULATOR_SO_VERSION= $(shell make -sC src so-version)
DEB_FILENAME= cartesi-machine-v$(MACHINE_EMULATOR_VERSION)_$(DEB_ARCH).deb
BIN_RUNTIME_PATH= $(PREFIX)/bin
LIB_RUNTIME_PATH= $(PREFIX)/lib
DOC_RUNTIME_PATH= $(PREFIX)/doc/cartesi-machine
SHARE_RUNTIME_PATH= $(PREFIX)/share/cartesi-machine
IMAGES_RUNTIME_PATH= $(SHARE_RUNTIME_PATH)/images
LUA_RUNTIME_CPATH= $(PREFIX)/lib/lua/5.4
LUA_RUNTIME_PATH= $(PREFIX)/share/lua/5.4

TESTS_DEB_FILENAME= cartesi-machine-tests-v$(MACHINE_EMULATOR_VERSION)_$(DEB_ARCH).deb
TESTS_DATA_DEB_FILENAME= cartesi-machine-tests-data-v$(MACHINE_EMULATOR_VERSION).deb
TESTS_DATA_RUNTIME_PATH= $(SHARE_RUNTIME_PATH)/tests/data
TESTS_SCRIPTS_RUNTIME_PATH= $(SHARE_RUNTIME_PATH)/tests/scripts
TESTS_LUA_RUNTIME_PATH= $(SHARE_RUNTIME_PATH)/tests/lua
TESTS_DOC_RUNTIME_PATH= $(PREFIX)/doc/cartesi-machine-tests
TESTS_DATA_DOC_RUNTIME_PATH= $(PREFIX)/doc/cartesi-machine-tests-data

ifeq ($(TARGET_OS),Darwin)
LIBCARTESI=libcartesi.dylib
LIBCARTESI_JSONRPC=libcartesi_jsonrpc.dylib
LIBCARTESI_SO=libcartesi-$(MACHINE_EMULATOR_SO_VERSION).dylib
LIBCARTESI_SO_JSONRPC=libcartesi_jsonrpc-$(MACHINE_EMULATOR_SO_VERSION).dylib
else
LIBCARTESI=libcartesi.so
LIBCARTESI_JSONRPC=libcartesi_jsonrpc.so
LIBCARTESI_SO=libcartesi-$(MACHINE_EMULATOR_SO_VERSION).so
LIBCARTESI_SO_JSONRPC=libcartesi_jsonrpc-$(MACHINE_EMULATOR_SO_VERSION).so
endif

BIN_INSTALL_PATH=    $(abspath $(DESTDIR)$(BIN_RUNTIME_PATH))
LIB_INSTALL_PATH=    $(abspath $(DESTDIR)$(LIB_RUNTIME_PATH))
DOC_INSTALL_PATH=    $(abspath $(DESTDIR)$(DOC_RUNTIME_PATH))
SHARE_INSTALL_PATH=  $(abspath $(DESTDIR)$(SHARE_RUNTIME_PATH))
IMAGES_INSTALL_PATH= $(abspath $(DESTDIR)$(IMAGES_RUNTIME_PATH))
UARCH_INSTALL_PATH=  $(abspath $(SHARE_INSTALL_PATH)/uarch)
LUA_INSTALL_CPATH=   $(abspath $(DESTDIR)$(LUA_RUNTIME_CPATH))
LUA_INSTALL_PATH=    $(abspath $(DESTDIR)$(LUA_RUNTIME_PATH))
INC_INSTALL_PATH=    $(abspath $(DESTDIR)$(PREFIX)/include/cartesi-machine)

TESTS_SCRIPTS_INSTALL_PATH= $(abspath $(DESTDIR)$(TESTS_SCRIPTS_RUNTIME_PATH))
TESTS_LUA_INSTALL_PATH= $(abspath $(DESTDIR)$(TESTS_LUA_RUNTIME_PATH))
TESTS_DOC_INSTALL_PATH= $(abspath $(DESTDIR)$(TESTS_DOC_RUNTIME_PATH))
TESTS_DATA_INSTALL_PATH= $(abspath $(DESTDIR)$(TESTS_DATA_RUNTIME_PATH))
TESTS_DATA_DOC_INSTALL_PATH= $(abspath $(DESTDIR)$(TESTS_DATA_DOC_RUNTIME_PATH))

INSTALL_FILE= install -m0644
INSTALL_EXEC= install -m0755
INSTALL_DIR= cp -RP
SYMLINK= ln -sf
CHMOD_EXEC= chmod 0755
STRIP= strip
STRIP_BINARY= $(STRIP)
STRIP_SHARED= $(STRIP) -S -x
STRIP_STATIC= $(STRIP) -S

EMU_TO_BIN= src/jsonrpc-remote-cartesi-machine src/merkle-tree-hash
EMU_TO_LIB= src/$(LIBCARTESI_SO) src/$(LIBCARTESI_SO_JSONRPC)
EMU_TO_LIB_A= src/libcartesi.a src/libcartesi_jsonrpc.a
EMU_LUA_TO_BIN= src/cartesi-machine.lua src/cartesi-machine-stored-hash.lua
EMU_TO_LUA_PATH= src/cartesi/util.lua src/cartesi/proof.lua src/cartesi/gdbstub.lua
EMU_TO_LUA_CPATH= src/cartesi.so
EMU_TO_LUA_CARTESI_CPATH= src/cartesi/jsonrpc.so
EMU_TO_INC= $(addprefix src/,jsonrpc-machine-c-api.h machine-c-api.h \
	    machine-c-defines.h machine-c-version.h pma-defines.h rtc-defines.h htif-defines.h uarch-defines.h)
UARCH_TO_SHARE= uarch-ram.bin

TESTS_TO_BIN= tests/build/misc/test-merkle-tree-hash tests/build/misc/test-machine-c-api
TESTS_LUA_TO_LUA_PATH=tests/lua/cartesi
TESTS_LUA_TO_TEST_LUA_PATH=$(wildcard tests/lua/*.lua)
TESTS_SCRIPTS_TO_TEST_SCRIPTS_PATH=$(wildcard tests/scripts/*.sh)
TESTS_DATA_TO_TESTS_DATA_PATH= tests/build/machine tests/build/uarch tests/build/uarch-riscv-arch-test tests/build/images

# Build settings
DEPDIR = third-party
SRCDIR = $(abspath src)
TESTSDIR = $(abspath tests)
DOWNLOADDIR = $(DEPDIR)/downloads
SUBCLEAN = $(addsuffix .clean,$(SRCDIR) uarch tests)

# Docker image tag
TAG ?= devel
DEBIAN_IMG ?= cartesi/machine-emulator:$(TAG).deb

# Docker image platform
BUILD_PLATFORM ?=

ifneq ($(BUILD_PLATFORM),)
DOCKER_PLATFORM=--platform $(BUILD_PLATFORM)
endif

# Code instrumentation
debug?=no
relwithdebinfo?=no
release?=no
sanitize?=no
coverage?=no

# If not build type is chosen, set the default to release with debug information,
# so the emulator is packaged correctly by default.
ifeq (,$(filter yes,$(relwithdebinfo) $(release) $(debug) $(sanitize)))
relwithdebinfo=yes
endif

export sanitize
export debug
export relwithdebinfo
export release
export coverage

COVERAGE_TOOLCHAIN?=gcc
export COVERAGE_TOOLCHAIN

# Mac OS X specific settings
ifeq ($(TARGET_OS),Darwin)
export CC = clang
export CXX = clang++
LIBRARY_PATH = "export DYLD_LIBRARY_PATH="

# Linux specific settings
else ifeq ($(TARGET_OS),Linux)
export CC=gcc
export CXX=g++
LIBRARY_PATH = "export LD_LIBRARY_PATH=$(SRCDIR)"

# Other system
else
export CC=gcc
export CXX=g++

endif

GENERATED_FILES= uarch/uarch-pristine-hash.c uarch/uarch-pristine-ram.c src/machine-c-version.h
ADD_GENERATED_FILES_DIFF= add-generated-files.diff

all: source-default

help:
	@echo 'Main targets:'
	@echo '* all                                 - Build the src/ code. To build from a clean clone, run: make submodules all'
	@echo '  uarch                               - Build microarchitecture (requires riscv64-cartesi-linux-gnu-* toolchain)'
	@echo '  uarch-with-linux-env                - Build microarchitecture using the linux-env docker image'
	@echo '  zkarch-with-linux-env               - Build zk microarchitecture using the linux-env docker image'
	@echo '  build-tests-all                     - Build all tests (machine, uarch and misc)'
	@echo '  build-tests-machine                 - Build machine emulator tests (requires rv64gc-lp64d riscv64-cartesi-linux-gnu-* toolchain)'
	@echo '  build-tests-machine-with-toolchain  - Build machine emulator tests using the rv64gc-lp64d toolchain docker image'
	@echo '  build-tests-uarch                   - Build microarchitecture rv64i instruction tests (requires rv64ima-lp64 riscv64-cartesi-linux-gnu-* toolchain)'
	@echo '  build-tests-uarch-with-toolchain    - Build microarchitecture rv64i instruction tests using the rv64ima-lp64 toolchain docker image'
	@echo '  build-tests-misc                    - Build miscellaneous tests'
	@echo '  build-tests-misc-with-builder-image - Build miscellaneous tests using the cartesi/machine-emulator:builder image'
	@echo '  test-machine                        - Run machine emulator tests'
	@echo '  test-uarch                          - Run uarch tests'
	@echo '  test-misc                           - Run miscellaneous tests'
	@echo '  test                                - Run all tests'
	@echo '  doc                                 - Build the doxygen documentation (requires doxygen)'
	@echo 'Docker images targets:'
	@echo '  build-emulator-image                - Build the machine-emulator debian based docker image'
	@echo '  build-debian-package                - Build the cartesi-machine.deb package from image'
	@echo '  build-linux-env                     - Build the linux environment docker image'
	@echo '  create-generated-files-patch        - Create patch that adds generated files to source tree'
	@echo 'Cleaning targets:'
	@echo '  clean                               - Clean the src/ artifacts'
	@echo '  depclean                            - Clean + dependencies'
	@echo '  distclean                           - Depclean + profile information and downloads'

$(SUBCLEAN): %.clean:
	@$(MAKE) -C $* clean

clean: $(SUBCLEAN)
	@rm -rf cartesi-machine-*.deb
	@rm -rf $(ADD_GENERATED_FILES_DIFF)

depclean: clean
	@rm -rf $(DOWNLOADDIR)

distclean: depclean

env:
	@echo $(LIBRARY_PATH)
	@echo "export PATH='$(SRCDIR):$(TESTSDIR)/misc:${PATH}'"
	@echo "export LUA_PATH_5_4='$(SRCDIR)/?.lua;$(TESTSDIR)/lua/?.lua;$${LUA_PATH_5_4:-;}'"
	@echo "export LUA_CPATH_5_4='$(SRCDIR)/?.so;$${LUA_CPATH_5_4:-;}'"

doc:
	cd doc && doxygen Doxyfile

bundle-boost: $(DEPDIR)/downloads/boost
$(DEPDIR)/downloads/boost:
	mkdir -p $(DOWNLOADDIR)
	wget -O $(DEPDIR)/downloads/boost_1_81_0.tar.gz https://boostorg.jfrog.io/artifactory/main/release/1.81.0/source/boost_1_81_0.tar.gz
	tar -C $(DEPDIR)/downloads -xzf $(DEPDIR)/downloads/boost_1_81_0.tar.gz boost_1_81_0/boost
	mv $(DEPDIR)/downloads/boost_1_81_0/boost $(DEPDIR)/downloads/boost
	rm -rf $(DEPDIR)/downloads/boost_1_81_0.tar.gz $(DEPDIR)/downloads/boost_1_81_0

submodules:
	git submodule update --init --recursive

hash luacartesi:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

libcartesi libcartesi_jsonrpc libcartesi.a libcartesi_jsonrpc.a libcartesi.so libcartesi_jsonrpc.so:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) $@

version:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -sC $(SRCDIR) $@

test:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C tests $@

test% coverage% build-tests%:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C tests $@

build-tests-misc-with-builder-image: build-emulator-builder-image

lint check-format format check-format-lua check-lua format-lua:
	@$(MAKE) $@-src $@-tests

lint-% check-format-% format-% check-format-lua-% check-lua-% format-lua-%:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(if $(findstring -src,$@),src,tests) $(subst -src,,$(subst -tests,,$@))

source-default:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR)

uarch: $(SRCDIR)/machine-c-version.h
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C uarch

zkarch: $(SRCDIR)/machine-c-version.h
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C zkarch

$(SRCDIR)/machine-c-version.h:
	@eval $$($(MAKE) -s --no-print-directory env); $(MAKE) -C $(SRCDIR) machine-c-version.h

build-emulator-builder-image:
	docker build $(DOCKER_PLATFORM) --build-arg DEBUG=$(debug) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --target builder -t cartesi/machine-emulator:builder -f Dockerfile .

build-emulator-linux-env-image build-linux-env:
	docker build $(DOCKER_PLATFORM) --target linux-env -t cartesi/machine-emulator:linux-env -f Dockerfile .

build-emulator-image:
	docker build $(DOCKER_PLATFORM) --build-arg DEBUG=$(debug) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION) -t cartesi/machine-emulator:$(TAG) -f Dockerfile .

build-emulator-tests-image: build-emulator-builder-image build-emulator-image
	docker build $(DOCKER_PLATFORM) --build-arg DEBUG=$(debug) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION) --build-arg TAG=$(TAG) -t cartesi/machine-emulator:tests -f tests/Dockerfile .

build-emulator-tests-builder-image: build-emulator-builder-image
	docker build $(DOCKER_PLATFORM) --target tests-builder --build-arg DEBUG=$(debug) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION) --build-arg TAG=$(TAG) -t cartesi/machine-emulator:tests-builder -f tests/Dockerfile .

build-debian-package:
	docker build $(DOCKER_PLATFORM) --target debian-packager --build-arg DEBUG=$(debug) --build-arg COVERAGE=$(coverage) --build-arg SANITIZE=$(sanitize) --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION) -t $(DEBIAN_IMG) -f Dockerfile .

build-tests-debian-packages: build-emulator-builder-image
	docker build $(DOCKER_PLATFORM) --target tests-debian-packager --build-arg MACHINE_EMULATOR_VERSION=$(MACHINE_EMULATOR_VERSION) --build-arg TAG=$(TAG) -t cartesi/machine-emulator:tests-debian-packager -f tests/Dockerfile .
	$(MAKE) copy-tests-debian-packages

copy-tests-debian-packages:
	docker create --name tests-debian-packages $(DOCKER_PLATFORM) cartesi/machine-emulator:tests-debian-packager
	docker cp tests-debian-packages:/usr/src/emulator/$(TESTS_DEB_FILENAME) .
	docker cp tests-debian-packages:/usr/src/emulator/$(TESTS_DATA_DEB_FILENAME) .
	docker rm tests-debian-packages

copy:
	docker create --name uarch-ram-bin $(DOCKER_PLATFORM) $(DEBIAN_IMG)
	docker cp uarch-ram-bin:/usr/src/emulator/$(DEB_FILENAME) .
	docker cp uarch-ram-bin:/usr/src/emulator/src/machine-c-version.h .
	docker cp uarch-ram-bin:/usr/src/emulator/uarch/uarch-ram.bin .
	docker cp uarch-ram-bin:/usr/src/emulator/uarch/uarch-pristine-ram.c .
	docker cp uarch-ram-bin:/usr/src/emulator/uarch/uarch-pristine-hash.c .
	docker rm uarch-ram-bin

check-linux-env:
	@if docker images $(DOCKER_PLATFORM) -q cartesi/machine-emulator:linux-env 2>/dev/null | grep -q .; then \
		echo "Docker image cartesi/machine-emulator:linux-env exists"; \
	else \
		echo "Docker image cartesi/machine-emulator:linux-env does not exist. Creating:"; \
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
		cartesi/machine-emulator:linux-env /bin/bash

linux-env-exec: check-linux-env
	@docker run --hostname linux-env --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`:/opt/cartesi/machine-emulator \
		-w /opt/cartesi/machine-emulator \
		cartesi/machine-emulator:linux-env /bin/bash -c "$(CONTAINER_COMMAND)"

uarch-with-linux-env:
	@$(MAKE) linux-env-exec CONTAINER_COMMAND="make uarch"

zkarch-with-linux-env:
	@$(MAKE) linux-env-exec CONTAINER_COMMAND="make zkarch"

# Create install directories
$(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH) $(LUA_INSTALL_PATH) $(LUA_INSTALL_CPATH) $(LUA_INSTALL_CPATH)/cartesi $(LUA_INSTALL_PATH)/cartesi $(INC_INSTALL_PATH) $(IMAGES_INSTALL_PATH) $(UARCH_INSTALL_PATH) $(TESTS_DATA_INSTALL_PATH) $(TESTS_SCRIPTS_INSTALL_PATH) $(TESTS_LUA_INSTALL_PATH):
	mkdir -m 0755 -p $@

install-headers: $(INC_INSTALL_PATH)
	$(INSTALL_FILE) $(EMU_TO_INC) $(INC_INSTALL_PATH)

install-static-libs: $(LIB_INSTALL_PATH)
	$(INSTALL_FILE) $(EMU_TO_LIB_A) $(LIB_INSTALL_PATH)
	$(STRIP_STATIC) $(subst src/,$(LIB_INSTALL_PATH)/,$(EMU_TO_LIB_A))

install-shared-libs: $(LIB_INSTALL_PATH)
	$(INSTALL_EXEC) $(EMU_TO_LIB) $(LIB_INSTALL_PATH)
	$(SYMLINK) $(LIBCARTESI_SO) $(LIB_INSTALL_PATH)/$(LIBCARTESI)
	$(SYMLINK) $(LIBCARTESI_SO_JSONRPC) $(LIB_INSTALL_PATH)/$(LIBCARTESI_JSONRPC)
	$(STRIP_SHARED) $(subst src/,$(LIB_INSTALL_PATH)/,$(EMU_TO_LIB))

install-lua-libs: $(LUA_INSTALL_PATH)/cartesi $(LUA_INSTALL_CPATH)/cartesi
	$(INSTALL_FILE) $(EMU_LUA_TO_BIN) $(LUA_INSTALL_PATH)
	$(INSTALL_FILE) $(EMU_TO_LUA_PATH) $(LUA_INSTALL_PATH)/cartesi
	$(INSTALL_EXEC) $(EMU_TO_LUA_CPATH) $(LUA_INSTALL_CPATH)
	$(INSTALL_EXEC) $(EMU_TO_LUA_CARTESI_CPATH) $(LUA_INSTALL_CPATH)/cartesi
	$(STRIP_SHARED) $(subst src/,$(LUA_INSTALL_CPATH)/,$(EMU_TO_LUA_CPATH))
	$(STRIP_SHARED) $(subst src/,$(LUA_INSTALL_CPATH)/,$(EMU_TO_LUA_CARTESI_CPATH))

install-bins: $(BIN_INSTALL_PATH)
	$(INSTALL_EXEC) $(EMU_TO_BIN) $(BIN_INSTALL_PATH)
	$(STRIP_BINARY) $(subst src/,$(BIN_INSTALL_PATH)/,$(EMU_TO_BIN))

install-lua-bins: $(BIN_INSTALL_PATH)
	cat tools/template/cartesi-machine.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_IMAGES_PATH|$(IMAGES_RUNTIME_PATH)|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/cartesi-machine
	cat tools/template/cartesi-machine-stored-hash.template | sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(LUA_RUNTIME_PATH)|g' > $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash
	$(CHMOD_EXEC) $(BIN_INSTALL_PATH)/cartesi-machine $(BIN_INSTALL_PATH)/cartesi-machine-stored-hash

install-shared-files: $(IMAGES_INSTALL_PATH)
	$(INSTALL_DIR) tools/gdb $(SHARE_INSTALL_PATH)/gdb

install: install-headers install-static-libs install-shared-libs install-lua-libs install-bins install-lua-bins install-shared-files

install-uarch: install $(UARCH_INSTALL_PATH)
	$(INSTALL_FILE) uarch/$(UARCH_TO_SHARE) $(UARCH_INSTALL_PATH)

debian-package: install
	mkdir -p $(DESTDIR)/DEBIAN $(DOC_INSTALL_PATH)
	$(INSTALL_FILE) COPYING $(DOC_INSTALL_PATH)/copyright
	sed 's|ARG_VERSION|$(MACHINE_EMULATOR_VERSION)|g;s|ARG_ARCH|$(DEB_ARCH)|g' tools/template/control.template > $(DESTDIR)/DEBIAN/control
	dpkg-deb -Zxz --root-owner-group --build $(DESTDIR) $(DEB_FILENAME)

install-tests-data: | $(TESTS_DATA_INSTALL_PATH)
	$(INSTALL_DIR) $(TESTS_DATA_TO_TESTS_DATA_PATH) $(TESTS_DATA_INSTALL_PATH)

install-tests: | $(LUA_INSTALL_PATH) $(BIN_INSTALL_PATH) $(TESTS_SCRIPTS_INSTALL_PATH) $(TESTS_LUA_INSTALL_PATH)
	$(INSTALL_EXEC) $(TESTS_TO_BIN) $(BIN_INSTALL_PATH)
	$(INSTALL_DIR) $(TESTS_LUA_TO_LUA_PATH) $(LUA_INSTALL_PATH)
	$(INSTALL_DIR) $(TESTS_LUA_TO_TEST_LUA_PATH) $(TESTS_LUA_INSTALL_PATH)
	$(INSTALL_DIR) $(TESTS_SCRIPTS_TO_TEST_SCRIPTS_PATH) $(TESTS_SCRIPTS_INSTALL_PATH)
	sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(TESTS_LUA_RUNTIME_PATH)|g;s|ARG_TESTS_PATH|$(TESTS_DATA_RUNTIME_PATH)/machine|g' tools/template/cartesi-machine-tests.template > $(BIN_INSTALL_PATH)/cartesi-machine-tests
	sed 's|ARG_LUA_PATH|$(LUA_RUNTIME_PATH)/?.lua|g;s|ARG_LUA_CPATH|$(LUA_RUNTIME_CPATH)/?.so|g;s|ARG_LUA_RUNTIME_PATH|$(TESTS_LUA_RUNTIME_PATH)|g;s|ARG_TESTS_UARCH_PATH|$(TESTS_DATA_RUNTIME_PATH)/uarch|g' tools/template/uarch-riscv-tests.template > $(BIN_INSTALL_PATH)/uarch-riscv-tests
	$(CHMOD_EXEC) $(BIN_INSTALL_PATH)/cartesi-machine-tests $(BIN_INSTALL_PATH)/uarch-riscv-tests

tests-data-debian-package: install-tests-data
	mkdir -p $(DESTDIR)/DEBIAN $(TESTS_DATA_DOC_INSTALL_PATH)
	$(INSTALL_FILE) tools/template/tests-data-copyright.template $(TESTS_DATA_DOC_INSTALL_PATH)/tests-data-copyright
	sed 's|ARG_VERSION|$(MACHINE_EMULATOR_VERSION)|g;s|ARG_ARCH|$(DEB_ARCH)|g' tools/template/tests-data-control.template > $(DESTDIR)/DEBIAN/control
	dpkg-deb -Zxz --root-owner-group --build $(DESTDIR) $(TESTS_DATA_DEB_FILENAME)

tests-debian-package: install-tests
	mkdir -p $(DESTDIR)/DEBIAN $(TESTS_DOC_INSTALL_PATH)
	$(INSTALL_FILE) tools/template/tests-copyright.template $(TESTS_DOC_INSTALL_PATH)/copyright
	sed 's|ARG_VERSION|$(MACHINE_EMULATOR_VERSION)|g;s|ARG_ARCH|$(DEB_ARCH)|g' tools/template/tests-control.template > $(DESTDIR)/DEBIAN/control
	dpkg-deb -Zxz --root-owner-group --build $(DESTDIR) $(TESTS_DEB_FILENAME)

create-generated-files-patch: $(ADD_GENERATED_FILES_DIFF)

$(ADD_GENERATED_FILES_DIFF): $(GENERATED_FILES)
	git add -f $(GENERATED_FILES)
	git diff --no-prefix --staged --output=$(ADD_GENERATED_FILES_DIFF)
	git reset -- $(GENERATED_FILES)

.PHONY: help all submodules doc clean distclean src luacartesi hash uarch zkarch \
	create-generated-files-patch $(SUBDIRS) $(SUBCLEAN)

