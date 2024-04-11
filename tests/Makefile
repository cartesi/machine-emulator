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

PREFIX = /opt/cartesi
INSTALLDIR = $(PREFIX)/tests

LUA_BIN ?= $(shell which lua5.4)

TOOLCHAIN_DOCKER_REPOSITORY ?= cartesi/toolchain
TOOLCHAIN_TAG ?= 0.17.0

BUILDDIR = $(abspath build)
RISCV_PREFIX = riscv64-cartesi-linux-gnu-

MACHINE_EMULATOR_SRC_DIR = $(abspath ../src)

MACHINE_EMULATOR_SO_VERSION= $(shell make -sC ../src so-version)

TARGETS_WITH_TOOLCHAIN = $(addsuffix -with-toolchain,build-tests-machine build-tests-uarch machine uarch misc riscv-tests riscv-arch-test)

CARTESI_IMAGES_PATH ?= $(abspath ./build/images)
CARTESI_MACHINES_PATH ?= $(abspath ./build/machines)
CARTESI_TESTS_PATH ?= $(abspath ./build/machine)
CARTESI_TESTS_UARCH_PATH ?= $(abspath ./build/uarch)

export CARTESI_IMAGES_PATH
export CARTESI_MACHINES_PATH
export CARTESI_TESTS_PATH
export CARTESI_TESTS_UARCH_PATH

TARGET_OS ?= $(shell uname -s)
ifeq ($(TARGET_OS),Darwin)
LIBCARTESI_SO=libcartesi-$(MACHINE_EMULATOR_SO_VERSION).dylib
LIBCARTESI_SO_JSONRPC=libcartesi_jsonrpc-$(MACHINE_EMULATOR_SO_VERSION).dylib

NUM_JOBS := $(shell sysctl -n hw.ncpu)
else
LIBCARTESI_SO=libcartesi-$(MACHINE_EMULATOR_SO_VERSION).so
LIBCARTESI_SO_JSONRPC=libcartesi_jsonrpc-$(MACHINE_EMULATOR_SO_VERSION).so

NUM_JOBS := $(shell nproc)
endif

ifeq ($(coverage),yes)
NUM_JOBS = 1
endif

CREATE_MACHINES_OPTS ?=
ifeq ($(rollup_init),yes)
CREATE_MACHINES_OPTS += --rollup-init
endif

COVERAGE_TOOLCHAIN?=gcc
COVERAGE_OUTPUT_DIR=$(BUILDDIR)/coverage
COVERAGE_WORKLOAD=\
	dhrystone 1000000; \
	whetstone 10000
COVERAGE_SOURCES=$(filter-out ../src/%.pb.h, $(wildcard ../src/*.h) $(wildcard ../src/*.cpp))

ifeq ($(sanitize),yes)
ifeq ($(TARGET_OS),Darwin)
LIBASAN_SO=$(shell realpath `$(CC) -print-file-name=libclang_rt.asan_osx_dynamic.dylib`)
LD_PRELOAD_PREFIX=DYLD_INSERT_LIBRARIES="$(LIBASAN_SO)"
else
LIBASAN_SO=$(shell realpath `$(CC) -print-file-name=libasan.so`)
LIBSTDCPP_SO=$(shell realpath `$(CC) -print-file-name=libstdc++.so`)
LD_PRELOAD="$(LIBASAN_SO) $(LIBSTDCPP_SO)"
LD_PRELOAD_PREFIX=LD_PRELOAD=$(LD_PRELOAD)
endif
LUA=$(LD_PRELOAD_PREFIX) $(LUA_BIN)
else
LUA=$(LUA_BIN)
endif

RUN_ARCH_TEST = $(LUA) $(abspath ./lua/run-rv64i-arch-test.lua)

CARTESI_IMAGES = $(CARTESI_IMAGES_PATH)/linux.bin

STYLUA=stylua
STYLUA_FLAGS=--indent-type Spaces --collapse-simple-statement Always

build-tests-all: misc build-tests-machine-with-toolchain build-tests-uarch-with-toolchain images

build-tests-machine: machine riscv-tests

build-tests-uarch: uarch riscv-arch-test

build-tests-misc: misc

build-tests-images: images

build-tests-uarch-with-toolchain uarch-with-toolchain riscv-arch-test-with-toolchain: TOOLCHAIN_TAG:=0.17.0-rv64ima-lp64

machine uarch misc:
	@$(MAKE) $(BUILDDIR)/$@
	@$(MAKE) -C $@ BUILDDIR=$(BUILDDIR)/$@

riscv-tests: $(BUILDDIR)/riscv-tests $(BUILDDIR)/machine
	@cd $(BUILDDIR)/$@ && ../../../third-party/riscv-tests/configure
	@$(MAKE) -C $(BUILDDIR)/$@ RISCV_PREFIX=$(RISCV_PREFIX) isa
	@cp -a $(BUILDDIR)/riscv-tests/isa/*.bin $(BUILDDIR)/riscv-tests/isa/*.dump $(BUILDDIR)/machine
	@cd $(BUILDDIR)/riscv-tests/isa && find . -maxdepth 1 -type f ! -name "*.*" -exec cp -a {} $(BUILDDIR)/machine/{}.elf \;
	@rm -rf $(BUILDDIR)/riscv-tests

riscv-arch-test:
	@$(MAKE) $(BUILDDIR)/uarch-$@
	@$(MAKE) -C ../third-party/riscv-arch-test/riscv-target/cartesi TOOLCHAIN_PREFIX=$(RISCV_PREFIX) MACHINE_EMULATOR_SRC_DIR=$(MACHINE_EMULATOR_SRC_DIR)
	@$(MAKE) -C ../third-party/riscv-arch-test build XLEN=64 RISCV_TARGET=cartesi RISCV_ISA=rv64i RISCV_DEVICE=I TOOLCHAIN_PREFIX=$(RISCV_PREFIX) MACHINE_EMULATOR_SRC_DIR=$(MACHINE_EMULATOR_SRC_DIR) WORK=$(BUILDDIR)/uarch-$@ JOBS=-j$$(nproc)

$(BUILDDIR)/%:
	@mkdir -p $@

$(CARTESI_IMAGES): | $(CARTESI_IMAGES_PATH)
	@wget -nc -i dependencies -P $(CARTESI_IMAGES_PATH)
	@shasum -ca 256 dependencies.sha256
	@cd $(CARTESI_IMAGES_PATH) && ln -s rootfs-tools-v0.15.0-output-unification-test3.ext2 rootfs.ext2
	@cd $(CARTESI_IMAGES_PATH) && ln -s linux-6.5.13-ctsi-1-v0.20.0.bin linux.bin

images: | $(CARTESI_IMAGES)

dependencies.sha256:
	@shasum -a 256 $(BUILDDIR)/images/* > $@

clean:
	@$(MAKE) -C ../third-party/riscv-arch-test/riscv-target/cartesi clean
	@$(MAKE) -C misc clean
	@rm -f *.profdata *.profraw *.gcda *.gcov
	@rm -rf $(BUILDDIR)

toolchain-env:
	@docker run --hostname toolchain-env -it --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`/../:/usr/src/emulator \
		-w /usr/src/emulator/tests \
		$(TOOLCHAIN_DOCKER_REPOSITORY):$(TOOLCHAIN_TAG) /bin/bash

toolchain-exec:
	@docker run --hostname toolchain-env --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`/../:/usr/src/emulator \
		-w /usr/src/emulator/tests \
		$(TOOLCHAIN_DOCKER_REPOSITORY):$(TOOLCHAIN_TAG) $(CONTAINER_COMMAND)

emulator-builder-exec:
	@docker run --hostname toolchain-env --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`:/usr/src/emulator/tests \
		-w /usr/src/emulator/tests \
		cartesi/machine-emulator:builder $(CONTAINER_COMMAND)

$(TARGETS_WITH_TOOLCHAIN):
	$(MAKE) toolchain-exec CONTAINER_COMMAND="make -j\$$(nproc) $(subst -with-toolchain,,$@)" TOOLCHAIN_DOCKER_REPOSITORY=$(TOOLCHAIN_DOCKER_REPOSITORY) TOOLCHAIN_TAG=$(TOOLCHAIN_TAG)

build-tests-misc-with-builder-image:
	$(MAKE) emulator-builder-exec CONTAINER_COMMAND="make -j\$$(nproc) build-tests-misc"

create-machines $(CARTESI_MACHINES_PATH):
	@./lua/create-machines.lua $(CREATE_MACHINES_OPTS)

clean-machines:
	@rm -rf build/machines/tests

test-machine:
	$(LUA) ./lua/cartesi-machine-tests.lua --jobs=$(NUM_JOBS) run

test-uarch:
	$(LUA) ./lua/cartesi-machine-tests.lua --jobs=$(NUM_JOBS) run_uarch

test-uarch-compare:
	$(LUA) ./lua/cartesi-machine-tests.lua --test="^rv64ui.*$$" --jobs=$(NUM_JOBS) run_host_and_uarch

test-uarch-rv64ui:
	$(LUA) ./lua/uarch-riscv-tests.lua run

test-uarch-interpreter:
	$(MAKE) -C ../third-party/riscv-arch-test verify XLEN=64 RISCV_TARGET=cartesi RISCV_ISA=rv64i RISCV_DEVICE=I WORK=$(BUILDDIR)/uarch-riscv-arch-test RUN_ARCH_TEST='$(RUN_ARCH_TEST)'

test-hash:
	$(LD_PRELOAD_PREFIX) ./build/misc/test-merkle-tree-hash --log2-root-size=30 --log2-leaf-size=12 --input=build/misc/test-merkle-tree-hash

test-jsonrpc: | $(CARTESI_IMAGES) $(CARTESI_MACHINES_PATH)
	./scripts/test-jsonrpc-server.sh ../src/jsonrpc-remote-cartesi-machine '$(LUA) ../src/cartesi-machine.lua' '$(LUA) ./lua/cartesi-machine-tests.lua' '$(LUA)'

test-lua: | $(CARTESI_IMAGES)
	./scripts/run-lua-tests.sh '$(LUA)'

test-c-api: | $(CARTESI_IMAGES)
	./build/misc/test-machine-c-api

test-save-and-load: | $(CARTESI_IMAGES)
	./scripts/test-save-and-load.sh '$(LUA) ../src/cartesi-machine.lua'

test-misc: test-c-api test-hash test-save-and-load

test-generate-uarch-logs: $(BUILDDIR)/uarch-riscv-tests-json-logs
	$(LUA) ./lua/uarch-riscv-tests.lua --output-dir=$(BUILDDIR)/uarch-riscv-tests-json-logs --proofs --proofs-frequency=1 --create-uarch-reset-log json-step-logs
	tar -czf uarch-riscv-tests-json-logs.tar.gz -C $(BUILDDIR) uarch-riscv-tests-json-logs

coverage-machine:
	$(LUA) ../src/cartesi-machine.lua -- "$(COVERAGE_WORKLOAD)"
	# Test interactive mode (to cover mcycle overwriting)
	echo uname | $(LUA) ../src/cartesi-machine.lua -i sh
	# Test max mcycle (to cover max mcycle branch)
	$(LUA) ../src/cartesi-machine.lua --max-mcycle=1

coverage-uarch:
	$(LUA) ./lua/cartesi-machine-tests.lua --test=".*csr.*" run_uarch
	$(LUA) ./lua/cartesi-machine-tests.lua --test=".*csr.*" run_host_and_uarch
	$(LUA) ./lua/htif-yield.lua --uarch

ifeq ($(COVERAGE_TOOLCHAIN),gcc)
LCOV_CONFIG=--rc lcov_branch_coverage=1
coverage-report: $(COVERAGE_OUTPUT_DIR)
	rm -f ../src/*.pb.cc.gcda ../src/*.pb.h.gcda
	gcov --demangled-names --relative-only --branch-probabilities ../src/*.gcda
	lcov --capture --directory ../src/ --no-external --exclude '*.pb.*' -o coverage.info $(LCOV_CONFIG) --quiet
	genhtml --quiet coverage.info --output-directory $(COVERAGE_OUTPUT_DIR)/gcc $(LCOV_CONFIG)
	lcov --list coverage.info $(LCOV_CONFIG) | tee $(COVERAGE_OUTPUT_DIR)/coverage.txt
	lcov --summary coverage.info $(LCOV_CONFIG) | tee -a $(COVERAGE_OUTPUT_DIR)/coverage.txt
else ifeq ($(COVERAGE_TOOLCHAIN),clang)
coverage-report: $(COVERAGE_OUTPUT_DIR)
	llvm-profdata merge -sparse $(shell find . -name 'coverage*.profraw') -o coverage.profdata
	llvm-cov show -format=html -output-dir=$(COVERAGE_OUTPUT_DIR)/clang -instr-profile=coverage.profdata \
		../src/cartesi.so \
		-object ../src/cartesi/jsonrpc.so \
		-object ../src/$(LIBCARTESI_SO) \
		-object ../src/jsonrpc-remote-cartesi-machine \
		$(COVERAGE_SOURCES)

export LLVM_PROFILE_FILE=coverage-%p.profraw
endif

test: test-save-and-load test-machine test-uarch test-uarch-rv64ui test-uarch-interpreter test-lua test-jsonrpc test-c-api test-hash

lint format check-format:
	@$(MAKE) -C misc $@

format-lua:
	@$(STYLUA) $(STYLUA_FLAGS) lua/

check-format-lua:
	@$(STYLUA) $(STYLUA_FLAGS) --check lua/

check-lua:
	luacheck lua/

.PHONY: machine uarch misc riscv-tests riscv-arch-test
