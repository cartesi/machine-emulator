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

LUA ?= $(shell which lua5.4)

TOOLCHAIN_DOCKER_REPOSITORY ?= cartesi/toolchain
TOOLCHAIN_TAG ?= 0.16.0

BUILDDIR = $(abspath build)
RISCV_PREFIX = riscv64-cartesi-linux-gnu-

MACHINE_EMULATOR_SRC_DIR = $(abspath ../src)

TARGETS_WITH_TOOLCHAIN = $(addsuffix -with-toolchain,build-tests-machine build-tests-uarch machine uarch misc riscv-tests riscv-arch-test)

CARTESI_IMAGES_PATH ?= $(abspath ./build/images)
CARTESI_TESTS_PATH ?= $(abspath ./build/machine)
CARTESI_TESTS_UARCH_PATH ?= $(abspath ./build/uarch)

RUN_ARCH_TEST = $(LUA) $(abspath ./lua/run-rv64i-arch-test.lua)

CARTESI_IMAGES = $(CARTESI_IMAGES_PATH)/linux.bin

export CARTESI_IMAGES_PATH
export CARTESI_TESTS_PATH
export CARTESI_TESTS_UARCH_PATH

OS := $(shell uname -s)
ifeq ($(OS),Linux)
    NUM_JOBS := $(shell nproc)
else ifeq ($(OS),Darwin) # macOS
    NUM_JOBS := $(shell sysctl -n hw.ncpu)
else ifneq (,$(findstring CYGWIN,$(OS))) # Cygwin
    NUM_JOBS := $(shell nproc)
else ifneq (,$(findstring MSYS,$(OS))) # MSYS/MINGW
    NUM_JOBS := $(shell nproc)
else ifneq (,$(findstring MINGW,$(OS))) # Another check for MINGW
    NUM_JOBS := $(shell nproc)
else
    NUM_JOBS := 1
endif

build-tests-all: misc build-tests-machine-with-toolchain build-tests-uarch-with-toolchain images

build-tests-machine: machine riscv-tests

build-tests-uarch: uarch riscv-arch-test

build-tests-misc: misc

build-tests-images: images

build-tests-uarch-with-toolchain uarch-with-toolchain riscv-arch-test-with-toolchain: TOOLCHAIN_TAG:=0.16.0-rv64ima-lp64

machine uarch misc:
	@$(MAKE) $(BUILDDIR)/$@
	@$(MAKE) -C $@ BUILDDIR=$(BUILDDIR)/$@

riscv-tests:
	@cd $@ && ./configure
	@$(MAKE) -C $@ RISCV_PREFIX=$(RISCV_PREFIX)
	@$(MAKE) copy-riscv-tests

riscv-arch-test:
	@$(MAKE) $(BUILDDIR)/uarch-$@
	@$(MAKE) -C $@/riscv-target/cartesi TOOLCHAIN_PREFIX=$(RISCV_PREFIX) MACHINE_EMULATOR_SRC_DIR=$(MACHINE_EMULATOR_SRC_DIR)
	@$(MAKE) -C $@ build XLEN=64 RISCV_TARGET=cartesi RISCV_ISA=rv64i RISCV_DEVICE=I TOOLCHAIN_PREFIX=$(RISCV_PREFIX) MACHINE_EMULATOR_SRC_DIR=$(MACHINE_EMULATOR_SRC_DIR) WORK=$(BUILDDIR)/uarch-$@ JOBS=-j$$(nproc)

$(BUILDDIR)/%:
	@mkdir -p $(BUILDDIR)/$*

$(CARTESI_IMAGES): | $(CARTESI_IMAGES_PATH)
	@wget -nc -i dependencies -P $(CARTESI_IMAGES_PATH)
	@shasum -ca 256 dependencies.sha256
	@cd $(CARTESI_IMAGES_PATH) && ln -s rootfs-tools-v0.14.1.ext2 rootfs.ext2
	@cd $(CARTESI_IMAGES_PATH) && ln -s linux-6.5.9-ctsi-1-v0.19.1.bin linux.bin

images: | $(CARTESI_IMAGES)

dependencies.sha256:
	@shasum -a 256 $(BUILDDIR)/images/* > $@

copy-riscv-tests: $(BUILDDIR)/machine
	@cp -a riscv-tests/isa/*.bin riscv-tests/isa/*.dump $(BUILDDIR)/machine
	@cd riscv-tests/isa && find . -maxdepth 1 -type f ! -name "*.*" -exec cp -a {} $(BUILDDIR)/machine/{}.elf \;

clean:
	@$(MAKE) -C riscv-arch-test/riscv-target/cartesi clean
	@rm -rf $(BUILDDIR)

toolchain-env:
	@docker run --hostname toolchain-env -it --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`/../:/opt/cartesi/machine-emulator \
		-w /opt/cartesi/machine-emulator/tests \
		$(TOOLCHAIN_DOCKER_REPOSITORY):$(TOOLCHAIN_TAG)

toolchain-exec:
	@docker run --hostname toolchain-env --rm \
		-e USER=$$(id -u -n) \
		-e GROUP=$$(id -g -n) \
		-e UID=$$(id -u) \
		-e GID=$$(id -g) \
		-v `pwd`/../:/opt/cartesi/machine-emulator \
		-w /opt/cartesi/machine-emulator/tests \
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

test-machine:
	$(LUA) ./lua/cartesi-machine-tests.lua --jobs=$(NUM_JOBS) run

test-uarch:
	$(LUA) ./lua/cartesi-machine-tests.lua --jobs=$(NUM_JOBS) run_uarch

test-uarch-compare:
	$(LUA) ./lua/cartesi-machine-tests.lua --test="^rv64ui.*$$" --jobs=$(NUM_JOBS) run_host_and_uarch

test-uarch-rv64ui:
	$(LUA) ./lua/uarch-riscv-tests.lua run

test-uarch-interpreter:
	$(MAKE) -C riscv-arch-test -n verify XLEN=64 RISCV_TARGET=cartesi RISCV_ISA=rv64i RISCV_DEVICE=I WORK=$(BUILDDIR)/uarch-riscv-arch-test RUN_ARCH_TEST="$(RUN_ARCH_TEST)"

test-hash:
	$(LD_PRELOAD_PREFIX) ./build/misc/test-merkle-tree-hash --log2-root-size=30 --log2-leaf-size=12 --input=build/misc/test-merkle-tree-hash

test-grpc: | $(CARTESI_IMAGES)
	./scripts/test-grpc-server.sh ../src/remote-cartesi-machine '$(LUA) ../src/cartesi-machine.lua' '$(LUA) ./lua/cartesi-machine-tests.lua' '$(LUA)'

test-jsonrpc: | $(CARTESI_IMAGES)
	./scripts/test-jsonrpc-server.sh ../src/jsonrpc-remote-cartesi-machine '$(LUA) ../src/cartesi-machine.lua' '$(LUA) ./lua/cartesi-machine-tests.lua' '$(LUA)'

test-lua: | $(CARTESI_IMAGES)
	./scripts/run-lua-tests.sh $(LD_PRELOAD)

test-c-api: | $(CARTESI_IMAGES)
	$(LD_PRELOAD_PREFIX) ./build/misc/test-machine-c-api

test-save-and-load: | $(CARTESI_IMAGES)
	./scripts/test-save-and-load.sh '$(LUA) ../src/cartesi-machine.lua'

test-uarch-for-coverage:
	$(LUA) ./lua/cartesi-machine-tests.lua --test=".*csr.*" run_uarch
	$(LUA) ./lua/cartesi-machine-tests.lua --test=".*csr.*" run_host_and_uarch
	$(LUA) ./lua/htif-yield.lua --uarch

test-generate-uarch-logs: $(BUILDDIR)/uarch-riscv-tests-json-logs
	$(LUA) ./lua/uarch-riscv-tests.lua --output-dir=$(BUILDDIR)/uarch-riscv-tests-json-logs --proofs --proofs-frequency=1 json-step-logs
	$(LUA) ./lua/uarch-riscv-tests.lua --output-dir=$(BUILDDIR)/uarch-riscv-tests-json-logs --proofs json-reset-log
	tar -czf uarch-riscv-tests-json-logs.tar.gz -C $(BUILDDIR) uarch-riscv-tests-json-logs

test: test-save-and-load test-machine test-uarch test-uarch-rv64ui test-uarch-interpreter test-lua test-grpc test-jsonrpc test-c-api

.PHONY: machine uarch misc riscv-tests riscv-arch-test

# The following is currently not in used.
#CYCLE_PERIOD ?= 13
#HASH_DIR = hashes/$(CYCLE_PERIOD)
#LOG_DIR = logs/$(CYCLE_PERIOD)
#GROUND_TRUTH_DIR ?= ground-truth
#CONCURRENCY_MERKLE_TREE ?= 0
#
#ifneq ($(wildcard $(CARTESI_TESTS_PATH)),)
#TESTS=$(shell find $(CARTESI_TESTS_PATH) -name '*.bin' -type f -print | xargs basename -a)
#endif
#TEST_HASHES=$(addprefix $(HASH_DIR)/,$(TESTS:.bin=.hashes))
#TEST_LOGS=$(addprefix $(LOG_DIR)/,$(TESTS:.bin=.json.br))
#TRUTH_HASHES=$(addprefix $(GROUND_TRUTH_DIR)/,$(TEST_HASHES))
#TRUTH_LOGS=$(addprefix $(GROUND_TRUTH_DIR)/,$(TEST_LOGS))
#
#HASH_EACH_CYCLE_DIR=
#TEST_EACH_CYCLE_HASHES=
#ifneq ($(strip $(CYCLE_PERIOD)),1)
#HASH_EACH_CYCLE_DIR = hashes/1
#TEST_EACH_CYCLE_HASHES=$(addprefix $(HASH_EACH_CYCLE_DIR)/,$(TESTS:.bin=.hashes))
#endif
#
#$(HASH_DIR) $(LOG_DIR) $(GROUND_TRUTH_DIR)/$(HASH_DIR) $(GROUND_TRUTH_DIR)/$(LOG_DIR) $(HASH_EACH_CYCLE_DIR):
#	mkdir -p $@
#
#test-hashes: $(TEST_HASHES)
#
#test-logs: $(TEST_LOGS)
#
#truth-hashes: $(TRUTH_HASHES)
#
#truth-logs: $(TRUTH_LOGS)
#
#compare-hashes: | $(TEST_EACH_CYCLE_HASHES) $(TEST_HASHES)
#	@for t in $(TESTS) ; do \
#		result=$$(tail -n +2 -q $(HASH_DIR)/$${t%.bin}.hashes $(HASH_EACH_CYCLE_DIR)/$${t%.bin}.hashes | sort -s -n | uniq | awk -v step=-1 '{pline=line; line=$$0; pstep=step; step=$$1; if (pstep >= 0 && pstep == step) {print(pline); print(line); exit 1;}}'); \
#		if [ "$$result" != "" ]; then \
#			echo $$t ;\
#			echo "$$result"; \
#			exit 1; \
#		fi \
#	done
#
#$(HASH_EACH_CYCLE_DIR)/%.hashes: $(CARTESI_TESTS_PATH)/%.bin | $(HASH_EACH_CYCLE_DIR)
#	$(LUA) cartesi-machine-tests.lua --test-path=$(CARTESI_TESTS_PATH) --test="$(notdir $<)" --periodic-action=1 --output=$@ --concurrency=update_merkle_tree:$(CONCURRENCY_MERKLE_TREE) hash
#
#$(HASH_DIR)/%.hashes: $(CARTESI_TESTS_PATH)/%.bin | $(HASH_DIR)
#	$(LUA) cartesi-machine-tests.lua --test-path=$(CARTESI_TESTS_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$@ --concurrency=update_merkle_tree:$(CONCURRENCY_MERKLE_TREE) hash
#	diff $@ $(GROUND_TRUTH_DIR)/$@
#
#$(LOG_DIR)/%.json.br: $(CARTESI_TESTS_PATH)/%.bin $(LOG_DIR)
#	$(LUA) cartesi-machine-tests.lua --test-path=$(CARTESI_TESTS_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$(basename $@) step
#	brotli -j -f $(basename $@)
#	diff $@ $(GROUND_TRUTH_DIR)/$@
#
#$(GROUND_TRUTH_DIR)/$(HASH_DIR)/%.hashes: $(CARTESI_TESTS_PATH)/%.bin | $(GROUND_TRUTH_DIR)/$(HASH_DIR)
#	$(LUA) cartesi-machine-tests.lua --test-path=$(CARTESI_TESTS_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$@ --concurrency=update_merkle_tree:$(CONCURRENCY_MERKLE_TREE) hash
#
#$(GROUND_TRUTH_DIR)/$(LOG_DIR)/%.json.br: $(CARTESI_TESTS_PATH)/%.bin $(GROUND_TRUTH_DIR)/$(LOG_DIR)
#	$(LUA) cartesi-machine-tests.lua --test-path=$(CARTESI_TESTS_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$(basename $@) step
#	brotli -j -f $(basename $@)

