# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LUA_BIN          ?= lua5.4
LUA              ?= $(LUA_BIN)
EMULATOR_DIR     := $(abspath ..)
CARTESI_SP1_CLI  := $(abspath rust/target/release/cartesi-sp1-cli)
GUEST_ELF        := $(abspath cpp/guest.elf)
MACHINE_TEST     ?=

TARGET_OS ?= $(shell uname -s)
ifeq ($(TARGET_OS),Darwin)
NUM_JOBS ?= $(shell sysctl -n hw.ncpu)
else
NUM_JOBS ?= $(shell nproc)
endif

# Fixture dirs are absolute so they survive the cd into $(EMULATOR_DIR) in the recipe.
FIXTURES_DIR     := test/fixtures
MACHINE_FIXTURES_DIR := $(abspath $(FIXTURES_DIR)/cartesi-machine-tests)
ONE_MCYCLE_DIR   := $(abspath $(FIXTURES_DIR)/one-mcycle)
STEP_LOG         := $(ONE_MCYCLE_DIR)/one-mcycle.log
PROOF            := $(abspath $(FIXTURES_DIR))/one-mcycle.groth16.proof
SEAL             := $(abspath solidity/test/fixtures/seal.bin)
JOURNAL          := $(abspath $(FIXTURES_DIR))/journal.bin

# Proving backend, chosen from the environment so a host with a GPU uses it
# without being told. Override to force a configuration:
#   make SP1_FEATURES=              CPU only
#   make SP1_FEATURES=cuda          STARK on GPU (the usual GPU build)
#   make SP1_FEATURES=cuda,groth16-cuda
#                                   also routes the Groth16 wrap through ICICLE.
#                                   Needs a Go toolchain, ICICLE shared libraries
#                                   and an ICICLE licence; without a licence it
#                                   silently falls back to CPU.
SP1_FEATURES ?= $(shell command -v nvidia-smi >/dev/null 2>&1 && echo cuda)
PROVER       ?= $(if $(findstring cuda,$(SP1_FEATURES)),cuda,cpu)

# Without a GPU the Groth16 wrap runs in the sp1-gnark container, published for
# linux/amd64 only. On other hosts ask Docker for the amd64 image so it runs
# under emulation instead of failing to resolve a manifest.
HOST_ARCH := $(shell uname -m)
ifeq ($(PROVER),cpu)
ifneq ($(HOST_ARCH),x86_64)
export DOCKER_DEFAULT_PLATFORM = linux/amd64
endif
endif

export SP1_FEATURES

.PHONY: all cpp rust solidity test test-solidity fixtures seal clean help

help:
	@echo "SP1 backend"
	@echo ""
	@echo "  make all         Build the guest and the host CLI"
	@echo "  make fixtures    Record step-log fixtures (needs a built emulator)"
	@echo "  make seal        Prove the one-mcycle fixture to a Groth16 seal"
	@echo "  make test        Run host tests (no GPU required)"
	@echo "  make test-solidity  Run the on-chain tests (needs seal)"
	@echo ""
	@echo "  SP1_FEATURES=$(SP1_FEATURES)   PROVER=$(PROVER)"

all: cpp rust

cpp:
	$(MAKE) -C cpp
	$(MAKE) -C cpp sha-abi-guest.elf

rust:
	$(MAKE) -C rust release

solidity:
	$(MAKE) -C solidity build

# Record fixtures with the emulator's shared recorders:
#   cartesi-machine-tests/  machine step logs
#   one-mcycle/             one 1-mcycle log for the prove -> seal -> on-chain path
#   reject-machine/         structurally-invalid logs the guest must reject
fixtures:
	@mkdir -p $(MACHINE_FIXTURES_DIR)
	# The record-*.lua recorders require an empty output dir (they never delete);
	# clear stale fixtures so a re-run starts clean. The recorders recreate the dirs.
	rm -rf $(abspath $(FIXTURES_DIR))/reject-machine $(ONE_MCYCLE_DIR)
	@cd $(EMULATOR_DIR) && eval $$($(MAKE) env) && \
	  $(LUA) tests/lua/cartesi-machine-tests.lua --jobs=$(NUM_JOBS) --hash-function=sha256 \
	    $(if $(MACHINE_TEST),--test='$(MACHINE_TEST)',) \
	    --test-path=tests/build/machine \
	    --save-step-logs=$(MACHINE_FIXTURES_DIR) run_step && \
	  $(LUA) tests/lua/record-one-mcycle.lua --hash-function=sha256 \
	    --output-dir=$(ONE_MCYCLE_DIR) && \
	  $(LUA) tests/lua/record-adversarial-machine.lua \
	    --fixtures-dir=$(abspath $(FIXTURES_DIR)) \
	    --output-dir=$(abspath $(FIXTURES_DIR))/reject-machine

$(STEP_LOG):
	@echo "$(STEP_LOG) not found; run 'make fixtures' (needs a built emulator)" >&2
	@exit 1

$(CARTESI_SP1_CLI): FORCE
	@$(MAKE) -C rust release

FORCE:

# A Groth16 proof of the one-mcycle log, split into the seal a contract consumes.
# The journal is not kept: it is abi.encode of values the Solidity test states
# directly.
$(SEAL): $(STEP_LOG) $(CARTESI_SP1_CLI) $(GUEST_ELF)
	@mkdir -p $(dir $(SEAL))
	@ROW=$$(sed -n 2p $(ONE_MCYCLE_DIR)/_manifest.csv) && \
	  BEFORE=$$(echo "$$ROW" | cut -d, -f6) && \
	  CYCLES=$$(echo "$$ROW" | cut -d, -f5) && \
	  AFTER=$$(echo "$$ROW" | cut -d, -f7) && \
	  $(CARTESI_SP1_CLI) --guest-elf $(GUEST_ELF) --prover $(PROVER) \
	    prove "$$BEFORE" $(STEP_LOG) "$$CYCLES" "$$AFTER" $(PROOF) groth16 && \
	  $(CARTESI_SP1_CLI) --guest-elf $(GUEST_ELF) seal $(PROOF) $(SEAL) $(JOURNAL)

seal: $(SEAL)

test: cpp rust
	$(MAKE) -C rust test

test-solidity: $(SEAL)
	$(MAKE) -C solidity test

clean:
	$(MAKE) -C cpp clean
	-$(MAKE) -C rust clean
	-$(MAKE) -C solidity clean
	rm -rf $(FIXTURES_DIR)
	rm -f $(SEAL)
