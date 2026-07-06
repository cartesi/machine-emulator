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

# Set RISC0_TEST_DEV_ONLY=1 to skip the full proving pipeline tests.
# By default, `make test` runs both dev-mode interpreter tests and the
# full pipeline (prove -> verify -> compress -> verify-seal -> solidity).
RISC0_TEST_DEV_ONLY ?= 0

LUA_BIN          ?= lua5.4
LUA              ?= $(LUA_BIN)
STEP_LOG_UTIL    := $(abspath ../src/step-log-util.lua)
CARTESI_RISC0_CLI := $(abspath rust/target/debug/cartesi-risc0-cli)
EMULATOR_DIR     := $(abspath ..)
# Restricts which machine tests are recorded (Lua pattern, full match); default = all.
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
RECEIPT          := $(FIXTURES_DIR)/receipt.bin
SEAL             := $(FIXTURES_DIR)/seal.bin
JOURNAL          := $(FIXTURES_DIR)/journal.bin

all: rust

rust: cpp
	@$(MAKE) -C $@

cpp:
	@$(MAKE) -C $@

test: rust test-dev-mode
ifneq ($(RISC0_TEST_DEV_ONLY),1)
test: test-pipeline test-solidity
endif

check-format:
	@$(MAKE) -C rust check-format

format:
	@$(MAKE) -C rust format

test-dev-mode:
	@$(MAKE) -C rust test

test-pipeline: $(SEAL)
	@echo "--- Verifying receipt ---"
	@HASH_BEFORE=$$($(LUA) $(STEP_LOG_UTIL) root-hash-before $(STEP_LOG)) && \
	CYCLE_COUNT=$$($(LUA) $(STEP_LOG_UTIL) requested-cycle-count $(STEP_LOG)) && \
	HASH_AFTER=$$($(LUA) $(STEP_LOG_UTIL) root-hash-after $(STEP_LOG)) && \
	$(CARTESI_RISC0_CLI) verify \
		$(RECEIPT) "$$HASH_BEFORE" "$$CYCLE_COUNT" "$$HASH_AFTER" && \
	echo "--- Verifying seal ---" && \
	$(CARTESI_RISC0_CLI) verify-seal \
		$(SEAL) $(JOURNAL) "$$HASH_BEFORE" "$$CYCLE_COUNT" "$$HASH_AFTER" && \
	echo "--- Pipeline test passed ---"

# Depends on $(SEAL) so parallel make cannot start the Solidity fork tests
# before the pipeline has produced the seal fixture they consume.
test-solidity: $(SEAL)
	@$(MAKE) -C solidity test

# Host-side Rust coverage, mirroring `test`: dev-mode suite always; the real proving
# pipeline is added through an instrumented CLI unless RISC0_TEST_DEV_ONLY=1. Profiles
# accumulate across both (--no-report) and render once at the end. Informational, like
# the solidity-step coverage -- it should never gate CI.
COVERAGE_CLI := cargo llvm-cov run --no-report --locked --bin cartesi-risc0-cli --
COV_RECEIPT  := $(abspath $(FIXTURES_DIR))/coverage-receipt.bin
COV_SEAL     := $(abspath $(FIXTURES_DIR))/coverage-seal.bin
COV_JOURNAL  := $(abspath $(FIXTURES_DIR))/coverage-journal.bin

coverage:
	@$(MAKE) -C rust coverage
ifneq ($(RISC0_TEST_DEV_ONLY),1)
	@$(MAKE) coverage-pipeline
endif
	@$(MAKE) -C rust coverage-report

coverage-pipeline: $(STEP_LOG)
	@echo "--- Instrumented pipeline (prove -> verify -> compress -> verify-seal) ---"
	@HASH_BEFORE=$$($(LUA) $(STEP_LOG_UTIL) root-hash-before $(STEP_LOG)) && \
	CYCLE_COUNT=$$($(LUA) $(STEP_LOG_UTIL) requested-cycle-count $(STEP_LOG)) && \
	HASH_AFTER=$$($(LUA) $(STEP_LOG_UTIL) root-hash-after $(STEP_LOG)) && \
	rm -f $(COV_RECEIPT) $(COV_SEAL) $(COV_JOURNAL) && \
	cd rust && \
	$(COVERAGE_CLI) prove "$$HASH_BEFORE" $(STEP_LOG) "$$CYCLE_COUNT" "$$HASH_AFTER" $(COV_RECEIPT) && \
	$(COVERAGE_CLI) verify $(COV_RECEIPT) "$$HASH_BEFORE" "$$CYCLE_COUNT" "$$HASH_AFTER" && \
	$(COVERAGE_CLI) compress $(COV_RECEIPT) $(COV_SEAL) $(COV_JOURNAL) && \
	$(COVERAGE_CLI) verify-seal $(COV_SEAL) $(COV_JOURNAL) "$$HASH_BEFORE" "$$CYCLE_COUNT" "$$HASH_AFTER" && \
	$(COVERAGE_CLI) image-id

# Generate risc0's fixtures via the emulator's shared recorders (needs a built emulator):
#   cartesi-machine-tests/  machine step logs for dev-mode replay coverage
#   one-mcycle/             one 1-mcycle log for the prove->compress->Sepolia pipeline
#   reject-machine/         structurally-invalid logs the guest must reject (tampers the above)
fixtures:
	@mkdir -p $(MACHINE_FIXTURES_DIR)
	# The record-*.lua recorders require an empty output dir (they never delete); clear any stale
	# reject/one-mcycle fixtures here so a re-run starts clean. The recorders recreate the dirs.
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

$(RECEIPT): $(STEP_LOG) $(CARTESI_RISC0_CLI)
	@mkdir -p $(FIXTURES_DIR)
	@echo "--- Proving step log ---"
	@HASH_BEFORE=$$($(LUA) $(STEP_LOG_UTIL) root-hash-before $(STEP_LOG)) && \
	CYCLE_COUNT=$$($(LUA) $(STEP_LOG_UTIL) requested-cycle-count $(STEP_LOG)) && \
	HASH_AFTER=$$($(LUA) $(STEP_LOG_UTIL) root-hash-after $(STEP_LOG)) && \
	$(CARTESI_RISC0_CLI) prove \
		"$$HASH_BEFORE" $(STEP_LOG) "$$CYCLE_COUNT" "$$HASH_AFTER" \
		$(RECEIPT)

$(SEAL): $(RECEIPT) $(CARTESI_RISC0_CLI)
	@echo "--- Compressing receipt to Groth16 ---"
	$(CARTESI_RISC0_CLI) compress \
		$(RECEIPT) $(SEAL) $(JOURNAL)

ARTIFACTS_DIR ?= $(abspath artifacts)

export-artifacts: rust
	@$(MAKE) -C rust export-artifacts ARTIFACTS_DIR=$(ARTIFACTS_DIR)
	@$(MAKE) -C solidity src/ImageID.sol
	@cp solidity/src/ImageID.sol $(ARTIFACTS_DIR)/ImageID.sol
	@echo "ImageID.sol copied to $(ARTIFACTS_DIR)"

image-id: rust
	@$(MAKE) -C rust image-id

clean:
	-@$(MAKE) -C cpp clean
	-@$(MAKE) -C rust clean
	-@$(MAKE) -C solidity clean
	rm -rf $(FIXTURES_DIR)

.PHONY: all cpp rust clean check-format format test test-dev-mode test-pipeline test-solidity coverage coverage-pipeline export-artifacts image-id fixtures
