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
STEP_LOG_UTIL    := $(abspath step-log-util.lua)
CARTESI_RISC0_CLI := $(abspath rust/target/debug/cartesi-risc0-cli)
CARTESI_MACHINE  ?= cartesi-machine.lua

FIXTURES_DIR     := test/fixtures
STEP_LOG         := $(FIXTURES_DIR)/step.log
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

test-dev-mode:
	@$(MAKE) -C rust test

test-pipeline: $(SEAL)
	@echo "--- Verifying receipt ---"
	@HASH_BEFORE=$$($(LUA) $(STEP_LOG_UTIL) root-hash-before $(STEP_LOG)) && \
	MCYCLE_COUNT=$$($(LUA) $(STEP_LOG_UTIL) mcycle-count $(STEP_LOG)) && \
	HASH_AFTER=$$($(LUA) $(STEP_LOG_UTIL) root-hash-after $(STEP_LOG)) && \
	$(CARTESI_RISC0_CLI) verify \
		$(RECEIPT) "$$HASH_BEFORE" "$$MCYCLE_COUNT" "$$HASH_AFTER" && \
	echo "--- Verifying seal ---" && \
	$(CARTESI_RISC0_CLI) verify-seal \
		$(SEAL) $(JOURNAL) "$$HASH_BEFORE" "$$MCYCLE_COUNT" "$$HASH_AFTER" && \
	echo "--- Pipeline test passed ---"

test-solidity:
	@$(MAKE) -C solidity test

$(STEP_LOG):
	@mkdir -p $(FIXTURES_DIR)
	@echo "--- Generating step log ---"
	$(CARTESI_MACHINE) \
		--hash-tree=hash_function:sha256 \
		--max-mcycle=0 \
		--log-step=1,$@

$(RECEIPT): $(STEP_LOG)
	@echo "--- Proving step log ---"
	@HASH_BEFORE=$$($(LUA) $(STEP_LOG_UTIL) root-hash-before $(STEP_LOG)) && \
	MCYCLE_COUNT=$$($(LUA) $(STEP_LOG_UTIL) mcycle-count $(STEP_LOG)) && \
	HASH_AFTER=$$($(LUA) $(STEP_LOG_UTIL) root-hash-after $(STEP_LOG)) && \
	$(CARTESI_RISC0_CLI) prove \
		"$$HASH_BEFORE" $(STEP_LOG) "$$MCYCLE_COUNT" "$$HASH_AFTER" \
		$(RECEIPT)

$(SEAL): $(RECEIPT)
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

.PHONY: all cpp rust clean test test-dev-mode test-pipeline test-solidity export-artifacts image-id
