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

# Solidity library that replays Cartesi binary step logs on-chain to verify a single
# uarch step, a uarch reset, or a send_cmio_response.

EMULATOR_DIR := $(abspath ..)
LUA_BIN      ?= $(shell which lua5.4)
FIXTURES_DIR := test/fixtures

# Restricts which uarch tests are recorded into fixtures. Default = the full
# rv64ui-uarch suite, so any instruction-handler or ECALL transpilation
# regression is caught. Override for quick iteration, e.g.
#   make UARCH_TEST_PATTERN='rv64ui%-uarch%-add.-%.bin' fixtures
UARCH_TEST_PATTERN ?= rv64ui%-uarch%-.+%.bin

.PHONY: all dep build test coverage fmt fmt-check fixtures fixtures-clean clean \
        gen-constants check-gen-constants \
        gen-transpiled check-gen-transpiled \
        gen-all check-gen-all test-transpile

# Plain `make` builds the contracts (mirrors risc0); fixtures and test stay explicit.
all: build

# forge-std is a test-only dependency, installed on demand into the gitignored
# lib/ rather than committed as a git submodule. Keeping it out of the submodule
# set means a plain `make submodules` (or any C++-only checkout) never clones it.
dep:
	@if [ ! -d lib/forge-std ]; then \
		forge install foundry-rs/forge-std@v1.16.1 --no-git; \
	else \
		echo "Dependencies already installed (lib/forge-std exists)"; \
	fi

build: dep
	forge build

test: dep fmt-check
	forge test -vv

# --ir-minimum is required because the test profile compiles with via_ir.
coverage: dep
	forge coverage --ir-minimum --no-match-coverage 'test/'

fmt:
	forge fmt

fmt-check:
	forge fmt --check

# gen-constants reads the live cartesi Lua module, so it needs the emulator's
# LUA_PATH_5_4 / LUA_CPATH_5_4 (a built cartesi.so); gen-transpiled needs only lpeg.
gen-constants:
	@eval $$($(MAKE) -sC $(EMULATOR_DIR) --no-print-directory env) && \
	  $(LUA_BIN) tools/gen-emulator-constants.lua > src/EmulatorConstants.sol
	@forge fmt src/EmulatorConstants.sol
	@echo "Regenerated src/EmulatorConstants.sol"

check-gen-constants:
	@eval $$($(MAKE) -sC $(EMULATOR_DIR) --no-print-directory env) && \
	  $(LUA_BIN) tools/gen-emulator-constants.lua > /tmp/EmulatorConstants.gen.sol
	@forge fmt /tmp/EmulatorConstants.gen.sol
	@diff -u src/EmulatorConstants.sol /tmp/EmulatorConstants.gen.sol \
	  || { echo "ERROR: src/EmulatorConstants.sol is stale. Run 'make gen-constants' and commit."; exit 1; }
	@echo "src/EmulatorConstants.sol is in sync with the generator."

gen-transpiled:
	$(LUA_BIN) tools/transpile-uarch.lua $(EMULATOR_DIR)/src/uarch-step.cpp         src/UArchStep.sol         UArchStep         uarchStep
	$(LUA_BIN) tools/transpile-uarch.lua $(EMULATOR_DIR)/src/uarch-reset-state.cpp  src/UArchReset.sol        UArchReset        uarchResetState
	$(LUA_BIN) tools/transpile-uarch.lua $(EMULATOR_DIR)/src/send-cmio-response.cpp src/SendCmioResponse.sol  SendCmioResponse  sendCmioResponse
	@forge fmt src/UArchStep.sol src/UArchReset.sol src/SendCmioResponse.sol

check-gen-transpiled:
	@$(LUA_BIN) tools/transpile-uarch.lua $(EMULATOR_DIR)/src/uarch-step.cpp         /tmp/UArchStep.gen.sol         UArchStep         uarchStep
	@$(LUA_BIN) tools/transpile-uarch.lua $(EMULATOR_DIR)/src/uarch-reset-state.cpp  /tmp/UArchReset.gen.sol        UArchReset        uarchResetState
	@$(LUA_BIN) tools/transpile-uarch.lua $(EMULATOR_DIR)/src/send-cmio-response.cpp /tmp/SendCmioResponse.gen.sol  SendCmioResponse  sendCmioResponse
	@forge fmt /tmp/UArchStep.gen.sol /tmp/UArchReset.gen.sol /tmp/SendCmioResponse.gen.sol
	@for f in UArchStep UArchReset SendCmioResponse; do \
	  diff -u src/$$f.sol /tmp/$$f.gen.sol \
	    || { echo "ERROR: src/$$f.sol is stale. Run 'make gen-transpiled' and commit."; exit 1; }; \
	done
	@echo "All transpiled .sol files are in sync with the C++ sources."

test-transpile:
	$(LUA_BIN) tools/test-transpile-uarch.lua

gen-all:       gen-constants gen-transpiled
check-gen-all: check-gen-constants check-gen-transpiled test-transpile

# One fixture set per recorder, each with its own _manifest.csv. The adversarial
# recorders tamper the valid logs, so they must run last; all recorders use
# emulator-relative paths, hence the cd into $(EMULATOR_DIR).
fixtures: fixtures-clean
	@mkdir -p $(FIXTURES_DIR)
	@cd $(EMULATOR_DIR) && eval $$($(MAKE) env) && \
	  $(LUA_BIN) tests/lua/uarch-riscv-tests.lua \
	    --test-path=tests/build/uarch \
	    --test='$(UARCH_TEST_PATTERN)' \
	    --output-dir=$(abspath $(FIXTURES_DIR))/uarch-tests-per-cycle \
	    --per-cycle-logs \
	    record_uarch_tests && \
	  $(LUA_BIN) tests/lua/record-solidity-uarch-scope.lua \
	    --output-dir=$(abspath $(FIXTURES_DIR))/uarch-solidity-scope && \
	  $(LUA_BIN) tests/lua/record-send-cmio-response.lua \
	    --output-dir=$(abspath $(FIXTURES_DIR))/send-cmio-response && \
	  $(LUA_BIN) tests/lua/record-reset-uarch.lua \
	    --output-dir=$(abspath $(FIXTURES_DIR))/reset-uarch && \
	  $(LUA_BIN) tests/lua/record-adversarial-uarch.lua \
	    --fixtures-dir=$(abspath $(FIXTURES_DIR)) \
	    --output-dir=$(abspath $(FIXTURES_DIR))/reject-uarch && \
	  $(LUA_BIN) tests/lua/record-adversarial-send-cmio-response.lua \
	    --fixtures-dir=$(abspath $(FIXTURES_DIR)) \
	    --output-dir=$(abspath $(FIXTURES_DIR))/reject-send-cmio-response

fixtures-clean:
	rm -rf $(FIXTURES_DIR)

# No forge dependency, so the top-level clean works without Foundry installed.
clean: fixtures-clean
	rm -rf out cache broadcast
