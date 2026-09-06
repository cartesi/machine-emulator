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

RISC0_DEV_MODE ?= 1
# Machine step logs the dev-mode test replays (generate with `make -C .. fixtures`).
CARTESI_STEP_LOGS_PATH ?= $(abspath ../test/fixtures/cartesi-machine-tests)
ARTIFACTS_DIR ?= $(abspath ../artifacts)
RISC0_FEATURES ?=

export RISC0_DEV_MODE
export CARTESI_STEP_LOGS_PATH

ifneq ($(RISC0_FEATURES),)
CARGO_FEATURES = --features "$(RISC0_FEATURES)"
endif

all:
	cargo build --locked $(CARGO_FEATURES)

test:
	cargo test --locked $(CARGO_FEATURES)

# Host-side coverage (dev-mode tests; needs cargo-llvm-cov + llvm-tools-preview).
# The guest is out of scope: it runs inside the zkVM and cannot be instrumented.
# --no-report accumulates profiles so `coverage-pipeline` (risc0/Makefile) can add
# the real proving pipeline on top before the report is rendered.
coverage:
	cargo llvm-cov --no-report --locked $(CARGO_FEATURES)

coverage-report:
	cargo llvm-cov report --lcov --output-path lcov.info
	cargo llvm-cov report --summary-only | tee coverage-summary.txt

# The guest is a separate workspace (its own Cargo.lock), so cargo fmt at the
# root does not reach it; format and check it explicitly.
format:
	cargo fmt
	cargo fmt --manifest-path methods/guest/Cargo.toml

check-format:
	cargo fmt --check
	cargo fmt --check --manifest-path methods/guest/Cargo.toml

export-artifacts: all
	cargo run --locked --bin cartesi-risc0-cli -- export-artifacts $(ARTIFACTS_DIR)

image-id:
	@cargo run --locked --quiet --bin cartesi-risc0-cli -- image-id

clean:
	@if command -v cargo >/dev/null 2>&1; then cargo clean; fi
	@rm -rf $(ARTIFACTS_DIR)
	@rm -f lcov.info coverage-summary.txt *.profraw

.PHONY: all test coverage coverage-report format check-format clean export-artifacts image-id
