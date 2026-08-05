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

GUEST_ELF ?= $(abspath ../cpp/guest.elf)
ARTIFACTS_DIR ?= $(abspath ../artifacts)
# cuda accelerates the STARK. groth16-cuda additionally routes gnark through
# ICICLE, which needs a Go toolchain, ICICLE shared libraries and an ICICLE
# licence -- see machine-emulator-private/sp1-gpu-benchmark/icicle-licensing-finding.md
SP1_FEATURES ?=

ifneq ($(SP1_FEATURES),)
CARGO_FEATURES = --features "$(SP1_FEATURES)"
endif

all:
	cargo build --locked $(CARGO_FEATURES)

release:
	cargo build --locked --release $(CARGO_FEATURES)

# The reject-fixture tests execute the guest without proving, so they need no
# GPU. They do need ../cpp/guest.elf and ../test/fixtures.
test:
	cargo test --locked $(CARGO_FEATURES)

coverage:
	cargo llvm-cov --no-report --locked $(CARGO_FEATURES)

coverage-report:
	cargo llvm-cov report --lcov --output-path lcov.info
	cargo llvm-cov report --summary-only | tee coverage-summary.txt

format:
	cargo fmt

check-format:
	cargo fmt --check

export-artifacts: release
	cargo run --locked --release --bin cartesi-sp1-cli -- \
	    --guest-elf $(GUEST_ELF) export-artifacts $(ARTIFACTS_DIR)

vkey:
	@cargo run --locked --release --quiet --bin cartesi-sp1-cli -- \
	    --guest-elf $(GUEST_ELF) vkey

clean:
	@if command -v cargo >/dev/null 2>&1; then cargo clean; fi
	@rm -rf $(ARTIFACTS_DIR)
	@rm -f lcov.info coverage-summary.txt *.profraw

.PHONY: all release test coverage coverage-report format check-format clean export-artifacts vkey
