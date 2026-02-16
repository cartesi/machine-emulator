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
CARTESI_STEP_LOGS_PATH ?= $(abspath ../../tests/build/step-logs)
ARTIFACTS_DIR ?= $(abspath ../artifacts)
RISC0_FEATURES ?=

export RISC0_DEV_MODE
export CARTESI_STEP_LOGS_PATH

ifneq ($(RISC0_FEATURES),)
CARGO_FEATURES = --features "$(RISC0_FEATURES)"
endif

all:
	cargo build $(CARGO_FEATURES)

test:
	cargo test $(CARGO_FEATURES)

export-artifacts: all
	cargo run --bin cartesi-risc0-cli -- export-artifacts $(ARTIFACTS_DIR)

image-id:
	@cargo run --quiet --bin cartesi-risc0-cli -- image-id

clean:
	@if command -v cargo >/dev/null 2>&1; then cargo clean; fi
	@rm -rf $(ARTIFACTS_DIR)

.PHONY: all test clean export-artifacts image-id
