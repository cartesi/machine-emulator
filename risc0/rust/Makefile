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

all:
	cargo build

test: create-test-fixtures
	RISC0_DEV_MODE=$(RISC0_DEV_MODE) cargo test

create-test-fixtures:
	$(MAKE) -C cartesi-risc0/tests

clean-test-fixtures:
	$(MAKE) -C cartesi-risc0/tests clean

clean: clean-test-fixtures
	cargo clean

.PHONY: all test create-test-fixtures clean-test-fixtures clean
