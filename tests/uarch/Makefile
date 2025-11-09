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

PREFIX = /opt/cartesi
INSTALLDIR = $(PREFIX)/tests

UARCH_ENV_DIR := $(abspath .)
EMULATOR_SRC_DIR := $(abspath ../../src)
RISCV_PREFIX ?= riscv64-unknown-elf-
RISCV_GCC ?= $(RISCV_PREFIX)gcc
RISCV_GCC_OPTS ?= -static  -march=rv64i -mabi=lp64 -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles
RISCV_OBJDUMP ?= $(RISCV_PREFIX)objdump --disassemble-all --disassemble-zeroes --section=.text --section=.text.startup --section=.text.init --section=.data
RISCV_OBJCOPY ?= $(RISCV_PREFIX)objcopy -S -O binary

# Tests provided by us
TESTS = fence ebreak ecall-putchar ecall-unsupported ecall-mark-page-dirty ecall-write-tlb
SRC_DIR = $(abspath .)
BUILDDIR ?= $(abspath ./build)
TEST_NAMES = $(addprefix rv64ui-uarch-, $(TESTS))
TESTS_BIN_NAMES = $(addsuffix .bin, $(TEST_NAMES))
TESTS_DUMP_NAMES = $(addsuffix .dump, $(TEST_NAMES))
TESTS_SOURCES = $(addprefix $(SRC_DIR)/, $(addsuffix .S, $(TESTS)))
TESTS_PREFIX = $(BUILDDIR)/rv64ui-uarch-
TARGET_TESTS = $(addprefix $(BUILDDIR)/, $(TEST_NAMES))

# Tests provided by third party riscv tests
THIRDPARTY_TESTS = \
	add addi addiw addw \
	and andi \
	auipc \
	beq bge bgeu blt bltu bne \
	simple \
	jal jalr \
	lb lbu lh lhu lw lwu ld \
	lui \
	or ori \
	sb sh sw sd \
	sll slli slliw sllw \
	slt slti sltiu sltu \
	sra srai sraiw sraw \
	srl srli srliw srlw \
	sub subw \
	xor xori

THIRDPARTY_SRC_DIR := $(abspath ../../third-party/riscv-tests/isa/rv64ui)
THIRDPARTY_TEST_NAMES = $(addprefix rv64ui-uarch-, $(THIRDPARTY_TESTS))
THIRDPARTY_TESTS_BIN_NAMES = $(addsuffix .bin, $(THIRDPARTY_TEST_NAMES))
THIRDPARTY_TESTS_DUMP_NAMES = $(addsuffix .dump, $(THIRDPARTY_TEST_NAMES))
THIRDPARTY_TESTS_SOURCES = $(addprefix $(THIRDPARTY_SRC_DIR)/, $(addsuffix .S, $(THIRDPARTY_TESTS)))
TARGET_THIRDPARTY_TESTS = $(addprefix $(BUILDDIR)/, $(THIRDPARTY_TEST_NAMES))

TARGET_TEST_BINS  = \
	$(addprefix $(BUILDDIR)/, $(THIRDPARTY_TESTS_BIN_NAMES)) \
	$(addprefix $(BUILDDIR)/, $(TESTS_BIN_NAMES))

TARGET_TEST_DUMPS = \
	$(addprefix $(BUILDDIR)/, $(THIRDPARTY_TESTS_DUMP_NAMES)) \
	$(addprefix $(BUILDDIR)/, $(TESTS_DUMP_NAMES))

TARGETS =  \
	$(TARGET_THIRDPARTY_TESTS)  \
	$(TARGET_TESTS)  \
	$(TARGET_TEST_BINS) \
	$(TARGET_TEST_DUMPS)

all: $(TARGETS) catalog

clean:
	@rm -rf $(TARGETS) $(BUILDDIR)

catalog:
	cp rv64ui-uarch-catalog.json $(BUILDDIR)/

$(TARGET_THIRDPARTY_TESTS): $(THIRDPARTY_TESTS_SOURCES) | $(BUILDDIR)
	$(RISCV_GCC) $(RISCV_GCC_OPTS) -I$(UARCH_ENV_DIR) \
		-I$(THIRDPARTY_SRC_DIR)/../macros/scalar \
		-I$(EMULATOR_SRC_DIR) \
		-T$(UARCH_ENV_DIR)/link.ld \
		$(subst $(TESTS_PREFIX),$(THIRDPARTY_SRC_DIR)/,$@).S -o $@

$(TARGET_TESTS): $(TESTS_SOURCES) | $(BUILDDIR)
	$(RISCV_GCC) $(RISCV_GCC_OPTS) -I$(UARCH_ENV_DIR) \
		-I$(THIRDPARTY_SRC_DIR)/../macros/scalar \
		-I$(EMULATOR_SRC_DIR) \
		-T$(UARCH_ENV_DIR)/link.ld \
		$(subst $(TESTS_PREFIX),$(SRC_DIR)/,$@).S -o $@

%.bin: %
	$(RISCV_OBJCOPY) $* $*.bin

%.dump: %
	$(RISCV_OBJDUMP) $* > $*.dump

$(BUILDDIR):
	mkdir -p $@

