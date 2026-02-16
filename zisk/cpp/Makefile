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

#  builds the Cartesi Machine interpreter as a static library for ZisK.
#
# Build pipeline:
#   C++ Source -> LLVM 20 Clang++ -> RISC-V .o -> libcartesi-zisk.a
#
# The LLVM version match is CRITICAL: ZisK's llc uses 20.1.7-rust-dev, so we
# must use LLVM 20.x to avoid IR compatibility issues with complex C++ templates.
#
# Requirements:
#   - LLVM 20.x with Clang targeting RISC-V (user must install separately)
#   - libc++ headers for freestanding compilation (included in LLVM)
#
# Unlike risc0 which bundles a complete toolchain, ZisK requires the user to
# provide a compatible LLVM 20 installation. The libc++ headers from this
# toolchain are used in freestanding mode - we provide minimal stub files
# (inttypes.h, bits/types/mbstate_t.h) to satisfy header dependencies without
# a full C library.
#
# Configuration (passed from parent Makefile or environment):
#   LLVM20_DIR      - Path to LLVM 20 installation (required)
#   LIBCXX_INCLUDE  - Path to libc++ headers (default: $LLVM20_DIR/include/c++/v1)
#

LLVM20_DIR ?=
ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifeq ($(LLVM20_DIR),)
$(error LLVM20_DIR not set. Run from parent Makefile or set manually.)
endif
ifeq ($(wildcard $(LLVM20_DIR)/bin/clang++),)
$(error LLVM 20 Clang not found at $(LLVM20_DIR)/bin/clang++)
endif
endif

# libc++ headers from the LLVM 20 toolchain
LIBCXX_INCLUDE ?= $(LLVM20_DIR)/include/c++/v1

CXX := $(LLVM20_DIR)/bin/clang++
CC := $(LLVM20_DIR)/bin/clang
AR := $(LLVM20_DIR)/bin/llvm-ar
NM := $(LLVM20_DIR)/bin/llvm-nm
EMULATOR_SRC_DIR := $(abspath ../../src)
EMULATOR_TOOLS_DIR := $(abspath ../../tools)
THIRD_PARTY_DIR := $(abspath ../../third-party)
TARGET_TRIPLE := riscv64-unknown-elf
MARCH := rv64ima
MABI := lp64


# Flags to minimize undefined behavior
UBFLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

CXXFLAGS := \
	-target $(TARGET_TRIPLE) \
	-march=$(MARCH) -mabi=$(MABI) \
	-mcmodel=medany \
	-fPIC \
	-std=c++23 \
	-DZKARCHITECTURE=1 \
	-ffreestanding \
	-fno-exceptions \
	-fno-rtti \
	-fno-threadsafe-statics \
	-fno-use-cxa-atexit \
	-fvisibility=hidden \
	-nostdinc++ \
	$(UBFLAGS) \
	-O2 \
	-include zk-runtime.h \
	-I. \
	-isystem $(LIBCXX_INCLUDE) \
	-I$(THIRD_PARTY_DIR)/llvm-flang-uint128 \
	-I$(THIRD_PARTY_DIR) \
	-I$(EMULATOR_SRC_DIR)

CFLAGS := \
	-target $(TARGET_TRIPLE) \
	-march=$(MARCH) -mabi=$(MABI) \
	-mcmodel=medany \
	-fPIC \
	-DZKARCHITECTURE=1 \
	-ffreestanding \
	-fvisibility=hidden \
	$(UBFLAGS) \
	-O2 \
	-I. \
	-I$(THIRD_PARTY_DIR)

ZISKARCH_SOURCES := \
	zisk-replay-steps.cpp \
	zisk-runtime.cpp

EMULATOR_SOURCES := \
	interpret.cpp \
	htif-address-range.cpp \
	plic-address-range.cpp \
	clint-address-range.cpp

THIRDPARTY_SOURCES_C := \
	printf.c

ZISKARCH_OBJS := $(patsubst %.cpp,%.o,$(ZISKARCH_SOURCES))
EMULATOR_OBJS := $(patsubst %.cpp,%.o,$(EMULATOR_SOURCES))
THIRDPARTY_OBJS := $(patsubst %.c,%.o,$(THIRDPARTY_SOURCES_C))

ALL_OBJS := $(ZISKARCH_OBJS) $(EMULATOR_OBJS) $(THIRDPARTY_OBJS)

# Output library
LIBRARY := libcartesi-zisk.a

.PHONY: all clean info symbols

all: $(LIBRARY)

# Generated headers must exist before any emulator source compiles (-j safe)
GENERATED_HEADERS := $(EMULATOR_SRC_DIR)/machine-c-version.h $(EMULATOR_SRC_DIR)/interpret-jump-table.h

$(EMULATOR_SRC_DIR)/machine-c-version.h:
	make -C $(EMULATOR_SRC_DIR) machine-c-version.h

$(EMULATOR_SRC_DIR)/interpret-jump-table.h: $(EMULATOR_TOOLS_DIR)/gen-interpret-jump-table.lua
	$< > $@

$(ZISKARCH_OBJS): %.o: %.cpp
	@echo "[CXX] $< -> $@"
	$(CXX) $(CXXFLAGS) -c -o $@ $<

interpret.o: $(EMULATOR_SRC_DIR)/interpret.cpp | $(GENERATED_HEADERS)
	@echo "[CXX] $< -> $@"
	$(CXX) $(CXXFLAGS) -c -o $@ $<

htif-address-range.o: $(EMULATOR_SRC_DIR)/htif-address-range.cpp | $(GENERATED_HEADERS)
	@echo "[CXX] $< -> $@"
	$(CXX) $(CXXFLAGS) -c -o $@ $<

plic-address-range.o: $(EMULATOR_SRC_DIR)/plic-address-range.cpp | $(GENERATED_HEADERS)
	@echo "[CXX] $< -> $@"
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clint-address-range.o: $(EMULATOR_SRC_DIR)/clint-address-range.cpp | $(GENERATED_HEADERS)
	@echo "[CXX] $< -> $@"
	$(CXX) $(CXXFLAGS) -c -o $@ $<

printf.o: $(THIRD_PARTY_DIR)/printf/printf.c
	@echo "[CC] $< -> $@"
	$(CC) $(CFLAGS) -c -o $@ $<

# Create static library
$(LIBRARY): $(ALL_OBJS)
	$(AR) rcs $@ $^

clean:
	rm -f *.o *.a

ifneq ($(LLVM20_DIR),)
	@echo ""
	@echo "Clang version:"
	@$(CXX) --version | head -1
endif
