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

# ZisK Prover Integration for Cartesi Machine
#
# This builds the ZisK prover program that can generate zero-knowledge proofs
# of Cartesi Machine state transitions.
#
# Requirements:
#   - LLVM 20.x with Clang, LLD, and libc++ headers (RISC-V target)
#   - ZisK toolchain: cargo-zisk, ziskemu (install via ziskup)
#   - Rust toolchain (installed via rustup)
#
# Usage:
#   make all                      Build C++ library and Rust ELF
#   make test                     Run tests (delegates to test/Makefile)
#   make test FILTER=xori         Run filtered tests
#   make clean                    Clean build artifacts

#------------------------------------------------------------------------------
# Directory Configuration
#------------------------------------------------------------------------------

ROOT_DIR := $(abspath .)
CPP_DIR := $(ROOT_DIR)/cpp
RUST_DIR := $(ROOT_DIR)/rust
TEST_DIR := $(ROOT_DIR)/test

#------------------------------------------------------------------------------
# ZisK Tools (installed via ziskup)
#------------------------------------------------------------------------------

ZISK_HOME ?= $(HOME)/.zisk
CARGO_ZISK ?= $(ZISK_HOME)/bin/cargo-zisk

# Validate ZisK tools for build targets
ifeq ($(filter clean help info test,$(MAKECMDGOALS)),)
ifeq ($(wildcard $(CARGO_ZISK)),)
$(error cargo-zisk not found at $(CARGO_ZISK). Install ZisK: curl -L https://raw.githubusercontent.com/0xPolygonHermez/zisk/main/ziskup/install.sh | bash)
endif
endif

#------------------------------------------------------------------------------
# LLVM 20 Toolchain
#------------------------------------------------------------------------------

# LLVM 20 installation path (must be set by user or environment)
LLVM20_DIR ?=

# libc++ headers location (usually inside LLVM installation)
LIBCXX_INCLUDE ?= $(LLVM20_DIR)/include/c++/v1

# Validate LLVM for build targets (not clean, help, info, or test)
ifeq ($(filter clean help info test,$(MAKECMDGOALS)),)
ifeq ($(LLVM20_DIR),)
$(error LLVM20_DIR not set. Please set it to your LLVM 20 installation path. Example: make LLVM20_DIR=/opt/homebrew/opt/llvm@20 all)
endif
ifeq ($(wildcard $(LLVM20_DIR)/bin/clang++),)
$(error LLVM 20 Clang not found at $(LLVM20_DIR)/bin/clang++. Please verify your LLVM20_DIR setting.)
endif
endif

#------------------------------------------------------------------------------
# Build Outputs
#------------------------------------------------------------------------------

CPP_LIB := $(CPP_DIR)/libcartesi-zisk.a
RUST_ELF := $(RUST_DIR)/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk

#------------------------------------------------------------------------------
# Targets
#------------------------------------------------------------------------------

.PHONY: all cpp rust test clean distclean info help

all: cpp rust

# Build C++ interpreter library
cpp:
	@echo ""
	@echo "[CPP] Building Cartesi Machine interpreter library..."
	$(MAKE) -C $(CPP_DIR) all \
		LLVM20_DIR="$(LLVM20_DIR)" \
		LIBCXX_INCLUDE="$(LIBCXX_INCLUDE)"

# Build Rust ZisK prover program
rust: cpp
	@echo ""
	@echo "[RUST] Building ZisK prover program..."
	cd $(RUST_DIR) && $(CARGO_ZISK) build --release
	@echo ""
	@echo "ELF built: $(RUST_ELF)"
	@ls -lh $(RUST_ELF)

# Run tests (delegates to test/Makefile)
# Supports: make test FILTER=<pattern> verify=yes
test:
	$(MAKE) -C $(TEST_DIR) test FILTER="$(FILTER)" verify="$(verify)"

clean:
	-$(MAKE) -C $(CPP_DIR) clean
	-cd $(RUST_DIR) && cargo clean 2>/dev/null || rm -rf $(RUST_DIR)/target
	-$(MAKE) -C $(TEST_DIR) clean

distclean: clean

info:
	@echo "Directories:"
	@echo "  ROOT_DIR:       $(ROOT_DIR)"
	@echo "  CPP_DIR:        $(CPP_DIR)"
	@echo "  RUST_DIR:       $(RUST_DIR)"
	@echo "  TEST_DIR:       $(TEST_DIR)"
	@echo ""
	@echo "LLVM 20 Toolchain:"
	@echo "  LLVM20_DIR:     $(LLVM20_DIR)"
	@echo "  LIBCXX_INCLUDE: $(LIBCXX_INCLUDE)"
ifneq ($(LLVM20_DIR),)
	@echo "  Clang version:  $$($(LLVM20_DIR)/bin/clang++ --version 2>/dev/null | head -1 || echo 'not found')"
endif
	@echo ""
	@echo "ZisK Toolchain:"
	@echo "  ZISK_HOME:      $(ZISK_HOME)"
	@echo "  CARGO_ZISK:     $(CARGO_ZISK)"
ifneq ($(wildcard $(CARGO_ZISK)),)
	@echo "  cargo-zisk:     $$($(CARGO_ZISK) --version 2>/dev/null || echo 'not found')"
endif
	@echo ""
	@echo "Build Outputs:"
	@echo "  CPP_LIB:        $(CPP_LIB)"
	@echo "  RUST_ELF:       $(RUST_ELF)"

help:
	@echo "ZisK Prover Integration"
	@echo ""
	@echo "Build targets:"
	@echo "  all            Build C++ library and Rust ELF (default)"
	@echo "  cpp            Build C++ interpreter library only"
	@echo "  rust           Build Rust ZisK prover program"
	@echo "  clean          Remove build artifacts"
	@echo "  info           Show configuration"
	@echo ""
	@echo "Test targets:"
	@echo "  test           Run tests (see test/Makefile for options)"
	@echo "  test FILTER=x  Run tests matching pattern 'x'"
	@echo ""
	@echo "Required environment:"
	@echo "  LLVM20_DIR     Path to LLVM 20 installation"
	@echo ""
	@echo "Example:"
	@echo "  make LLVM20_DIR=/opt/homebrew/opt/llvm@20 all"
	@echo "  make test FILTER=xori"
