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

# Fuzz testing for the Cartesi machine emulator.
#
# Prerequisites:
#   - Clang/Clang++ with libFuzzer support (Clang 6+)
#
# Usage:
#   make                          # build all fuzz targets (and libcartesi with fuzz=yes)
#   make run-fuzz-interpret       # run the interpreter fuzzer
#   make fuzz-seed-corpus         # build seed corpus from test binaries

TARGET_OS ?= $(shell uname)

# Fuzzer requires Clang
CC = clang
CXX = clang++

# Build configuration
slirp ?= yes
threads ?= yes

BUILDDIR ?= .
SRCDIR = ../../src

INCS = -I$(SRCDIR) -I../../third-party/ankerl -I../../third-party/nlohmann-json -I../../third-party/downloads

# Core flags: C++23, fuzzer + sanitizers
CXXFLAGS += -std=gnu++23 -g -O1 -fno-omit-frame-pointer
CXXFLAGS += -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
CXXFLAGS += -fvisibility=hidden
CXXFLAGS += $(INCS)

LDFLAGS += -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all

ifeq ($(threads),yes)
CXXFLAGS += -fopenmp
LDFLAGS += -fopenmp
endif

# Libraries needed by libcartesi
ifeq ($(slirp),yes)
ifeq ($(TARGET_OS),Darwin)
BREW_PREFIX = $(shell brew --prefix 2>/dev/null)
ifneq ($(BREW_PREFIX),)
LIBS += -L$(BREW_PREFIX)/lib -lslirp
else
PORT_PREFIX = /opt/local
LIBS += -L$(PORT_PREFIX)/lib -lslirp
endif
else
LIBS += -lslirp
endif
endif

# Fuzz targets
FUZZ_TARGETS = $(BUILDDIR)/fuzz-interpret

.PHONY: all clean run-fuzz-interpret fuzz-seed-corpus

all: $(FUZZ_TARGETS)

# -- Static library dependencies ----------------------------------------------
# When invoked from the parent build system, the libraries are already built.
# When invoked standalone, build them with Clang and fuzz=yes.

$(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a:
	@$(MAKE) -C $(SRCDIR) CC=clang CXX=clang++ fuzz=yes $(@F)

# -- Fuzz targets -------------------------------------------------------------

$(BUILDDIR)/fuzz-interpret: fuzz-interpret.cpp $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	$(CXX) $(CXXFLAGS) -o $@ $< $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a $(LDFLAGS) $(LIBS)

# -- Run targets --------------------------------------------------------------

# Run with a corpus directory. Creates it if needed.
# Pass FUZZ_ARGS for additional libFuzzer flags (e.g. FUZZ_ARGS="-max_total_time=300")
FUZZ_ARGS ?=

run-fuzz-interpret: $(BUILDDIR)/fuzz-interpret fuzz-seed-corpus
	@mkdir -p corpus/interpret
	ASAN_OPTIONS=detect_container_overflow=0 $(BUILDDIR)/fuzz-interpret corpus/interpret seed-corpus/ $(FUZZ_ARGS)

# -- Seed corpus --------------------------------------------------------------
#
# Builds seed inputs from the riscv-tests ISA binaries. Each seed is a file
# structured as the harness expects:
#   [2 control bytes] [128 CSR bytes] [256 GPR bytes] [256 FP bytes] [code...]
#
# Requires riscv-tests to be built first (make build-tests-machine in tests/).

SEED_DIR = seed-corpus

fuzz-seed-corpus: $(SEED_DIR)/.stamp

$(SEED_DIR)/.stamp: gen-seed-corpus.sh
	@mkdir -p $(SEED_DIR)
	@bash gen-seed-corpus.sh $(SEED_DIR)
	@touch $@

# -- Clean --------------------------------------------------------------------

clean:
	rm -f $(FUZZ_TARGETS)
	rm -rf corpus/ $(SEED_DIR)/
