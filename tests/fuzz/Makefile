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
# Targets:
#   fuzz-interpret  Fast interpreter fuzzer. Exercises the RISC-V interpreter
#                   with fuzzed registers, CSRs, page tables, and code.
#
#   fuzz-step       Differential step verification fuzzer. For each fuzzed
#                   machine state, runs a single big-machine step through four
#                   independent paths and asserts all produce the same root hash:
#                     1. cm_run()              — fast interpreter
#                     2. cm_run_uarch()        — uarch execution + reset
#                     3. cm_log/verify_step_uarch() cycle-by-cycle — uarch fraud proofs
#                     4. cm_log/verify_step()  — page-based fraud proofs
#
#   fuzz-shadow-state  Shadow state bulk write fuzzer. Sets up a plausible machine
#                   via fuzz_create_machine(), then overwrites the entire shadow
#                   state (registers + TLB) with raw fuzz data via cm_write_memory().
#                   Exercises shadow state validation, hot TLB reinitialization,
#                   and lazy TLB verification with hostile inputs.
#
# All targets share the same input format and corpus directory. Run
# fuzz-interpret first to build up the corpus quickly, then run fuzz-step
# to verify all execution paths agree on the discovered inputs.
#
# Usage:
#   make                          # build all fuzz targets
#   make run-fuzz-interpret       # run the interpreter fuzzer
#   make run-fuzz-step            # run the step verification fuzzer
#   make run-fuzz                 # run fuzz-interpret then fuzz-step (recommended)
#   make fuzz-seed-corpus         # build seed corpus from test binaries
#
# Pass per-target libFuzzer flags:
#   make run-fuzz FUZZ_INTERPRET_ARGS="-max_total_time=60" FUZZ_STEP_ARGS="-max_total_time=300"

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
FUZZ_TARGETS = $(BUILDDIR)/fuzz-interpret $(BUILDDIR)/fuzz-step $(BUILDDIR)/fuzz-shadow-state

.PHONY: all clean distclean run-fuzz run-fuzz-interpret run-fuzz-step run-fuzz-shadow-state fuzz-seed-corpus fuzz-coverage fuzz-coverage-clean

all: $(FUZZ_TARGETS)

# -- Static library dependencies ----------------------------------------------
# When invoked from the parent build system, the libraries are already built.
# When invoked standalone, build them with Clang and fuzz=yes.

$(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a:
	@$(MAKE) -C $(SRCDIR) CC=clang CXX=clang++ fuzz=yes $(@F)

# -- Fuzz targets -------------------------------------------------------------

FUZZ_LINK = $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a $(LDFLAGS) $(LIBS)

$(BUILDDIR)/fuzz-interpret: fuzz-interpret.cpp fuzz-common.h $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	$(CXX) $(CXXFLAGS) -o $@ $< $(FUZZ_LINK)

$(BUILDDIR)/fuzz-step: fuzz-step.cpp fuzz-common.h $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	$(CXX) $(CXXFLAGS) -o $@ $< $(FUZZ_LINK)

$(BUILDDIR)/fuzz-shadow-state: fuzz-shadow-state.cpp fuzz-common.h $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	$(CXX) $(CXXFLAGS) -o $@ $< $(FUZZ_LINK)

# -- Run targets --------------------------------------------------------------

# All fuzz targets share a single corpus directory. Inputs discovered by the
# fast fuzz-interpret target serve as seeds for the slower fuzz-step target.
CORPUS_DIR = corpus
FUZZ_INTERPRET_ARGS ?=
FUZZ_STEP_ARGS ?=
FUZZ_SHADOW_STATE_ARGS ?=

# Recommended entry point: runs fuzz-interpret to build up the corpus,
# then fuzz-step to verify all 4 execution paths agree.
run-fuzz: run-fuzz-interpret run-fuzz-step run-fuzz-shadow-state

run-fuzz-interpret: $(BUILDDIR)/fuzz-interpret fuzz-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 $(BUILDDIR)/fuzz-interpret $(CORPUS_DIR) seed-corpus/ $(FUZZ_INTERPRET_ARGS)

run-fuzz-step: $(BUILDDIR)/fuzz-step fuzz-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 $(BUILDDIR)/fuzz-step $(CORPUS_DIR) seed-corpus/ $(FUZZ_STEP_ARGS)

run-fuzz-shadow-state: $(BUILDDIR)/fuzz-shadow-state fuzz-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 $(BUILDDIR)/fuzz-shadow-state $(CORPUS_DIR) seed-corpus/ $(FUZZ_SHADOW_STATE_ARGS)

# -- Seed corpus --------------------------------------------------------------
#
# Builds seed inputs from the riscv-tests ISA binaries. Each seed is a file
# structured as the harness expects:
#   [2 control bytes] [848 registers_state bytes] [code...]
#
# Requires riscv-tests to be built first (make build-tests-machine in tests/).

SEED_DIR = seed-corpus

fuzz-seed-corpus: $(SEED_DIR)/.stamp

$(SEED_DIR)/.stamp: gen-seed-corpus.sh
	@mkdir -p $(SEED_DIR)
	@bash gen-seed-corpus.sh $(SEED_DIR)
	@touch $@

# -- Coverage report ----------------------------------------------------------
#
# Builds coverage-instrumented binaries, replays the corpus to collect
# profile data, and generates an HTML coverage report.
#
# Usage:
#   make fuzz-coverage TARGET=fuzz-shadow-state   # default target
#   make fuzz-coverage TARGET=fuzz-interpret
#   open cov-report/index.html

TARGET ?= fuzz-shadow-state
COV_BUILDDIR = $(BUILDDIR)/cov
COV_FLAGS = -fprofile-instr-generate -fcoverage-mapping
COV_CXXFLAGS = $(CXXFLAGS) $(COV_FLAGS)
COV_LINK = $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a $(LDFLAGS) $(COV_FLAGS) $(LIBS)

# Coverage report for a fuzz target. Replays the corpus through a
# coverage-instrumented binary and generates an HTML report.
#
# Prerequisites: rebuild libcartesi with coverage instrumentation:
#   make -C ../../src clean
#   make -C ../../src CC=clang CXX=clang++ fuzz=yes coverage=yes COVERAGE_TOOLCHAIN=clang
#
# Usage:
#   make fuzz-coverage TARGET=fuzz-shadow-state
#   make fuzz-coverage TARGET=fuzz-interpret
#   open cov-report/index.html

$(COV_BUILDDIR)/$(TARGET): $(TARGET).cpp fuzz-common.h $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	@mkdir -p $(COV_BUILDDIR)
	$(CXX) $(COV_CXXFLAGS) -o $@ $< $(COV_LINK)

fuzz-coverage: $(COV_BUILDDIR)/$(TARGET) fuzz-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 LLVM_PROFILE_FILE=$(COV_BUILDDIR)/fuzz.profraw \
		$(COV_BUILDDIR)/$(TARGET) $(CORPUS_DIR) seed-corpus/ -runs=0
	llvm-profdata merge -sparse $(COV_BUILDDIR)/fuzz.profraw -o $(COV_BUILDDIR)/fuzz.profdata
	llvm-cov report $(COV_BUILDDIR)/$(TARGET) -instr-profile=$(COV_BUILDDIR)/fuzz.profdata
	llvm-cov show $(COV_BUILDDIR)/$(TARGET) -instr-profile=$(COV_BUILDDIR)/fuzz.profdata \
		--format=html -output-dir=cov-report
	@echo "Coverage report: cov-report/index.html"

fuzz-coverage-clean:
	rm -rf $(COV_BUILDDIR) cov-report

# -- Clean --------------------------------------------------------------------

clean: fuzz-coverage-clean
	rm -f $(FUZZ_TARGETS)
	rm -rf $(SEED_DIR)/

distclean: clean
	rm -rf $(CORPUS_DIR)/
