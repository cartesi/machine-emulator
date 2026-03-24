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
#   fuzz-interpret  Fast interpreter fuzzer. Uses a persistent machine to avoid
#                   create/destroy overhead. Exercises the RISC-V interpreter
#                   with fuzzed registers, CSRs, page tables, code, and
#                   hostile TLB entries written via shadow state bulk write.
#
#   fuzz-interpret-step  Differential step verification fuzzer. For each fuzzed
#                   machine state, runs a single big-machine step through four
#                   independent paths and asserts all produce the same root hash:
#                     1. cm_run()              -- fast interpreter
#                     2. cm_run_uarch()        -- uarch execution + reset
#                     3. cm_log/verify_step_uarch() cycle-by-cycle -- uarch fraud proofs
#                     4. cm_log/verify_step()  -- page-based fraud proofs
#
# Both targets share the same input format and corpus directory. Run
# fuzz-interpret first to build up the corpus quickly, then run the step
# fuzzer to verify all execution paths agree on the discovered inputs.
#
# Usage:
#   make                                # build all fuzz targets
#   make run-fuzz-interpret             # run the interpreter fuzzer
#   make run-fuzz-interpret-step        # run the step verification fuzzer
#   make run-fuzz                       # run all fuzzers (recommended)
#   make fuzz-seed-corpus               # build seed corpus from test binaries
#
# Pass per-target libFuzzer flags:
#   make run-fuzz FUZZ_INTERPRET_ARGS="-max_total_time=60" FUZZ_INTERPRET_STEP_ARGS="-max_total_time=300"

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
FUZZ_TARGETS = \
	$(BUILDDIR)/fuzz-interpret \
	$(BUILDDIR)/fuzz-interpret-step

.PHONY: all clean distclean run-fuzz \
	run-fuzz-interpret run-fuzz-interpret-step \
	check-seed-corpus fuzz-seed-corpus fuzz-coverage fuzz-coverage-clean

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

$(BUILDDIR)/fuzz-interpret-step: fuzz-interpret-step.cpp fuzz-common.h $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	$(CXX) $(CXXFLAGS) -o $@ $< $(FUZZ_LINK)

# -- Run targets --------------------------------------------------------------

CORPUS_DIR = corpus
FUZZ_INTERPRET_ARGS ?=
FUZZ_INTERPRET_STEP_ARGS ?=

# Recommended entry point: runs all fuzzers in sequence.
run-fuzz: run-fuzz-interpret run-fuzz-interpret-step

check-seed-corpus:
	@test -d $(SEED_DIR) && test "$$(ls -A $(SEED_DIR) 2>/dev/null)" || \
		{ echo "Error: seed corpus not found. Generate it first (with a non-fuzz build):" >&2; \
		  echo "  eval \$$(make env)" >&2; \
		  echo "  cd tests/fuzz && lua5.4 gen-seed-corpus.lua $(SEED_DIR) --test-path=../build/machine" >&2; \
		  exit 1; }

run-fuzz-interpret: $(BUILDDIR)/fuzz-interpret check-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 $(BUILDDIR)/fuzz-interpret $(CORPUS_DIR) $(SEED_DIR)/ $(FUZZ_INTERPRET_ARGS)

run-fuzz-interpret-step: $(BUILDDIR)/fuzz-interpret-step check-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 $(BUILDDIR)/fuzz-interpret-step $(CORPUS_DIR) $(SEED_DIR)/ $(FUZZ_INTERPRET_STEP_ARGS)

# -- Seed corpus --------------------------------------------------------------
#
# Generates seed inputs by running riscv-tests ISA binaries and snapshotting
# machine state at interesting points. Each seed is structured as:
#   [2 control bytes] [848 registers_state bytes] [page_table_data...] [code...]
#
# The Lua generator runs tests, captures live register state from shadow memory,
# and extracts SV39 page tables for VM tests.
#
# Requires riscv-tests to be built first (make build-tests-machine in tests/).

SEED_DIR = seed-corpus

fuzz-seed-corpus: $(SEED_DIR)/.stamp

$(SEED_DIR)/.stamp: gen-seed-corpus.lua fuzz-common.h
	lua5.4 gen-seed-corpus.lua $(SEED_DIR) --test-path=$(CARTESI_TESTS_PATH)
	@touch $@

# -- Coverage report ----------------------------------------------------------
#
# Replays the corpus through a coverage-instrumented binary and generates
# an HTML coverage report.
#
# Prerequisites: rebuild libcartesi with coverage instrumentation:
#   make -C ../../src clean
#   make -C ../../src fuzz=yes coverage=yes
#
# Usage:
#   make fuzz-coverage TARGET=fuzz-interpret
#   make fuzz-coverage TARGET=fuzz-interpret-step
#   open cov-report/index.html

TARGET ?= fuzz-interpret
COV_BUILDDIR = $(BUILDDIR)/cov
COV_FLAGS = -fprofile-instr-generate -fcoverage-mapping
COV_CXXFLAGS = $(CXXFLAGS) $(COV_FLAGS)
COV_LINK = $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a $(LDFLAGS) $(COV_FLAGS) $(LIBS)

$(COV_BUILDDIR)/$(TARGET): $(TARGET).cpp fuzz-common.h $(SRCDIR)/libcartesi.a $(SRCDIR)/libcartesi_hash_tree.a
	@mkdir -p $(COV_BUILDDIR)
	$(CXX) $(COV_CXXFLAGS) -o $@ $< $(COV_LINK)

fuzz-coverage: $(COV_BUILDDIR)/$(TARGET) fuzz-seed-corpus
	@mkdir -p $(CORPUS_DIR)
	ASAN_OPTIONS=detect_container_overflow=0 LLVM_PROFILE_FILE=$(COV_BUILDDIR)/fuzz.profraw \
		$(COV_BUILDDIR)/$(TARGET) $(CORPUS_DIR) $(SEED_DIR)/ -runs=0
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
	rm -rf $(FUZZ_TARGETS:=.dSYM)
	rm -f crash-* fuzz-*.log
