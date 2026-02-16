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

#
# Test Cartesi ZisK Prover
#
# Step logs are passed directly to ziskemu as input — no conversion needed.
# The step log contains the 72-byte header (hash_before + mcycle + hash_after)
# followed by the pages and siblings.
#
# Usage:
#   make test                      Run all tests (emulator only, fast)
#   make test FILTER=xori          Run tests matching "xori"
#   make test verify=yes           Run with constraint verification (slow)
#   make prove FILTER=xori         Generate proofs for matching tests
#   make clean                     Remove generated files
#
# Prerequisites:
#   - Step logs must exist: make -C ../../tests create-step-logs
#   - ZisK ELF must be built: make -C .. rust

ZISK_DIR := $(abspath ..)
TESTS_DIR := $(abspath ../../tests)

ZISK_HOME ?= $(HOME)/.zisk
ZISKEMU ?= $(ZISK_HOME)/bin/ziskemu
CARGO_ZISK ?= $(ZISK_HOME)/bin/cargo-zisk
STEP_LOGS_PATH ?= $(TESTS_DIR)/build/step-logs
OUTPUTS_DIR := $(CURDIR)/outputs
ELF := $(ZISK_DIR)/rust/target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk

# Test file filtering (grep -i pattern)
FILTER ?=
# constraint verification (slow, disabled by default)
verify ?= no
# verbose output for verify-constraints (shows individual constraints)
verbose ?= yes

STEP_LOGS_EXIST := $(wildcard $(STEP_LOGS_PATH))
ALL_STEP_LOGS := $(wildcard $(STEP_LOGS_PATH)/step-*.log)
ifneq ($(FILTER),)
STEP_LOGS := $(shell echo "$(ALL_STEP_LOGS)" | tr ' ' '\n' | grep -i "$(FILTER)" || true)
else
STEP_LOGS := $(ALL_STEP_LOGS)
endif
NUM_STEP_LOGS := $(words $(STEP_LOGS))

.PHONY: all test prove verify-proof clean distclean help
.PHONY: check-step-logs check-elf check-prove-filter

all: test

check-prove-filter:
ifeq ($(FILTER),)
	@echo "Error: FILTER is required for prove target (proof generation is very slow)"
	@exit 1
endif

check-step-logs:
ifeq ($(STEP_LOGS_EXIST),)
	@echo "Error: Step logs directory not found at $(STEP_LOGS_PATH)"
	@exit 1
endif
ifeq ($(NUM_STEP_LOGS),0)
	@echo "Error: No step logs found$(if $(FILTER), matching '$(FILTER)',)"
	@exit 1
endif

$(OUTPUTS_DIR):
	mkdir -p $@

# Run each step log through ziskemu directly (step log = input)
test: check-step-logs | $(OUTPUTS_DIR)
	@echo "ELF:      $(ELF)"
	@echo "Logs:     $(STEP_LOGS_PATH)"
	@echo "Outputs:  $(OUTPUTS_DIR)"
	@echo "Filter:   $(if $(FILTER),$(FILTER),(all))"
	@echo "Verify:   $(verify)"
	@echo "Total:    $(NUM_STEP_LOGS) tests"
	@echo ""
	@passed=0; failed=0; failed_tests=""; total=0; \
	for log in $(STEP_LOGS); do \
		base=$$(basename "$$log" .log); \
		total=$$((total + 1)); \
		out_dir=$(OUTPUTS_DIR)/$$base; \
		mkdir -p "$$out_dir"; \
		printf "%-55s " "$$base"; \
		if ! $(ZISKEMU) -e $(ELF) -i "$$log" -o "$$out_dir/public_output_values.bin" >/dev/null 2>&1; then \
			echo "FAIL (ziskemu)"; \
			failed=$$((failed + 1)); \
			failed_tests="$$failed_tests\n  - $$base (ziskemu)"; \
			continue; \
		fi; \
		if [ "$(verify)" = "yes" ]; then \
			echo "ziskemu OK"; \
			verbose_flag=""; \
			if [ "$(verbose)" = "yes" ]; then verbose_flag="-v"; fi; \
			if ! $(CARGO_ZISK) verify-constraints -e $(ELF) -i "$$log" $$verbose_flag 2>&1; then \
				echo "FAIL (constraints)"; \
				failed=$$((failed + 1)); \
				failed_tests="$$failed_tests\n  - $$base (constraints)"; \
				continue; \
			fi; \
		fi; \
		echo "PASS"; \
		passed=$$((passed + 1)); \
	done; \
	echo ""; \
	echo "Results: $$passed passed, $$failed failed (of $$total)"; \
	if [ $$failed -gt 0 ]; then \
		echo ""; \
		echo "Failed tests:$$failed_tests"; \
		exit 1; \
	fi

# Generate ZK proofs -> outputs/<name>/result.json + vadcop_final_proof.bin
prove: check-prove-filter check-step-logs | $(OUTPUTS_DIR)
	@echo "Generating ZisK Proof"
	@echo "ELF:      $(ELF)"
	@echo "Logs:     $(STEP_LOGS_PATH)"
	@echo "Outputs:  $(OUTPUTS_DIR)"
	@echo "Filter:   $(FILTER)"
	@echo "Total:    $(NUM_STEP_LOGS) proofs to generate"
	@echo ""
	@generated=0; failed=0; total=0; \
	for log in $(STEP_LOGS); do \
		base=$$(basename "$$log" .log); \
		total=$$((total + 1)); \
		proof_dir=$(OUTPUTS_DIR)/$$base; \
		echo "$$base"; \
		mkdir -p "$$proof_dir"; \
		verbose_flag=""; \
		if [ "$(verbose)" = "yes" ]; then verbose_flag="-v"; fi; \
		if ! $(CARGO_ZISK) prove -e $(ELF) -i "$$log" -o "$$proof_dir" -a -y $$verbose_flag 2>&1; then \
			echo "FAIL"; \
			failed=$$((failed + 1)); \
			continue; \
		fi; \
		echo "OK"; \
		generated=$$((generated + 1)); \
	done; \
	echo ""; \
	echo "Results: $$generated generated, $$failed failed (of $$total)"; \
	if [ $$failed -gt 0 ]; then exit 1; fi

# Verify generated proofs
verify-proof: check-prove-filter
	@echo "Verifying ZisK Proofs"
	@echo "Outputs:  $(OUTPUTS_DIR)"
	@echo "Filter:   $(FILTER)"
	@echo ""
	@verified=0; failed=0; total=0; \
	for proof in $(OUTPUTS_DIR)/*/vadcop_final_proof.bin; do \
		[ ! -f "$$proof" ] && continue; \
		dir=$$(dirname "$$proof"); \
		base=$$(basename "$$dir"); \
		if ! echo "$$base" | grep -qi "$(FILTER)"; then \
			continue; \
		fi; \
		total=$$((total + 1)); \
		printf "%-55s " "$$base"; \
		if ! $(CARGO_ZISK) verify -p "$$proof" >/dev/null 2>&1; then \
			echo "FAIL"; \
			failed=$$((failed + 1)); \
			continue; \
		fi; \
		echo "OK"; \
		verified=$$((verified + 1)); \
	done; \
	echo ""; \
	echo "Results: $$verified verified, $$failed failed (of $$total)"; \
	if [ $$failed -gt 0 ]; then exit 1; fi

clean:
	rm -rf $(OUTPUTS_DIR)

distclean: clean

help:
	@echo "  test           Run tests in ZisK emulator (default)"
	@echo "  prove          Generate ZK proofs (slow, requires FILTER)"
	@echo "  verify-proof   Verify generated proofs (requires FILTER)"
	@echo "  clean          Remove generated files"
	@echo "  help           Show this help"
	@echo ""
	@echo "Options:"
	@echo "  FILTER=<pattern>  Filter tests by pattern (case-insensitive grep)"
	@echo "  verify=yes        Enable constraint verification (slow, ~70-80s each)"
	@echo "  verbose=no        Suppress constraint details (default: yes)"
	@echo ""
