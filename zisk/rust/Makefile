# builds the Rust program that wraps the C++ step replayer for ZisK
# Usage:
#   make all     - Build ELF
#   make run     - Run in emulator
#   make verify  - Verify constraints
#   make clean   - Clean artifacts
#

CARGO_ZISK ?= $(HOME)/.zisk/bin/cargo-zisk
ZISKEMU ?= $(HOME)/.zisk/bin/ziskemu

ifeq ($(wildcard $(CARGO_ZISK)),)
$(error cargo-zisk not found. Install ZisK toolchain first.)
endif

CPP_DIR := $(abspath ../cpp)
CPP_LIB := $(CPP_DIR)/libcartesi-zisk.a
ELF := target/riscv64ima-zisk-zkvm-elf/release/cartesi-zisk

.PHONY: all run verify clean

all: $(ELF)

$(ELF): $(CPP_LIB) src/main.rs build.rs Cargo.toml
	$(CARGO_ZISK) build --release

$(CPP_LIB):
	@echo "C++ library not found. Building..."
	$(MAKE) -C $(CPP_DIR) all

# Run in emulator with input
run: $(ELF)
	$(ZISKEMU) -e $(ELF) -i $(INPUT)

# Verify constraints - requires input
verify: $(ELF)
	$(CARGO_ZISK) verify-constraints -e $(ELF) -i $(INPUT)

clean:
	cargo clean 2>/dev/null || rm -rf target
