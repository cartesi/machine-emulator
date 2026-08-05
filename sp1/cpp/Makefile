# The SP1 GNU toolchain is installed by 'sp1up --c-toolchain' (or by hand) under ~/.sp1.
# The compiler is not pinned by SP1's Docker builder, which covers Rust guests only,
# so the toolchain tag below is our own pin. See Dockerfile for the canonical build.
SP1_CPP_TOOLCHAIN_TAG := 2026.02.13

# Only detect toolchain for non-clean targets (allows clean to work without it installed)
ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifndef SP1_CPP_TOOLCHAIN_DIR
SP1_CPP_TOOLCHAIN_DIR := $(firstword $(wildcard $(HOME)/.sp1/riscv64im-$(SP1_CPP_TOOLCHAIN_TAG)))/bin
ifeq ($(SP1_CPP_TOOLCHAIN_DIR),/bin)
  $(error sp1 cpp toolchain not found under $(HOME)/.sp1/riscv64im-$(SP1_CPP_TOOLCHAIN_TAG); extract the riscv64im tarball from succinctlabs/riscv-gnu-toolchain release $(SP1_CPP_TOOLCHAIN_TAG) there)
endif
endif
ifndef SP1_ZKEVM_SDK_DIR
SP1_ZKEVM_SDK_DIR := $(firstword $(wildcard $(HOME)/.sp1/zkevm-sdk-*))
ifeq ($(SP1_ZKEVM_SDK_DIR),)
  $(error sp1 zkevm C SDK not found under $(HOME)/.sp1; extract zkevm-sdk-*.tar.gz from a succinctlabs/sp1 release there)
endif
endif
SP1_CPP_TOOLCHAIN_PREFIX = $(SP1_CPP_TOOLCHAIN_DIR)/riscv64-unknown-elf-
endif

EMULATOR_SRC_DIR = $(abspath ../../src)
EMULATOR_TOOLS_DIR = $(abspath ../../tools)
THIRD_PARTY_DIR ?= $(abspath ../../third-party)

CC := $(SP1_CPP_TOOLCHAIN_PREFIX)gcc
# SP1's loader rejects segments that are both writable and executable; GNU ld
# emits a single RWX LOAD for the zkvm.ld script, ld.lld splits R-X from RW
# (matching SP1's documented link line).
LD := $(shell command -v ld.lld ld.lld-mp-21 /opt/local/bin/ld.lld-mp-21 2>/dev/null | head -1)
ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifeq ($(LD),)
  $(error ld.lld not found; SP1 guests must be linked with lld)
endif
endif
CXX := $(SP1_CPP_TOOLCHAIN_PREFIX)g++
OBJCOPY := $(SP1_CPP_TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(SP1_CPP_TOOLCHAIN_PREFIX)objdump
READELF := $(SP1_CPP_TOOLCHAIN_PREFIX)readelf
STRIP := $(SP1_CPP_TOOLCHAIN_PREFIX)strip

OPTFLAGS=-O2 -g0

ifeq ($(dump),yes)
DUMP_DEFS+=-DDUMP_INSN
DUMP_DEFS+=-DDUMP_REGS
DUMP_DEFS+=-DDUMP_HASH_TREE_STATS
DUMP_DEFS+=-DDUMP_ILLEGAL_INSN_EXCEPTIONS
DUMP_DEFS+=-DDUMP_EXCEPTIONS
DUMP_DEFS+=-DDUMP_INTERRUPTS
DUMP_DEFS+=-DDUMP_MMU_EXCEPTIONS
DUMP_DEFS+=-DDUMP_INVALID_CSR
DUMP_DEFS+=-DDUMP_INSN_HIST
DUMP_DEFS+=-DDUMP_STATS
DUMP_DEFS+=-DDUMP_SCOPED_NOTE
DUMP_DEFS+=-DDUMP_STATE_ACCESS
endif

# Flags to minimize undefined behavior
UBFLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

# SP1's executor has no misaligned load/store support (a misaligned access makes the
# program unprovable), hence -mstrict-align. rv64 synthesizes uint128 natively, so
# AVOID_NATIVE_UINT128_T is not needed. NO_STD_VECTOR is: freestanding libstdc++
# has no <vector>.
CFLAGS := -march=rv64im -mabi=lp64 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) -MMD -MP \
	-DZKARCHITECTURE=1 \
	-DNO_STD_VECTOR=1 \
	$(DUMP_DEFS) \
	-ffreestanding \
	-nostartfiles \
	-nostdlib \
	-fno-exceptions \
	-mstrict-align \
	-mcmodel=medany -static -fvisibility=hidden \
	-I. \
	-I$(SP1_ZKEVM_SDK_DIR)/include \
	-I$(THIRD_PARTY_DIR)/llvm-flang-uint128 \
	-I$(THIRD_PARTY_DIR) \
	-I$(EMULATOR_SRC_DIR)

CXXFLAGS := -std=c++23 -fno-rtti -fno-threadsafe-statics -fno-use-cxa-atexit

SP1ARCH_SOURCES=\
	sp1-replay-steps.cpp \
	sp1-runtime.cpp

EMULATOR_SOURCES=\
	interpret.cpp \
	htif-address-range.cpp \
	plic-address-range.cpp \
	clint-address-range.cpp

SP1_THIRDPARTY_SOURCES_C=\
	../../third-party/printf/printf.c

SP1_THIRDPARTY_OBJS = $(patsubst %.c,%.sp1_thirdparty_c.o,$(SP1_THIRDPARTY_SOURCES_C))
SP1ARCH_OBJS = $(patsubst %.cpp,%.sp1arch_cpp.o,$(SP1ARCH_SOURCES))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))

.PHONY: all clean

all: guest.elf

# Exercises the sha precompiles against a host reference; not shipped.
sha-abi-guest.elf: sha-abi-guest.sp1arch_cpp.o sp1-runtime.sp1arch_cpp.o $(SP1_THIRDPARTY_OBJS)
	$(LD) -static --gc-sections -u _start -T $(SP1_ZKEVM_SDK_DIR)/zkvm.ld \
		sha-abi-guest.sp1arch_cpp.o sp1-runtime.sp1arch_cpp.o $(SP1_THIRDPARTY_OBJS) \
		$(SP1_ZKEVM_SDK_DIR)/libzkevm.a -o $@
	$(STRIP) --strip-all $@

GENERATED_HEADERS := $(EMULATOR_SRC_DIR)/cm-version.h $(EMULATOR_SRC_DIR)/interpret-jump-table.hpp

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp | $(GENERATED_HEADERS)
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

%.emulator_c.o: $(EMULATOR_SRC_DIR)/%.c | $(GENERATED_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

$(EMULATOR_SRC_DIR)/cm-version.h:
	make -C $(EMULATOR_SRC_DIR) cm-version.h

$(EMULATOR_SRC_DIR)/interpret-jump-table.hpp: $(EMULATOR_TOOLS_DIR)/gen-interpret-jump-table.lua
	$< > $@

%.sp1arch_cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(<F)

%.sp1_thirdparty_c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# SP1's loader rejects any ELF segment below STACK_TOP (0x78000000), and never runs
# static constructors (__start calls main() directly, skipping .init_array); the
# post-link checks turn either mistake into a build failure instead of a silent one.
#
# Stripping is not cosmetic. SP1 builds the program from PT_LOAD segments plus a
# symbol-table lookup, so a symbol table is an input to the vkey that no build
# flag controls; with none, host-to-host differences in linker symbol ordering
# cannot reach it. Stripped builds come out byte-identical across hosts, which
# also makes a plain sha256 of the ELF a usable check.
guest.elf: $(EMULATOR_OBJS) $(SP1ARCH_OBJS) $(SP1_THIRDPARTY_OBJS)
	$(LD) -static --gc-sections -u _start -T $(SP1_ZKEVM_SDK_DIR)/zkvm.ld \
		$(EMULATOR_OBJS) $(SP1ARCH_OBJS) $(SP1_THIRDPARTY_OBJS) \
		$(SP1_ZKEVM_SDK_DIR)/libzkevm.a -o $@
	@if $(READELF) -S $@ | grep -qE '\.(pre)?init_array'; then \
		echo "ERROR: $@ has static constructors (init_array); SP1 never runs them"; \
		rm -f $@; exit 1; \
	fi
	@for a in $$($(READELF) -l $@ | awk '/LOAD/ {print $$3}'); do \
		if [ $$((a)) -lt $$((0x78000000)) ]; then \
			echo "ERROR: $@ has a LOAD segment below STACK_TOP 0x78000000"; \
			rm -f $@; exit 1; \
		fi; \
	done
	@if $(READELF) -l $@ | grep -q '\bNOTE\b'; then \
		echo "ERROR: $@ has a PT_NOTE segment; SP1 parses it into untrusted memory"; \
		rm -f $@; exit 1; \
	fi
	$(STRIP) --strip-all $@

# Rebuild objects when an included header (e.g. shared emulator sources) changes.
-include $(wildcard *.d)

clean:
	@rm -f *.o *.d guest.elf sha-abi-guest.elf
