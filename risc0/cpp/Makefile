# The cpp toolchain version is pinned: risc0-replay-steps.o is linked into the guest, so its
# compiler is part of the Image ID. A different toolchain produces a different Image ID even
# with the Docker (reproducible) guest build. Keep in sync with the CI pin.
RISC0_CPP_TOOLCHAIN_VERSION := 2024.1.5

# Only detect toolchain for non-clean targets (allows clean to work without it installed)
ifeq ($(filter clean,$(MAKECMDGOALS)),)
ifndef RISC0_CPP_TOOLCHAIN_DIR
RISC0_CPP_TOOLCHAIN_DIR := $(firstword $(wildcard $(HOME)/.risc0/toolchains/*$(RISC0_CPP_TOOLCHAIN_VERSION)-cpp-*))/riscv32im-*/bin
ifeq ($(RISC0_CPP_TOOLCHAIN_DIR),/riscv32im-*/bin)
  $(error risc0 cpp toolchain $(RISC0_CPP_TOOLCHAIN_VERSION) not found; install it with 'rzup install cpp $(RISC0_CPP_TOOLCHAIN_VERSION)')
endif
endif
RISC0_CPP_TOOLCHAIN_PREFIX = $(RISC0_CPP_TOOLCHAIN_DIR)/riscv32-unknown-elf-
endif

EMULATOR_SRC_DIR = $(abspath ../../src)
EMULATOR_TOOLS_DIR = $(abspath ../../tools)
THIRD_PARTY_DIR ?= $(abspath ../../third-party)

CC := $(RISC0_CPP_TOOLCHAIN_PREFIX)gcc
LD := $(RISC0_CPP_TOOLCHAIN_PREFIX)ld
CXX := $(RISC0_CPP_TOOLCHAIN_PREFIX)g++
OBJCOPY := $(RISC0_CPP_TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(RISC0_CPP_TOOLCHAIN_PREFIX)objdump

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

CFLAGS := -march=rv32im -mabi=ilp32 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) -MMD -MP \
	-DZKARCHITECTURE=1 \
	-DNO_STD_VECTOR=1 \
	$(DUMP_DEFS) \
	-DAVOID_NATIVE_UINT128_T=1 \
	-ffreestanding \
	-nostartfiles \
	-nostdlib \
	-fno-exceptions \
	-mstrict-align \
	-mcmodel=medany -static -fvisibility=hidden \
	-I. \
	-I$(THIRD_PARTY_DIR)/llvm-flang-uint128 \
	-I$(THIRD_PARTY_DIR) \
	-I$(EMULATOR_SRC_DIR)

CXXFLAGS := -std=c++23 -fno-rtti -fno-threadsafe-statics -fno-use-cxa-atexit

RISC0ARCH_SOURCES=\
	risc0-replay-steps.cpp \
	risc0-runtime.cpp

EMULATOR_SOURCES=\
	interpret.cpp \
	htif-address-range.cpp \
	plic-address-range.cpp \
	clint-address-range.cpp

RISC0_THIRDPARTY_SOURCES_C=\
	../../third-party/printf/printf.c

RISC0_THIRDPARTY_OBJS = $(patsubst %.c,%.risc0_thirdparty_c.o,$(RISC0_THIRDPARTY_SOURCES_C))
RISC0ARCH_OBJS = $(patsubst %.cpp,%.risc0arch_cpp.o,$(RISC0ARCH_SOURCES))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))

.PHONY: all clean

all: risc0-replay-steps.o

GENERATED_HEADERS := $(EMULATOR_SRC_DIR)/cm-version.h $(EMULATOR_SRC_DIR)/interpret-jump-table.hpp

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp | $(GENERATED_HEADERS)
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

%.emulator_c.o: $(EMULATOR_SRC_DIR)/%.c | $(GENERATED_HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)


$(EMULATOR_SRC_DIR)/cm-version.h:
	make -C $(EMULATOR_SRC_DIR) cm-version.h

$(EMULATOR_SRC_DIR)/interpret-jump-table.hpp: $(EMULATOR_TOOLS_DIR)/gen-interpret-jump-table.lua
	$< > $@

%.risc0arch_cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(<F)

%.risc0arch_c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $(<F)

%.risc0_thirdparty_c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

risc0-replay-steps.o: $(EMULATOR_SRC_DIR)/cm-version.h $(EMULATOR_SRC_DIR)/interpret-jump-table.hpp $(EMULATOR_OBJS) $(RISC0ARCH_OBJS) $(RISC0_THIRDPARTY_OBJS)
	$(LD) -relocatable $(EMULATOR_OBJS) $(RISC0ARCH_OBJS) $(RISC0_THIRDPARTY_OBJS) -o $@

# Rebuild objects when an included header (e.g. shared emulator sources) changes.
-include $(wildcard *.d)

clean:
	@rm -f *.o *.d
