
ifndef RISC0_CPP_TOOLCHAIN_DIR
ifeq ($(shell command -v rzup 2>/dev/null),)
  $(error "can't find rzup is not installed, I need it to find the risc0 cpp toolchain")
endif
RISC0_CPP_TOOLCHAIN_DIR := $(shell rzup show 2>/dev/null | grep -A1 "cpp" | grep -E "^\s*\*" | sed 's/.*\*\s*//' | head -1 | xargs -I {} find ~/.risc0 -name "*{}-cpp-*" -type d 2>/dev/null | head -1)/riscv32im-*/bin
endif
RISC0_CPP_TOOLCHAIN_PREFIX = $(RISC0_CPP_TOOLCHAIN_DIR)/riscv32-unknown-elf-

EMULATOR_SRC_DIR = $(abspath ../../src)
EMULATOR_TOOLS_DIR = $(abspath ../../tools)
THIRD_PARTY_DIR ?= $(abspath ../../third-party)

BOOST_INC_DIR = /usr/include/boost
ifeq ($(UNAME),Darwin)
HOST_CXX := clang++
# Homebrew installation
ifneq (,$(wildcard /usr/local/opt/boost/lib))
BOOST_INC_DIR =/usr/local/opt/boost/include
else # Macports installation
BOOST_INC_DIR = /opt/local/include
endif
else
HOST_CXX := g++
endif

HOST_CFLAGS := -I$(THIRD_PARTY_DIR)/tiny_sha3 -I$(EMULATOR_SRC_DIR)

CC := $(RISC0_CPP_TOOLCHAIN_PREFIX)gcc
LD := $(RISC0_CPP_TOOLCHAIN_PREFIX)ld
CXX := $(RISC0_CPP_TOOLCHAIN_PREFIX)g++
OBJCOPY := $(RISC0_CPP_TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(RISC0_CPP_TOOLCHAIN_PREFIX)objdump

OPTFLAGS=-O2 -g0

# Asserts are always enabled by now, but in the far future we should disable them
# OPTFLAGS+=-DNDEBUG

# Flags to minimize undefined behavior
UBFLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

CFLAGS := -march=rv32im -mabi=ilp32 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) \
	-DRISC0ARCHITECTURE=1 \
	-DAVOID_NATIVE_UINT128_T=1 \
	-ffreestanding \
	-nostartfiles \
	-nostdlib \
	-fno-exceptions \
	-mstrict-align \
	-mcmodel=medany -static -fvisibility=hidden \
	-I. \
	-I$(THIRD_PARTY_DIR)/llvm-flang-uint128 \
	-I$(EMULATOR_SRC_DIR) \
	-I$(BOOST_INC_DIR)

CXXFLAGS := -std=c++17 -fno-rtti

RISC0ARCH_SOURCES=\
	risc0-replay-steps.cpp \
	risc0-runtime.cpp

EMULATOR_SOURCES=\
	interpret.cpp \
	pma-driver.cpp \
	htif.cpp \
	shadow-tlb.cpp \
	shadow-state.cpp \
	shadow-uarch-state.cpp \
	plic.cpp \
	clint.cpp

RISC0ARCH_OBJS = $(patsubst %.cpp,%.risc0arch_cpp.o,$(RISC0ARCH_SOURCES))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))

.PHONY: all clean

all: risc0-replay-steps.o

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

$(EMULATOR_SRC_DIR)/machine-c-version.h:
	make -C $(EMULATOR_SRC_DIR) machine-c-version.h

$(EMULATOR_SRC_DIR)/interpret-jump-table.h: $(EMULATOR_TOOLS_DIR)/gen-interpret-jump-table.lua
	$< > $@

%.risc0arch_cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(<F)

risc0-replay-steps.o: $(EMULATOR_SRC_DIR)/machine-c-version.h $(EMULATOR_SRC_DIR)/interpret-jump-table.h $(EMULATOR_OBJS) $(RISC0ARCH_OBJS)
	$(LD) -relocatable $(EMULATOR_OBJS) $(RISC0ARCH_OBJS) -o $@

clean:
	@rm -f *.o
