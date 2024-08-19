TOOLCHAIN_PREFIX ?= riscv32-unknown-elf-

EMULATOR_SRC_DIR = ../src
THIRD_PARTY_DIR := ../third-party

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

CC := $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld
CXX := $(TOOLCHAIN_PREFIX)g++
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(TOOLCHAIN_PREFIX)objdump

OPTFLAGS=-O2 -g0

# Asserts are always enabled by now, but in the far future we should disable them
# OPTFLAGS+=-DNDEBUG

# Flags to minimize undefined behavior
UBFLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

CFLAGS := -march=rv32im -mabi=ilp32 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) \
	-DZKARCHITECTURE=1 \
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

ZKARCH_SOURCES=\
	zkarch-replay_steps.cpp \
	zkarch-runtime.cpp

EMULATOR_SOURCES=\
	interpret.cpp \
	pma-driver.cpp \
	htif.cpp \
	shadow-tlb.cpp \
	shadow-state.cpp \
	shadow-uarch-state.cpp \
	shadow-pmas.cpp \
	plic.cpp \
	clint.cpp

ZKARCH_OBJS = $(patsubst %.cpp,%.zkarch_cpp.o,$(ZKARCH_SOURCES))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))

.PHONY: all clean

all: zkarch-replay-steps.o

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

%.zkarch_cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(<F)

zkarch-replay-steps.o: $(EMULATOR_OBJS) $(ZKARCH_OBJS)
	$(LD) -relocatable $(EMULATOR_OBJS) $(ZKARCH_OBJS) -o $@

clean:
	@rm -f *.o
