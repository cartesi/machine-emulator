TOOLCHAIN_PREFIX ?= riscv64-cartesi-linux-gnu-

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
WARNFLAGS := -Wall -Wextra -Wpedantic -Wno-array-bounds -Werror

CFLAGS := -march=rv64i -mabi=lp64 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) $(WARNFLAGS) \
	-DMICROARCHITECTURE=1 \
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

UARCH_SOURCES=\
	uarch-printf.c \
	uarch-run.cpp \
	uarch-runtime.cpp

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

COMPUTE_UARCH_CPP_SOURCES=\
	compute-uarch-pristine-hash.cpp \
	$(EMULATOR_SRC_DIR)/machine-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/back-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/pristine-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/complete-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/full-merkle-tree.cpp
COMPUTE_UARCH_C_SOURCES=\
	$(THIRD_PARTY_DIR)/tiny_sha3/sha3.c \
	uarch-pristine-ram.c

UARCH_OBJS = $(patsubst %.c,%.uarch_c.o,$(patsubst %.cpp,%.uarch_cpp.o,$(UARCH_SOURCES)))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))

.PHONY: all clean

all: uarch-ram.bin uarch-pristine-ram.c uarch-pristine-hash.c

compute-uarch-pristine-hash: $(COMPUTE_UARCH_CPP_SOURCES) $(COMPUTE_UARCH_C_SOURCES)
	$(HOST_CXX) $(HOST_CFLAGS) -o $@ -x c $(COMPUTE_UARCH_C_SOURCES) -x c++ $(COMPUTE_UARCH_CPP_SOURCES)

uarch-pristine-hash.c:  compute-uarch-pristine-hash
	./compute-uarch-pristine-hash > $@

uarch-pristine-ram.c: uarch-ram.bin
	@(echo '// This file is auto-generated and should not be modified'; \
		echo '#include <stddef.h>'; \
		xxd -i -n uarch_pristine_ram $<) > $@ || rm $@

uarch-ram.bin: uarch-ram.elf
	$(OBJCOPY) -S -O binary  $^ $@

uarch-ram.elf: $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o uarch-ram.ld
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Wl,-Tuarch-ram.ld  -o $@ $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o  -lgcc

uarch-ram-entry.o: uarch-ram-entry.S
	$(CC) $(CFLAGS) -c -o $@ $(<F)

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

%.uarch_c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $(<F)

%.uarch_cpp.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(<F)

%.ld: %.ld.in
	$(CC) -o $(@F).tmp -x c $(CFLAGS) -E $(^F)
	grep -v '^#' $@.tmp > $@

clean-executables:
	@rm -f compute-uarch-pristine-hash

clean-auto-generated:
	@rm -f uarch-pristine-hash.c uarch-pristine-ram.c

clean: clean-executables clean-auto-generated
	@rm -f *.ld *.elf *.bin *.tmp link.ld *.o
