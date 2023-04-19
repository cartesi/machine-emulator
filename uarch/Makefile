TOOLCHAIN_PREFIX ?= riscv64-cartesi-linux-gnu-

EMULATOR_SRC_DIR = ../src
MACHINE_EMULATOR_DEFINES_DIR := ../lib/machine-emulator-defines
THIRD_PARTY_DIR := ../third-party

BOOST_INC_DIR = /usr/include/boost
ifeq ($(UNAME),Darwin)
# Homebrew installation
ifneq (,$(wildcard /usr/local/opt/boost/lib))
BOOST_INC_DIR =/usr/local/opt/boost/include
else # Macports installation
BOOST_INC_DIR = /opt/local/include
endif
endif

CC := $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld
CXX := $(TOOLCHAIN_PREFIX)g++
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(TOOLCHAIN_PREFIX)objdump

#
ifeq ($(relwithdebinfo),yes)
OPTFLAGS+=-O2 -DNDEBUG -g
else ifeq ($(release),yes)
OPTFLAGS+=-O2 -DNDEBUG -g0
else ifeq ($(debug),yes)
OPTFLAGS+=-Og -g
else
OPTFLAGS+=-O2 -g0
endif

# Link time optimizations
ifeq ($(lto),yes)
OPTFLAGS+=-flto=auto
endif

# Flags to minimize undefined behavior
UBFLAGS := -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks

CFLAGS := -march=rv64i -mabi=lp64 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) \
	-DMICROARCHITECTURE=1 \
	-DAVOID_NATIVE_UINT128_T=1 \
	-ffreestanding \
	-nostartfiles \
	-nostdlib \
	-fno-exceptions \
	-mstrict-align \
	-mcmodel=medany -static -fvisibility=hidden \
	-I. \
	-I$(MACHINE_EMULATOR_DEFINES_DIR) \
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
	shadow-pmas.cpp \
	clint.cpp \
	plic.cpp

UARCH_OBJS = $(patsubst %.c,%.uarch_c.o,$(patsubst %.cpp,%.uarch_cpp.o,$(UARCH_SOURCES)))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))
TARGETS=$(UARCH_OBJS) $(EMULATOR_OBJS)

.PHONY: all clean

all: $(TARGETS) uarch-ram.bin

uarch-ram.bin: uarch-ram.elf
	$(OBJCOPY) -S -O binary  $^ $@

uarch-ram.elf: $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o uarch-ram.ld
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Wl,-Tuarch-ram.ld  -o $@  $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o  -lgcc

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

clean:
	rm -f *.ld *.elf *.bin *.tmp link.ld *.o
