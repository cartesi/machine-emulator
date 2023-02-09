TOOLCHAIN_IMAGE_TAG ?= cartesi/toolchain:0.11.0
TOOLCHAIN_PREFIX ?= riscv64-cartesi-linux-gnu-

CONTAINER_ROOT_DIR = /opt/cartesi/uarch
UARCH_SRC_DIR = $(abspath .)
CONTAINER_UARCH_SRC_DIR = $(CONTAINER_ROOT_DIR)/src/uarch
EMULATOR_SRC_DIR = $(abspath ../src)
CONTAINER_EMULATOR_SRC_DIR = $(CONTAINER_ROOT_DIR)/src/emulator
MACHINE_EMULATOR_DEFINES_DIR := $(abspath ../lib)/machine-emulator-defines
CONTAINER_MACHINE_EMULATOR_DEFINES_DIR := $(CONTAINER_ROOT_DIR)/defines
THIRD_PARTY_DIR := $(abspath ../third-party)
CONTAINER_THIRD_PARTY_DIR := $(CONTAINER_ROOT_DIR)/third-party
OUTPUT_DIR := $(abspath .)
CONTAINER_OUTPUT_DIR := $(CONTAINER_ROOT_DIR)/build

BOOST_INC_DIR = /usr/include/boost
CONTAINER_BOOST_INC_DIR := $(CONTAINER_ROOT_DIR)/boost
ifeq ($(UNAME),Darwin)
# Homebrew installation
ifneq (,$(wildcard /usr/local/opt/boost/lib))
BOOST_INC_DIR =/usr/local/opt/boost/include
else # Macports installation
BOOST_INC_DIR = /opt/local/include
endif
endif

RUN_TOOLCHAIN=docker run --rm  \
	--hostname toolchain-env \
	-e USER=$$(id -u -n) \
	-e GROUP=$$(id -g -n) \
	-e UID=$$(id -u) \
	-e GID=$$(id -g) \
	-v $(OUTPUT_DIR):$(CONTAINER_OUTPUT_DIR) \
	-v $(UARCH_SRC_DIR):$(CONTAINER_UARCH_SRC_DIR) \
	-v $(EMULATOR_SRC_DIR):$(CONTAINER_EMULATOR_SRC_DIR) \
	-v $(MACHINE_EMULATOR_DEFINES_DIR):$(CONTAINER_MACHINE_EMULATOR_DEFINES_DIR) \
	-v $(THIRD_PARTY_DIR):$(CONTAINER_THIRD_PARTY_DIR) \
	-v $(BOOST_INC_DIR):$(CONTAINER_BOOST_INC_DIR) \
	-w $(CONTAINER_OUTPUT_DIR) \
	-t ${TOOLCHAIN_IMAGE_TAG} 

CC := $(RUN_TOOLCHAIN) $(TOOLCHAIN_PREFIX)gcc
LD := $(RUN_TOOLCHAIN) $(TOOLCHAIN_PREFIX)ld
CXX := $(RUN_TOOLCHAIN) $(TOOLCHAIN_PREFIX)g++
OBJCOPY := $(RUN_TOOLCHAIN) $(TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(RUN_TOOLCHAIN) $(TOOLCHAIN_PREFIX)objdump

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

CFLAGS :=  -march=rv64i -mabi=lp64 -Wl,--gc-sections $(OPTFLAGS) $(UBFLAGS) \
 	-DMICROARCHITECTURE=1 \
 	-DAVOID_NATIVE_UINT128_T=1 \
	-ffreestanding \
	-nostartfiles \
	-nostdlib \
	-fno-exceptions \
	-mstrict-align \
    -mcmodel=medany -static -fvisibility=hidden \
	-I$(CONTAINER_MACHINE_EMULATOR_DEFINES_DIR) \
	-I$(CONTAINER_THIRD_PARTY_DIR)/llvm-flang-uint128 \
	-I$(CONTAINER_EMULATOR_SRC_DIR) \
	-I$(CONTAINER_UARCH_SRC_DIR) \
	-I$(CONTAINER_BOOST_INC_DIR)
	
CXXFLAGS :=  -std=c++17 -fno-rtti \

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
	clint.cpp

UARCH_ROM_OBJS =\
	uarch-run.bin.o \
	uarch-rom-entry.o \
	uarch-runtime.uarch_cpp.o \
	shadow-state.emulator_cpp.o

UARCH_OBJS = $(patsubst %.c,%.uarch_c.o,$(patsubst %.cpp,%.uarch_cpp.o,$(UARCH_SOURCES)))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))
TARGETS=$(UARCH_OBJS) $(EMULATOR_OBJS)

.PHONY: all clean

all: $(TARGETS) uarch-ram.bin

uarch-ram.bin: uarch-ram.elf
	$(OBJCOPY) -S -O binary  $^ $@

uarch-ram.elf: $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o uarch-ram.ld
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Wl,-T$(CONTAINER_OUTPUT_DIR)/uarch-ram.ld  -o $@  $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o  -lgcc

uarch-ram-entry.o: $(UARCH_SRC_DIR)/uarch-ram-entry.S
	$(CC) $(CFLAGS) -c -o $@ $(CONTAINER_UARCH_SRC_DIR)/$(<F)

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(CONTAINER_EMULATOR_SRC_DIR)/$(<F)

%.uarch_c.o: $(UARCH_SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $(CONTAINER_UARCH_SRC_DIR)/$(<F)

%.uarch_cpp.o: $(UARCH_SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $@ $(CONTAINER_UARCH_SRC_DIR)/$(<F)

%.ld: $(UARCH_SRC_DIR)/%.ld.in
	$(CC) -o $(@F).tmp -x c $(CFLAGS) -E $(CONTAINER_UARCH_SRC_DIR)/$(^F)
	grep -v '^#' $@.tmp > $@

clean:
	rm -f *.ld *.elf *.bin *.tmp link.ld *.o
