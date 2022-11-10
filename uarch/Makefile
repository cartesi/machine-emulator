TOOLCHAIN_IMAGE_TAG ?= cartesi/toolchain:0.11.0
TOOLCHAIN_PREFIX ?= riscv64-cartesi-linux-gnu-

CONTAINER_ROOT_DIR = /opt/cartesi/uarch
UARCH_SRC_DIR = $(abspath .)
CONTAINER_UARCH_SRC_DIR = $(CONTAINER_ROOT_DIR)/src/uarch
SOFTFP_SRC_DIR = $(abspath ../third-party/tinyemu-softfp)
CONTAINER_SOFTFP_SRC_DIR = $(CONTAINER_ROOT_DIR)/third-party/tinyemu-softfp
EMULATOR_SRC_DIR = $(abspath ../src)
CONTAINER_EMULATOR_SRC_DIR = $(CONTAINER_ROOT_DIR)/src/emulator
MACHINE_EMULATOR_DEFINES_DIR := $(abspath ../lib)/machine-emulator-defines
CONTAINER_MACHINE_EMULATOR_DEFINES_DIR := $(CONTAINER_ROOT_DIR)/defines
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
	-v $(SOFTFP_SRC_DIR):$(CONTAINER_SOFTFP_SRC_DIR) \
	-v $(MACHINE_EMULATOR_DEFINES_DIR):$(CONTAINER_MACHINE_EMULATOR_DEFINES_DIR) \
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
	-ffreestanding \
	-nostartfiles \
	-nostdlib \
	-fno-exceptions \
    -mcmodel=medany -static -fvisibility=hidden \
	-I$(CONTAINER_MACHINE_EMULATOR_DEFINES_DIR) \
	-I$(CONTAINER_EMULATOR_SRC_DIR) \
	-I$(CONTAINER_SOFTFP_SRC_DIR) \
	-I$(CONTAINER_UARCH_SRC_DIR) \
	-I$(CONTAINER_BOOST_INC_DIR)
	
CXXFLAGS :=  -std=c++17 -fno-rtti \

UARCH_SOURCES=\
	uarch-printf.c \
	uarch-run.cpp \
	uarch-runtime.cpp

EMULATOR_SOURCES=\
	interpret.cpp \
	soft-float.cpp \
	pma-driver.cpp \
	htif.cpp \
	shadow-tlb.cpp \
	shadow-state.cpp \
	shadow-pmas.cpp \
	clint.cpp
UARCH_OBJS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(UARCH_SOURCES)))
EMULATOR_OBJS = $(patsubst %.c,%.o,$(patsubst %.cpp,%.o,$(EMULATOR_SOURCES)))
UARCH_CPP_TARGETS=$(patsubst %.cpp,%.uarch_cpp,$(filter %.cpp,$(UARCH_SOURCES)))
UARCH_C_TARGETS=$(patsubst %.c,%.uarch_c,$(filter %.c,$(UARCH_SOURCES)))
EMULATOR_CPP_TARGETS=$(patsubst %.cpp,%.emulator_cpp,$(filter %.cpp,$(EMULATOR_SOURCES)))
TARGETS=$(UARCH_C_TARGETS) $(UARCH_CPP_TARGETS) $(EMULATOR_CPP_TARGETS)

.PHONY: all clean

all: $(TARGETS) uarch-rom.bin
 
uarch-rom.bin: uarch-rom.elf
	$(OBJCOPY) -S -O binary  $^ $@

uarch-rom.elf: $(TARGETS) uarch-rom-entry.o uarch-rom.ld uarch-run.bin.o
	$(CC) $(CFLAGS) -Wl,uarch-rom.ld -o $@ uarch-run.bin.o uarch-rom-entry.o uarch-runtime.o shadow-state.o

uarch-rom-entry.o: $(UARCH_SRC_DIR)/uarch-rom-entry.S
	$(CC) $(CFLAGS) -c -o $(CONTAINER_OUTPUT_DIR)/$(@F) $(CONTAINER_UARCH_SRC_DIR)/$(<F)

uarch-run.bin.o: uarch-run.bin
	$(LD) -r -b binary -o $@ $^ 

uarch-run.bin: uarch-run.elf
	$(OBJCOPY) -S -O binary  $^ $@

uarch-run.elf: $(UARCH_TARGETS) $(EMULATOR_TARGETS) uarch-ram-entry.o uarch-ram.ld
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Wl,-T$(CONTAINER_OUTPUT_DIR)/uarch-ram.ld  -o $@  $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o  -lgcc

uarch-ram-entry.o: $(UARCH_SRC_DIR)/uarch-ram-entry.S
	$(CC) $(CFLAGS) -c -o $(CONTAINER_OUTPUT_DIR)/$(@F) $(CONTAINER_UARCH_SRC_DIR)/$(<F)

%.emulator_cpp: $(EMULATOR_SRC_DIR)/%.cpp 
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $(CONTAINER_OUTPUT_DIR)/$(subst .cpp,.o,$(<F))  $(CONTAINER_EMULATOR_SRC_DIR)/$(<F)

%.uarch_c: $(UARCH_SRC_DIR)/%.c 
	$(CC) $(CFLAGS) -c -o $(CONTAINER_OUTPUT_DIR)/$(subst .c,.o,$(<F)) $(CONTAINER_UARCH_SRC_DIR)/$(<F)

%.uarch_cpp: $(UARCH_SRC_DIR)/%.cpp 
	$(CXX) $(CXXFLAGS) $(CFLAGS) -c -o $(CONTAINER_OUTPUT_DIR)/$(subst .cpp,.o,$(<F))  $(CONTAINER_UARCH_SRC_DIR)/$(<F)

%.ld: $(UARCH_SRC_DIR)/%.ld.in
	$(CC) -o $(CONTAINER_OUTPUT_DIR)/$(@F).tmp -x c $(CFLAGS) -E  $(CONTAINER_UARCH_SRC_DIR)/$(^F)
	grep -v '^#' $@.tmp > $@

clean:
	rm -f *.ld *.elf *.bin *.tmp link.ld *.o

MICRO_EMULATOR_ROM_BIN := $(abspath uarch-rom.bin)
MACRO_EMULATOR_ROM_BIN := $(abspath ../../rom.bin)
MACRO_EMULATOR_RAM_BIN := $(abspath ../../linux.bin)
RUNNER_SCRIPT := $(abspath ./run-micro-emulator.lua)
SRCDIR := $(abspath .)
run:
	$(RUNNER_SCRIPT) $(MICRO_EMULATOR_ROM_BIN)  $(MACRO_EMULATOR_ROM_BIN) $(MACRO_EMULATOR_RAM_BIN)
