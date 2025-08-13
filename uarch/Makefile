TOOLCHAIN_PREFIX ?= riscv64-unknown-elf-
TOOLCHAIN_LIBS = -lgcc

ifeq ($(DEV_ENV_HAS_TOOLCHAIN),yes)
TOOLCHAIN_INCS=\
	-I/usr/riscv64-linux-gnu/include/c++/14 \
	-I/usr/riscv64-linux-gnu/include/c++/14/riscv64-linux-gnu \
	-I/usr/riscv64-linux-gnu/include
else
TOOLCHAIN_INCS=
endif

EMULATOR_SRC_DIR = ../src
THIRD_PARTY_DIR := ../third-party

ifeq ($(UNAME),Darwin)
HOST_CXX := clang++
HOST_CC := clang
else
HOST_CXX := g++
HOST_CC := gcc
endif
HOST_CFLAGS := -I$(EMULATOR_SRC_DIR)
HOST_CXXFLAGS := -std=c++23

CC := $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld
CXX := $(TOOLCHAIN_PREFIX)g++
OBJCOPY := $(TOOLCHAIN_PREFIX)objcopy
OBJDUMP := $(TOOLCHAIN_PREFIX)objdump

# Instructions supported by the microarchitecture interpreter (rv64ui)
SUPPORTED_UARCH_INSN := add|addi|addiw|addw|and|andi|auipc|beq|bge|bgeu|blt|bltu|bne|ebreak|ecall|fence|jal|jalr|lb|lbu|ld|lh|$\
	lhu|lui|lw|lwu|or|ori|sb|sd|sh|sll|slli|slliw|sllw|slt|slti|sltiu|sltu|sra|srai|sraiw|sraw|srl|srli|srliw|srlw|sub|$\
	subw|sw|xor|xori

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
	$(UARCH_DEFS) \
	$(TOOLCHAIN_INCS)

CXXFLAGS := -std=c++23 -fno-rtti \
	-fno-threadsafe-statics \
	-fno-use-cxa-atexit

UARCH_SOURCES=\
	third-party/printf/printf.c \
	uarch-run.cpp \
	uarch-ecall.c \
	uarch-runtime.cpp

EMULATOR_SOURCES=\
	$(EMULATOR_SRC_DIR)/interpret.cpp \
	$(EMULATOR_SRC_DIR)/htif-address-range.cpp \
	$(EMULATOR_SRC_DIR)/plic-address-range.cpp \
	$(EMULATOR_SRC_DIR)/clint-address-range.cpp

COMPUTE_SOURCES=\
	compute-uarch-pristine-hash.cpp \
	$(EMULATOR_SRC_DIR)/back-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/pristine-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/complete-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/full-merkle-tree.cpp \
	$(EMULATOR_SRC_DIR)/keccak-256-hasher.cpp \
	$(EMULATOR_SRC_DIR)/sha-256-hasher.cpp \
	$(EMULATOR_SRC_DIR)/is-pristine.cpp \
	uarch-pristine-ram.c

UARCH_OBJS = $(patsubst %.c,%.uarch_c.o,$(patsubst %.cpp,%.uarch_cpp.o,$(UARCH_SOURCES)))
EMULATOR_OBJS = $(patsubst %.c,%.emulator_c.o,$(patsubst %.cpp,%.emulator_cpp.o,$(EMULATOR_SOURCES)))
COMPUTE_OBJS = $(patsubst %.c,%.compute_c.o,$(patsubst %.cpp,%.compute_cpp.o,$(COMPUTE_SOURCES)))

LINTER_SOURCES=$(strip $(wildcard uarch-*.cpp))
LINTER_HEADERS=$(strip $(wildcard uarch-*.h))
EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
CLANG_TIDY_HEADER_FILTER=$(CURDIR)/($(subst $(SPACE),|,$(LINTER_HEADERS)))
CLANG_TIDY=clang-tidy
CLANG_TIDY_TARGETS=$(patsubst %.cpp,%.clang-tidy,$(LINTER_SOURCES))
CLANG_TIDY_FLAGS=--warnings-as-errors=*
CLANG_TIDY_WARNS=-Wthread-safety -Wglobal-constructors -Wno-unused-command-line-argument -Wno-format

.PHONY: all clean validate-instruction-set

all: uarch-ram.bin uarch-pristine-ram.c uarch-pristine-hash.c validate-instruction-set

compute-uarch-pristine-hash: $(COMPUTE_OBJS)
	$(HOST_CXX) $(HOST_CFLAGS) $(HOST_CXXFLAGS) -o $@ $^

uarch-pristine-hash.c: compute-uarch-pristine-hash
	./compute-uarch-pristine-hash > $@

uarch-pristine-ram.c: uarch-ram.bin
	@(echo '// This file is auto-generated and should not be modified'; \
		echo '#include <stddef.h>'; \
		xxd -i -n uarch_pristine_ram $<) > $@ || rm $@

uarch-ram.bin: uarch-ram.elf
	$(OBJCOPY) -S -O binary  $^ $@

uarch-ram.elf.insn.txt: uarch-ram.elf.objdump
	grep -oP '^\s*[0-9a-f]{4,8}\:\s+[0-9a-f]{4,8}\s+\K[a-z]\S+' $(^F) | sort -u > $@

uarch-ram.elf.objdump: uarch-ram.elf
	@$(OBJDUMP) -M no-aliases  -d $(^F) > $@

validate-instruction-set: uarch-ram.elf.insn.txt
	@grep  -v -w -E "$(SUPPORTED_UARCH_INSN)" $(<F);\
	if [ $$? -eq 0 ]; then\
		echo "Unsupported uarch instruction(s) detected. See objdump output in in uarch-ram.elf.objdump"; \
		false;\
	fi

uarch-ram.elf: $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o uarch-ram.ld
	$(CXX) $(CFLAGS) $(CXXFLAGS) -Wl,-Tuarch-ram.ld  -o $@ $(EMULATOR_OBJS) $(UARCH_OBJS) uarch-ram-entry.o $(TOOLCHAIN_LIBS)

uarch-ram-entry.o: uarch-ram-entry.S
	$(CC) $(CFLAGS) -c -o $@ $<

%.compute_cpp.o: %.cpp
	$(HOST_CXX) $(HOST_CFLAGS) $(HOST_CXXFLAGS) -c -o $@ $<

%.compute_c.o: %.c
	$(HOST_CC) $(HOST_CFLAGS) -c -o $@ $<

%.emulator_cpp.o: %.cpp
	$(CXX) $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

%.uarch_c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.uarch_cpp.o: %.cpp
	$(CXX) $(CFLAGS) $(CXXFLAGS) -c -o $@ $<

%.ld: %.ld.in
	$(CC) -o $(@F).tmp -x c $(CFLAGS) -E $(^F)
	grep -v '^#' $@.tmp > $@

%.clang-tidy: %.cpp
	$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $(CLANG_TIDY_FLAGS) $< -- -target riscv64-linux-gnu $(CFLAGS) $(CXXFLAGS) $(CLANG_TIDY_WARNS) 2>/dev/null
	@touch $@

lint: $(CLANG_TIDY_TARGETS)

clean-executables:
	@rm -f compute-uarch-pristine-hash

clean-auto-generated:
	@rm -f uarch-pristine-hash.c uarch-pristine-ram.c

clean: clean-executables clean-auto-generated
	@rm -f *.ld *.elf *.bin *.tmp *.o *.clang-tidy *.insn.txt *.objdump $(UARCH_OBJS) $(EMULATOR_OBJS) $(COMPUTE_OBJS)
