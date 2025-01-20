TOOLCHAIN_PREFIX ?= riscv64-unknown-elf-
TOOLCHAIN_LIBS = -lgcc

ifeq ($(DEV_ENV_HAS_TOOLCHAIN),yes)
TOOLCHAIN_INCS=\
	-I/usr/riscv64-linux-gnu/include/c++/12 \
	-I/usr/riscv64-linux-gnu/include/c++/12/riscv64-linux-gnu \
	-I/usr/riscv64-linux-gnu/include
else
TOOLCHAIN_INCS=
endif

EMULATOR_SRC_DIR = ../src
THIRD_PARTY_DIR := ../third-party

ifeq ($(UNAME),Darwin)
HOST_CXX := clang++
else
HOST_CXX := g++
endif

HOST_CFLAGS := -I$(THIRD_PARTY_DIR)/tiny_sha3 -I$(EMULATOR_SRC_DIR)

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

CXXFLAGS := -std=c++20 -fno-rtti

UARCH_SOURCES=\
	uarch-printf.c \
	uarch-run.cpp \
	uarch-ecall.c \
	uarch-runtime.cpp

EMULATOR_SOURCES=\
	interpret.cpp \
	pma-driver.cpp \
	htif.cpp \
	shadow-tlb.cpp \
	shadow-state.cpp \
	shadow-uarch-state.cpp \
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

LINTER_IGNORE_SOURCES=uarch-printf.c uarch-pristine-hash.c uarch-pristine-ram.c
LINTER_IGNORE_HEADERS=uarch-printf.h
LINTER_SOURCES=$(filter-out $(LINTER_IGNORE_SOURCES),$(strip $(wildcard uarch-*.cpp) $(wildcard uarch-*.c)))
LINTER_HEADERS=$(filter-out $(LINTER_IGNORE_HEADERS),$(strip $(wildcard uarch-*.h)))
EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
CLANG_TIDY_HEADER_FILTER=$(CURDIR)/($(subst $(SPACE),|,$(LINTER_HEADERS)))
CLANG_TIDY=clang-tidy
CLANG_TIDY_TARGETS=$(patsubst %.cpp,%.clang-tidy,$(patsubst %.c,%.clang-tidy,$(LINTER_SOURCES)))

.PHONY: all clean validate-instruction-set

all: uarch-ram.bin uarch-pristine-ram.c uarch-pristine-hash.c validate-instruction-set

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
	$(CC) $(CFLAGS) -c -o $@ $(<F)

%.emulator_cpp.o: $(EMULATOR_SRC_DIR)/%.cpp
	$(CXX) $(CFLAGS) $(CXXFLAGS) -c -o $@ $(EMULATOR_SRC_DIR)/$(<F)

%.uarch_c.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $(<F)

%.uarch_cpp.o: %.cpp
	$(CXX) $(CFLAGS) $(CXXFLAGS) -c -o $@ $(<F)

%.ld: %.ld.in
	$(CC) -o $(@F).tmp -x c $(CFLAGS) -E $(^F)
	grep -v '^#' $@.tmp > $@

%.clang-tidy: %.cpp
	$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $(CLANG_TIDY_FLAGS) $< -- -target riscv64-linux-gnu $(CFLAGS) $(CXXFLAGS) -Wno-unused-command-line-argument 2>/dev/null
	@touch $@

lint: $(CLANG_TIDY_TARGETS)

clean-executables:
	@rm -f compute-uarch-pristine-hash

clean-auto-generated:
	@rm -f uarch-pristine-hash.c uarch-pristine-ram.c

clean: clean-executables clean-auto-generated
	@rm -f *.ld *.elf *.bin *.tmp link.ld *.o *.clang-tidy *.insn.txt *.objdump
