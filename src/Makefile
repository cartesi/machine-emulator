# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
#

EMULATOR_MARCHID=15

# Every new emulator release should bump these constants
EMULATOR_VERSION_MAJOR=0
EMULATOR_VERSION_MINOR=15
EMULATOR_VERSION_PATCH=2
EMULATOR_VERSION_LABEL=

TARGET_OS?=$(shell uname)

LUA_INC=$(shell pkg-config --cflags-only-I lua5.4)
LUA_LIB=$(shell pkg-config --libs lua5.4)
LUA_BIN=lua5.4
GRPC_DIR=../lib/grpc-interfaces

PROTOC=protoc
PROTOC_FLAGS=--experimental_allow_proto3_optional
GRPC_CPP_PLUGIN=$(shell which grpc_cpp_plugin)

# Are we on an environment that has the riscv64-cartesi-linux-gnu-* toolchain?
DEV_ENV_HAS_TOOLCHAIN ?= no

# If instead of building the microarchitecture you  wamt to use a pre-built image file, modify this variable to
# indicate the path of the desired file.
UARCH_RAM_IMAGE ?= ../uarch/uarch-ram.bin

# Code instrumentation
release?=no
sanitize?=no
coverage?=no
nothreads?=no

COVERAGE_TOOLCHAIN?=gcc
COVERAGE_OUTPUT_DIR?=coverage
CARTESI_TESTS_PATH?=/opt/cartesi/share/cartesi-machine/tests

# So we can use gcc to check if there are unused symbols
ifeq ($(gc),yes)
GCFLAGS=-fno-inline-small-functions -fno-inline -fdata-sections -ffunction-sections
GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections
endif

# Mac OS X specific setup
ifeq ($(TARGET_OS),Darwin)
PICCFLAGS=-fPIC
SOLDFLAGS=-bundle -undefined dynamic_lookup
LIBLDFLAGS=-dynamiclib
EXELDFLAGS=
PTHREAD_CFLAGS=
PTHREAD_LDFLAGS=-lpthread
CC=clang
CXX=clang++
AR=libtool -static -o
INCS=

ifeq ($(MACOSX_DEPLOYMENT_TARGET),)
export MACOSX_DEPLOYMENT_TARGET := $(shell sw_vers -productVersion | sed -E "s/([[:digit:]]+)\.([[:digit:]]+)\..+/\1.\2.0/")
endif

# Homebrew installation
ifneq (,$(shell which brew))
BREW_PREFIX = $(shell brew --prefix)
BOOST_LIB_DIR=-L$(BREW_PREFIX)/lib
BOOST_INC=-I$(BREW_PREFIX)/include
GRPC_PROTOBUF_INC=$(shell pkg-config --cflags-only-I grpc++ protobuf)
GRPC_PROTOBUF_LIB=$(shell pkg-config --libs grpc++ protobuf)

# Macports installation
else ifneq (,$(shell which port))
PORT_PREFIX = /opt/local
BOOST_LIB_DIR=-L$(PORT_PREFIX)/libexec/boost/1.81/lib
BOOST_INC=-I$(PORT_PREFIX)/libexec/boost/1.81/include
GRPC_PROTOBUF_INC=-I$(PORT_PREFIX)/include
GRPC_PROTOBUF_LIB=-L$(PORT_PREFIX)/lib -lgrpc++ -lgrpc -lgpr -lprotobuf -lpthread -labsl_synchronization
else
$(error Neither Homebrew nor MacPorts is installed)
endif

LIBCARTESI=libcartesi-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).dylib
LIBCARTESI_LDFLAGS=-install_name '@rpath/$(LIBCARTESI)'
LIBCARTESI_MERKLE_TREE=libcartesi_merkle_tree-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).dylib
LIBCARTESI_MERKLE_TREE_LDFLAGS=-install_name '@rpath/$(LIBCARTESI_MERKLE_TREE)'
LIBCARTESI_GRPC=libcartesi_grpc-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).dylib
LIBCARTESI_GRPC_LDFLAGS=-install_name '@rpath/$(LIBCARTESI_GRPC)'
LIBCARTESI_JSONRPC=libcartesi_jsonrpc-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).dylib
LIBCARTESI_JSONRPC_LDFLAGS=-install_name '@rpath/$(LIBCARTESI_JSONRPC)'
PROFILE_DATA=default.profdata

# Linux or some other POSIX platform
else

# Linux specific setup
PICCFLAGS=-fPIC
SOLDFLAGS=-shared $(PICCFLAGS) $(GCLDFLAGS)
LIBLDFLAGS=$(SOLDFLAGS)
EXELDFLAGS=$(GCLDFLAGS)
PTHREAD_CFLAGS=-pthread
PTHREAD_LDFLAGS=-pthread -lpthread
CC=gcc
CXX=g++
AR=ar rcs
INCS=

BOOST_INC=
GRPC_PROTOBUF_INC=$(shell pkg-config --cflags-only-I grpc++ protobuf)
GRPC_PROTOBUF_LIB=$(shell pkg-config --libs grpc++ protobuf)
LIBCARTESI=libcartesi-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).so
LIBCARTESI_LDFLAGS=
LIBCARTESI_MERKLE_TREE=libcartesi_merkle_tree-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).so
LIBCARTESI_MERKLE_TREE_LDFLAGS=
LIBCARTESI_GRPC=libcartesi_grpc-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).so
LIBCARTESI_GRPC_LDFLAGS=
LIBCARTESI_JSONRPC=libcartesi_jsonrpc-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).so
LIBCARTESI_JSONRPC_LDFLAGS=
PROFILE_DATA=

endif

LIBCARTESI_LIBS=
LIBCARTESI_MERKLE_TREE_LIBS=
LIBCARTESI_GRPC_LIBS=$(GRPC_PROTOBUF_LIB)
LIBCARTESI_JSONRPC_LIBS=
LUACARTESI_LIBS=
LUACARTESI_GRPC_LIBS=$(GRPC_PROTOBUF_LIB)
LUACARTESI_JSONRPC_LIBS=
REMOTE_CARTESI_MACHINE_LIBS=$(GRPC_PROTOBUF_LIB)
JSONRPC_REMOTE_CARTESI_MACHINE_LIBS=
TEST_MACHINE_C_API_LIBS=$(GRPC_PROTOBUF_LIB)
HASH_LIBS=

#DEFS+= -DMT_ALL_DIRTY

WARNS=-Wall -Wpedantic

# Place our include directories before the system's
INCS+= \
	-I../third-party/llvm-flang-uint128 \
	-I../third-party/tiny_sha3 \
	-I../third-party/downloads \
	-I../third-party/mongoose-7.12 \
	$(BOOST_INC)

ifeq ($(dump),yes)
#DEFS+=-DDUMP_ILLEGAL_INSN_EXCEPTIONS
#DEFS+=-DDUMP_EXCEPTIONS
#DEFS+=-DDUMP_INTERRUPTS
DEFS+=-DDUMP_HIST
#DEFS+=-DDUMP_MMU_EXCEPTIONS
#DEFS+=-DDUMP_INVALID_MEM_ACCESS
#DEFS+=-DDUMP_INVALID_CSR
#DEFS+=-DDUMP_INSN
#DEFS+=-DDUMP_REGS
#DEFS+=-DDUMP_COUNTERS
endif

ifeq ($(relwithdebinfo),yes)
OPTFLAGS+=-O2 -g
else ifeq ($(release),yes)
OPTFLAGS+=-O2
else ifeq ($(debug),yes)
OPTFLAGS+=-Og -g
else ifeq ($(sanitize),yes)
OPTFLAGS+=-Og -g
else
OPTFLAGS+=-O2 -g
endif

# Git commit hash (for releases)
ifneq ($(git_commit),)
DEFS+=-DGIT_COMMIT='"$(git_commit)"'
endif

# Allow mongoose to receive large messages
# The biggest message is reset uarch with large_data: 2x 4MB + small data + overhad
MONGOOSE_DEFS+=-DMG_MAX_RECV_SIZE=12582912

# Optimization flags
ifneq (,$(filter yes,$(relwithdebinfo) $(release)))
DEFS+=-DNDEBUG
## Mongoose log is disabled because it generates code using __FILE__ macro,
## which is reported as an error when packaging in some Linux distributions.
MONGOOSE_DEFS+=-DMG_ENABLE_LOG=0
ifneq (,$(filter gcc,$(CC)))
# The following flag helps GCC to eliminate more redundant computations in the interpret loop,
# saving some host instructions and improving performance.
# This flag is usually enabled by default at -O3,
# but we don't use -O3 because it enables some other flags that are not worth for the interpreter.
OPTFLAGS+=-fgcse-after-reload -fpredictive-commoning -fsplit-paths -ftree-partial-pre
endif
# Disable jump tables, because it degrades the instruction decoding performance in the interpret loop,
# since it generates a memory indirection that has a high cost in opcode switches.
OPTFLAGS+=-fno-jump-tables
endif

# Link time optimizations
ifeq ($(lto),yes)
OPTFLAGS+=-flto=auto
endif

ifeq ($(sanitize),yes)
# Enable address and undefined sanitizers
UBFLAGS+=-fsanitize=address,undefined -fno-sanitize-recover=all
LIBASAN_SO=$(shell realpath `$(CC) -print-file-name=libasan.so`)
LIBSTDCPP_SO=$(shell realpath `$(CC) -print-file-name=libstdc++.so`)
LD_PRELOAD="$(LIBASAN_SO) $(LIBSTDCPP_SO)"
LD_PRELOAD_PREFIX=LD_PRELOAD=$(LD_PRELOAD)
LUA=$(LD_PRELOAD_PREFIX) $(LUA_BIN)
else
# Flags to minimize undefined behavior
UBFLAGS+=-fno-strict-aliasing
UBFLAGS+=-fno-strict-overflow
UBFLAGS+=-fno-delete-null-pointer-checks
LD_PRELOAD_PREFIX=
LUA=$(LUA_BIN)
endif

# Compile for current system processor
ifeq ($(native),yes)
CC_MARCH=-march=native
else
CC_MARCH=
endif

# Workload to use in PGO
PGO_WORKLOAD=\
	tar c -C / bin | gzip > a.tar.gz && gzip -c a.tar.gz | sha256sum; \
	dhrystone 5000000; \
	whetstone 25000

# We ignore uarch-pristine-ram.c because it is generated by xxd.
# We ignore uarch-pristine-state-hash.cpp because it is generated by compute-uarch-pristine-hash.
LINTER_IGNORE_SOURCES=uarch-pristine-ram.c uarch-pristine-state-hash.cpp
LINTER_IGNORE_HEADERS=%.pb.h
LINTER_SOURCES=$(filter-out $(LINTER_IGNORE_SOURCES),$(strip $(wildcard *.cpp) $(wildcard *.c)))
LINTER_HEADERS=$(filter-out $(LINTER_IGNORE_HEADERS),$(strip $(wildcard *.hpp) $(wildcard *.h)))

CLANG_TIDY=clang-tidy
CLANG_TIDY_TARGETS=$(patsubst %.cpp,%.clang-tidy,$(patsubst %.c,%.clang-tidy,$(LINTER_SOURCES)))

CLANG_FORMAT=clang-format
CLANG_FORMAT_UARCH_FILES:=$(wildcard ../uarch/*.cpp)
CLANG_FORMAT_UARCH_FILES:=$(filter-out %uarch-printf%,$(strip $(CLANG_FORMAT_UARCH_FILES)))
CLANG_FORMAT_FILES:=$(wildcard *.cpp) $(wildcard *.c) $(wildcard *.h) $(wildcard *.hpp) $(CLANG_FORMAT_UARCH_FILES)
CLANG_FORMAT_IGNORE_FILES:=uarch-pristine-ram.c uarch-pristine-state-hash.cpp
CLANG_FORMAT_FILES:=$(filter-out %.pb.h,$(strip $(CLANG_FORMAT_FILES)))
CLANG_FORMAT_FILES:=$(filter-out $(CLANG_FORMAT_IGNORE_FILES),$(strip $(CLANG_FORMAT_FILES)))

STYLUA=stylua
STYLUA_FLAGS=--indent-type Spaces --collapse-simple-statement Always

EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
CLANG_TIDY_HEADER_FILTER=$(PWD)/($(subst $(SPACE),|,$(LINTER_HEADERS)))

ifeq ($(nothreads),no)
CFLAGS+=$(PTHREAD_CFLAGS)
CXXFLAGS+=$(PTHREAD_CFLAGS)
LDFLAGS+=$(PTHREAD_LDFLAGS)
else
DEFS+=-DNO_THREADS
endif

CXXFLAGS+=$(OPTFLAGS) -std=gnu++17 -fvisibility=hidden -MMD $(PICCFLAGS) $(CC_MARCH) $(INCS) $(GCFLAGS) $(UBFLAGS) $(DEFS) $(WARNS)
CFLAGS+=$(OPTFLAGS) -std=gnu99 -fvisibility=hidden -MMD $(PICCFLAGS) $(CC_MARCH) $(INCS) $(GCFLAGS) $(UBFLAGS) $(DEFS) $(WARNS)
LDFLAGS+=$(UBFLAGS)

COVERAGE_WORKLOAD=\
	dhrystone 1000000; \
	whetstone 10000
COVERAGE_CPP_SOURCES=$(wildcard *.cpp)
COVERAGE_SOURCES=$(filter-out %.pb.h, $(wildcard *.h) $(wildcard *.cpp))
ifeq ($(coverage),yes)
ifeq ($(COVERAGE_TOOLCHAIN),gcc)
CC=gcc
CXX=g++
CXXFLAGS+=-g -Og -fno-dce -fno-inline -DCODE_COVERAGE --coverage
LDFLAGS+=--coverage
LCOV_CONFIG=--rc lcov_branch_coverage=1
else ifeq ($(COVERAGE_TOOLCHAIN),clang)
CC=clang
CXX=clang++
CXXFLAGS+=-g -O0 -DCODE_COVERAGE -fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=-fprofile-instr-generate -fcoverage-mapping
export LLVM_PROFILE_FILE=coverage-%p.profraw
else ifneq ($(COVERAGE_TOOLCHAIN),)
$(error invalid value for COVERAGE_TOOLCHAIN: $(COVERAGE_TOOLCHAIN))
endif
endif

CXXFLAGS+=$(MYCXXFLAGS) $(MYDEFS)
CFLAGS+=$(MYCFLAGS) $(MYDEFS)
LDFLAGS+=$(MYLDFLAGS)
SOLDFLAGS+=$(MYSOLDFLAGS)
LIBLDFLAGS+=$(MYLIBLDFLAGS)
EXELDFLAGS+=$(MYEXELDFLAGS)

all: libcartesi.a libcartesi_merkle_tree.a libcartesi_jsonrpc.a c-api luacartesi jsonrpc-remote-cartesi-machine grpc hash

luacartesi: cartesi.so cartesi/grpc.so cartesi/jsonrpc.so

grpc: cartesi/jsonrpc.so cartesi/grpc.so remote-cartesi-machine

jsonrpc: cartesi/jsonrpc.so jsonrpc-remote-cartesi-machine

hash: merkle-tree-hash

c-api: $(LIBCARTESI) $(LIBCARTESI_MERKLE_TREE) $(LIBCARTESI_GRPC) $(LIBCARTESI_JSONRPC)

.PHONY: all generate use clean lint format format-lua check-format check-format-lua luacartesi grpc hash c-api compile_flags.txt

LIBCARTESI_OBJS:= \
	pma-driver.o \
	clint.o \
	clint-factory.o \
	dtb.o \
	os.o \
	htif.o \
	htif-factory.o \
	shadow-state.o \
	shadow-state-factory.o \
	shadow-pmas.o \
	shadow-pmas-factory.o \
	shadow-tlb.o \
	shadow-tlb-factory.o \
	shadow-uarch-state.o \
	shadow-uarch-state-factory.o \
	pma.o \
	machine.o \
	machine-config.o \
	json-util.o \
	base64.o \
	interpret.o \
	virtual-machine.o \
	uarch-machine.o \
	uarch-step.o \
	uarch-reset-state.o \
	uarch-interpret.o \
	machine-c-api.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o

CARTESI_CLUA_OBJS:= \
	clua.o \
	clua-i-virtual-machine.o \
	clua-htif.o \
	clua-machine-util.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o

LUACARTESI_OBJS:= \
	clua-cartesi.o \
	clua-machine.o \
	$(CARTESI_CLUA_OBJS)

PROTOBUF_GEN_OBJS:= \
	versioning.pb.o \
	cartesi-machine.pb.o \
	cartesi-machine-checkin.pb.o

GRPC_GEN_OBJS:= \
	cartesi-machine.grpc.pb.o \
	cartesi-machine-checkin.grpc.pb.o

LIBCARTESI_MERKLE_TREE_OBJS:= \
	sha3.o \
	machine-merkle-tree.o \
	back-merkle-tree.o \
	pristine-merkle-tree.o \
	complete-merkle-tree.o \
	full-merkle-tree.o

MERKLE_TREE_HASH_OBJS:= \
	merkle-tree-hash.o

COMPUTE_UARCH_PRISTINE_HASH_OBJS := \
	compute-uarch-pristine-hash.o \
	uarch-pristine-ram.o

LIBCARTESI_GRPC_OBJS:= \
	grpc-virtual-machine.o \
	grpc-machine-c-api.o \
	protobuf-util.o \
	$(GRPC_GEN_OBJS) \
	$(PROTOBUF_GEN_OBJS)

LIBCARTESI_JSONRPC_OBJS:= \
	jsonrpc-virtual-machine.o \
	jsonrpc-machine-c-api.o \
	mongoose.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o

LUACARTESI_GRPC_OBJS:= \
	clua-cartesi-grpc.o \
	clua-grpc-machine.o \
	$(CARTESI_CLUA_OBJS)

LUACARTESI_JSONRPC_OBJS:= \
	clua-cartesi-jsonrpc.o \
	clua-jsonrpc-machine.o \
	$(CARTESI_CLUA_OBJS)

PROTO_OBJS:= \
	$(PROTOBUF_GEN_OBJS) \
	$(GRPC_GEN_OBJS)

$(PROTO_OBJS): CXXFLAGS +=  -Wno-zero-length-array -Wno-unused-parameter -Wno-deprecated-declarations -Wno-deprecated-copy -Wno-type-limits

PROTO_SOURCES:=$(PROTO_OBJS:.o=.cc)

REMOTE_CARTESI_MACHINE_OBJS:= \
	remote-machine.o \
	slog.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o

JSONRPC_REMOTE_CARTESI_MACHINE_OBJS:= \
	jsonrpc-remote-machine.o \
	jsonrpc-discover.o \
	mongoose.o \
	slog.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o

ifeq ($(gperf),yes)
DEFS+=-DGPERF
LIBCARTESI_LIBS+=-lprofiler
LIBCARTESI_MERKLE_TREE_LIBS+=-lprofiler
LIBCARTESI_GRPC_LIBS+=-lprofiler
LIBCARTESI_JSONRPC_LIBS+=-lprofiler
LUACARTESI_LIBS+=-lprofiler
LUACARTESI_GRPC_LIBS+=-lprofiler
LUACARTESI_JSONRPC_LIBS+=-lprofiler
endif

version:
	@echo $(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).$(EMULATOR_VERSION_PATCH)$(EMULATOR_VERSION_LABEL)

so-version:
	@echo $(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR)

libcartesi: libcartesi.a $(LIBCARTESI)
libcartesi.so: $(LIBCARTESI) $(LIBCARTESI_MERKLE_TREE)
libcartesi_merkle_tree: libcartesi_merkle_tree.a $(LIBCARTESI_MERKLE_TREE)
libcartesi_merkle_tree.so: $(LIBCARTESI_MERKLE_TREE)
libcartesi_grpc: libcartesi_grpc.a $(LIBCARTESI_GRPC)
libcartesi_grpc.so: $(LIBCARTESI_GRPC)
libcartesi_jsonrpc: libcartesi_jsonrpc.a $(LIBCARTESI_JSONRPC)
libcartesi_jsonrpc.so: $(LIBCARTESI_JSONRPC)

libcartesi.a: $(LIBCARTESI_OBJS)
	$(AR) $@ $^

libcartesi_merkle_tree.a: $(LIBCARTESI_MERKLE_TREE_OBJS)
	$(AR) $@ $^

libcartesi_grpc.a: $(LIBCARTESI_GRPC_OBJS)
	$(AR) $@ $^

libcartesi_jsonrpc.a: $(LIBCARTESI_JSONRPC_OBJS)
	$(AR) $@ $^

$(LIBCARTESI_MERKLE_TREE): $(LIBCARTESI_MERKLE_TREE_OBJS)
	$(CXX) -o $@ $^ $(LIBCARTESI_MERKLE_TREE_LIBS) $(LDFLAGS) $(LIBCARTESI_MERKLE_TREE_LDFLAGS) $(LIBLDFLAGS)

$(LIBCARTESI): $(LIBCARTESI_OBJS) libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(LIBCARTESI_LIBS) $(LDFLAGS) $(LIBCARTESI_LDFLAGS) $(LIBLDFLAGS)

$(LIBCARTESI_GRPC): $(LIBCARTESI_GRPC_OBJS) libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(LIBCARTESI_GRPC_LIBS) $(LDFLAGS) $(LIBCARTESI_GRPC_LDFLAGS) $(LIBLDFLAGS)

$(LIBCARTESI_JSONRPC): $(LIBCARTESI_JSONRPC_OBJS) libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(LIBCARTESI_JSONRPC_LIBS) $(LDFLAGS) $(LIBCARTESI_JSONRPC_LDFLAGS) $(LIBLDFLAGS)

cartesi.so: $(LUACARTESI_OBJS) libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(LUACARTESI_LIBS) $(LDFLAGS) $(SOLDFLAGS)

cartesi/grpc.so: $(LUACARTESI_GRPC_OBJS) libcartesi_grpc.a libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(LUACARTESI_GRPC_LIBS) $(LDFLAGS) $(SOLDFLAGS)

cartesi/jsonrpc.so: $(LUACARTESI_JSONRPC_OBJS) libcartesi_jsonrpc.a libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(LUACARTESI_JSONRPC_LIBS) $(LDFLAGS) $(SOLDFLAGS)

lint: $(CLANG_TIDY_TARGETS)

format:
	@$(CLANG_FORMAT) -i $(CLANG_FORMAT_FILES)

check-format:
	@$(CLANG_FORMAT) -Werror --dry-run $(CLANG_FORMAT_FILES)

format-lua:
	@$(STYLUA) $(STYLUA_FLAGS) .

check-format-lua:
	@$(STYLUA) $(STYLUA_FLAGS) --check .

check-lua:
	luacheck .

fs.ext2: fs/*
	genext2fs -f -i 512 -b 8192 -d fs fs.ext2
	truncate -s %4096 fs.ext2

generate: CXXFLAGS += -fprofile-generate
generate: LDFLAGS += -fprofile-generate
generate: luacartesi

use: CXXFLAGS += -fprofile-use -Wno-missing-profile
use: LDFLAGS += -fprofile-use
use: $(PROFILE_DATA) luacartesi

coverage-workload:
	$(LUA) cartesi-machine.lua -- "$(COVERAGE_WORKLOAD)"
	# Test interactive mode (to cover mcycle overwriting)
	echo uname | $(LUA) cartesi-machine.lua -i sh
	# Test max mcycle (to cover max mcycle branch)
	$(LUA) cartesi-machine.lua --max-mcycle=1

coverage-workload-uarch:
	$(MAKE) -C ../tests test-uarch-for-coverage

compile_flags.txt:
	@echo "$(CXXFLAGS)" "-xc++" | sed -e $$'s/ \{1,\}/\\\n/g' | grep -v "MMD" > $@

luacartesi-pgo:
	$(MAKE) --no-print-directory generate
	./cartesi-machine.lua -- "$(PGO_WORKLOAD)"
	$(MAKE) clean-libcartesi
	$(MAKE) --no-print-directory use
	$(MAKE) clean-profile

ifeq ($(COVERAGE_TOOLCHAIN),gcc)
coverage-report:
	rm -f *.pb.cc.gcda *.pb.h.gcda
	gcov --demangled-names --relative-only --branch-probabilities *.gcda
	lcov --capture --directory . --no-external --exclude '*.pb.*' -o coverage.info $(LCOV_CONFIG) --quiet
	genhtml --quiet coverage.info --output-directory $(COVERAGE_OUTPUT_DIR)/gcc $(LCOV_CONFIG)
	lcov --list coverage.info $(LCOV_CONFIG) | tee $(COVERAGE_OUTPUT_DIR)/coverage.txt
	lcov --summary coverage.info $(LCOV_CONFIG) | tee -a $(COVERAGE_OUTPUT_DIR)/coverage.txt
else ifeq ($(COVERAGE_TOOLCHAIN),clang)
coverage-report:
	llvm-profdata merge -sparse $(shell find . -name 'coverage*.profraw') -o coverage.profdata
	llvm-cov show -format=html -output-dir=$(COVERAGE_OUTPUT_DIR)/clang -instr-profile=coverage.profdata \
		./cartesi.so \
		-object ./cartesi/grpc.so \
		-object ./cartesi/jsonrpc.so \
		-object ./$(LIBCARTESI) \
		-object ./$(LIBCARTESI_GRPC) \
		-object ./remote-cartesi-machine \
		-object ./jsonrpc-remote-cartesi-machine \
		$(COVERAGE_SOURCES)
endif

valgrind: luacartesi
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) cartesi-machine-tests.lua --test-path="$(CARTESI_TESTS_PATH)" --test=".*" run
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) cartesi-machine.lua --initial-hash --final-hash -- /bin/true

ifeq ($(TARGET_OS),Darwin)
$(PROFILE_DATA):
	llvm-profdata merge -output=default.profdata default*.profraw
endif

compute-uarch-pristine-hash: $(COMPUTE_UARCH_PRISTINE_HASH_OBJS) libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(HASH_LIBS) $(LDFLAGS) $(EXELDFLAGS)

merkle-tree-hash: $(MERKLE_TREE_HASH_OBJS) libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(HASH_LIBS) $(LDFLAGS) $(EXELDFLAGS)

grpc-interfaces: $(PROTO_SOURCES)

remote-cartesi-machine: $(REMOTE_CARTESI_MACHINE_OBJS) libcartesi_grpc.a libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(REMOTE_CARTESI_MACHINE_LIBS) $(LDFLAGS) $(EXELDFLAGS)

jsonrpc-remote-cartesi-machine: $(JSONRPC_REMOTE_CARTESI_MACHINE_OBJS) libcartesi_jsonrpc.a libcartesi.a libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(JSONRPC_REMOTE_CARTESI_MACHINE_LIBS) $(LDFLAGS) $(EXELDFLAGS)

$(PROTOBUF_GEN_OBJS) $(GRPC_GEN_OBJS) protobuf-util.o grpc-virtual-machine.o grpc-machine-c-api.o remote-machine.o remote-cartesi-machine: CXXFLAGS += $(GRPC_PROTOBUF_INC)

clua-%.o clua.o: CXXFLAGS += $(LUA_INC)

.PRECIOUS: %.grpc.pb.cc %.grpc.pb.h %.pb.cc %.pb.h

%.grpc.pb.cc: $(GRPC_DIR)/%.proto
	$(PROTOC) $(PROTOC_FLAGS) -I$(<D) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $<

%.pb.cc: $(GRPC_DIR)/%.proto
	$(PROTOC) $(PROTOC_FLAGS) -I$(GRPC_DIR) --cpp_out=. $<

protobuf-util.o: $(PROTOBUF_GEN_OBJS)

grpc-virtual-machine.o grpc-machine-c-api.o remote-machine.o: $(GRPC_GEN_OBJS) $(PROTOBUF_GEN_OBJS)

machine-c-version.h: ../tools/template/machine-c-version.h.template
	sed "s|EMULATOR_MARCHID|$(EMULATOR_MARCHID)|g;s|EMULATOR_VERSION_MAJOR|$(EMULATOR_VERSION_MAJOR)|g;s|EMULATOR_VERSION_MINOR|$(EMULATOR_VERSION_MINOR)|g;s|EMULATOR_VERSION_PATCH|$(EMULATOR_VERSION_PATCH)|g;s|EMULATOR_VERSION_LABEL|$(EMULATOR_VERSION_LABEL)|g" $< > $@

jsonrpc-discover.cpp: jsonrpc-discover.json
	echo '// This file is auto-generated and should not be modified' > jsonrpc-discover.cpp
	echo 'namespace cartesi {' >> jsonrpc-discover.cpp
	echo 'extern char const *const jsonrpc_discover_json = R"json(' >> jsonrpc-discover.cpp
	cat jsonrpc-discover.json >> jsonrpc-discover.cpp
	echo ')json";' >> jsonrpc-discover.cpp
	echo '} // namespace cartesi' >> jsonrpc-discover.cpp

uarch-pristine-state-hash.cpp:  compute-uarch-pristine-hash
	@echo '// This file is auto-generated and should not be modified' > $@
	@echo '#include "uarch-pristine-state-hash.h"' >> $@
	@echo 'namespace cartesi {' >> $@
	@echo '    const machine_merkle_tree::hash_type uarch_pristine_state_hash{' >> $@
	@./compute-uarch-pristine-hash  >> $@
	@echo '    };' >> $@
	@echo '} // namespace cartesi' >> $@

%.clang-tidy: %.cpp $(PROTO_SOURCES) machine-c-version.h
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $< -- $(CXXFLAGS) $(LUA_INC) $(GRPC_PROTOBUF_INC) 2>/dev/null
	@$(CXX) $(CXXFLAGS) $(LUA_INC) $(GRPC_PROTOBUF_INC) $< -MM -MT $@ -MF $@.d > /dev/null 2>&1
	@touch $@

%.clang-tidy: %.c $(PROTO_SOURCES)
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $< -- $(CFLAGS) 2>/dev/null
	@$(CC) $(CFLAGS) $< -MM -MT $@ -MF $@.d > /dev/null 2>&1
	@touch $@

mongoose.o: ../third-party/mongoose-7.12/mongoose.c
	$(CC) $(CFLAGS) $(MONGOOSE_DEFS) -c -o $@ $<

sha3.o: ../third-party/tiny_sha3/sha3.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp machine-c-version.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.cc $(PROTO_SOURCES)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

uarch-pristine-ram.c: $(UARCH_RAM_IMAGE)
	@(echo '#include <stddef.h>'; xxd -i -n uarch_pristine_ram $<) > $@ || rm $@

$(UARCH_RAM_IMAGE):
	@if [ "$(DEV_ENV_HAS_TOOLCHAIN)" = "yes" ]; then \
		$(MAKE) -C .. uarch; \
	else \
		$(MAKE) -C .. uarch-with-linux-env; \
	fi

clean: clean-auto-generated clean-coverage clean-profile clean-proto-sources clean-tidy clean-libcartesi clean-executables

clean-auto-generated:
	@rm -f jsonrpc-discover.cpp machine-c-version.h uarch-pristine-ram.c uarch-pristine-state-hash.cpp

clean-proto-sources:
	@rm -f *.pb.cc *.pb.h

clean-tidy:
	@rm -f *.clang-tidy

clean-objs:
	@rm -f *.o *.d

clean-libcartesi: clean-objs
	@rm -f *.so *.a cartesi/*.so

clean-executables:
	@rm -f jsonrpc-remote-cartesi-machine remote-cartesi-machine merkle-tree-hash

clean-coverage:
	@rm -f *.profdata *.profraw tests/*.profraw *.gcda *.gcov coverage.info coverage.txt
	@rm -rf coverage-gcc coverage-clang

clean-profile:
	@rm -f *.profdata *.profraw tests/*.profraw *.gcda *.gcno

-include $(wildcard *.d)
