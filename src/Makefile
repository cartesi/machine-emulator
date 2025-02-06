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

EMULATOR_MARCHID=18

# Every new emulator release should bump these constants
EMULATOR_VERSION_MAJOR=0
EMULATOR_VERSION_MINOR=18
EMULATOR_VERSION_PATCH=1
EMULATOR_VERSION_LABEL=

TARGET_OS?=$(shell uname)

LUA_INC=$(shell pkg-config --cflags-only-I lua5.4)
LUA_LIB=$(shell pkg-config --libs lua5.4)
LUA_BIN=lua5.4

# Are we on an environment that has the riscv64-cartesi-linux-gnu-* toolchain?
DEV_ENV_HAS_TOOLCHAIN ?= no

# If instead of building the microarchitecture you want to use a pre-built image file, modify this variable to
# indicate the path of the desired file.
UARCH_PRISTINE_RAM_C ?= ../uarch/uarch-pristine-ram.c
UARCH_PRISTINE_HASH_C ?= ../uarch/uarch-pristine-hash.c

# Code instrumentation
release?=no
sanitize?=no
coverage?=no
threads?=yes
slirp?=yes

COVERAGE_TOOLCHAIN?=gcc

CARTESI_TESTS_PATH?=../tests/build/machine

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

BREW_PREFIX=$(shell which brew)
PORT_PREFIX=$(shell which port)

ifeq ($(MACOSX_DEPLOYMENT_TARGET),)
export MACOSX_DEPLOYMENT_TARGET := $(shell sw_vers -productVersion | sed -E "s/([[:digit:]]+)\.([[:digit:]]+)\..+/\1.\2.0/")
endif

# Homebrew installation
ifneq (,$(BREW_PREFIX))
BREW_PREFIX=$(shell brew --prefix)
BOOST_LIB_DIR=-L$(BREW_PREFIX)/lib
BOOST_INC=-I$(BREW_PREFIX)/include
SLIRP_LIB=-L$(BREW_PREFIX)/lib -lslirp
SLIRP_INC=-I$(BREW_PREFIX)/libslirp/include

# Macports installation
else ifneq (,$(PORT_PREFIX))
INSTALL_PREFIX=/opt/local
BOOST_LIB_DIR=-L$(INSTALL_PREFIX)/libexec/boost/1.81/lib
BOOST_INC=-I$(INSTALL_PREFIX)/libexec/boost/1.81/include
SLIRP_LIB=-L$(INSTALL_PREFIX)/lib -lslirp
SLIRP_INC=-I$(INSTALL_PREFIX)/include

else
$(warning Neither Homebrew nor MacPorts prefix found)
endif

SO_EXT=dylib
LIBCARTESI_LDFLAGS=-install_name '@rpath/$(LIBCARTESI)'
LIBCARTESI_MERKLE_TREE_LDFLAGS=-install_name '@rpath/$(LIBCARTESI_MERKLE_TREE)'
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
SLIRP_INC=
SLIRP_LIB=-lslirp
SO_EXT=so
LIBCARTESI_LDFLAGS=
LIBCARTESI_MERKLE_TREE_LDFLAGS=
LIBCARTESI_JSONRPC_LDFLAGS=
PROFILE_DATA=

endif

LIBCARTESI=libcartesi-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).$(SO_EXT)
LIBCARTESI_MERKLE_TREE=libcartesi_merkle_tree-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).$(SO_EXT)
LIBCARTESI_JSONRPC=libcartesi_jsonrpc-$(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).$(SO_EXT)

ifeq ($(slirp),yes)
# Workaround for building with macports lua-luarocks installation
machine.o: INCS+=$(SLIRP_INC)
machine.clang-tidy: INCS+=$(SLIRP_INC)
virtio-net-carrier-slirp.o: INCS+=$(SLIRP_INC)
virtio-net-carrier-slirp.clang-tidy: INCS+=$(SLIRP_INC)
#INCS+=$(SLIRP_INC)
LIBCARTESI_COMMON_LIBS+=$(SLIRP_LIB)
else
DEFS+=-DNO_SLIRP
endif

LIBCARTESI_LIBS=$(LIBCARTESI_COMMON_LIBS)
LIBCARTESI_MERKLE_TREE_LIBS=
LIBCARTESI_JSONRPC_LIBS=$(LIBCARTESI_COMMON_LIBS)
LUACARTESI_LIBS=$(LIBCARTESI_COMMON_LIBS)
LUACARTESI_JSONRPC_LIBS=$(LIBCARTESI_COMMON_LIBS)
JSONRPC_REMOTE_CARTESI_MACHINE_LIBS=$(LIBCARTESI_COMMON_LIBS)
HASH_LIBS=

#DEFS+= -DMT_ALL_DIRTY

WARNS=-Wall -Wextra -Wpedantic

# Place our include directories before the system's
INCS+= \
	-I../third-party/llvm-flang-uint128 \
	-I../third-party/tiny_sha3 \
	-I../third-party/nlohmann-json \
	-I../third-party/downloads \
	$(BOOST_INC)

# Use 64-bit offsets for file operations in POSIX APIs
DEFS+=-D_FILE_OFFSET_BITS=64

# Disable json filesystem to support more compilers
DEFS+=-DJSON_HAS_FILESYSTEM=0

# Disable ASIO threads and use asio select() backend to avoid potential issues fork()
DEFS+=-DBOOST_ASIO_DISABLE_THREADS -DBOOST_ASIO_DISABLE_EPOLL -DBOOST_ASIO_DISABLE_EVENTFD

ifeq ($(dump),yes)
#DUMP_DEFS+=-DDUMP_ILLEGAL_INSN_EXCEPTIONS
#DUMP_DEFS+=-DDUMP_EXCEPTIONS
#DUMP_DEFS+=-DDUMP_INTERRUPTS
#DUMP_DEFS+=-DDUMP_MMU_EXCEPTIONS
#DUMP_DEFS+=-DDUMP_INVALID_MEM_ACCESS
#DUMP_DEFS+=-DDUMP_INVALID_CSR
#DUMP_DEFS+=-DDUMP_REGS
DUMP_DEFS+=-DDUMP_INSN_HIST
DUMP_DEFS+=-DDUMP_STATS
DUMP_DEFS+=-DDUMP_INSN
DUMP_DEFS+=-DDUMP_UARCH_INSN
DUMP_DEFS+=-DDUMP_SCOPED_NOTE
DUMP_DEFS+=-DDUMP_STATE_ACCESS
DUMP_DEFS+=-DDUMP_UARCH_STATE_ACCESS
endif
DEFS += $(DUMP_DEFS)
# Pass down UARCH_DEFS to sub-makefiles
export UARCH_DEFS += $(DUMP_DEFS)

# By default we compile in release with debug information,
# so the emulator is packaged correctly by default.
ifeq (,$(filter yes,$(relwithdebinfo) $(release) $(debug) $(sanitize)))
relwithdebinfo=yes
endif

ifeq ($(relwithdebinfo),yes)
OPTFLAGS+=-O2 -g
INTERPRET_CXXFLAGS+=-DNDEBUG # disable asserts only for interpret.cpp
else ifeq ($(release),yes)
OPTFLAGS+=-O2
DEFS+=-DNDEBUG # disable all asserts
DEFS+=-DBOOST_ASIO_DISABLE_ERROR_LOCATION # remove line/function location from error messages
else ifeq ($(debug),yes)
OPTFLAGS+=-Og -g -fno-omit-frame-pointer
OPTFLAGS+=-D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-clash-protection -fstack-protector-strong
else ifeq ($(sanitize),yes)
OPTFLAGS+=-O1 -g -fno-omit-frame-pointer
OPTFLAGS+=-D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -fstack-clash-protection -fstack-protector-strong
endif

# Git commit hash (for releases)
ifneq ($(git_commit),)
DEFS+=-DGIT_COMMIT='"$(git_commit)"'
endif

# The SHA3 is third party library we always want to compile with O3
SHA3_CFLAGS=-O3

# Optimization flags for the interpreter
ifneq (,$(filter yes,$(relwithdebinfo) $(release)))
ifneq (,$(findstring gcc,$(CC)))
# The following improves computed goto dispatch as stated in GCC manual
INTERPRET_CXXFLAGS+=-fno-gcse
# The following remove extra jumps in the computed goto dispatch
# INTERPRET_CXXFLAGS+=-fno-crossjumping
# The interpreter dispatch loop performs better as a big inlined function
INTERPRET_CXXFLAGS+=-finline-limit=1024
# The interpreter hot loop is big and puts pressure on register allocation, this improves register use
INTERPRET_CXXFLAGS+=-frename-registers -fweb
# The interpreter instruction dispatch is big, the following reduces its size minimizing CPU cache pressure
INTERPRET_CXXFLAGS+=-freorder-blocks-algorithm=simple
# Some distributions enables stack protector by default, make sure it's disabled
INTERPRET_CXXFLAGS+=-fno-stack-protector
endif
endif

# Make testing new optimization options easier
INTERPRET_CXXFLAGS+=$(MYINTERPRET_CXXFLAGS)

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

LINTER_IGNORE_SOURCES=
LINTER_IGNORE_HEADERS=interpret-jump-table.h
LINTER_SOURCES=$(filter-out $(LINTER_IGNORE_SOURCES),$(strip $(wildcard *.cpp) $(wildcard *.c)))
LINTER_HEADERS=$(filter-out $(LINTER_IGNORE_HEADERS),$(strip $(wildcard *.hpp) $(wildcard *.h)))

CLANG_TIDY=clang-tidy
CLANG_TIDY_TARGETS=$(patsubst %.cpp,%.clang-tidy,$(patsubst %.c,%.clang-tidy,$(LINTER_SOURCES)))

CLANG_FORMAT=clang-format
CLANG_FORMAT_UARCH_FILES:=$(wildcard ../uarch/*.cpp) $(wildcard ../uarch/*.h)
CLANG_FORMAT_UARCH_FILES:=$(filter-out %uarch-printf%,$(strip $(CLANG_FORMAT_UARCH_FILES)))
CLANG_FORMAT_FILES:=$(wildcard *.cpp) $(wildcard *.c) $(wildcard *.h) $(wildcard *.hpp) $(CLANG_FORMAT_UARCH_FILES)
CLANG_FORMAT_IGNORE_FILES:=interpret-jump-table.h
CLANG_FORMAT_FILES:=$(strip $(CLANG_FORMAT_FILES))
CLANG_FORMAT_FILES:=$(filter-out $(CLANG_FORMAT_IGNORE_FILES),$(strip $(CLANG_FORMAT_FILES)))

STYLUA=stylua
STYLUA_FLAGS=--indent-type Spaces --collapse-simple-statement Always

EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
CLANG_TIDY_HEADER_FILTER=$(CURDIR)/($(subst $(SPACE),|,$(LINTER_HEADERS)))

ifeq ($(threads),yes)
CFLAGS+=$(PTHREAD_CFLAGS)
CXXFLAGS+=$(PTHREAD_CFLAGS)
LDFLAGS+=$(PTHREAD_LDFLAGS)
else
DEFS+=-DNO_THREADS
endif

CXXFLAGS+=$(OPTFLAGS) -std=gnu++20 -fvisibility=hidden -MMD $(PICCFLAGS) $(CC_MARCH) $(INCS) $(GCFLAGS) $(UBFLAGS) $(DEFS) $(WARNS)
CFLAGS+=$(OPTFLAGS) -std=gnu99 -fvisibility=hidden -MMD $(PICCFLAGS) $(CC_MARCH) $(INCS) $(GCFLAGS) $(UBFLAGS) $(DEFS) $(WARNS)
LDFLAGS+=$(UBFLAGS)

ifeq ($(coverage),yes)
ifeq ($(COVERAGE_TOOLCHAIN),gcc)
CC=gcc
CXX=g++
CXXFLAGS+=-g -Og -fno-dce -fno-inline -DCODE_COVERAGE --coverage
LDFLAGS+=--coverage
else ifeq ($(COVERAGE_TOOLCHAIN),clang)
CC=clang
CXX=clang++
CXXFLAGS+=-g -O0 -DCODE_COVERAGE -fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=-fprofile-instr-generate -fcoverage-mapping
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

all: libcartesi libcartesi_merkle_tree libcartesi_jsonrpc c-api luacartesi jsonrpc-remote-cartesi-machine hash

luacartesi: libluacartesi.a cartesi.so libluacartesi_jsonrpc.a cartesi/jsonrpc.so

jsonrpc: cartesi/jsonrpc.so jsonrpc-remote-cartesi-machine

hash: merkle-tree-hash

c-api: $(LIBCARTESI) $(LIBCARTESI_MERKLE_TREE) $(LIBCARTESI_JSONRPC)

.PHONY: all generate use clean lint format format-lua check-format check-format-lua luacartesi hash c-api compile_flags.txt

LIBCARTESI_OBJS:= \
	pma-driver.o \
	clint.o \
	clint-factory.o \
	plic.o \
	plic-factory.o \
	virtio-factory.o \
	virtio-device.o \
	virtio-console.o \
	virtio-p9fs.o \
	virtio-net.o \
	virtio-net-carrier-tuntap.o \
	virtio-net-carrier-slirp.o \
	dtb.o \
	os.o \
	htif.o \
	htif-factory.o \
	shadow-state.o \
	shadow-state-factory.o \
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
	sha3.o \
	machine-merkle-tree.o \
	pristine-merkle-tree.o \
	machine-c-api.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o \
	uarch-pristine-hash.o \
    uarch-interpret.o \
	uarch-step.o \
	uarch-reset-state.o \
	send-cmio-response.o \
	replay-step-state-access-interop.o

CARTESI_CLUA_OBJS:= \
	clua.o \
	clua-i-virtual-machine.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o \
	uarch-pristine-hash.o

LUACARTESI_OBJS:= \
	clua-cartesi.o \
	$(CARTESI_CLUA_OBJS)

LIBCARTESI_MERKLE_TREE_OBJS:= \
	sha3.o \
	machine-merkle-tree.o \
	back-merkle-tree.o \
	pristine-merkle-tree.o \
	complete-merkle-tree.o \
	full-merkle-tree.o

MERKLE_TREE_HASH_OBJS:= \
	merkle-tree-hash.o

LIBCARTESI_JSONRPC_OBJS:= \
	jsonrpc-virtual-machine.o \
	os.o \
	jsonrpc-machine-c-api.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o \
	uarch-pristine-hash.o

LUACARTESI_JSONRPC_OBJS:= \
	clua-cartesi-jsonrpc.o \
	$(CARTESI_CLUA_OBJS)

JSONRPC_REMOTE_CARTESI_MACHINE_OBJS:= \
	jsonrpc-remote-machine.o \
	jsonrpc-discover.o \
	slog.o \
	uarch-pristine-ram.o \
	uarch-pristine-state-hash.o \
	uarch-pristine-hash.o

ifeq ($(gperf),yes)
DEFS+=-DGPERF
LIBCARTESI_LIBS+=-lprofiler
LIBCARTESI_MERKLE_TREE_LIBS+=-lprofiler
LIBCARTESI_JSONRPC_LIBS+=-lprofiler
LUACARTESI_LIBS+=-lprofiler
LUACARTESI_JSONRPC_LIBS+=-lprofiler
endif

version:
	@echo $(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR).$(EMULATOR_VERSION_PATCH)$(EMULATOR_VERSION_LABEL)

so-version:
	@echo $(EMULATOR_VERSION_MAJOR).$(EMULATOR_VERSION_MINOR)

libcartesi: libcartesi.a libcartesi.$(SO_EXT)
libcartesi.$(SO_EXT): $(LIBCARTESI) $(LIBCARTESI_MERKLE_TREE)
	ln -sf $< $@
libcartesi_merkle_tree: libcartesi_merkle_tree.a libcartesi_merkle_tree.$(SO_EXT)
libcartesi_merkle_tree.$(SO_EXT): $(LIBCARTESI_MERKLE_TREE)
	ln -sf $< $@
libcartesi_jsonrpc: libcartesi_jsonrpc.a libcartesi_jsonrpc.$(SO_EXT)
libcartesi_jsonrpc.$(SO_EXT): $(LIBCARTESI_JSONRPC)
	ln -sf $< $@

libcartesi.a: $(LIBCARTESI_OBJS)
	$(AR) $@ $^

libcartesi_merkle_tree.a: $(LIBCARTESI_MERKLE_TREE_OBJS)
	$(AR) $@ $^

libcartesi_jsonrpc.a: $(LIBCARTESI_JSONRPC_OBJS)
	$(AR) $@ $^

libluacartesi.a: $(LUACARTESI_OBJS)
	$(AR) $@ $^

libluacartesi_jsonrpc.a: $(LUACARTESI_JSONRPC_OBJS)
	$(AR) $@ $^

$(LIBCARTESI_MERKLE_TREE): $(LIBCARTESI_MERKLE_TREE_OBJS)
	$(CXX) -o $@ $^ $(LIBCARTESI_MERKLE_TREE_LIBS) $(LDFLAGS) $(LIBCARTESI_MERKLE_TREE_LDFLAGS) $(LIBLDFLAGS)

$(LIBCARTESI): $(LIBCARTESI_OBJS)
	$(CXX) -o $@ $^ $(LIBCARTESI_LIBS) $(LDFLAGS) $(LIBCARTESI_LDFLAGS) $(LIBLDFLAGS)

$(LIBCARTESI_JSONRPC): $(LIBCARTESI_JSONRPC_OBJS) libcartesi.a
	$(CXX) -o $@ $^ $(LIBCARTESI_JSONRPC_LIBS) $(LDFLAGS) $(LIBCARTESI_JSONRPC_LDFLAGS) $(LIBLDFLAGS)

cartesi.so: $(LUACARTESI_OBJS) libcartesi.a
	$(CXX) -o $@ $^ $(LUACARTESI_LIBS) $(LDFLAGS) $(SOLDFLAGS)

cartesi/jsonrpc.so: $(LUACARTESI_JSONRPC_OBJS) libcartesi_jsonrpc.a libcartesi.a
	$(CXX) -o $@ $^ $(LUACARTESI_JSONRPC_LIBS) $(LDFLAGS) $(SOLDFLAGS)

lint: $(CLANG_TIDY_TARGETS)
	@$(MAKE) --no-print-directory -C ../uarch lint

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

compile_flags.txt:
	@echo "$(CXXFLAGS)" "-xc++" | sed -e $$'s/ \{1,\}/\\\n/g' | grep -v "MMD" > $@

luacartesi-pgo:
	$(MAKE) --no-print-directory generate
	./cartesi-machine.lua -- "$(PGO_WORKLOAD)"
	$(MAKE) clean-libcartesi
	$(MAKE) --no-print-directory use
	$(MAKE) clean-profile

valgrind: luacartesi
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) cartesi-machine-tests.lua --test-path="$(CARTESI_TESTS_PATH)" --test=".*" run
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) cartesi-machine.lua --initial-hash --final-hash -- /bin/true

ifeq ($(TARGET_OS),Darwin)
$(PROFILE_DATA):
	llvm-profdata merge -output=default.profdata default*.profraw
endif

merkle-tree-hash: $(MERKLE_TREE_HASH_OBJS) libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(HASH_LIBS) $(LDFLAGS) $(EXELDFLAGS)

jsonrpc-remote-cartesi-machine: $(JSONRPC_REMOTE_CARTESI_MACHINE_OBJS) libcartesi_jsonrpc.a libcartesi.a
	$(CXX) -o $@ $^ $(JSONRPC_REMOTE_CARTESI_MACHINE_LIBS) $(LDFLAGS) $(EXELDFLAGS)

clua-%.o clua.o: CXXFLAGS += $(LUA_INC)

machine-c-version.h: ../tools/template/machine-c-version.h.template
	sed "s|EMULATOR_MARCHID|$(EMULATOR_MARCHID)|g;s|EMULATOR_VERSION_MAJOR|$(EMULATOR_VERSION_MAJOR)|g;s|EMULATOR_VERSION_MINOR|$(EMULATOR_VERSION_MINOR)|g;s|EMULATOR_VERSION_PATCH|$(EMULATOR_VERSION_PATCH)|g;s|EMULATOR_VERSION_LABEL|$(EMULATOR_VERSION_LABEL)|g" $< > $@

jsonrpc-discover.cpp: jsonrpc-discover.json
	echo '// This file is auto-generated and should not be modified' > jsonrpc-discover.cpp
	echo 'namespace cartesi {' >> jsonrpc-discover.cpp
	echo 'extern char const *const jsonrpc_discover_json = R"json(' >> jsonrpc-discover.cpp
	cat jsonrpc-discover.json >> jsonrpc-discover.cpp
	echo ')json";' >> jsonrpc-discover.cpp
	echo '} // namespace cartesi' >> jsonrpc-discover.cpp

%.clang-tidy: %.cpp machine-c-version.h interpret-jump-table.h
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $(CLANG_TIDY_FLAGS) $< -- $(CXXFLAGS) $(LUA_INC) -DCLANG_TIDY_LINT 2>/dev/null
	@$(CXX) $(CXXFLAGS) $(LUA_INC) $< -MM -MT $@ -MF $@.d > /dev/null 2>&1
	@touch $@

%.clang-tidy: %.c
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $(CLANG_TIDY_FLAGS) $< -- $(CFLAGS) -DCLANG_TIDY_LINT 2>/dev/null
	@$(CC) $(CFLAGS) $< -MM -MT $@ -MF $@.d > /dev/null 2>&1
	@touch $@

sha3.o: ../third-party/tiny_sha3/sha3.c
	$(CC) $(CFLAGS) $(SHA3_CFLAGS) -c -o $@ $<

uarch-pristine-ram.o: $(UARCH_PRISTINE_RAM_C)
	$(CC) $(CFLAGS) -c -o $@ $<

uarch-pristine-hash.o: $(UARCH_PRISTINE_HASH_C)
	$(CC) $(CFLAGS) -c -o $@ $<

interpret-jump-table.h: ../tools/gen-interpret-jump-table.lua
	$< > $@

interpret.o: interpret.cpp machine-c-version.h interpret-jump-table.h
	$(CXX) $(CXXFLAGS) $(INTERPRET_CXXFLAGS) -c -o $@ $<

%.o: %.cpp machine-c-version.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

../uarch/uarch-pristine-ram.c ../uarch/uarch-pristine-hash.c: generate-uarch-pristine

generate-uarch-pristine: machine-c-version.h interpret-jump-table.h
ifeq (,$(wildcard ../uarch/uarch-pristine-hash.c))
	@if [ "$(DEV_ENV_HAS_TOOLCHAIN)" = "yes" ]; then \
		$(MAKE) -C .. uarch; \
	else \
		$(MAKE) -C .. uarch-with-toolchain; \
	fi
endif

clean: clean-auto-generated clean-coverage clean-profile clean-tidy clean-libcartesi clean-executables

clean-auto-generated:
	@rm -f jsonrpc-discover.cpp machine-c-version.h interpret-jump-table.h

clean-tidy:
	@rm -f *.clang-tidy

clean-objs:
	@rm -f *.o *.d

clean-libcartesi: clean-objs
	@rm -f *.so *.a cartesi/*.so *.dylib

clean-executables:
	@rm -f jsonrpc-remote-cartesi-machine merkle-tree-hash compute-uarch-pristine-hash

clean-coverage:
	@rm -f *.profdata *.profraw *.gcda *.gcov coverage.info coverage.txt

clean-profile:
	@rm -f *.profdata *.profraw *.gcda *.gcno

-include $(wildcard *.d)
