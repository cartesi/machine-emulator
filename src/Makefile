# Copyright 2019 Cartesi Pte. Ltd.
#
# This file is part of the machine-emulator. The machine-emulator is free
# software: you can redistribute it and/or modify it under the terms of the GNU
# Lesser General Public License as published by the Free Software Foundation,
# either version 3 of the License, or (at your option) any later version.
#
# The machine-emulator is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
#

UNAME:=$(shell uname)

BUILDDIR ?= $(abspath ../build/$(UNAME)_$(shell uname -m))

LUA_DIR:=$(BUILDDIR)
LUA_INC:=-I$(LUA_DIR)/include/luapp/5.3
LUA_LIB:=-L$(LUA_DIR)/lib -lluapp5.3
LUA_BIN?=$(LUA_DIR)/bin/luapp5.3
CRYPTOPP_LIB:=-L$(BUILDDIR)/lib -lcryptopp
CRYPTOPP_INC:=-I$(BUILDDIR)/include
GRPC_DIR:=../lib/grpc-interfaces

PROTOC:=$(BUILDDIR)/bin/protoc
GRPC_CPP_PLUGIN=$(BUILDDIR)/bin/grpc_cpp_plugin

# So we can use gcc to check if there are unused symbols
ifeq ($(gc),yes)
GCFLAGS= -fno-inline-small-functions -fno-inline -fdata-sections -ffunction-sections
GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)
endif

# Mac OS X specific setup
SOLDFLAGS_Darwin:=-bundle -undefined dynamic_lookup
CC_Darwin=clang
CXX_Darwin=clang++
INCS_Darwin=

ifeq ($(UNAME),Darwin)
SOLDFLAGS_Darwin+=-Wl,-rpath,$(BUILDDIR)/lib
# Homebrew installation
ifneq (,$(wildcard /usr/local/opt/boost/lib))
BOOST_LIB_DIR_Darwin=-L/usr/local/opt/boost/lib
BOOST_INC_Darwin=-I/usr/local/opt/boost/include
else # Macports installation
BOOST_LIB_DIR_Darwin=-L/opt/local/lib
BOOST_INC_Darwin=-I/opt/local/include
endif
endif

BOOST_SERIAL_LIB_Darwin:=$(BOOST_LIB_DIR_Darwin) -lboost_serialization-mt
BOOST_CORO_LIB_Darwin:=$(BOOST_LIB_DIR_Darwin) -lboost_coroutine-mt -lboost_context-mt
GRPC_INC_Darwin=-I$(BUILDDIR)/include
GRPC_LIB_Darwin=-L$(BUILDDIR)/lib -lgrpc++ -lgrpc -lgpr -lprotobuf -lpthread
LIBCARTESI_Darwin=libcartesi.dylib
LIBCARTESI_LDFLAGS_Darwin=-dynamiclib -undefined dynamic_lookup -install_name '@rpath/$(LIBCARTESI_Darwin)'
LIBCARTESI_TESTS_LDFLAGS_Darwin=-Wl,-rpath,'@executable_path/..'
PROFILE_DATA_Darwin=default.profdata

# Linux specific setup
SOLDFLAGS_Linux:=-shared -fPIC -pthread
CC_Linux=gcc
CXX_Linux=g++
INCS_Linux=
FS_LIB_Linux=-lstdc++fs
BOOST_SERIAL_LIB_Linux:=-lboost_serialization
BOOST_CORO_LIB_Linux:=-lboost_coroutine -lboost_context
BOOST_INC_Linux=
GRPC_INC_Linux:=-I$(BUILDDIR)/include
GRPC_LIB_Linux:=-L$(BUILDDIR)/lib -lgrpc++ -lgrpc -lgpr -lprotobuf -lpthread
LIBCARTESI_Linux=libcartesi.so
LIBCARTESI_LDFLAGS_Linux:=$(SOLDFLAGS_Linux)
LIBCARTESI_TESTS_LDFLAGS_Linux=-Wl,-rpath,'$$ORIGIN/..'
PROFILE_DATA_Linux=

CC=$(CC_$(UNAME))
CXX=$(CXX_$(UNAME))
CC_MARCH=
SOLDFLAGS:=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)
FS_LIB=$(FS_LIB_$(UNAME))
BOOST_SERIAL_LIB=$(BOOST_SERIAL_LIB_$(UNAME))
BOOST_CORO_LIB=$(BOOST_CORO_LIB_$(UNAME))
BOOST_INC=$(BOOST_INC_$(UNAME))
GRPC_LIB=$(GRPC_LIB_$(UNAME))
GRPC_INC=$(GRPC_INC_$(UNAME))
LIBCARTESI=$(LIBCARTESI_$(UNAME))
LIBCARTESI_LDFLAGS=$(LIBCARTESI_LDFLAGS_$(UNAME))
LIBCARTESI_TESTS_LDFLAGS=$(LIBCARTESI_TESTS_LDFLAGS_$(UNAME))
LIBCARTESI_LIB=-L. -lcartesi

CARTESI_LIBS:=$(CRYPTOPP_LIB) $(BOOST_SERIAL_LIB)
LUACARTESI_LIBS:=$(CRYPTOPP_LIB) $(BOOST_SERIAL_LIB)
LUACARTESI_GRPC_LIBS:=$(CRYPTOPP_LIB) $(BOOST_SERIAL_LIB) $(GRPC_LIB)
GRPC_SRV_LIBS:=$(CRYPTOPP_LIB) $(GRPC_LIB) $(FS_LIB) $(BOOST_SERIAL_LIB)
GRPC_PRX_LIBS:=$(CRYPTOPP_LIB) $(GRPC_LIB) $(BOOST_CORO_LIB)

#DEFS+= -DMT_ALL_DIRTY

WARNS=-W -Wall -pedantic

# Place our include directories before the system's
INCS= -I../lib/machine-emulator-defines $(LUA_INC) $(CRYPTOPP_INC) $(BOOST_INC) $(GRPC_INC) $(INCS_$(UNAME))

ifeq ($(dump),yes)
#DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_EXCEPTIONS
DEFS+=-DDUMP_HIST
#DEFS+=-DDUMP_MMU_EXCEPTIONS
#DEFS+=-DDUMP_INVALID_MEM_ACCESS
#DEFS+=-DDUMP_INVALID_CSR
#DEFS+=-DDUMP_INSN
#DEFS+=-DDUMP_REGS
#DEFS+=-DDUMP_COUNTERS
endif

ifeq ($(release),yes)
DEFS+=-DNDEBUG
else
DEFS+=-g
endif

# Compile for current system processor
ifeq ($(native),yes)
CC_MARCH=-march=native
endif

# We ignore xkcp-keccak-256-hasher.cpp because it is missing a header file.
# The file is not being compiled but we want to keep it for reference.
LINTER_IGNORE_SOURCES=xkcp-keccak-256-hasher.cpp
LINTER_IGNORE_HEADERS=%.pb.h
LINTER_SOURCES=$(filter-out $(LINTER_IGNORE_SOURCES),$(strip $(wildcard *.cpp) $(wildcard *.c)))
LINTER_HEADERS=$(filter-out $(LINTER_IGNORE_HEADERS),$(strip $(wildcard *.hpp) $(wildcard *.h)))

CLANG_TIDY=$(shell which clang-tidy-11 || which clang-tidy)
CLANG_TIDY_TARGETS=$(patsubst %.cpp,%.clang-tidy,$(patsubst %.c,%.clang-tidy,$(LINTER_SOURCES)))

EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
CLANG_TIDY_HEADER_FILTER=$(PWD)/($(subst $(SPACE),|,$(LINTER_HEADERS)))

# -fsanitize=undefined
CXXFLAGS=-O2 -std=c++17 -fvisibility=hidden -fPIC -MMD $(CC_MARCH) $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CFLAGS=-O2 -std=c99 -fvisibility=hidden -fPIC -MMD $(CC_MARCH) $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

all: luacartesi grpc hash c-api

.PHONY: all generate use clean test lint luacartesi grpc hash docker c-api test-merkle-tree-hash

CARTESI_OBJS:= \
	clint.o \
	rom.o \
	htif.o \
	dhd.o \
	dhd-source.o \
	shadow.o \
	machine-merkle-tree.o \
	pristine-merkle-tree.o \
	pma.o \
	machine.o \
	machine-config.o \
	interpret.o \
	virtual-machine.o \
	machine-c-api.o

LUACARTESI_OBJS:= \
	clint.o \
	rom.o \
	htif.o \
	dhd.o \
	dhd-source.o \
	shadow.o \
	machine-merkle-tree.o \
	pristine-merkle-tree.o \
	pma.o \
	machine.o \
	machine-config.o \
	interpret.o \
	virtual-machine.o \
	clua-cartesi.o \
	clua-i-virtual-machine.o \
	clua-machine.o \
	clua-htif.o \
	clua-machine-util.o \
	clua.o

LUACARTESI_GRPC_GEN_OBJS:= \
	versioning.pb.o \
	cartesi-machine.pb.o \
	cartesi-machine.grpc.pb.o

LUACARTESI_GRPC_OBJS:= \
	machine-merkle-tree.o \
	pristine-merkle-tree.o \
	clua-i-virtual-machine.o \
	clua-htif.o \
	clua-machine-util.o \
	$(LUACARTESI_GRPC_GEN_OBJS) \
	grpc-util.o \
	grpc-virtual-machine.o \
	clua-cartesi-grpc.o \
	clua-grpc-machine.o \
	clua.o

ifeq ($(gperf),yes)
DEFS+=-DGPERF
CARTESI_LIBS+=-lprofiler
LUACARTESI_LIBS+=-lprofiler
endif

$(LIBCARTESI): $(CARTESI_OBJS)
	$(CXX) $(LIBCARTESI_LDFLAGS) -o $@ $^ $(CARTESI_LIBS)

cartesi.so: $(LUACARTESI_OBJS)
	$(CXX) $(SOLDFLAGS) -o $@ $^ $(LUACARTESI_LIBS)

cartesi/grpc.so: $(LUACARTESI_GRPC_OBJS)
	$(CXX) $(SOLDFLAGS) -o $@ $^ $(LUACARTESI_GRPC_LIBS)

test: luacartesi
	$(LUA_BIN) cartesi-machine-tests.lua --test-path="$(TEST_PATH)" --test=".*" run

test-hash: hash
	tests/test-merkle-tree-hash --log2-root-size=30 --log2-leaf-size=12 --input=tests/test-merkle-tree-hash

test-grpc: luacartesi grpc
	./cartesi-machine-server -a 127.0.0.1:5001 && sleep 1
	$(LUA_BIN) cartesi-machine-tests.lua --server=127.0.0.1:5001 --test-path="$(TEST_PATH)" --test=".*" run

test-scripts: luacartesi
	for x in `find tests -maxdepth 1 -type f -name "*.lua"` ; do $(LUA_BIN) $$x || exit 1; done

test-c-api: c-api
	tests/test-machine-c-api

lint: $(CLANG_TIDY_TARGETS)

fs.ext2: fs/*
	genext2fs -f -i 512 -b 8192 -d fs fs.ext2
	truncate -s %4096 fs.ext2

generate: CXXFLAGS += -fprofile-generate
generate: SOLDFLAGS += -fprofile-generate
generate: luacartesi

cov: CXXFLAGS += -O0 -g -fprofile-arcs -ftest-coverage
cov: SOLDFLAGS += -fprofile-arcs

cov: luacartesi
	$(LUA_BIN) ./cartesi-machine-tests.lua
	$(LUA_BIN) ./test-machine.lua
	$(LUA_BIN) ./cartesi-machine.lua --cmdline='-- /bin/true'
	gcov *.cpp
	lcov --capture --directory . --output-file cartesi.info
	genhtml cartesi.info --output-directory coverage


valgrind: luacartesi
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) cartesi-machine-tests.lua
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) cartesi-machine.lua --initial-hash --final-hash --memory-size=16 --batch --cmdline="-- /bin/true"


$(PROFILE_DATA_Darwin):
	llvm-profdata merge -output=default.profdata default*.profraw

use: CXXFLAGS += -fprofile-use
use: SOLDFLAGS += -fprofile-use
use: $(PROFILE_DATA_$(UNAME)) luacartesi

luacartesi: cartesi.so

grpc: cartesi/grpc.so cartesi-machine-server cartesi-machine-proxy

hash: merkle-tree-hash tests/test-merkle-tree-hash

c-api: $(LIBCARTESI) tests/test-machine-c-api

MERKLE_TREE_HASH_OBJS:= \
	back-merkle-tree.o \
	pristine-merkle-tree.o \
	merkle-tree-hash.o

TEST_MERKLE_TREE_HASH_OBJS:= \
	back-merkle-tree.o \
	pristine-merkle-tree.o \
	complete-merkle-tree.o \
	full-merkle-tree.o \
	test-merkle-tree-hash.o

TEST_MACHINE_C_API_OBJS:= \
    test-machine-c-api.o

PROTO_OBJS:= \
	versioning.pb.o \
	cartesi-machine.pb.o \
	cartesi-machine.grpc.pb.o

$(PROTO_OBJS): CXXFLAGS +=  -Wno-zero-length-array -Wno-unused-parameter -Wno-deprecated-declarations -Wno-deprecated-copy

PROTO_SOURCES:=$(PROTO_OBJS:.o=.cc)

GRPC_PRX_OBJS:= \
	$(PROTO_OBJS) \
	grpc-util.o \
	machine-merkle-tree.o \
	pristine-merkle-tree.o \
	proxy.o

GRPC_SRV_OBJS:= \
	$(PROTO_OBJS) \
	server.o \
	grpc-util.o \
	clint.o \
	rom.o \
	htif.o \
	dhd.o \
	dhd-source.o \
	shadow.o \
	machine-merkle-tree.o \
	pristine-merkle-tree.o \
	pma.o \
	machine.o \
	machine-config.o \
	interpret.o

CYCLE_PERIOD ?= 13
HASH_DIR = hashes/$(CYCLE_PERIOD)
LOG_DIR = logs/$(CYCLE_PERIOD)
GROUND_TRUTH_DIR ?= ground-truth
CONCURRENCY_MERKLE_TREE ?= 0

ifneq ($(strip $(TEST_PATH)),)
TESTS=$(shell ./cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test=".*" list)
endif
TEST_HASHES=$(addprefix $(HASH_DIR)/,$(TESTS:.bin=.hashes))
TEST_LOGS=$(addprefix $(LOG_DIR)/,$(TESTS:.bin=.json.br))
TRUTH_HASHES=$(addprefix $(GROUND_TRUTH_DIR)/,$(TEST_HASHES))
TRUTH_LOGS=$(addprefix $(GROUND_TRUTH_DIR)/,$(TEST_LOGS))

HASH_EACH_CYCLE_DIR=
TEST_EACH_CYCLE_HASHES=
ifneq ($(strip $(CYCLE_PERIOD)),1)
HASH_EACH_CYCLE_DIR = hashes/1
TEST_EACH_CYCLE_HASHES=$(addprefix $(HASH_EACH_CYCLE_DIR)/,$(TESTS:.bin=.hashes))
endif

$(HASH_DIR) $(LOG_DIR) $(GROUND_TRUTH_DIR)/$(HASH_DIR) $(GROUND_TRUTH_DIR)/$(LOG_DIR) $(HASH_EACH_CYCLE_DIR):
	mkdir -p $@

test-hashes: $(TEST_HASHES)

test-logs: $(TEST_LOGS)

truth-hashes: $(TRUTH_HASHES)

truth-logs: $(TRUTH_LOGS)

compare-hashes: | $(TEST_EACH_CYCLE_HASHES) $(TEST_HASHES)
	@for t in $(TESTS) ; do \
		result=$$(tail -n +2 -q $(HASH_DIR)/$${t%.bin}.hashes $(HASH_EACH_CYCLE_DIR)/$${t%.bin}.hashes | sort -s -n | uniq | awk -v step=-1 '{pline=line; line=$$0; pstep=step; step=$$1; if (pstep >= 0 && pstep == step) {print(pline); print(line); exit 1;}}'); \
		if [ "$$result" != "" ]; then \
			echo $$t ;\
			echo "$$result"; \
			exit 1; \
		fi \
	done

$(HASH_EACH_CYCLE_DIR)/%.hashes: $(TEST_PATH)/%.bin | $(HASH_EACH_CYCLE_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --periodic-action=1 --output=$@ --concurrency=update_merkle_tree:$(CONCURRENCY_MERKLE_TREE) hash

$(HASH_DIR)/%.hashes: $(TEST_PATH)/%.bin | $(HASH_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$@ --concurrency=update_merkle_tree:$(CONCURRENCY_MERKLE_TREE) hash
	diff $@ $(GROUND_TRUTH_DIR)/$@

$(LOG_DIR)/%.json.br: $(TEST_PATH)/%.bin $(LOG_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$(basename $@) step
	brotli -j -f $(basename $@)
	diff $@ $(GROUND_TRUTH_DIR)/$@

$(GROUND_TRUTH_DIR)/$(HASH_DIR)/%.hashes: $(TEST_PATH)/%.bin | $(GROUND_TRUTH_DIR)/$(HASH_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$@ --concurrency=update_merkle_tree:$(CONCURRENCY_MERKLE_TREE) hash

$(GROUND_TRUTH_DIR)/$(LOG_DIR)/%.json.br: $(TEST_PATH)/%.bin $(GROUND_TRUTH_DIR)/$(LOG_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --periodic-action=$(CYCLE_PERIOD) --output=$(basename $@) step
	brotli -j -f $(basename $@)

merkle-tree-hash: $(MERKLE_TREE_HASH_OBJS)
	$(CXX) -o $@ $^ $(CRYPTOPP_LIB)

tests/test-merkle-tree-hash: $(TEST_MERKLE_TREE_HASH_OBJS)
	$(CXX) -o $@ $^ $(CRYPTOPP_LIB)

grpc-interfaces: $(PROTO_SOURCES)

cartesi-machine-server: $(GRPC_SRV_OBJS)
	$(CXX) -o $@ $^ $(GRPC_SRV_LIBS)

cartesi-machine-proxy: $(GRPC_PRX_OBJS)
	$(CXX) -o $@ $^ $(GRPC_PRX_LIBS)

cartesi-machine-server cartesi-machine-proxy: CXXFLAGS := $(GRPC_INC) $(CXXFLAGS)

tests/test-machine-c-api: $(TEST_MACHINE_C_API_OBJS) $(LIBCARTESI)
	$(CXX) $(LIBCARTESI_TESTS_LDFLAGS) -o $@ $(TEST_MACHINE_C_API_OBJS) $(LIBCARTESI_LIB)

.PRECIOUS: %.grpc.pb.cc %.grpc.pb.h %.pb.cc %.pb.h

%.grpc.pb.cc: $(GRPC_DIR)/%.proto
	$(PROTOC) -I$(GRPC_DIR) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $<

%.pb.cc: $(GRPC_DIR)/%.proto
	$(PROTOC) -I$(GRPC_DIR) --cpp_out=. $<

grpc-util.o grpc-virtual-machine.o: $(LUACARTESI_GRPC_GEN_OBJS)

%.clang-tidy: %.cpp $(PROTO_SOURCES)
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $< -- $(CXXFLAGS) 2>/dev/null

%.clang-tidy: %.c
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $< -- $(CFLAGS) 2>/dev/null

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f dis/*.o dis/*.d *.pb.cc *.pb.h *.gcno *.o *.d $(LIBCARTESI) cartesi.so cartesi/grpc.so cartesi-machine-server cartesi-machine-proxy merkle-tree-hash tests/test-merkle-tree-hash tests/test-machine-c-api

profile-clean:
	rm -f *.profdata *.profraw *.gcda

-include $(wildcard *.d)
