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

GRPC_INC:=-I$(BUILDDIR)/include
GRPC_LIB:=-L$(BUILDDIR)/lib -lgrpc++ -lgrpc -lprotobuf -lpthread

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
BOOST_LIB_Darwin=-L/opt/local/lib -L/usr/local/opt/boost/lib -lboost_program_options-mt
BOOST_INC_Darwin=-I/opt/local/include -I/usr/local/opt/boost/include
PROFILE_DATA_Darwin=default.profdata

# Linux specific setup
SOLDFLAGS_Linux:=-shared -fPIC -pthread
CC_Linux=gcc
CXX_Linux=g++
INCS_Linux=
FS_LIB_Linux=-lstdc++fs
BOOST_LIB_Linux=-lboost_program_options
BOOST_INC_Linux=
PROFILE_DATA_Linux=

CC=$(CC_$(UNAME))
CXX=$(CXX_$(UNAME))
CC_MARCH=
SOLDFLAGS:=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)
FS_LIB=$(FS_LIB_$(UNAME))
BOOST_LIB=$(BOOST_LIB_$(UNAME))
BOOST_INC=$(BOOST_INC_$(UNAME))

LUACARTESI_LIBS:=$(CRYPTOPP_LIB)
GRPC_SRV_LIBS:=$(CRYPTOPP_LIB) $(XKCP_LIB) $(GRPC_LIB) $(FS_LIB) $(BOOST_LIB)

#DEFS+= -DMT_ALL_DIRTY

WARNS=-W -Wall -pedantic

# Place our include directories before the system's
INCS= -I../lib/machine-emulator-defines $(LUA_INC) $(CRYPTOPP_INC) $(BOOST_INC) $(INCS_$(UNAME))

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

# -fsanitize=undefined
CXXFLAGS=-O2 -std=c++17 -fvisibility=hidden -fPIC -MMD $(CC_MARCH) $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CFLAGS=-O2 -fvisibility=hidden -fPIC -MMD $(CC_MARCH) $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

all: luacartesi grpc hash

.PHONY: all generate use clean test luacartesi grpc hash docker

LUACARTESI_OBJS:= \
	clint.o \
	rom.o \
	htif.o \
	shadow.o \
	merkle-tree.o \
	pma.o \
	machine.o \
	interpret.o \
	luacartesi.o

ifeq ($(gperf),yes)
DEFS+=-DGPERF
LUACARTESI_LIBS+=-lprofiler
endif

cartesi.so: $(LUACARTESI_OBJS)
	$(CXX) $(SOLDFLAGS) -o $@ $^ $(LUACARTESI_LIBS)

test: luacartesi
	$(LUA_BIN) cartesi-machine-tests.lua --test-path="$(TEST_PATH)" --test=".*" run

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

grpc: cartesi-machine-server cartesi-machine-client

hash: cartesi-machine-hash

HASH_OBJS:= \
	hash.o

PROTO_OBJS:= \
	cartesi-base.pb.o \
	core.pb.o \
	core.grpc.pb.o \
	manager-low.pb.o \
	manager-low.grpc.pb.o

$(PROTO_OBJS): CXXFLAGS +=  -Wno-unused-parameter

GRPC_CLT_OBJS:= \
	$(PROTO_OBJS) \
	client.o

GRPC_SRV_OBJS:= \
	$(PROTO_OBJS) \
    server.o \
	clint.o \
	rom.o \
	htif.o \
	shadow.o \
	merkle-tree.o \
	pma.o \
	machine.o \
	interpret.o \
	manager-client.o

CYCLE_SKIP ?= 13
HASH_DIR = hashes/$(CYCLE_SKIP)
LOG_DIR = logs/$(CYCLE_SKIP)
HASH_TRUTH_DIR =

ifneq ($(strip $(TEST_PATH)),)
TESTS=$(shell ./cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test=".*" list)
endif
TEST_HASHES=$(addprefix $(HASH_DIR)/,$(TESTS:.bin=.hashes))
TEST_LOGS=$(addprefix $(LOG_DIR)/,$(TESTS:.bin=.json.br))

GROUND_TRUTH_DIR ?= ground-truth

$(HASH_DIR):
	mkdir -p $(HASH_DIR)

$(LOG_DIR):
	mkdir -p $(LOG_DIR)

test-hashes: $(TEST_HASHES)

test-logs: $(TEST_LOGS)

$(HASH_DIR)/%.hashes: $(TEST_PATH)/%.bin $(HASH_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --skip=$(CYCLE_SKIP) hash >  $@
	diff $@ $(GROUND_TRUTH_DIR)/$@

$(LOG_DIR)/%.json.br: $(TEST_PATH)/%.bin $(LOG_DIR)
	$(LUA_BIN) cartesi-machine-tests.lua --test-path=$(TEST_PATH) --test="$(notdir $<)" --skip=$(CYCLE_SKIP) step > $(basename $@)
	brotli -j -f $(basename $@)
	diff $@ $(GROUND_TRUTH_DIR)/$@

cartesi-machine-hash: $(HASH_OBJS)
	$(CXX) -o $@ $^ $(CRYPTOPP_LIB)

cartesi-machine-server: $(GRPC_SRV_OBJS)
	$(CXX) -o $@ $^ $(GRPC_SRV_LIBS)

cartesi-machine-client: $(GRPC_CLT_OBJS)
	$(CXX) -o $@ $^ $(GRPC_LIB)

cartesi-machine-server cartesi-machine-client: CXXFLAGS := $(GRPC_INC) $(CXXFLAGS)

.PRECIOUS: %.grpc.pb.cc %.grpc.pb.h %.pb.cc %.pb.h

%.grpc.pb.cc: $(GRPC_DIR)/%.proto
	$(PROTOC) -I$(GRPC_DIR) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $<

%.pb.cc: $(GRPC_DIR)/%.proto
	$(PROTOC) -I$(GRPC_DIR) --cpp_out=. $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f dis/*.o dis/*.d *.pb.cc *.pb.h *.gcno *.o *.d cartesi.so cartesi-machine-server cartesi-machine-client cartesi-machine-hash

profile-clean:
	rm -f *.profdata *.profraw *.gcda

-include $(wildcard *.d)
