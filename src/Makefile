UNAME:=$(shell uname)

BUILDDIR ?= $(abspath ../build/$(UNAME)_$(shell uname -m))

LUA_DIR:=$(BUILDDIR)
LUA_INC:=-I$(LUA_DIR)/include/luapp/5.3
LUA_LIB:=-L$(LUA_DIR)/lib -lluapp5.3
LUA_BIN?=$(LUA_DIR)/bin/luapp5.3
CRYPTOPP_LIB:=-L$(BUILDDIR)/lib -lcryptopp
CRYPTOPP_INC:=-I$(BUILDDIR)/include
GRPC_DIR:=../lib/cartesi-grpc

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
BOOST_LIB_Darwin=-L/opt/local/lib -lboost_program_options-mt
BOOST_INC_Darwin=-I/opt/local/include

# Linux specific setup
SOLDFLAGS_Linux:=-shared -fPIC -pthread
CC_Linux=gcc
CXX_Linux=g++
INCS_Linux=
FS_LIB_Linux=-lstdc++fs
BOOST_LIB_Linux=-lboost_program_options
BOOST_INC_Linux=

CC=$(CC_$(UNAME))
CXX=$(CXX_$(UNAME))
SOLDFLAGS:=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)
FS_LIB=$(FS_LIB_$(UNAME))
BOOST_LIB=$(BOOST_LIB_$(UNAME))
BOOST_INC=$(BOOST_INC_$(UNAME))

LUACARTESI_LIBS:=$(CRYPTOPP_LIB)
GRPC_SRV_LIBS:=$(CRYPTOPP_LIB) $(XKCP_LIB) $(GRPC_LIB) $(FS_LIB) $(BOOST_LIB)

#DEFS+= -DMT_ALL_DIRTY

WARNS=-W -Wall -pedantic

# Place our include directories before the system's
INCS=$(LUA_INC) $(CRYPTOPP_INC) $(BOOST_INC) $(INCS_$(UNAME))

ifeq ($(dump),yes)
DEFS+=-DUMP_ILLEGAL_INSN
DEFS+=-DDUMP_EXCEPTIONS
#DEFS+=-DDUMP_MMU_EXCEPTIONS
#DEFS+=-DDUMP_INVALID_MEM_ACCESS
#DEFS+=-DDUMP_INVALID_CSR
DEFS+=-DDUMP_INSN
DEFS+=-DDUMP_REGS
#DEFS+=-DDUMP_COUNTERS
endif

# -fsanitize=undefined
CXXFLAGS=-O2 -std=c++17 -march=native -fvisibility=hidden -fPIC -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CFLAGS=-O2 -g -march=native -fvisibility=hidden -fPIC -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

all: luacartesi grpc

.PHONY: all generate use clean test luacartesi grpc docker

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
	$(LUA_BIN) tests.lua

fs.ext2: fs/*
	genext2fs -f -i 512 -b 8192 -d fs fs.ext2
	truncate -s %4096 fs.ext2

generate: CXXFLAGS += -fprofile-generate
generate: SOLDFLAGS += -fprofile-generate

cov: CXXFLAGS += -O0 -g -fprofile-arcs -ftest-coverage
cov: SOLDFLAGS += -fprofile-arcs

cov: luacartesi
	$(LUA_BIN) ./tests.lua
	$(LUA_BIN) ./test-machine.lua
	$(LUA_BIN) ./run.lua --cmdline='-- /bin/true'
	gcov *.cpp
	lcov --capture --directory . --output-file cartesi.info
	genhtml cartesi.info --output-directory coverage

generate: luacartesi
	$(LUA_BIN) ./run.lua --ram-image=kernel.bin --root-backing=rootfs.bin --batch --cmdline="-- /root/benchmark/whetstone.rv64imafd 500"

valgrind: luacartesi
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) tests.lua
	valgrind --leak-check=full --tool=memcheck --track-origins=yes $(LUA_BIN) run.lua --initial-hash --final-hash --memory-size=16 --batch --cmdline="-- /bin/true"

use: CXXFLAGS += -fprofile-use
use: SOLDFLAGS += -fprofile-use

use: luacartesi

luacartesi: cartesi.so

grpc: server client

#??D
# On Mac OS, use "install_name_tool -change <rel-dylib> <abs-dylib> <binary>"
# on the executables to make sure the dylibs linked are the ones we built
# in third_party?
# On Linux, use "patchelf --set-rpath <lib-path> <binary>" on all .so we built
# and also on the executables?
# Then change again after we run install?

PROTO_OBJS:= \
	cartesi-base.pb.o \
	core.pb.o \
	core.grpc.pb.o \
	manager-low.pb.o \
	manager-low.grpc.pb.o

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

server: $(GRPC_SRV_OBJS)
	$(CXX) -o $@ $^ $(GRPC_SRV_LIBS)

client: $(GRPC_CLT_OBJS)
	$(CXX) -o $@ $^ $(GRPC_LIB)

server client: CXXFLAGS := $(GRPC_INC) $(CXXFLAGS)

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
	rm -f dis/*.o dis/*.d *.gcda *.pb.cc *.pb.h *.gcno *.o *.d cartesi.so server client

-include $(wildcard *.d)
