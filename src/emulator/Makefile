UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags lua53)
LUA_LIB:=$(shell pkg-config --libs lua53)
FDT_LIB:=-lfdt
CRYPTOPP_LIB:=-lcryptopp
GRPC_INC:=$(shell pkg-config --cflags protobuf grpc)
GRPC_LIB:=$(shell pkg-config --libs protobuf grpc++ grpc)

PROTOC:=protoc
GRPC_CPP_PLUGIN=$(shell which grpc_cpp_plugin)

# So we can use gcc to check if there are unused symbols
ifeq ($(gc),yes)
GCFLAGS= -fno-inline-small-functions -fno-inline -fdata-sections -ffunction-sections
GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)
endif

LUACARTESI_LIBS:=$(FDT_LIB) $(CRYPTOPP_LIB)
HASH_LIBS:=$(CRYPTOPP_LIB)

# Common setup
# cryptopp
#   git clone git@github.com:cartesi/cryptopp.git
#   cd cryptopp
#   git checkout cartesi
#   make
#   sudo make install
# grpc
#   git clone --branch v1.16.0 --depth 1 https://github.com/grpc/grpc.git
#   cd grpc
#   git checkout v1.16.0
#   git submodule update --init
#   make
#   sudo make install

# Mac OS X specific setup
# Lua
#   port install lua
# lua53.pc is missing.
#   Link from lua.pc to lua53.pc in /opt/local/lib/pkgconfig
# libfdt
#   git clone https://git.kernel.org/pub/scm/utils/dtc/dtc.git
#   cd dtc
#   sudo make NO_PYTHON=1 PREFIX=/usr/local install
#
SOLDFLAGS_Darwin:= -L/usr/local/lib -L/opt/local/lib -bundle -undefined dynamic_lookup
CC_Darwin=clang
CXX_Darwin=clang++

# Linux specific setup
# libfdt
#   apt-get install libfdt-dev
#
SOLDFLAGS_Linux:= -L/usr/local/lib -shared -fpic
CC_Linux=gcc
CXX_Linux=g++

CC:=$(CC_$(UNAME))
CXX:=$(CXX_$(UNAME))
SOLDFLAGS:=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)

WARNS=-W -Wall -pedantic

INCS=-I/usr/local/include $(LUA_INC) $(FDT_INC)

ifeq ($(dump),yes)
#DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_EXCEPTIONS
#DEFS+=-DDUMP_MMU_EXCEPTIONS
#DEFS+=-DDUMP_INVALID_MEM_ACCESS
#DEFS+=-DDUMP_INVALID_CSR
#DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_INSN
DEFS+=-DDUMP_COUNTERS
#DEFS+=-DDUMP_EXCEPTIONS
endif

CXXFLAGS=-Ofast -std=c++14 -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CFLAGS=-Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

ALL=cartesi.so

.PHONY: all generate use clean test grpc

all: $(ALL)

LUACARTESI_OBJS:= \
	clint.o \
	htif.o \
	shadow.o \
	emulator.o \
	merkle-tree.o \
	pma.o \
	machine.o \
	luacartesi.o

ifeq ($(gperf),yes)
DEFS+=-DGPERF
LUACARTESI_LIBS+=-lprofiler
endif

cartesi.so: $(LUACARTESI_OBJS)
	$(CXX) $(SOLDFLAGS) -o $@ $^ $(LUACARTESI_LIBS)

test: cartesi.so
	lua tests.lua

fs.ext2: fs/*
	genext2fs -f -i 512 -b 8192 -d fs fs.ext2

hash: hash.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/usr/local/lib $(HASH_LIBS)

generate: CXXFLAGS += -fprofile-generate
generate: SOLDFLAGS += -fprofile-generate

generate: cartesi.so
	lua run.lua --ram-image=kernel.bin --root-backing=rootfs.bin --batch --cmdline="-- /root/benchmark/whetstone.rv64imafd 500"

print:
	echo CXXFLAGS=$(CXXFLAGS)
	echo CXX=$(CXX)
	echo UNAME=$(UNAME)
	echo $(CC_$(UNAME))
	echo $(CXX_$(UNAME))

use: CXXFLAGS += -fprofile-use
use: SOLDFLAGS += -fprofile-use

use: cartesi.so

grpc: server client

GRPC_OBJS:= \
	core.pb.o \
	core.grpc.pb.o

server: $(GRPC_OBJS) server.o
	$(CXX) -o $@ $^ $(GRPC_LIB)

client: $(GRPC_OBJS) client.o
	$(CXX) -o $@ $^ $(GRPC_LIB)

server client: CXXFLAGS := $(filter-out -fpic -fvisibility=hidden,$(CXXFLAGS) $(GRPC_INC))

.PRECIOUS: %.grpc.pb.cc
%.grpc.pb.cc: %.proto
	$(PROTOC) --grpc_out=. --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) $<

.PRECIOUS: %.pb.cc
%.pb.cc: %.proto
	$(PROTOC) --cpp_out=. $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f dis/*.o dis/*.d *.o *.d cartesi.so server client

-include $(wildcard *.d)
