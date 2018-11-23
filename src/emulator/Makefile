UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags luapp53)
LUA_LIB:=$(shell pkg-config --libs luapp53)
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
#   cd third_party/protobuf
#   sudo make install

# Mac OS X specific setup
# Lua for C++
#    wget https://www.lua.org/ftp/lua-5.3.5.tar.gz
#    tar -zxvf lua-5.3.5.tar.gz
#    cd lua-5.3.5
#    patch -p1 < image-ci/luapp.patch
#    make macosx
#    sudo make install
#    sudo cp image-ci/luapp53.pc /usr/local/lib/pkgconfig
#    sudo ln -s /usr/local/lib/luapp5.3 /usr/local/bin/luapp
# libfdt
#   git clone https://git.kernel.org/pub/scm/utils/dtc/dtc.git
#   cd dtc
#   sudo make NO_PYTHON=1 PREFIX=/usr/local install
# Boost
#   port install boost
#
SOLDFLAGS_Darwin:= -L/usr/local/lib -L/opt/local/lib -bundle -undefined dynamic_lookup
CC_Darwin=clang
CXX_Darwin=clang++
INCS_Darwin=-I/opt/local/include

# Linux specific setup
# Lua for C++
#    wget https://www.lua.org/ftp/lua-5.3.5.tar.gz
#    tar -zxvf lua-5.3.5.tar.gz
#    cd lua-5.3.5
#    patch -p1 < image-ci/luapp.patch
#    make linux
#    sudo make install
#    sudo cp image-ci/luapp53.pc /usr/local/lib/pkgconfig
#    sudo ln -s /usr/local/lib/luapp5.3 /usr/local/bin/luapp
# libfdt
#   apt-get install libfdt-dev
# Boost
#   apt-get install libboost-dev
#
SOLDFLAGS_Linux:= -L/usr/local/lib -shared -fpic
CC_Linux=gcc
CXX_Linux=g++
INCS_Linux=

CC:=$(CC_$(UNAME))
CXX:=$(CXX_$(UNAME))
SOLDFLAGS:=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)

WARNS=-W -Wall -pedantic

INCS=$(INCS_$(UNAME)) -I/usr/local/include $(LUA_INC) $(FDT_INC)

ifeq ($(dump),yes)
#DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_EXCEPTIONS
#DEFS+=-DDUMP_MMU_EXCEPTIONS
#DEFS+=-DDUMP_INVALID_MEM_ACCESS
#DEFS+=-DDUMP_INVALID_CSR
#DEFS+=-DUMP_ILLEGAL_INSN
DEFS+=-DDUMP_INSN
#DEFS+=-DDUMP_COUNTERS
#DEFS+=-DDUMP_EXCEPTIONS
endif

CXXFLAGS=-Ofast -std=c++17 -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CFLAGS=-Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

ALL=cartesi.so

.PHONY: all generate use clean test grpc docker

all: $(ALL)

LUACARTESI_OBJS:= \
	clint.o \
	htif.o \
	shadow.o \
	emulator.o \
	emulator-config.o \
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
	luapp tests.lua

fs.ext2: fs/*
	genext2fs -f -i 512 -b 8192 -d fs fs.ext2

hash: hash.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/usr/local/lib $(HASH_LIBS)

generate: CXXFLAGS += -fprofile-generate
generate: SOLDFLAGS += -fprofile-generate

generate: cartesi.so
	./run.lua --ram-image=kernel.bin --root-backing=rootfs.bin --batch --cmdline="-- /root/benchmark/whetstone.rv64imafd 500"

valgrind: cartesi.so
	valgrind --leak-check=full --tool=memcheck --show-leak-kinds=all luapp tests.lua
	valgrind --leak-check=full --tool=memcheck --track-origins=yes luapp run.lua --batch --cmdline="-- /bin/true"

print:
	echo CXXFLAGS=$(CXXFLAGS)
	echo CXX=$(CXX)
	echo UNAME=$(UNAME)
	echo $(CC_$(UNAME))
	echo $(CXX_$(UNAME))

use: CXXFLAGS += -fprofile-use
use: SOLDFLAGS += -fprofile-use

use: cartesi.so

docker:
	 docker run -it --rm -v `pwd`:/root/emulator -w /root/emulator cartesi/image-ci

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
