UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags luapp53)
LUA_LIB:=$(shell pkg-config --libs luapp53)
# Make sure we are using a static libfdt
FDT_LIB:=/usr/local/lib/libfdt.a
FDT_INC:=-I/usr/local/include
CRYPTOPP_LIB:=-lcryptopp
BOOST_PO_LIB:=-lboost_program_options
GRPC_DIR:=../../cartesi-grpc
GRPC_INC:=$(shell pkg-config --cflags protobuf grpc)
GRPC_LIB:=$(shell pkg-config --libs protobuf grpc++ grpc)

PROTOC:=protoc
GRPC_CPP_PLUGIN=$(shell which grpc_cpp_plugin)

# So we can use gcc to check if there are unused symbols
ifeq ($(gc),yes)
GCFLAGS= -fno-inline-small-functions -fno-inline -fdata-sections -ffunction-sections
GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)
endif

# Common setup
# libfdt
#   git clone git@github.com:cartesi/dtc.git
#   cd dtc
#   git checkout cartesi
#   sudo make NO_PYTHON=1 PREFIX=/usr/local install
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
# -fsanitize=undefined
SOLDFLAGS_Linux:= -L/usr/local/lib -shared -fpic
CC_Linux=gcc
CXX_Linux=g++
INCS_Linux=
FS_LIB_Linux=-lstdc++fs
#XKCP_LIB_Linux:= -Lthird_party/XKCP/Haswell/lib -lkeccak
#XKCP_INC_Linux:= -Ithird_party/XKCP/Haswell/include

CC:=$(CC_$(UNAME))
CXX:=$(CXX_$(UNAME))
SOLDFLAGS:=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)
FS_LIB=$(FS_LIB_$(UNAME))

XKCP_LIB:=$(XKCP_LIB_$(UNAME))
XKCP_INC:=$(XKCP_INC_$(UNAME))

LUACARTESI_LIBS:=$(FDT_LIB) $(CRYPTOPP_LIB) $(XKCP_LIB)
GRPC_SRV_LIBS:=$(FDT_LIB) $(CRYPTOPP_LIB) $(XKCP_LIB) $(GRPC_LIB) $(FS_LIB) $(BOOST_PO_LIB)
HASH_LIBS:=$(CRYPTOPP_LIB) $(XKCP_LIB)

#DEFS+= -DMT_ALL_DIRTY

WARNS=-W -Wall -pedantic

INCS=$(INCS_$(UNAME)) -I/usr/local/include $(LUA_INC) $(FDT_INC) $(XKCP_INC)

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
CXXFLAGS=-O2 -std=c++17 -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CFLAGS=-O2 -g -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

ALL=cartesi.so

.PHONY: all generate use clean test grpc docker

all: $(ALL)

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

test: cartesi.so
	luapp tests.lua

fs.ext2: fs/*
	genext2fs -f -i 512 -b 8192 -d fs fs.ext2
	truncate -s %4096 fs.ext2

hash: hash.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/usr/local/lib $(HASH_LIBS)

generate: CXXFLAGS += -fprofile-generate
generate: SOLDFLAGS += -fprofile-generate

cov: CXXFLAGS += -O0 -g -fprofile-arcs -ftest-coverage
cov: SOLDFLAGS += -fprofile-arcs

cov: cartesi.so
	./tests.lua
	./test-machine.lua
	./run.lua --cmdline='-- /bin/true'
	gcov *.cpp
	lcov --capture --directory . --output-file cartesi.info
	genhtml cartesi.info --output-directory coverage

generate: cartesi.so
	./run.lua --ram-image=kernel.bin --root-backing=rootfs.bin --batch --cmdline="-- /root/benchmark/whetstone.rv64imafd 500"

valgrind: cartesi.so
	valgrind --leak-check=full --tool=memcheck --track-origins=yes luapp tests.lua
	valgrind --leak-check=full --tool=memcheck --track-origins=yes luapp run.lua --initial-hash --final-hash --memory-size=16 --batch --cmdline="-- /bin/true"

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

server client: CXXFLAGS := $(filter-out -fpic -fvisibility=hidden,$(CXXFLAGS) $(GRPC_INC))

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
	rm -f dis/*.o dis/*.d *.gcda *.pb.cc *.gcno *.o *.d cartesi.so server client

-include $(wildcard *.d)
