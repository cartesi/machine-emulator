UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags lua53)
LUA_LIB:=$(shell pkg-config --libs lua53)
FDT_LIB:=-lfdt
CRYPTOPP_LIB:=-lcryptopp

# So we can use gcc to check if there are unused symbols
ifeq ($(gc),yes)
GCFLAGS= -fno-inline-small-functions -fno-inline -fdata-sections -ffunction-sections
GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)
endif

LIBS:=$(FDT_LIB) $(CRYPTOPP_LIB)

# Common setup
# cryptopp
#   git clone git@github.com:cartesi/cryptopp.git
#   cd cryptopp
#   git checkout cartesi
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

CC?=$(CC_$(UNAME))
CXX?=$(CXX_$(UNAME))
SOLDFLAGS?=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)

WARNS=-W -Wall -pedantic

INCS=-I/usr/local/include $(LUA_INC) $(FDT_INC)

ifeq ($(dump),yes)
#DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_EXCEPTIONS -DDUMP_MMU_EXCEPTIONS -DDUMP_INVALID_MEM_ACCESS -DDUMP_INVALID_CSR -DUMP_ILLEGAL_INSN
DEFS+=-DDUMP_INSN
#DEFS+=-DDUMP_COUNTERS
#DEFS+=-DDUMP_EXCEPTIONS
endif

CFLAGS=-Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)
CXXFLAGS=-Ofast -std=c++14 -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(WARNS)

ALL=emu.so

.PHONY: all generate use clean test

all: $(ALL)

OBJS:= \
	clint.o \
	htif.o \
	shadow.o \
	emulator.o \
	pma.o \
	machine.o \
	luaemu.o

ifeq ($(gperf),yes)
DEFS+=-DGPERF
LIBS+=-lprofiler
endif

emu.so: $(OBJS)
	$(CXX) $(SOLDFLAGS) -o $@ $^ $(LIBS)

test: emu.so
	lua tests.lua

fs.ext2: fs/*
	genext2fs -i 512 -b 8192 -d fs fs.ext2

hash: hash.o
	$(CXX) $(CXXFLAGS) -o $@ $^ -L/usr/local/lib $(LIBS)

generate: CFLAGS += -fprofile-generate
generate: CXXFLAGS += -fprofile-generate
generate: SOLDFLAGS += -fprofile-generate

generate: emu.so
	lua run.lua --ram-image=kernel.bin --root-backing=rootfs.bin --batch --cmdline="-- /root/benchmark/whetstone.rv64imafd 500"

use: CFLAGS += -fprofile-use
use: CXXFLAGS += -fprofile-use
use: SOLDFLAGS += -fprofile-use

use: emu.so

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d $(ALL)

-include $(wildcard *.d)
