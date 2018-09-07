UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags lua53)
LUA_LIB:=$(shell pkg-config --libs lua53)
FDT_INC:=
FDT_LIB:=-lfdt

# So we can use gcc to check if there are unused symbols
ifeq ($(gc),yes)
GCFLAGS= -fno-inline-small-functions -fno-inline -fdata-sections -ffunction-sections
GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)
endif

LIBS:=$(FDT_LIB)

# Mac OS X setup
# Lua
#   port install lua
# lua53.pc is missing.
#   Link from lua.pc to lua53.pc in /opt/local/lib/pkgconfig
# libfdt
#   git clone https://git.kernel.org/pub/scm/utils/dtc/dtc.git
#   cd dtc
#   sudo make NO_PYTHON=1 PREFIX=/usr/local install
#
SOLDFLAGS_Darwin:= -L/opt/local/lib -L/opt/local/lib/libomp -bundle -undefined dynamic_lookup
CC_Darwin=clang
CXX_Darwin=clang++

# Linux settings
# libfdt
#   apt-get install libfdt-dev
#
SOLDFLAGS_Linux:= -shared -fpic
CC_Linux=gcc
CXX_Linux=g++

CC?=$(CC_$(UNAME))
CXX?=$(CXX_$(UNAME))
SOLDFLAGS?=$(SOLDFLAGS_$(UNAME)) $(GCLDFLAGS)

WARNS=-W -Wall -pedantic

INCS=$(LUA_INC)

ifeq ($(dump),yes)
#DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_EXCEPTIONS -DDUMP_MMU_EXCEPTIONS -DDUMP_INVALID_MEM_ACCESS -DDUMP_INVALID_CSR -DUMP_ILLEGAL_INSN
DEFS+=-DDUMP_INSN
#DEFS+=-DDUMP_COUNTERS
#DEFS+=-DDUMP_EXCEPTIONS
endif

ifeq ($(wallclock),yes)
DEFS+=-DWALLCLOCK
endif

CFLAGS=$(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(GCFLAGS)
CXXFLAGS=$(WARNS) -Ofast -std=c++14 -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS) $(GCFLAGS)

ALL=emu.so

.PHONY: all generate use clean test

all: $(ALL)

OBJS:= \
	emulator.o \
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
