UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags lua53)
LUA_LIB:=$(shell pkg-config --libs lua53)
FDT_INC:=
FDT_LIB:=-lfdt

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
SOLDFLAGS_Linux:= -shared -fpic -g
CC_Linux=gcc
CXX_Linux=g++

CC?=$(CC_$(UNAME))
CXX?=$(CXX_$(UNAME))
SOLDFLAGS?=$(SOLDFLAGS_$(UNAME))

WARNS=-W -Wall -pedantic

INCS=$(LUA_INC)

ifeq ($(dump),yes)
DEFS+=-DUMP_ILLEGAL_INSN
#DEFS+=-DDUMP_EXCEPTIONS -DDUMP_MMU_EXCEPTIONS -DDUMP_INVALID_MEM_ACCESS -DDUMP_INVALID_CSR -DUMP_ILLEGAL_INSN
endif
#-DDUMP_INSN


# so we can use gcc to check if there are unused symbols
# GCFLAGS=-fdata-sections -ffunction-sections
# GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)

CFLAGS=$(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS)
CXXFLAGS=-std=c++14 $(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS) $(DEFS)

ALL=emu.so

.PHONY: all generate use clean test

all: $(ALL)

OBJS:= \
	iomem.o \
	machine.o \
	luaemu.o \
	riscv_cpu.o

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
	lua run.lua --boot-image=kernel.bin --root-backing=rv64ima.bin --batch --cmdline="-- /root/benchmark/whetstone.rv64imafd 1500"

use: CFLAGS += -fprofile-use
use: CXXFLAGS += -fprofile-use
use: SOLDFLAGS += -fprofile-use

use: emu.so
	$(CXX) $(SOLDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d $(ALL)

-include $(wildcard *.d)
