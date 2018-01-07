#
# RISCV emulator
#
# Copyright (c) 2016-2017 Fabrice Bellard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


UNAME:=$(shell uname)

LUA_INC:=$(shell pkg-config --cflags lua53)
LUA_LIB:=$(shell pkg-config --libs lua53)

SOLDFLAGS_Darwin:= -L/opt/local/lib -L/opt/local/lib/libomp -bundle -undefined dynamic_lookup
CC_Darwin=clang
CXX_Darwin=clang++

SOLDFLAGS_Linux:= -shared -fpic
CC_Linux=gcc
CXX_Linux=g++

CC?=$(CC_$(UNAME))
CXX?=$(CXX_$(UNAME))
SOLDFLAGS?=$(SOLDFLAGS_$(UNAME))

WARNS=-W -Wall -Wno-unused-parameter -Wno-unused-result

INCS=$(LUA_INC)

# so we can use gcc to check if there are unused symbols
# GCFLAGS=-fdata-sections -ffunction-sections
# GCLDFLAGS=-Wl,--gc-sections,--print-gc-sections $(LUA_LIB)

CFLAGS=$(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS)
CXXFLAGS=-std=c++14 $(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS) $(GCFLAGS)

ALL=emu.so

all: $(ALL)

OBJS:= \
	virtio.o \
	pci.o \
	fdt.o \
	cutils.o \
	iomem.o \
	machine.o \
	luaemu.o \
	riscv_machine.o \
	riscv_cpu.o

riscv_cpu.o: CFLAGS += -DMAX_XLEN=64 -DFLEN=0

emu.so: $(OBJS)
	$(CC) $(SOLDFLAGS) -o $@ $^

main: $(OBJS) main.o
	$(CC) -o $@ $^ $(GCLDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d $(ALL)

-include $(wildcard *.d)
