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

CFLAGS=$(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS)
CXXFLAGS=-std=c++14 $(WARNS) -Ofast -march=native -fpic -fvisibility=hidden -MMD $(INCS)

ALL=emu.so

all: $(ALL)

OBJS:= \
	virtio.o \
	pci.o \
	cutils.o \
	iomem.o \
	machine.o \
	riscvemu.o \
	riscv_machine.o \
	riscv_cpu.o

riscv_cpu.o: CFLAGS += -DMAX_XLEN=64 -DFLEN=0

emu.so: $(OBJS)
	$(CC) $(SOLDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d $(ALL)

-include $(wildcard *.d)
