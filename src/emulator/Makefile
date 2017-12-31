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
#

CC=gcc
CFLAGS=-O2 -Wall -g -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -MMD
CFLAGS+=-D_GNU_SOURCE -DCONFIG_VERSION=\"$(shell cat VERSION)\"
CFLAGS+=-DFLEN=0
LDFLAGS=

ALL=emu

all: $(ALL)

EMU_OBJS:= \
	virtio.o \
	pci.o \
	fs.o \
	cutils.o \
	iomem.o \
	simplefb.o \
    json.o \
	machine.o \
	fs_disk.o \
	riscvemu.o \
	riscv_machine.o \
	riscv_cpu.o

LIBS=-lrt

OBJS:=$(EMU_OBJS)

riscv_cpu.o: CFLAGS += -DMAX_XLEN=64

emu: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d $(ALL)

-include $(wildcard *.d)
