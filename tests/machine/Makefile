# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PREFIX = /opt/cartesi
INSTALLDIR = $(PREFIX)/tests

SRCDIR := $(abspath src)
BUILDDIR ?= $(abspath build)
SRCCLEAN := $(addsuffix .clean,$(SRCDIR))

RISCV_PREFIX = riscv64-unknown-elf-
RVCC  = $(RISCV_PREFIX)gcc
RVCXX = $(RISCV_PREFIX)g++
RVCOPY = $(RISCV_PREFIX)objcopy
RVDUMP = $(RISCV_PREFIX)objdump

all: $(SRCDIR)

clean: $(SRCCLEAN)

depclean: clean
	rm -rf $(BUILDDIR)
	$(MAKE) -C $@ clean

distclean: clean
	rm -rf $(BUILDDIR)

$(SRCCLEAN): %.clean:
	$(MAKE) -C $* clean

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(SRCDIR): $(BUILDDIR)
	$(MAKE) -C $@ RISCV_PREFIX=$(RISCV_PREFIX) $(TARGET)

install:
	mkdir -p $(INSTALLDIR)
	cp -a $(BUILDDIR)/*.bin $(BUILDDIR)/*.dump $(BUILDDIR)/*.elf $(INSTALLDIR)


.PHONY: all clean distclean $(SRCDIR) $(SRCCLEAN) $(DEPCLEAN)
