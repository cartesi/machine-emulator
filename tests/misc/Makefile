# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: LGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
#

TARGET_OS?=$(shell uname)
BUILDDIR?=.

coverage?=no
sanitize?=no

COVERAGE_TOOLCHAIN?=gcc

# Mac OS X specific setup
ifeq ($(TARGET_OS),Darwin)
CC=clang
CXX=clang++

ifeq ($(MACOSX_DEPLOYMENT_TARGET),)
export MACOSX_DEPLOYMENT_TARGET := $(shell sw_vers -productVersion | sed -E "s/([[:digit:]]+)\.([[:digit:]]+)\..+/\1.\2.0/")
endif

# Homebrew installation
ifneq (,$(shell which brew))
BREW_PREFIX = $(shell brew --prefix)
BOOST_LIB_DIR=-L$(BREW_PREFIX)/lib
BOOST_INC=-I$(BREW_PREFIX)/include

# Macports installation
else ifneq (,$(shell which port))
PORT_PREFIX = /opt/local
BOOST_LIB_DIR=-L$(PORT_PREFIX)/libexec/boost/1.81/lib
BOOST_INC=-I$(PORT_PREFIX)/libexec/boost/1.81/include
else
$(error Neither Homebrew nor MacPorts is installed)
endif

# Linux or some other POSIX platform
else
CC=gcc
CXX=g++
endif

ifeq ($(coverage),yes)
ifeq ($(COVERAGE_TOOLCHAIN),gcc)
CXX=g++
CXXFLAGS+=-g -Og -fno-dce -fno-inline -DCODE_COVERAGE --coverage
LDFLAGS+=--coverage
else ifeq ($(COVERAGE_TOOLCHAIN),clang)
CXX=clang++
CXXFLAGS+=-g -O0 -DCODE_COVERAGE -fprofile-instr-generate -fcoverage-mapping
LDFLAGS+=-fprofile-instr-generate -fcoverage-mapping
else ifneq ($(COVERAGE_TOOLCHAIN),)
$(error invalid value for COVERAGE_TOOLCHAIN: $(COVERAGE_TOOLCHAIN))
endif
endif

ifeq ($(sanitize),yes)
# Enable address and undefined sanitizers
UBFLAGS+=-fsanitize=address,undefined -fno-sanitize-recover=all
else
# Flags to minimize undefined behavior
UBFLAGS+=-fno-strict-aliasing
UBFLAGS+=-fno-strict-overflow
UBFLAGS+=-fno-delete-null-pointer-checks
endif

# We ignore test-machine-c-api.cpp cause it takes too long.
LINTER_SOURCES=test-merkle-tree-hash.cpp
LINTER_HEADERS=$(wildcard *.h)

CLANG_TIDY=clang-tidy
CLANG_TIDY_TARGETS=$(patsubst %.cpp,%.clang-tidy,$(LINTER_SOURCES))

EMPTY:=
SPACE:=$(EMPTY) $(EMPTY)
CLANG_TIDY_HEADER_FILTER=$(CURDIR)/($(subst $(SPACE),|,$(LINTER_HEADERS)))

CLANG_FORMAT=clang-format
CLANG_FORMAT_FILES:=$(wildcard *.cpp) $(wildcard *.h)

INCS=-I../../src -I../../third-party/tiny_sha3 -I../../third-party/downloads
WARNS=-Wall -Wpedantic

CXXFLAGS+=-O2 -g -std=gnu++17 -fvisibility=hidden $(INCS) $(UBFLAGS) $(WARNS)

all: $(BUILDDIR)/test-merkle-tree-hash $(BUILDDIR)/test-machine-c-api

../../src/libcartesi.a ../../src/libcartesi_merkle_tree.a:
	$(info libcartesi.a and/or libcartesi_merkle_tree.a were not found! Build them first.)
	@exit 1

$(BUILDDIR)/test-merkle-tree-hash: test-merkle-tree-hash.cpp ../../src/libcartesi.a ../../src/libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(CXXFLAGS)

$(BUILDDIR)/test-machine-c-api: test-machine-c-api.cpp ../../src/libcartesi.a ../../src/libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(CXXFLAGS) $(BOOST_INC)

%.clang-tidy: %.cpp
	@$(CLANG_TIDY) --header-filter='$(CLANG_TIDY_HEADER_FILTER)' $< -- $(CXXFLAGS) $(BOOST_INC) 2>/dev/null
	@$(CXX) $(CXXFLAGS) $(BOOST_INC) $< -MM -MT $@ -MF $@.d > /dev/null 2>&1
	@touch $@

compile_flags.txt:
	@echo "$(CXXFLAGS)" "$(BOOST_INC)" "-xc++" | sed -e $$'s/ \{1,\}/\\\n/g' | grep -v "MMD" > $@

lint: $(CLANG_TIDY_TARGETS)

format:
	@$(CLANG_FORMAT) -i $(CLANG_FORMAT_FILES)

check-format:
	@$(CLANG_FORMAT) -Werror --dry-run $(CLANG_FORMAT_FILES)

clean-tidy:
	@rm -f *.clang-tidy

clean-objs:
	@rm -f *.o *.d

clean: clean-tidy clean-objs
	@rm -f $(BUILDDIR)/test-merkle-tree-hash $(BUILDDIR)/test-machine-c-api

.SUFFIXES:
