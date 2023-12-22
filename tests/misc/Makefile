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

# Mac OS X specific setup
ifeq ($(TARGET_OS),Darwin)
CC=clang
CXX=clang++
INCS=

# Homebrew installation
ifneq (,$(shell which brew))
BREW_PREFIX = $(shell brew --prefix)
BOOST_LIB_DIR=-L$(BREW_PREFIX)/lib
BOOST_INC=-I$(BREW_PREFIX)/include
GRPC_PROTOBUF_INC=$(shell pkg-config --cflags-only-I grpc++ protobuf)
GRPC_PROTOBUF_LIB=$(shell pkg-config --libs grpc++ protobuf)

# Macports installation
else ifneq (,$(shell which port))
PORT_PREFIX = /opt/local
BOOST_LIB_DIR=-L$(PORT_PREFIX)/libexec/boost/1.81/lib
BOOST_INC=-I$(PORT_PREFIX)/libexec/boost/1.81/include
GRPC_PROTOBUF_INC=-I$(PORT_PREFIX)/include
GRPC_PROTOBUF_LIB=-L$(PORT_PREFIX)/lib -lgrpc++ -lgrpc -lgpr -lprotobuf -lpthread -labsl_synchronization
else
$(error Neither Homebrew nor MacPorts is installed)
endif

ifeq ($(MACOSX_DEPLOYMENT_TARGET),)
export MACOSX_DEPLOYMENT_TARGET := $(shell sw_vers -productVersion | sed -E "s/([[:digit:]]+)\.([[:digit:]]+)\..+/\1.\2.0/")
endif

# Linux or some other POSIX platform
else
CC=gcc
CXX=g++
GRPC_PROTOBUF_INC=$(shell pkg-config --cflags-only-I grpc++ protobuf)
GRPC_PROTOBUF_LIB=$(shell pkg-config --libs grpc++ protobuf)
endif

all: $(BUILDDIR)/test-merkle-tree-hash $(BUILDDIR)/test-machine-c-api

../../src/libcartesi_grpc.a ../../src/libcartesi.a ../../src/libcartesi_merkle_tree.a:
	$(info libcartesi.a and/or libcartesi_grpc.a were not found! Build them first.)
	@exit 1

$(BUILDDIR)/test-merkle-tree-hash: test-merkle-tree-hash.cpp ../../src/libcartesi.a ../../src/libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ -I../../src -I../../third-party/tiny_sha3 -std=c++17 -g

$(BUILDDIR)/test-machine-c-api: test-machine-c-api.cpp ../../src/libcartesi_grpc.a ../../src/libcartesi.a ../../src/libcartesi_merkle_tree.a
	$(CXX) -o $@ $^ $(GRPC_PROTOBUF_LIB) -I../../src $(BOOST_INC) -I../../third-party/downloads -I../../third-party/tiny_sha3 -std=c++17 -g

clean:
	@rm -f $(BUILDDIR)/test-merkle-tree-hash $(BUILDDIR)/test-machine-c-api

.SUFFIXES:
