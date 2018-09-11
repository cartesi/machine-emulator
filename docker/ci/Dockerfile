FROM ubuntu:18.04

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

# Install Lua 5.3
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        lua5.3 liblua5.3-dev unzip libfdt-dev ca-certificates \
        build-essential autoconf automake libtool autotools-dev \
        git make pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Install cryptopp
# ----------------------------------------------------
RUN \
    git clone https://github.com/cartesi/cryptopp.git && \
    cd cryptopp && \
    git checkout cartesi && \
    make && \
    make install && \
    cd .. && \
    \rm -rf cryptopp

# Make sure we have an executable lua command
# in the PATh
# ----------------------------------------------------
RUN ln -s /usr/bin/lua5.3 /usr/bin/lua

USER root
WORKDIR ~
