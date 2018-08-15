FROM ubuntu:16.04

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

# Install Lua 5.3
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        lua5.3 liblua5.3-dev unzip libfdt-dev \
        build-essential autoconf automake libtool autotools-dev \
        git make pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Make sure we have an executable lua command
# in the PATh
# ----------------------------------------------------
RUN ln -s /usr/bin/lua5.3 /usr/bin/lua

USER root
WORKDIR ~
