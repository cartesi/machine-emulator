FROM ubuntu:16.04

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

ENV BASE=/opt/riscv

# Base system and user so we can do stuff
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        apt-utils vim wget curl zip unzip sudo && \
    mkdir -p $BASE && \
    adduser cartesi --gecos "" --disabled-password && \
    adduser cartesi sudo && \
    echo cartesi:cartesi | chpasswd && \
    rm -rf /var/lib/apt/lists/*

# Development basics
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        build-essential autoconf automake libtool autotools-dev \
        git make pkg-config patchutils gawk bison flex ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Obtain sources to linux, riscv-pk, and gcc
# ----------------------------------------------------
RUN \
    cd $BASE && \
    git clone https://github.com/sifive/freedom-u-sdk.git && \
    cd freedom-u-sdk && \
    git reset --hard b84ef550a159b6801a036862a8b0d15615c36b64 && \
    git submodule update --init --recursive
