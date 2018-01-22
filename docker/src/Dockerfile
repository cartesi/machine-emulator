FROM ubuntu:16.04

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

ENV BASE=/opt/riscv

# Base system and user so we can do stuff
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install -y apt-utils && \
    apt-get install -y vim wget curl sudo && \
    apt-get install -y zip unzip && \
    mkdir -p $BASE && \
    adduser themis --gecos "" --disabled-password && \
    adduser themis sudo && \
    echo themis:themis | chpasswd

# Development basics
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y autoconf automake libtool autotools-dev && \
    apt-get install -y git make pkg-config patchutils gawk bison flex

# Obtain sources to linux, riscv-pk, and gcc
# ----------------------------------------------------
RUN \
    cd $BASE && \
    git clone https://github.com/sifive/freedom-u-sdk.git && \
    cd freedom-u-sdk && \
    git reset --hard b84ef550a159b6801a036862a8b0d15615c36b64 && \
    git submodule update --init --recursive

