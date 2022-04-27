FROM ubuntu:22.04

MAINTAINER Diego Nehab <diego@cartesi.io>

ENV DEBIAN_FRONTEND=noninteractive

ENV BASE="/opt/emulator"

RUN \
    mkdir -p $BASE

RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        build-essential vim wget git libreadline-dev libboost-coroutine-dev \
        libboost-context-dev libboost-filesystem-dev \
        libssl-dev openssl libc-ares-dev zlib1g-dev clang-tidy-14 clang-format-14 \
        ca-certificates automake libtool patchelf cmake pkg-config lua5.3 liblua5.3-dev luarocks && \
    rm -rf /var/lib/apt/lists/*

RUN \
    luarocks install luasocket && \
    luarocks install luasec && \
    luarocks install lpeg && \
    luarocks install dkjson

ENV PATH="${PATH}:${BASE}/build/Linux_x86_64/bin"

WORKDIR $BASE

CMD ["/bin/bash", "-l"]
