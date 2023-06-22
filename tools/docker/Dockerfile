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
        ca-certificates automake libtool patchelf cmake pkg-config lua5.4 liblua5.4-dev \
        libb64-dev libcrypto++-dev nlohmann-json3-dev luarocks && \
    rm -rf /var/lib/apt/lists/*

RUN \
    luarocks install --lua-version=5.4 luasocket && \
    luarocks install --lua-version=5.4 luasec && \
    luarocks install --lua-version=5.4 luaposix && \
    luarocks install --lua-version=5.4 lpeg && \
    luarocks install --lua-version=5.4 md5 && \
    luarocks install --lua-version=5.4 dkjson

ENV PATH="${PATH}:${BASE}/build/Linux_x86_64/bin"

WORKDIR $BASE

CMD ["/bin/bash", "-l"]
