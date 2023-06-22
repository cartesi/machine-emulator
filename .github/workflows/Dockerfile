FROM cartesi/toolchain:0.11.0 as builder
ARG RELEASE=no

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
        build-essential wget git \
        libreadline-dev libboost-coroutine-dev libboost-context-dev \
        libboost-filesystem-dev libssl-dev libc-ares-dev zlib1g-dev \
        ca-certificates automake libtool patchelf cmake pkg-config lua5.4 liblua5.4-dev \
        luarocks libb64-dev libcrypto++-dev nlohmann-json3-dev && \
    rm -rf /var/lib/apt/lists/*

RUN luarocks install --lua-version=5.4 luasocket && \
    luarocks install --lua-version=5.4 luasec && \
    luarocks install --lua-version=5.4 luaposix && \
    luarocks install --lua-version=5.4 lpeg && \
    luarocks install --lua-version=5.4 md5 && \
    luarocks install --lua-version=5.4 dkjson

WORKDIR /usr/src/emulator
COPY . .

RUN make -j$(nproc) dep && \
    make -j$(nproc) release=$RELEASE git_commit=$GIT_COMMIT && \
    make -j$(nproc) uarch && \
    make install && \
    make clean && \
    rm -rf *

FROM ubuntu:22.04

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    libboost-coroutine1.74.0 \
    libboost-context1.74.0 \
    libboost-filesystem1.74.0 \
    libreadline8 \
    openssl \
    libc-ares2 \
    zlib1g \
    ca-certificates \
    libgomp1 \
    lua5.4 \
    genext2fs \
    libb64-0d \
    libcrypto++8 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/cartesi/bin:${PATH}"
WORKDIR /opt/cartesi
COPY --from=builder /opt/cartesi .

COPY --from=builder /usr/local/lib/lua /usr/local/lib/lua
COPY --from=builder /usr/local/share/lua /usr/local/share/lua

CMD [ "/opt/cartesi/bin/remote-cartesi-machine" ]
