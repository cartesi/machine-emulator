FROM ghcr.io/cartesi/toolchain:main-rv64ima-lp64 as linux-env
ARG RELEASE=no

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
        build-essential vim wget git \
        libreadline-dev libboost-coroutine-dev libboost-context-dev \
        libboost-filesystem-dev libssl-dev libc-ares-dev zlib1g-dev \
        ca-certificates automake libtool patchelf cmake pkg-config lua5.4 liblua5.4-dev \
        libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
        luarocks libb64-dev libcrypto++-dev nlohmann-json3-dev && \
    rm -rf /var/lib/apt/lists/*


RUN luarocks install --lua-version=5.4 luasocket && \
    luarocks install --lua-version=5.4 luasec && \
    luarocks install --lua-version=5.4 luaposix && \
    luarocks install --lua-version=5.4 lpeg && \
    luarocks install --lua-version=5.4 md5 && \
    luarocks install --lua-version=5.4 dkjson

WORKDIR /usr/src/emulator

FROM linux-env as dep-builder

COPY Makefile .
COPY third-party third-party

RUN make -j$(nproc) dep

FROM dep-builder as builder

COPY . .
RUN make -j$(nproc) release=$RELEASE git_commit=$GIT_COMMIT && \
    make -j$(nproc) uarch

FROM builder as installer

RUN make install

FROM debian:bookworm-20230612

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
    libgrpc++1.51 \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/opt/cartesi/bin:${PATH}"
WORKDIR /opt/cartesi
COPY --from=installer /opt/cartesi .

COPY --from=installer /usr/local/lib/lua /usr/local/lib/lua
COPY --from=installer /usr/local/share/lua /usr/local/share/lua

CMD [ "/opt/cartesi/bin/remote-cartesi-machine" ]
