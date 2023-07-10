FROM --platform=$TARGETPLATFORM cartesi/toolchain:0.15.0-rv64ima-lp64 as linux-env
ARG GIT_COMMIT=""
ARG RELEASE=no
ARG COVERAGE=no
ARG SANITIZE=no

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
        build-essential vim wget git clang-tidy-15 clang-format-15 lcov \
        libreadline-dev libboost-coroutine-dev libboost-context-dev \
        libboost-filesystem-dev libssl-dev libc-ares-dev zlib1g-dev \
        ca-certificates automake libtool patchelf cmake pkg-config lua5.4 liblua5.4-dev \
        libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
        luarocks libb64-dev libcrypto++-dev nlohmann-json3-dev && \
        update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 120 && \
        update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 120 && \
    rm -rf /var/lib/apt/lists/*


RUN luarocks install --lua-version=5.4 luasocket && \
    luarocks install --lua-version=5.4 luasec && \
    luarocks install --lua-version=5.4 luaposix && \
    luarocks install --lua-version=5.4 lpeg && \
    luarocks install --lua-version=5.4 md5 && \
    luarocks install --lua-version=5.4 dkjson && \
    luarocks install --lua-version=5.4 luacheck && \
    cargo install stylua@0.18.1 --features lua54

WORKDIR /usr/src/emulator

FROM --platform=$TARGETPLATFORM linux-env as dep-builder

COPY Makefile .
COPY third-party third-party

RUN make -j$(nproc) dep

FROM --platform=$TARGETPLATFORM dep-builder as builder

COPY . .
RUN make -j$(nproc) git_commit=$GIT_COMMIT release=$RELEASE coverage=$COVERAGE sanitize=$SANITIZE && \
    make -j$(nproc) uarch

FROM --platform=$TARGETPLATFORM builder as installer

RUN make install

# For testing purposes
ENV PATH="/opt/cartesi/bin:${PATH}"
ENV CARTESI_IMAGES_PATH=/opt/cartesi/share/images
ENV CARTESI_TESTS_PATH=/opt/cartesi/share/tests
ENV LUA_PATH_5_4="/opt/cartesi/share/lua/5.4/?.lua;;"
ENV LUA_CPATH_5_4="/opt/cartesi/lib/lua/5.4/?.so;;"

FROM --platform=$TARGETPLATFORM debian:bookworm-20230725-slim

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

RUN addgroup --system --gid 102 cartesi && \
    adduser --system --uid 102 --ingroup cartesi --disabled-login --no-create-home --home /nonexistent --gecos "cartesi user" --shell /bin/false cartesi

COPY --from=installer /opt/cartesi /opt/cartesi
COPY --from=installer /usr/local/lib/lua /usr/local/lib/lua
COPY --from=installer /usr/local/share/lua /usr/local/share/lua

ENV PATH="/opt/cartesi/bin:${PATH}"
ENV CARTESI_IMAGES_PATH=/opt/cartesi/share/images
ENV CARTESI_TESTS_PATH=/opt/cartesi/share/tests
ENV LUA_PATH_5_4="/opt/cartesi/share/lua/5.4/?.lua;;"
ENV LUA_CPATH_5_4="/opt/cartesi/lib/lua/5.4/?.so;;"

WORKDIR /opt/cartesi

EXPOSE 5002

USER cartesi

CMD [ "/opt/cartesi/bin/remote-cartesi-machine", "--server-address=0.0.0.0:5002"]
