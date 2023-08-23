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
        luarocks libb64-dev xsltproc nlohmann-json3-dev && \
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
ARG DEB_FILENAME=cartesi-machine.deb

COPY . .
RUN make -j$(nproc) git_commit=$GIT_COMMIT release=$RELEASE coverage=$COVERAGE sanitize=$SANITIZE && \
    make -j$(nproc) uarch

FROM --platform=$TARGETPLATFORM builder as debian-packager
RUN make install-uarch debian-package DESTDIR=$PWD/_install

FROM --platform=$TARGETPLATFORM debian-packager as installer
ARG MACHINE_EMULATOR_VERSION=0.0.0
ARG TARGETARCH

RUN make install-tests
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt install -y \
    ./cartesi-machine-v${MACHINE_EMULATOR_VERSION}_${TARGETARCH}.deb \
    && rm -rf /var/lib/apt/lists/*

ENV CARTESI_TESTS_PATH="/usr/share/cartesi-machine/tests"
ENV CARTESI_IMAGES_PATH="/usr/share/cartesi-machine/images"

FROM --platform=$TARGETPLATFORM debian:bookworm-20230725-slim
ARG MACHINE_EMULATOR_VERSION=0.0.0
ARG TARGETARCH

COPY --from=installer \
	/usr/src/emulator/cartesi-machine-v${MACHINE_EMULATOR_VERSION}_${TARGETARCH}.deb \
	cartesi-machine.deb
RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt install -y \
    ./cartesi-machine.deb \
    && rm -rf /var/lib/apt/lists/* \
    && rm cartesi-machine.deb

RUN addgroup --system --gid 102 cartesi && \
    adduser --system --uid 102 --ingroup cartesi --disabled-login --no-create-home --home /nonexistent --gecos "cartesi user" --shell /bin/false cartesi

WORKDIR /opt/cartesi

EXPOSE 5002

USER cartesi

CMD [ "/usr/bin/remote-cartesi-machine", "--server-address=0.0.0.0:5002"]
