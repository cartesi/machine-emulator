FROM --platform=$TARGETPLATFORM cartesi/toolchain:0.16.0-rv64ima-lp64 as linux-env
ARG GIT_COMMIT=""
ARG RELEASE=no
ARG COVERAGE=no
ARG SANITIZE=no

RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    build-essential vim wget git clang-tidy-15 clang-format-15 lcov \
    libboost1.81-dev libssl-dev \
    ca-certificates pkg-config lua5.4 liblua5.4-dev \
    libgrpc++-dev libprotobuf-dev protobuf-compiler-grpc \
    luarocks xxd && \
    update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-15 120 && \
    update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-15 120 && \
    rm -rf /var/lib/apt/lists/*


RUN luarocks install --lua-version=5.4 luasocket && \
    luarocks install --lua-version=5.4 luasec && \
    luarocks install --lua-version=5.4 luaposix && \
    luarocks install --lua-version=5.4 lpeg && \
    luarocks install --lua-version=5.4 dkjson && \
    luarocks install --lua-version=5.4 luacheck && \
    cargo install stylua@0.18.1 --features lua54

# Environment has the riscv64-cartesi-linux-gnu-* toolchain
ENV DEV_ENV_HAS_TOOLCHAIN=yes

WORKDIR /usr/src/emulator

FROM --platform=$TARGETPLATFORM linux-env as dep-builder

COPY Makefile .
COPY third-party third-party

RUN make -j$(nproc) dep

FROM --platform=$TARGETPLATFORM dep-builder as builder

COPY . .
RUN make -j$(nproc) git_commit=$GIT_COMMIT release=$RELEASE coverage=$COVERAGE sanitize=$SANITIZE

FROM --platform=$TARGETPLATFORM builder as debian-packager
ARG MACHINE_EMULATOR_VERSION=0.0.0

RUN make install-uarch debian-package DESTDIR=$PWD/_install

FROM --platform=$TARGETPLATFORM debian:bookworm-20230725-slim
ARG MACHINE_EMULATOR_VERSION=0.0.0
ARG TARGETARCH

COPY --from=debian-packager \
    /usr/src/emulator/cartesi-machine-v${MACHINE_EMULATOR_VERSION}_${TARGETARCH}.deb \
    cartesi-machine.deb
COPY --from=debian-packager /usr/local/lib/lua /usr/local/lib/lua
COPY --from=debian-packager /usr/local/share/lua /usr/local/share/lua

RUN apt-get update && DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    ./cartesi-machine.deb \
    && rm -rf /var/lib/apt/lists/* \
    && rm cartesi-machine.deb

RUN addgroup --system --gid 102 cartesi && \
    adduser --system --uid 102 --ingroup cartesi --disabled-login --no-create-home --home /nonexistent --gecos "cartesi user" --shell /bin/false cartesi

WORKDIR /opt/cartesi

EXPOSE 5002

USER cartesi

CMD [ "/usr/bin/remote-cartesi-machine", "--server-address=0.0.0.0:5002"]
