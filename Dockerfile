FROM debian:bookworm-20250113 AS toolchain

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        build-essential vim wget git lcov \
        libboost1.81-dev libssl-dev libslirp-dev \
        ca-certificates pkg-config lua5.4 liblua5.4-dev \
        luarocks xxd procps \
        g++-12-riscv64-linux-gnu=12.2.0-13cross1 \
        gcc-riscv64-unknown-elf=12.2.0-14+11+b1 && \
    rm -rf /var/lib/apt/lists/*

# Install clang 19
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        wget software-properties-common gnupg && \
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    add-apt-repository -y 'deb http://apt.llvm.org/bookworm/  llvm-toolchain-bookworm-19 main' && \
    add-apt-repository -y 'deb http://apt.llvm.org/bookworm/  llvm-toolchain-bookworm-19 main' && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        clang-tidy-19 clang-format-19 && \
    update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-19 120 && \
    update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-19 120 && \
    rm -rf /var/lib/apt/lists/*

# Install lua packages
RUN luarocks install --lua-version=5.4 luasocket && \
    luarocks install --lua-version=5.4 luasec && \
    luarocks install --lua-version=5.4 luaposix && \
    luarocks install --lua-version=5.4 luacheck

# Install stylua
RUN cd /tmp && \
    wget https://github.com/JohnnyMorganz/StyLua/releases/download/v0.20.0/stylua-linux-`uname -m`.zip && \
    case $(uname -m) in \
      x86_64)  echo "28eddb9257bf85b20b1c337e536b7a3d16ba308863f067d447c1f4d24c6dec64  stylua-linux-x86_64.zip"  | sha256sum --check ;; \
      aarch64) echo "376b675766bc0b9261b2b82c8d0f624c7e5f78e83bd8490330e0bf3d8f770ad7  stylua-linux-aarch64.zip" | sha256sum --check ;; \
    esac && \
    unzip stylua-linux-*.zip && \
    mv stylua /usr/local/bin/ && \
    rm -f stylua-linux-*.zip

# Environment has the riscv64 toolchains
ENV DEV_ENV_HAS_TOOLCHAIN=yes

# Install su-exec
RUN cd /tmp && \
    git clone --branch v0.2 --depth 1 https://github.com/ncopa/su-exec.git && \
    cd su-exec && \
    if [ `git rev-parse --verify HEAD` != 'f85e5bde1afef399021fbc2a99c837cf851ceafa' ]; then exit 1; fi && \
    make && \
    cp su-exec /usr/local/bin/ && \
    rm -rf /tmp/su-exec

# Install workaround to run as current user
COPY tools/docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Install necessary headers to make GNU libc work with lp64 ABI
COPY tools/gnu/stubs-lp64.h /usr/riscv64-linux-gnu/include/gnu/stubs-lp64.h

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
WORKDIR /usr/src/emulator
CMD ["/bin/bash", "-l"]

####################################################################################################
FROM toolchain AS builder
ARG GIT_COMMIT=""
ARG DEBUG=no
ARG COVERAGE=no
ARG SANITIZE=no

COPY . .
RUN make -j$(nproc) git_commit=$GIT_COMMIT debug=$DEBUG coverage=$COVERAGE sanitize=$SANITIZE

####################################################################################################
FROM builder AS debian-packager

RUN make install-uarch debian-package DESTDIR=$PWD/_install

####################################################################################################
FROM debian:bookworm-20250113-slim
ARG MACHINE_EMULATOR_VERSION=0.0.0
ARG TARGETARCH

COPY --from=debian-packager \
    /usr/src/emulator/cartesi-machine-v${MACHINE_EMULATOR_VERSION}_${TARGETARCH}.deb \
    cartesi-machine.deb
COPY --from=debian-packager /usr/local/lib/lua /usr/local/lib/lua
COPY --from=debian-packager /usr/local/share/lua /usr/local/share/lua

RUN apt-get update && \
    apt-get install -y ./cartesi-machine.deb && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* cartesi-machine.deb

RUN addgroup --system --gid 102 cartesi && \
    adduser --system --uid 102 --ingroup cartesi --disabled-login --no-create-home --home /nonexistent --gecos "cartesi user" --shell /bin/false cartesi

WORKDIR /opt/cartesi

EXPOSE 5002

USER cartesi

CMD [ "/usr/bin/cartesi-jsonrpc-machine", "--server-address=0.0.0.0:5002"]
