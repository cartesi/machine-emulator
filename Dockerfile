ARG BUILD_BASE=debian:trixie-20250811
ARG RUNTIME_BASE=debian:trixie-20250811-slim

FROM $BUILD_BASE AS toolchain

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        build-essential vim wget git gcovr \
        libboost1.83-dev libssl-dev libslirp-dev \
        ca-certificates pkg-config lua5.4 liblua5.4-dev luarocks \
        lua-check lua-socket lua-posix lua-lpeg \
        xxd procps unzip gosu \
        gpg \
        g++-14-riscv64-linux-gnu=14.2.0-19cross1 \
        gcc-riscv64-unknown-elf=14.2.0+19 && \
    rm -rf /var/lib/apt/lists/* && \
    luarocks --lua-version 5.4 install luacov && \
    luarocks --lua-version 5.4 install cluacov

# Install Clang 22 from LLVM toolchain repository
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/trixie/ llvm-toolchain-trixie-22 main" > /etc/apt/sources.list.d/llvm-toolchain-trixie-22.list && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        clang-tidy-22 clang-format-22 libomp-22-dev && \
    update-alternatives --install /usr/bin/clang-tidy clang-tidy /usr/bin/clang-tidy-22 100 && \
    update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-22 100 && \
    rm -rf /var/lib/apt/lists/*

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

# Install workaround to run as current user
COPY tools/docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Install necessary headers to make GNU libc work with lp64 ABI
COPY tools/rv64i-lp64-stubs/gnu/stubs-lp64.h /usr/riscv64-linux-gnu/include/gnu/stubs-lp64.h

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
WORKDIR /usr/src/emulator
CMD ["/bin/bash", "-l"]

####################################################################################################
FROM toolchain AS builder
ARG GIT_COMMIT=""
ARG DEBUG=no
ARG COVERAGE=no
ARG THREADS=yes
ARG SANITIZE=no

COPY . .
RUN make -j$(nproc) git_commit=$GIT_COMMIT debug=$DEBUG coverage=$COVERAGE threads=$THREADS sanitize=$SANITIZE

####################################################################################################
FROM builder AS debian-packager

RUN make install-uarch debian-package DESTDIR=$PWD/_install

####################################################################################################
FROM $RUNTIME_BASE
ARG TARGETARCH
ARG RUNTIME_BASE
LABEL io.cartesi.machine-emulator.base-image="$RUNTIME_BASE"

COPY --from=debian-packager /usr/src/emulator/machine-emulator_${TARGETARCH}.deb machine-emulator.deb
COPY tests/dependencies tests/dependencies.sha256 /usr/share/cartesi-machine/

RUN apt-get update && \
    apt-get install -y gosu ./machine-emulator.deb && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* machine-emulator.deb

# Carried but dormant (no ENTRYPOINT set here, so production behavior is
# unchanged): lets a derived dev image (e.g. doc/) opt into running as the host
# user by pointing ENTRYPOINT at this script. Needs gosu, installed above.
COPY tools/docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

RUN groupadd --system --gid 102 cartesi && \
    useradd --system --uid 102 --gid 102 --no-create-home --home /nonexistent --comment "cartesi user" --shell /bin/false cartesi

WORKDIR /opt/cartesi

EXPOSE 5002

USER cartesi

CMD [ "/usr/bin/cartesi-jsonrpc-machine", "--server-address=0.0.0.0:5002"]
