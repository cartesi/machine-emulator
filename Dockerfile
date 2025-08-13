FROM debian:trixie-20250811 AS toolchain

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
        build-essential vim wget git gcovr \
        libomp-19-dev libboost1.83-dev libssl-dev libslirp-dev \
        ca-certificates pkg-config lua5.4 liblua5.4-dev \
        lua-check lua-socket lua-posix lua-lpeg \
        xxd procps unzip gosu \
        clang-tidy clang-format \
        g++-14-riscv64-linux-gnu=14.2.0-19cross1 \
        gcc-riscv64-unknown-elf=14.2.0+19 && \
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
COPY tools/gnu/stubs-lp64.h /usr/riscv64-linux-gnu/include/gnu/stubs-lp64.h

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
FROM debian:trixie-20250811-slim
ARG TARGETARCH

COPY --from=debian-packager /usr/src/emulator/machine-emulator_${TARGETARCH}.deb machine-emulator.deb

RUN apt-get update && \
    apt-get install -y ./machine-emulator.deb && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* machine-emulator.deb

RUN groupadd --system --gid 102 cartesi && \
    useradd --system --uid 102 --gid 102 --no-create-home --home /nonexistent --comment "cartesi user" --shell /bin/false cartesi

WORKDIR /opt/cartesi

EXPOSE 5002

USER cartesi

CMD [ "/usr/bin/cartesi-jsonrpc-machine", "--server-address=0.0.0.0:5002"]
