FROM diegonehab/themis:src

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

# Build riscv's gcc
# ----------------------------------------------------
ENV THREADS=24

RUN \
    apt-get update && \
    apt-get install -y device-tree-compiler libmpc-dev libmpfr-dev && \
    apt-get install -y libgmp-dev libusb-1.0-0-dev texinfo gperf bc && \
    apt-get install -y zlib1g-dev libncurses-dev libexpat-dev

RUN \
    cd $BASE/freedom-u-sdk && \
    ABI=lp64 ISA=rv64ima make -j$THREADS $BASE/freedom-u-sdk/toolchain/bin/riscv64-unknown-linux-gnu-gcc

ENV PATH "${BASE}/freedom-u-sdk/toolchain/bin:${PATH}"
