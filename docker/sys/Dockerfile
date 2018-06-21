FROM cartesi/core:src

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

ENV THREADS=24

ENV OLDPATH=$PATH

# Copy and apply our patches
# ----------------------------------------------------
COPY linux_defconfig $BASE/freedom-u-sdk/conf
COPY riscv-pk.patch $BASE/freedom-u-sdk/riscv-pk
COPY riscv-gnu-toolchain.patch $BASE/freedom-u-sdk/riscv-gnu-toolchain
COPY riscv-qemu.patch $BASE/freedom-u-sdk/riscv-qemu
COPY Makefile.patch $BASE/freedom-u-sdk

RUN \
    cd $BASE/freedom-u-sdk && \
    patch -p1 < Makefile.patch && \
    cd riscv-pk && \
    patch -p1 < riscv-pk.patch && \
    cd ../riscv-qemu && \
    patch -p1 < riscv-qemu.patch && \
    cd ../riscv-gnu-toolchain && \
    patch -p1 < riscv-gnu-toolchain.patch

# Ideally, we should be able to compile a single version of
# gcc with --enable-multilib that would support
# ABI lp64d and ISA rv64imafd, as well as ABI lp64 and ISA rv64ima
# We need to compile the kernel and bbl with ABI lp64 and ISA
# rv64ima so bbl can emulate the floating-point
# instructions. The rest we can compile however we like, but
# should prefer ABI lp64d and ISA rv64imafd so that, in the
# future, we can use native floating-point.
# Unfortunately, buildroot gets confused with the sysroot
# layout of riscv's multilib and fails. So instead we
# compile two independent gcc.
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        device-tree-compiler libmpc-dev libmpfr-dev libgmp-dev \
        libusb-1.0-0-dev texinfo gperf bc zlib1g-dev libncurses-dev \
        libexpat-dev python && \
    rm -rf /var/lib/apt/lists/*

ENV ISA "rv64imafd"
ENV ABI "lp64d"
ENV RISCV "$BASE/$ISA-$ABI"

RUN \
    mkdir -p $RISCV && \
    cd $BASE/freedom-u-sdk && \
    \rm -rf work/riscv-gnu-toolchain && \
    toolchain_dest=$BASE/$ISA-$ABI make -j$THREADS $RISCV/bin/riscv64-unknown-linux-gnu-gcc && \
    \rm -rf work/riscv-gnu-toolchain

ENV ISA "rv64ima"
ENV ABI "lp64"
ENV RISCV "$BASE/$ISA-$ABI"

RUN \
    mkdir -p $RISCV && \
    cd $BASE/freedom-u-sdk && \
    \rm -rf work/riscv-gnu-toolchain && \
    toolchain_dest=$BASE/$ISA-$ABI make -j$THREADS $RISCV/bin/riscv64-unknown-linux-gnu-gcc && \
    \rm -rf work/riscv-gnu-toolchain

# We also need an compiler that does not target Linux, but
# simply target elf binaries. This is to build riscv-tests.
# ----------------------------------------------------
RUN \
    mkdir -p $RISCV && \
    cd $BASE/freedom-u-sdk && \
    \rm -rf work/riscv-gnu-toolchain && \
    mkdir -p work/riscv-gnu-toolchain && \
    cd work/riscv-gnu-toolchain && \
    $BASE/freedom-u-sdk/riscv-gnu-toolchain/configure --with-arch=rv64imafd --with-abi=lp64d --prefix=$BASE/elf-rv64imafd-lp64d && \
    make -j24 && \
    \rm -rf $BASE/work/riscv-gnu-toolchain

RUN \
    mkdir -p $RISCV && \
    cd $BASE/freedom-u-sdk && \
    \rm -rf work/riscv-gnu-toolchain && \
    mkdir -p work/riscv-gnu-toolchain && \
    cd work/riscv-gnu-toolchain && \
    $BASE/freedom-u-sdk/riscv-gnu-toolchain/configure --with-arch=rv64ima --with-abi=lp64 --prefix=$BASE/elf-rv64ima-lp64 && \
    make -j24 && \
    \rm -rf $BASE/work/riscv-gnu-toolchain

# Build riscv's kernel and bootloader with ABI lp64 and ISA rv64ima
# (emulating rv64imafd)
# ----------------------------------------------------
ENV ISA "rv64ima"
ENV ABI "lp64"
ENV RISCV "$BASE/$ISA-$ABI"
ENV PATH "$RISCV/bin:${OLDPATH}"

RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        libglib2.0-dev libssl-dev cpio && \
    rm -rf /var/lib/apt/lists/*

RUN \
    cd $BASE/freedom-u-sdk && \
    make -j$THREADS $BASE/freedom-u-sdk/work/linux/vmlinux && \
    cd $BASE/freedom-u-sdk && \
    make -j$THREADS $BASE/freedom-u-sdk/work/bbl.bin && \
    cp work/bbl.bin $BASE/kernel.bin && \
    cp work/riscv-pk/bbl $BASE/kernel.elf && \
    \rm -rf work/riscv-pk work/linux

# Build qemu
# ----------------------------------------------------
RUN \
    cd $BASE/freedom-u-sdk && \
    make -j$THREADS $BASE/freedom-u-sdk/work/riscv-qemu/prefix/bin/qemu-system-riscv64 && \
    mv work/riscv-qemu/prefix $BASE/riscv-qemu && \
    \rm -rf work/riscv-qemu

# Build spike
# ----------------------------------------------------
RUN \
    cd $BASE/freedom-u-sdk && \
    make -j$THREADS $BASE/freedom-u-sdk/work/riscv-fesvr/prefix/lib/libfesvr.so && \
    make -j$THREADS $BASE/freedom-u-sdk/work/riscv-isa-sim/prefix/bin/spike && \
    mv work/riscv-isa-sim/prefix $BASE/riscv-isa-sim && \
    mv work/riscv-fesvr/prefix $BASE/riscv-fesvr && \
    \rm -rf work/riscv-isa-sim && \
    \rm -rf work/riscv-fesvr

ENV PATH "${BASE}/rv64imafd-lp64d/bin:${BASE}/elf-rv64ima-lp64/bin:${BASE}/riscv-isa-sim/bin:${OLDPATH}"

ENV LD_LIBRARY_PATH "${BASE}/riscv-isa-sim/lib:${BASE}/riscv-fesvr/lib"

USER root

WORKDIR $BASE

CMD ["/bin/bash", "-l"]
