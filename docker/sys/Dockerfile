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

# Build qemu using host's compiler
# ----------------------------------------------------
RUN \
    cd $BASE/freedom-u-sdk && \
    make -j$THREADS $BASE/freedom-u-sdk/work/riscv-qemu/prefix/bin/qemu-system-riscv64 && \
    mv work/riscv-qemu/prefix $BASE/riscv-qemu && \
    \rm -rf work/riscv-qemu

# Build rootfs with ABI lp64d and ISA rv64g
# ----------------------------------------------------
ENV ISA "rv64imafd"
ENV ABI "lp64d"
ENV RISCV "$BASE/$ISA-$ABI"
ENV PATH "$RISCV/bin:${OLDPATH}"

COPY buildroot_rootfs_config $BASE/freedom-u-sdk/conf
COPY buildroot-lua.patch $BASE/freedom-u-sdk/buildroot
COPY skel $BASE/freedom-u-sdk/buildroot/skel

RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        rsync && \
    rm -rf /var/lib/apt/lists/*

RUN \
    cd $BASE/freedom-u-sdk/buildroot && \
    patch -p1 < buildroot-lua.patch && \
    cd .. && \
    make -j$THREADS $BASE/freedom-u-sdk/work/rootfs.bin && \
    cp work/rootfs.bin $BASE/rootfs.bin && \
    \rm -rf work

USER root

WORKDIR $BASE

CMD ["/bin/bash", "-l"]
