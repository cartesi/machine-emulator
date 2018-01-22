FROM diegonehab/themis:gcc

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

# Build riscv's kernel, bootloader, rootfs, and  qemu
# ----------------------------------------------------
RUN \
    apt-get update && \
    apt-get install -y python libglib2.0-dev libssl-dev cpio

# Copy and apply our patches
# ----------------------------------------------------
COPY linux_defconfig $BASE/freedom-u-sdk/conf
COPY riscv-pk.patch $BASE/freedom-u-sdk/riscv-pk
COPY riscv-qemu.patch $BASE/freedom-u-sdk/riscv-qemu
COPY Makefile.patch $BASE/freedom-u-sdk

RUN \
    cd $BASE/freedom-u-sdk && \
    patch -p1 < Makefile.patch && \
    cd riscv-pk && \
    patch -p1 < riscv-pk.patch && \
    cd ../riscv-qemu && \
    patch -p1 < riscv-qemu.patch

# Build kernel
# ----------------------------------------------------
RUN \
    cd $BASE/freedom-u-sdk && \
    ABI=lp64 ISA=rv64ima make -j$THREADS $BASE/freedom-u-sdk/work/linux/vmlinux

# Build bootloader linked with kernel
# ----------------------------------------------------
RUN \
    cd $BASE/freedom-u-sdk && \
    ABI=lp64 ISA=rv64ima make -j$THREADS $BASE/freedom-u-sdk/work/bbl.bin

# Build qemu
# ----------------------------------------------------
RUN \
    cd $BASE/freedom-u-sdk && \
    make -j$THREADS $BASE/freedom-u-sdk/work/riscv-qemu/prefix/bin/qemu-system-riscv64

# Build rootfs
# ----------------------------------------------------
COPY buildroot_rootfs_config $BASE/freedom-u-sdk/conf
COPY buildroot-lua.patch $BASE/freedom-u-sdk/buildroot
COPY skel $BASE/freedom-u-sdk/buildroot/skel

RUN \
    cd $BASE/freedom-u-sdk/buildroot && \
    patch -p1 < buildroot-lua.patch && \
    cd .. && \
    make -j$THREADS $BASE/freedom-u-sdk/work/rootfs.bin

