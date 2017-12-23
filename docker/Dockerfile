FROM ubuntu:16.04

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

ENV RISCV=/opt/riscv

# Base system and user so we can do stuff
RUN \
    apt-get update && \
    apt-get install -y apt-utils && \
    apt-get install -y vim wget curl sudo && \
    apt-get install -y zip unzip && \
    mkdir -p $RISCV && \
    adduser themis --gecos "" --disabled-password && \
    adduser themis sudo && \
    echo themis:themis | chpasswd

# Development basics
RUN \
    apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y autoconf automake libtool autotools-dev && \
    apt-get install -y git make pkg-config patchutils gawk bison flex

# Obtain sources to gcc (delete git history to save space)
RUN \
    cd $RISCV && \
    git clone https://github.com/riscv/riscv-gnu-toolchain.git && \
    cd riscv-gnu-toolchain && \
    git reset --hard dcda255e1f3d114e8d12b23c80b80382b51109d6 && \
    git submodule update --init --recursive && \
    find $RISCV -name ".git" -print0 | xargs -0 rm -rf

# Build riscv's gcc (delete source to save space)
ENV THREADS=24

RUN \
    apt-get update && \
    apt-get install -y device-tree-compiler libmpc-dev libmpfr-dev && \
    apt-get install -y libgmp-dev libusb-1.0-0-dev texinfo gperf bc && \
    apt-get install -y zlib1g-dev libncurses-dev libexpat-dev

RUN \
    cd $RISCV/riscv-gnu-toolchain && \
    ./configure --prefix=$RISCV --with-arch=rv64imafd --with-abi=lp64d && \
    make -j$THREADS linux && \
    rm -rf $RISCV/riscv-gnu-toolchain

ENV PATH "${RISCV}/bin:${PATH}"

# Build the linux kernel
ADD diskimage-linux-riscv-2017-08-06.tar.gz $RISCV
ADD riscv-linux-48ec1f0914a9203d2935d94912d3b6742144209e.tar.gz $RISCV

RUN \
    cd $RISCV/riscv-linux-48ec1f0914a9203d2935d94912d3b6742144209e && \
    patch -p1 < $RISCV/diskimage-linux-riscv-2017-08-06/patches/riscv-linux.diff && \
    cp $RISCV/diskimage-linux-riscv-2017-08-06/patches/config_linux_riscv64 .config && \
    sed -i "s/riscv32-unknown-linux-gnu/riscv64-unknown-linux-gnu/g" .config && \
    sed -i "s/CONFIG_ISA_C=y/# CONFIG_ISA_C is not set/g" .config && \
    make -j$THREADS ARCH=riscv vmlinux

# Build bootloader linked with kernel
COPY riscv-pk.patch $RISCV

RUN \
    cd $RISCV && \
    git clone https://github.com/riscv/riscv-pk.git && \
    cd riscv-pk && \
    git reset --hard 18087efa98d77918d55127c3d7745cd6d6d9d77b && \
    patch -p0 < $RISCV/diskimage-linux-riscv-2017-08-06/patches/riscv-pk.diff && \
    patch -p1 < $RISCV/riscv-pk.patch && \
    mkdir build  && cd build && \
    ../configure --with-payload=$RISCV/riscv-linux-48ec1f0914a9203d2935d94912d3b6742144209e/vmlinux --host=riscv64-unknown-linux-gnu && \
    CFLAGS="-march=rv64ima -mabi=lp64" make -j$THREADS bbl && \
    riscv64-unknown-linux-gnu-objcopy -O binary bbl $RISCV/kernel.bin

# remove kernel and bootloader sources
RUN \
    rm -rf $RISCV/riscv-pk && \
    rm -rf $RISCV/diskimage-linux-riscv-2017-08-06 && \
    rm -rf $RISCV/riscv-linux-48ec1f0914a9203d2935d94912d3b6742144209e

# Make root filesystem for riscv
RUN \
    apt-get update && \
    apt-get install -y genext2fs

COPY skel $RISCV/root

# Copy gcc support files
RUN \
    cd $RISCV/root && \
    cp $RISCV/sysroot/lib/libm-2.24.90.so lib && \
    cp $RISCV/sysroot/lib/ld-2.24.90.so lib && \
    cp $RISCV/sysroot/lib/libc-2.24.90.so lib && \
    ln -s libm-2.24.90.so lib/libm.so.6 && \
    ln -s ld-2.24.90.so lib/ld-linux-riscv64-lp64d.so.1 && \
    ln -s libc-2.24.90.so lib/libc.so.6

# Build lua and add it to root
COPY lua-5.3.4.patch $RISCV

RUN \
    cd $RISCV && \
    curl http://www.lua.org/ftp/lua-5.3.4.tar.gz | tar -xz && \
    cd lua-5.3.4 && \
    patch -p1 < $RISCV/lua-5.3.4.patch && \
    make -j$THREADS rv64 && \
    cp src/lua $RISCV/root/usr/bin && \
    cd .. && \
    rm -rf lua-5.3.4

# Build busybox and add it to root
COPY busybox-1.27.config $RISCV

RUN \
    cd $RISCV && \
    curl -L https://busybox.net/downloads/busybox-1.27.2.tar.bz2 | tar -xj && \
    cd busybox-1.27.2 && \
    cp $RISCV/busybox-1.27.config .config && \
    make -j$THREADS && \
    cp $RISCV/busybox-1.27.2/busybox $RISCV/root/bin && \
    cd .. && \
    rm -rf busybox-1.27.2

# build riscvemu without floating-point or compressed instruction support
RUN \
    apt-get update && \
    apt-get install -y libssl-dev libcurl4-openssl-dev

ADD riscvemu-2017-08-06.tar.gz $RISCV

COPY \
    riscvemu-2017-08-06.patch \
    riscvemu.cfg \
    $RISCV/

# Build emulator ----------------------------------------------------

RUN \
    cd $RISCV/riscvemu-2017-08-06 && \
    patch < $RISCV/riscvemu-2017-08-06.patch && \
    make -j$THREADS && \
    cp riscvemu64 $RISCV/bin

# Build ext2 filesystem containing root
RUN \
    cd $RISCV && \
    genext2fs -i 4096 -b 65536 -d root root.bin

USER themis

WORKDIR $RISCV

CMD ["/bin/bash", "-l"]
