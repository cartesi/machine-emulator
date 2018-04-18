FROM diegonehab/cartesi:sys

MAINTAINER Diego Nehab <diego.nehab@gmail.com>

ENV DEBIAN_FRONTEND=noninteractive

ENV THREADS=24

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
