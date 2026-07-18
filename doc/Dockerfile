ARG TAG=0.20.0
ARG MACHINE_GUEST_TOOLS_TAG
ARG MACHINE_LINUX_IMAGE_TAG
ARG MACHINE_LINUX_IMAGE_FILENAME
ARG MACHINE_LINUX_IMAGE_SHA256
ARG GENEXT2FS_VERSION=v1.5.6
# Base for the host-tool builder stages below. These stages compile binaries
# that are copied into the final emulator-based image, so the base must stay
# ABI-compatible with cartesi/machine-emulator:$TAG. It deliberately does NOT
# reference $TAG, so bumping the emulator image reuses the builders' cache.
# The Makefile overrides this with the emulator image's own base, read from its
# io.cartesi.machine-emulator.base-image label, so it tracks automatically if
# the emulator rebases.
ARG BUILDER_BASE=debian:trixie-20250811-slim

FROM $BUILDER_BASE AS hex-builder
ARG MACHINE_GUEST_TOOLS_TAG
USER root
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends g++ wget ca-certificates && \
    wget -qO- https://github.com/cartesi/machine-guest-tools/archive/refs/tags/$MACHINE_GUEST_TOOLS_TAG.tar.gz \
        | tar -xz -C /tmp --wildcards --strip-components=3 '*/sys-utils/hex/hex.cpp' && \
    g++ -O2 -o /usr/local/bin/hex /tmp/hex.cpp

FROM $BUILDER_BASE AS xgenext2fs-builder
ARG GENEXT2FS_VERSION
USER root
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y --no-install-recommends \
        automake autotools-dev build-essential libarchive-dev wget ca-certificates && \
    wget -qO- https://github.com/cartesi/genext2fs/archive/refs/tags/$GENEXT2FS_VERSION.tar.gz \
        | tar -xz -C /tmp && \
    cd /tmp/genext2fs-* && \
    ./autogen.sh && \
    ./configure --enable-libarchive --prefix=/usr/local && \
    make -j"$(nproc)" install

FROM scratch AS linux-image
ARG MACHINE_LINUX_IMAGE_TAG
ARG MACHINE_LINUX_IMAGE_FILENAME
ARG MACHINE_LINUX_IMAGE_SHA256
ADD --checksum=sha256:${MACHINE_LINUX_IMAGE_SHA256} --chmod=0644 \
    https://github.com/cartesi/machine-linux-image/releases/download/${MACHINE_LINUX_IMAGE_TAG}/${MACHINE_LINUX_IMAGE_FILENAME} \
    /linux.bin

FROM cartesi/machine-emulator:$TAG

USER root

RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get install -y \
        make pandoc \
        bash-completion bc devio device-tree-compiler e2tools file graphviz jq libarchive13 lua-dkjson lua-socket net-tools wget && \
    rm -rf /var/lib/apt/lists/*

# Snapshot cartesi-machine's bash completion into the canonical dir, then enable
# the framework loader by uncommenting the block Debian ships (disabled) in
# /etc/bash.bashrc. The package's /etc/profile.d snippet only covers login
# shells; the playground runs a non-login shell, which reads only bash.bashrc.
# With the loader active, the file lazy-loads on first `cartesi-machine <TAB>`.
RUN cartesi-machine --bash-completion > /usr/share/bash-completion/completions/cartesi-machine && \
    sed -i '/^#if ! shopt -oq posix; then/,/^#fi$/ s/^#//' /etc/bash.bashrc

COPY --from=hex-builder /usr/local/bin/hex /usr/local/bin/hex
COPY --from=xgenext2fs-builder /usr/local/bin/xgenext2fs /usr/local/bin/xgenext2fs

COPY --from=linux-image /linux.bin /usr/share/cartesi-machine/images/linux.bin
COPY recipes/rootfs-docs.ext2 /usr/share/cartesi-machine/images/rootfs-docs.ext2
RUN ln -s rootfs-docs.ext2 /usr/share/cartesi-machine/images/rootfs.ext2

ENV DEV_ENV_HAS_DOCGEN=yes
ENV PATH=/work/recipes:${PATH}

# Run as the host user: the entrypoint (carried dormant by the emulator image)
# reads the USER/UID/GID/GROUP env that run-docs-image / docs-image-exec pass
# and gosu-drops to it, so files written under /work are owned by the host user.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
