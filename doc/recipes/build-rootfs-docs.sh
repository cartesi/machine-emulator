#!/bin/sh
set -eu

# Cross-compile the dapp and assemble the rootfs as a flattened tarball.
docker buildx build --platform=linux/riscv64 \
    --output type=tar,dest=rootfs-docs.tar \
    -f Dockerfile.rootfs-docs .

# Convert the tarball into an ext2 image.
xgenext2fs -fzB 4096 -i 4096 -r +4000 \
    -a rootfs-docs.tar -L docs rootfs-docs.ext2
rm -f rootfs-docs.tar

# docs:begin null
# Embed the recipe-input fingerprint, used to detect a stale image.
e2cp rootfs-docs.inputs.sha256 rootfs-docs.ext2:/var/log/rootfs-docs.inputs.sha256
# docs:end null
