# Copyright Cartesi and individual authors (see AUTHORS)
# SPDX-License-Identifier: Apache-2.0
#
# Canonical build for the SP1 guest.
#
# `cargo prove build --docker` covers Rust guests only, so the pins here are
# ours. Everything that can influence the output bytes is fixed: the platform,
# the base image by digest, the toolchain and SDK tarballs by sha256, and lld by
# package version.
#
# The guest's vkey hash is what a verifier contract pins, so a toolchain change
# is a consensus change. The tarballs are pinned by content rather than by
# release tag because tags are mutable.
#
# Build:  docker build -f sp1/cpp/Dockerfile -t cartesi-sp1-guest .
# Output: docker run --rm cartesi-sp1-guest cat /out/guest.elf > guest.elf

# One platform on purpose: a canonical build everyone can reproduce, rather than
# a per-host build that happens to agree.
FROM --platform=linux/amd64 ubuntu:24.04@sha256:a08e551cb33850e4740772b38217fc1796a66da2506d312abe51acda354ff061

ARG SP1_CPP_TOOLCHAIN_TAG=2026.02.13
ARG SP1_CPP_TOOLCHAIN_SHA256=7294ee279f52a75b0ad669fff60277d52e520b2b5fd7065c8264ac1ad93c1334
ARG SP1_ZKEVM_SDK_VERSION=v6.3.1
ARG SP1_ZKEVM_SDK_SHA256=ef9124009aa88a5039f003bda51fc5210888cc6aa878320aac04666a3389bfb8
# The linker decides segment layout, so its version is part of the output.
ARG LLD_VERSION=1:18.0-59~exp2

# libmpc3/libmpfr6/libgmp10 are cc1plus runtime dependencies: the toolchain
# tarball links them dynamically and ships without them.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl make xz-utils \
        "lld=${LLD_VERSION}" \
        libmpc3 libmpfr6 libgmp10 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/.sp1 && cd /root/.sp1 && \
    curl -sSL -o toolchain.tar.gz \
      "https://github.com/succinctlabs/riscv-gnu-toolchain/releases/download/${SP1_CPP_TOOLCHAIN_TAG}/riscv64im-linux-amd64.tar.gz" && \
    echo "${SP1_CPP_TOOLCHAIN_SHA256}  toolchain.tar.gz" | sha256sum -c - && \
    mkdir -p "riscv64im-${SP1_CPP_TOOLCHAIN_TAG}" && \
    tar xzf toolchain.tar.gz -C "riscv64im-${SP1_CPP_TOOLCHAIN_TAG}" --strip-components=1 && \
    rm toolchain.tar.gz

RUN cd /root/.sp1 && \
    curl -sSL -o zkevm-sdk.tar.gz \
      "https://github.com/succinctlabs/sp1/releases/download/${SP1_ZKEVM_SDK_VERSION}/zkevm-sdk-${SP1_ZKEVM_SDK_VERSION}.tar.gz" && \
    echo "${SP1_ZKEVM_SDK_SHA256}  zkevm-sdk.tar.gz" | sha256sum -c - && \
    mkdir -p "zkevm-sdk-${SP1_ZKEVM_SDK_VERSION}" && \
    tar xzf zkevm-sdk.tar.gz -C "zkevm-sdk-${SP1_ZKEVM_SDK_VERSION}" --strip-components=1 && \
    rm zkevm-sdk.tar.gz

WORKDIR /build
COPY src/ src/
COPY tools/ tools/
COPY third-party/ third-party/
COPY sp1/cpp/ sp1/cpp/

# The generated headers are deterministic output of the checked-in generators,
# but they are produced by the host build, so they come in with the source
# rather than being regenerated here.
RUN test -f src/interpret-jump-table.hpp || \
      (echo "src/interpret-jump-table.hpp missing; run make -C .. src/interpret-jump-table.hpp first" >&2; exit 1)

RUN make -C sp1/cpp clean >/dev/null 2>&1 || true
RUN make -C sp1/cpp && mkdir -p /out && cp sp1/cpp/guest.elf /out/guest.elf

# A PT_NOTE segment would be parsed into the program's untrusted memory and so
# would change the vkey; the guest is not expected to have one.
RUN PREFIX=$(echo /root/.sp1/riscv64im-*/bin/riscv64-unknown-elf-) && \
    if "${PREFIX}readelf" -l /out/guest.elf | grep -q '\bNOTE\b'; then \
      echo "guest has a PT_NOTE segment; it feeds the vkey and must be accounted for" >&2; \
      exit 1; \
    fi && \
    echo "guest.elf sha256: $(sha256sum /out/guest.elf)"
