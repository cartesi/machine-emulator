#!/bin/bash
# Install the EVM tool chain into bugs/harness/work/foundry/bin (on PATH after `. bugs/env.sh`):
#   forge, cast, anvil  Foundry v1.5.1, copied out of ghcr.io/foundry-rs/foundry:v1.5.1 pinned by digest (the
#                       same image doc/Dockerfile.prt uses); fallback: the GitHub release tarball, sha256-pinned
#   just 1.57.0         (the version doc/Dockerfile.prt pins, same sha256)
#   solc 0.8.30         fetched by forge itself (svm, binaries.soliditylang.org) on first use
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
BIN="$WORK/foundry/bin"
mkdir -p "$BIN"
FOUNDRY_IMAGE=ghcr.io/foundry-rs/foundry:v1.5.1@sha256:3a70bfa9bd2c732a767bb60d12c8770b40e8f9b6cca28efc4b12b1be81c7f28e
FOUNDRY_TARBALL_SHA256=73640b01bd9ed29fdb4965085099371f8cf0dbbec3e2086cf54564efc4dcfe88
JUST_SHA256=45b548094283cb9739af8f13273b8cddeee869f5b4ef2bb631b1f311cb566155

if ! { [ -x "$BIN/forge" ] && "$BIN/forge" --version | grep -q 'v1.5.1'; }; then
    if ensure_docker && docker pull -q "$FOUNDRY_IMAGE" > /dev/null; then
        cid=$(docker create "$FOUNDRY_IMAGE")
        for t in forge cast anvil chisel; do docker cp "$cid:/usr/local/bin/$t" "$BIN/$t" > /dev/null; done
        docker rm "$cid" > /dev/null
        log "foundry from $FOUNDRY_IMAGE"
    else
        d="$WORK/dl-foundry"
        rm -rf "$d"
        mkdir -p "$d"
        curl -sSfL -o "$d/foundry.tar.gz" \
            "https://github.com/foundry-rs/foundry/releases/download/$FOUNDRY_VERSION/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz"
        verify_sha256 "$d/foundry.tar.gz" "$FOUNDRY_TARBALL_SHA256" || die "foundry tarball checksum"
        tar -xzf "$d/foundry.tar.gz" -C "$d"
        mv "$d"/{forge,cast,anvil,chisel} "$BIN/"
        rm -rf "$d"
        log "foundry from the release tarball"
    fi
fi
"$BIN/forge" --version | head -1

if ! [ -x "$BIN/just" ]; then
    d="$WORK/dl-just"
    rm -rf "$d"
    mkdir -p "$d"
    curl -sSfL -o "$d/just.tar.gz" \
        "https://github.com/casey/just/releases/download/$JUST_VERSION/just-$JUST_VERSION-x86_64-unknown-linux-musl.tar.gz"
    verify_sha256 "$d/just.tar.gz" "$JUST_SHA256" || die "just checksum"
    tar -xzf "$d/just.tar.gz" -C "$d" just
    mv "$d/just" "$BIN/just"
    rm -rf "$d"
fi
"$BIN/just" --version
