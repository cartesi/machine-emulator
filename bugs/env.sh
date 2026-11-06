#!/bin/bash
# Environment for the audit tests under bugs/. Source it from the repository root or from anywhere.
# It points Lua at the in-tree build (make -j at the repository root) and at the PRT recipes.
BUGS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$BUGS_DIR")"
export BUGS_DIR REPO_DIR
export LUA_PATH_5_4="$BUGS_DIR/?.lua;$REPO_DIR/src/?.lua;$REPO_DIR/doc/recipes/?.lua;;"
export LUA_CPATH_5_4="$REPO_DIR/src/?.so;;"
export PATH="$REPO_DIR/src:$PATH"
# Pinned kernel and machine-guest-tools rootfs (dependencies.lock). Override to use other copies.
export CARTESI_IMAGES_PATH="${CARTESI_IMAGES_PATH:-/home/user/images}"
# Pinned external components (AUDIT.md).
export MACHINE_SOLIDITY_STEP_DIR="${MACHINE_SOLIDITY_STEP_DIR:-/home/user/ext/machine-solidity-step}"
export MACHINE_GUEST_TOOLS_DIR="${MACHINE_GUEST_TOOLS_DIR:-/home/user/ext/machine-guest-tools}"
