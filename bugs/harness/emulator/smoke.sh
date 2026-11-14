#!/bin/bash
# Smoke check of the in-tree emulator and the pinned images: boots Linux with the machine-guest-tools rootfs
# and runs a command; checks the cartesi Lua module and the jsonrpc server start.
set -euo pipefail
. "$(dirname "$0")/../../env.sh"
out=$($CARTESI_MACHINE --quiet -- 'echo harness-smoke-$((6*7))' 2>&1)
grep -q 'harness-smoke-42' <<< "$out" || { echo "$out" >&2; exit 1; }
lua5.4 -e 'local c = require("cartesi"); assert(#c.UARCH_PRISTINE_STATE_HASH == 32)'
# remote machine through the jsonrpc server
lua5.4 - << 'LUA'
local jsonrpc = require("cartesi.jsonrpc")
local m = jsonrpc.spawn_server()
local cfg = { ram = { length = 1 << 20 }, processor = { registers = {} } }
m:create(cfg)
assert(m:read_reg("mcycle") == 0)
m:shutdown_server()
LUA
echo "emulator smoke ok"
