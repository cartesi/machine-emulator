#!/bin/bash
# Smoke check of the ASan+UBSan build: the Lua module resolves to the sanitizer build and libcartesi is
# instrumented; then the bare-metal smoke, a Linux boot and a jsonrpc remote machine run under the sanitizers.
set -euo pipefail
export HARNESS_SANITIZE=1
. "$(dirname "$0")/../../env.sh"
san_lua -e 'local p = package.searchpath("cartesi", package.cpath); assert(p:find("/sanitizer/"), p); print(p)'
syms=$(nm -D "$SANITIZER_SRC/libcartesi.so")
grep -q __asan_report <<< "$syms" || { echo "libcartesi not instrumented" >&2; exit 1; }
san_lua "$HARNESS/baremetal/smoke.lua"
out=$(eval "$CARTESI_MACHINE --quiet -- 'echo san-ok'" 2>&1)
grep -q san-ok <<< "$out" || { echo "$out" >&2; exit 1; }
san_lua - << 'LUA'
local jsonrpc = require("cartesi.jsonrpc")
local m = jsonrpc.spawn_server()
m:create({ ram = { length = 1 << 20 } })
assert(m:read_reg("mcycle") == 0)
m:run(1000)
m:shutdown_server()
LUA
echo "sanitizer smoke ok"
