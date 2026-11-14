#!/bin/bash
# Ready machine configurations under bugs/harness/work/configs/<name>/:
#
#   baremetal-minimal/         config.lua (ram 64 MiB = accept.bin bare-metal guest), machine/ stored at mcycle 0
#   baremetal-template/        config.lua (emit-output.bin guest), machine/ = valid-template-style machine: run to
#                              its first manual yield (rx-accepted, empty outputs root in the tx buffer), stored
#                              with its hash tree; root-hash.txt
#   linux-rootfs/              config.lua (linux.bin + machine-guest-tools rootfs.ext2, default bootargs, init
#                              runs the `cartesi-init` of the rootfs), machine/ stored at mcycle 0
#   valid-template/            Linux + guest-tools rootfs running an echo rollup app (see app.sh): stored by
#                              `cartesi-machine --assert-rolling-template --final-hash --store`, so it waits at a
#                              manual yield with the accepted reason and the empty outputs root; root-hash.txt
#   valid-template-calc/       the doc/recipes rolling calculator template (game-test-fixtures.sh), on the
#                              machine-guest-tools rootfs; input-*.bin advance inputs from the same fixture script
#
# All are reproducible machines (no unreproducible mode) with the default keccak256 hash tree.
# Idempotent: an existing configuration is kept unless --force is given.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
. "$HERE/../lib/common.sh"
. "$REPO/bugs/env.sh"

FORCE=no
[ "${1:-}" = --force ] && FORCE=yes
OUT="$WORK/configs"
mkdir -p "$OUT"

[ -f "$WORK/baremetal/accept.bin" ] || "$HARNESS/baremetal/build.sh"
[ -f "$LINUX_IMAGE" ] && [ -f "$ROOTFS_IMAGE" ] || "$HARNESS/emulator/fetch-images.sh"

need() { # need <name>: true if the config must be (re)built
    if [ "$FORCE" = yes ] || [ ! -f "$OUT/$1/.done" ]; then
        rm -rf "${OUT:?}/$1"
        mkdir -p "$OUT/$1"
        return 0
    fi
    log "config $1 exists"
    return 1
}

# Bare-metal configurations (Lua API)
for spec in baremetal-minimal:accept:0 baremetal-template:emit-output:1; do
    IFS=: read -r name bin run <<< "$spec"
    if need "$name"; then
        cp "$WORK/baremetal/$bin.bin" "$OUT/$name/guest.bin"
        lua5.4 - "$OUT/$name" "$run" << 'LUA'
local cartesi = require("cartesi")
local dir, run = arg[1], arg[2] == "1"
local cfg_text = string.format([[
-- bare-metal machine configuration (bugs/harness/configs/make-configs.sh)
return {
    ram = { length = 64 << 20, backing_store = { data_filename = %q } },
}
]], dir .. "/guest.bin")
local f = assert(io.open(dir .. "/config.lua", "w"))
f:write(cfg_text)
f:close()
local cfg = load(cfg_text)()
local m <close> = cartesi.machine(cfg)
if run then
    assert(m:run(math.maxinteger) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    local v = m:read_reg("htif_tohost")
    assert((v >> 32) & 0xffff == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
end
m:store(dir .. "/machine")
local h = io.open(dir .. "/root-hash.txt", "w")
h:write(cartesi.tohex(m:get_root_hash()), "\n")
h:close()
LUA
        touch "$OUT/$name/.done"
        log "config $name ok"
    fi
done

# Linux + guest-tools rootfs: configuration only (machine at mcycle 0)
if need linux-rootfs; then
    $CARTESI_MACHINE --no-init-splash --max-mcycle=0 --store-config="$OUT/linux-rootfs/config.lua" \
        --store="$OUT/linux-rootfs/machine" > "$OUT/linux-rootfs/log.txt" 2>&1
    lua5.4 "$HERE/root-hash.lua" "$OUT/linux-rootfs/machine" > "$OUT/linux-rootfs/root-hash.txt"
    touch "$OUT/linux-rootfs/.done"
    log "config linux-rootfs ok"
fi

# Valid template: echo app on the guest-tools rootfs.
if need valid-template; then
    cat > "$OUT/valid-template/app.sh" << 'EOF'
# Echo rollup app: each advance-state payload is emitted back as a notice and a report, then accepted;
# a payload equal to "reject" (0x72656a656374) is rejected; inspect-state queries get the query as a report.
s=accept
while :; do
    rollup "$s" > /tmp/req || exit 1
    s=accept
    t=$(jq -r .request_type /tmp/req)
    p=$(jq -r .data.payload /tmp/req)
    if [ "$p" = 0x72656a656374 ]; then s=reject; continue; fi
    if [ "$t" = advance_state ]; then
        jq '{payload: .data.payload}' /tmp/req | rollup notice > /dev/null
    fi
    jq '{payload: .data.payload}' /tmp/req | rollup report > /dev/null
done
EOF
    mkdir -p "$OUT/valid-template/app"
    cp "$OUT/valid-template/app.sh" "$OUT/valid-template/app/app.sh"
    tar --sort=name --mtime=2022-01-01 --owner=1000 --group=1000 --numeric-owner -cf "$OUT/valid-template/app.tar" \
        -C "$OUT/valid-template/app" .
    rm -rf "$OUT/valid-template/app"
    # flash drive with the app, made like doc/recipes/game-test-fixtures.sh does (reproducible)
    command -v xgenext2fs > /dev/null || "$HARNESS/emulator/build-xgenext2fs.sh" > /dev/null
    PATH="$WORK/bin:$PATH" xgenext2fs -fzB 4096 -i 4096 -a "$OUT/valid-template/app.tar" "$OUT/valid-template/app.ext2"
    rm -f "$OUT/valid-template/app.tar"
    $CARTESI_MACHINE --no-init-splash --assert-rolling-template --final-hash \
        --flash-drive=label:app,data_filename:"$OUT/valid-template/app.ext2",user:dapp \
        --store-config="$OUT/valid-template/config.lua" \
        --store="$OUT/valid-template/machine" -- 'sh /mnt/app/app.sh' > "$OUT/valid-template/log.txt" 2>&1 || {
        tail "$OUT/valid-template/log.txt" >&2
        die "valid-template creation failed"
    }
    lua5.4 "$HERE/root-hash.lua" "$OUT/valid-template/machine" > "$OUT/valid-template/root-hash.txt"
    touch "$OUT/valid-template/.done"
    log "config valid-template ok: $(cat "$OUT/valid-template/root-hash.txt")"
fi

# The doc/recipes rolling calculator template, on the guest-tools rootfs.
if need valid-template-calc; then
    command -v xgenext2fs > /dev/null || "$HARNESS/emulator/build-xgenext2fs.sh"
    (
        cd "$OUT/valid-template-calc"
        export PATH="$WORK/bin:$PATH"
        ln -sf "$REPO/src/cartesi-machine.lua" "$WORK/bin/cartesi-machine"
        ln -sf "$REPO/doc/recipes/cartesi-rollup-data.lua" "$WORK/bin/cartesi-rollup-data.lua"
        RECIPES_DIR="$REPO/doc/recipes" bash "$REPO/doc/recipes/game-test-fixtures.sh"
    ) > "$OUT/valid-template-calc/log.txt" 2>&1 || {
        tail "$OUT/valid-template-calc/log.txt" >&2
        die "valid-template-calc creation failed"
    }
    touch "$OUT/valid-template-calc/.done"
    log "config valid-template-calc ok: $(cat "$OUT/valid-template-calc/initial-hash")"
fi
ls "$OUT"
