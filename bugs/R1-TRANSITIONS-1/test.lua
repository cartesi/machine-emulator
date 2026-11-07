-- R1-TRANSITIONS-1: the reset leaf reported by collect_uarch_cycle_root_hashes must equal the hash of the canonical
-- uarch reset (machine::reset_uarch / log_reset_uarch + verify_reset_uarch, and UArchReset.sol on-chain), R2 and the
-- section 2 transition form "uarch step followed by the uarch reset".
-- collect_uarch_cycle_root_hashes does not call reset_uarch(): its fast reset (src/machine.cpp ~2887-2914) clears the
-- uarch registers and restores only the uarch-RAM words the uarch wrote during the mcycle. It never checks that the
-- rest of uarch RAM is pristine, while every canonical reset rewrites the whole uarch RAM with the pristine image.
-- The test creates two identical machines whose uarch RAM is pristine except 8 bytes at offset 0x170000 (supplied as
-- uarch.ram.backing_store, generated at test time). Machine A runs one mcycle through collect_uarch_cycle_root_hashes;
-- machine B runs the same mcycle with run_uarch, then log_reset_uarch + verify_reset_uarch. Both the last hash
-- (reset leaf) and the final root hashes must agree. A control with a pristine (zero-extended) image must agree too.
-- NOTE: the before-state is not reachable from a valid template (uarch not pristine; R8 forbids guest writes to uarch
-- RAM), so this is a divergence between paths at an unreachable state (section 8: High at most).
local cartesi = require("cartesi")

local function tohex(h)
    return (h:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local REPO = os.getenv("REPO_DIR") or "../.."
local f = assert(io.open(REPO .. "/uarch/uarch-ram.bin", "rb"))
local pristine = f:read("a")
f:close()

-- uarch RAM image: pristine program zero-extended to 0x180000 bytes, optionally with 8 nonzero bytes at 0x170000
local IMAGE_LEN = 0x180000
local DIRTY_OFFSET = 0x170000
assert(#pristine < DIRTY_OFFSET, "pristine uarch image unexpectedly large")
local function make_image(path, dirty)
    local img = pristine .. string.rep("\0", IMAGE_LEN - #pristine)
    if dirty then
        img = img:sub(1, DIRTY_OFFSET) .. "\x01\x02\x03\x04\x05\x06\x07\x08" .. img:sub(DIRTY_OFFSET + 9)
    end
    assert(#img == IMAGE_LEN)
    local o = assert(io.open(path, "wb"))
    o:write(img)
    o:close()
end

local function make_machine(image_path)
    local m = cartesi.machine({
        ram = { length = 0x10000 },
        uarch = { ram = { backing_store = { data_filename = image_path } } },
    })
    -- bare-metal guest at the RAM start: the infinite loop "j ." (0x0000006f)
    m:write_memory(0x80000000, string.pack("<I4", 0x0000006f))
    return m
end

local ZERO = string.rep("\0", cartesi.HASH_SIZE)

local function compare(dirty)
    local path = os.tmpname()
    make_image(path, dirty)
    local a <close> = make_machine(path)
    local b <close> = make_machine(path)
    os.remove(path)
    assert(a:get_root_hash() == b:get_root_hash(), "harness error: machines differ before the mcycle")
    local mcycle = a:read_reg("mcycle")

    -- Path A: computation-hash builder with its fast reset
    local collected = a:collect_uarch_cycle_root_hashes(mcycle + 1, 0, { ZERO, ZERO })
    local collect_reset = collected.hashes[#collected.hashes]
    local a_after = a:get_root_hash()

    -- Path B: uarch run, then the logged canonical reset verified by the replay verifier
    b:run_uarch(cartesi.UARCH_CYCLE_MAX)
    assert(b:read_reg("uarch_halt") ~= 0, "harness error: uarch did not halt")
    local before = b:get_root_hash()
    local log = b:log_reset_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
    local verified = b:verify_reset_uarch(before, log)
    local b_after = b:get_root_hash()
    assert(verified == b_after, "harness error: verify_reset_uarch disagrees with log_reset_uarch")
    assert(a:read_reg("mcycle") == b:read_reg("mcycle"), "harness error: mcycle differs")
    return collect_reset, verified, a_after, b_after
end

-- Control: pristine (zero-extended) uarch RAM image, paths must agree
local c1, c2, c3, c4 = compare(false)
if c1 ~= c2 or c3 ~= c4 then
    print("harness error: control with pristine uarch image already disagrees: " .. tohex(c1) .. " vs " .. tohex(c2))
    os.exit(2)
end
print("control (pristine uarch RAM): reset leaf " .. tohex(c1) .. " on both paths")

local r1, r2, r3, r4 = compare(true)
print("non-pristine uarch RAM: collect_uarch_cycle_root_hashes reset leaf " .. tohex(r1))
print("non-pristine uarch RAM: log_reset_uarch + verify_reset_uarch     " .. tohex(r2))
if r1 ~= r2 or r3 ~= r4 then
    print("R1-TRANSITIONS-1 FAIL: collect_uarch_cycle_root_hashes fast reset restores only uarch-RAM words dirtied "
        .. "in the mcycle, so with non-pristine uarch RAM its reset leaf (and resulting state) differs from the "
        .. "canonical uarch reset verified by verify_reset_uarch/UArchReset.sol")
    os.exit(1)
end
print("R1-TRANSITIONS-1 OK: reset leaf and post-reset state agree with the canonical uarch reset")
os.exit(0)
