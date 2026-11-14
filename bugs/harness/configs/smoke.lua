-- Smoke test of the ready configurations (bugs/harness/work/configs). lua5.4 configs/smoke.lua
local cartesi = require("cartesi")
local harness = require("harness")

local function load(name)
    return cartesi.machine(harness.config_dir(name) .. "/machine", {})
end

local function expect_accepted(m)
    assert(m:read_reg("iflags_Y") ~= 0, "not at a manual yield")
    local v = m:read_reg("htif_tohost")
    assert((v >> 32) & 0xffff == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "not accepted")
end

-- stored hashes match recorded root-hash.txt
for _, name in ipairs({ "baremetal-minimal", "baremetal-template", "linux-rootfs", "valid-template" }) do
    local m <close> = load(name)
    local want = harness.read_file(harness.config_dir(name) .. "/root-hash.txt"):gsub("%s", "")
    assert(cartesi.tohex(m:get_root_hash()) == want, name .. " root hash")
    io.stderr:write("  ok ", name, " loads with recorded root hash\n")
end

-- config.lua of the bare-metal minimal creates the same machine as the stored one
do
    local m <close> = cartesi.machine(harness.config("baremetal-minimal"))
    local s <close> = load("baremetal-minimal")
    assert(m:get_root_hash() == s:get_root_hash())
    io.stderr:write("  ok baremetal-minimal config.lua == stored machine\n")
end

-- valid templates: at an accepted manual yield; an advance input produces a notice and is accepted
for _, name in ipairs({ "baremetal-template", "valid-template" }) do
    local m <close> = load(name)
    expect_accepted(m)
    local payload = name == "valid-template" and harness.encode_advance({ payload = "hello from the harness" })
        or "hello from the harness"
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, payload, m:get_root_hash())
    local outputs = 0
    while true do
        local br = m:run(math.maxinteger)
        if br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            local v = m:read_reg("htif_tohost")
            if (v >> 32) & 0xffff == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then outputs = outputs + 1 end
        elseif br == cartesi.BREAK_REASON_YIELDED_MANUALLY then
            break
        else
            error(name .. ": unexpected break reason " .. br)
        end
    end
    expect_accepted(m)
    assert(outputs == 1, name .. ": expected one output")
    io.stderr:write("  ok ", name, " accepts an advance input with one output\n")
end

-- the calc template from doc/recipes: waits accepted
do
    local m <close> = cartesi.machine(harness.config_dir("valid-template-calc") .. "/rolling-calculator-template", {})
    expect_accepted(m)
    io.stderr:write("  ok valid-template-calc waits at an accepted manual yield\n")
end
io.stderr:write("configs smoke ok\n")
