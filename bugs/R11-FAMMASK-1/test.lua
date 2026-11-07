-- R11-FAMMASK-1: native vs uarch disagree on reads of mvendorid / marchid / mimpid.
--
-- What it checks (THREAT_MODEL.md R2, section 2 "state transition function ... defined on every state"):
-- from one before-state, native interpretation (machine:run, used by collect_mcycle_root_hashes to build the honest
-- claim) and the uarch path (log_step_uarch/verify_step_uarch + log_reset_uarch/verify_reset_uarch, i.e. what the
-- on-chain UArchStep/UArchReset replay) must reach the same canonical hash at the next mcycle boundary.
--
-- The native state access (src/state-access.hpp do_read_{mvendorid,marchid,mimpid}) and machine::read_reg return the
-- build constants and ignore the hashed shadow word, while the uarch bridge (i_prefer_shadow_state) reads the shadow
-- word. With a before-state whose shadow word differs from the constant, a single `csrr a0, <csr>` therefore writes
-- different values to a0 on the two paths, and the after-hashes differ. The before-state is fabricated (the guest and
-- write_reg cannot write these words), so this is a divergence at unreachable states only (section 8: High).
--
-- The fabricated state is made with the documented shadow-overwrite form of write_memory (whole shadow range) under
-- runtime skip_version_check; verify_hash_tree confirms the hash tree matches contents before stepping.
--
-- Exits 0 when both paths agree for all three CSRs (bug fixed), 1 otherwise.

local cartesi = require("cartesi")

local RAM_START = 0x80000000
local RT = { skip_version_check = true }

-- csrr a0, csr  (csrrs a0, csr, x0)  followed by  j .
local function csrr_a0(csr)
    return (csr << 20) | (2 << 12) | (10 << 7) | 0x73
end

local CSRS = {
    { name = "mvendorid", csr = 0xF11, init = cartesi.MVENDORID },
    { name = "marchid", csr = 0xF12, init = cartesi.MARCHID },
    { name = "mimpid", csr = 0xF13, init = cartesi.MIMPID },
}

local function hex(h)
    return (h:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

-- Build the fabricated before-state: program at RAM_START, shadow word of `reg` set to `value`.
local function build(reg, value)
    local m = cartesi.machine({ ram = { length = 0x10000 } }, RT)
    m:write_memory(RAM_START, string.pack("<I4I4", csrr_a0(reg.csr), 0x0000006f))
    local addr = m:get_reg_address(reg.name)
    local shadow = m:read_memory(cartesi.AR_SHADOW_STATE_START or 0, 0x8000)
    shadow = shadow:sub(1, addr) .. string.pack("<I8", value) .. shadow:sub(addr + 9)
    m:write_memory(0, shadow)
    assert(m:read_word(addr) == value, "failed to set shadow " .. reg.name)
    assert(m:verify_hash_tree(), "hash tree inconsistent after shadow overwrite")
    return m
end

local failures = 0
for _, reg in ipairs(CSRS) do
    local value = reg.init ~ 0x5a5a -- anything different from the build constant
    -- Native path (machine:run, the interpreter the honest operator's claim builders use).
    local n = build(reg, value)
    local before = n:get_root_hash()
    n:run(1)
    assert(n:read_reg("mcycle") == 1)
    local a0_native = n:read_reg("x10")
    local h_native = n:get_root_hash()

    -- Uarch path, logged and replayed through the verifiers (what the referee checks on-chain).
    local u = build(reg, value)
    assert(u:get_root_hash() == before)
    local h = before
    local steps = 0
    while u:read_reg("uarch_halt") == 0 do
        local log = u:log_step_uarch()
        local nh = u:get_root_hash()
        assert(cartesi.machine:verify_step_uarch(h, log) == nh, "verify_step_uarch rejected honest uarch log")
        h = nh
        steps = steps + 1
        assert(steps < 1000000, "uarch did not halt")
    end
    local rlog = u:log_reset_uarch()
    local rh = u:get_root_hash()
    assert(cartesi.machine:verify_reset_uarch(h, rlog) == rh, "verify_reset_uarch rejected honest reset log")
    assert(u:read_reg("mcycle") == 1)
    local a0_uarch = u:read_reg("x10")

    local shadow_word = u:read_word(u:get_reg_address(reg.name))
    print(string.format("%-9s shadow=0x%x const=0x%x read_reg=0x%x | native a0=0x%x hash=%s | uarch(verified) a0=0x%x hash=%s",
        reg.name, shadow_word, reg.init, n:read_reg(reg.name), a0_native, hex(h_native):sub(1, 16), a0_uarch,
        hex(rh):sub(1, 16)))
    if a0_native ~= a0_uarch or h_native ~= rh then
        failures = failures + 1
        print(string.format("FAIL %s: from the same before-state %s, `csrr a0,%s` gives a0=0x%x natively but a0=0x%x "
            .. "via the uarch verifiers; mcycle-1 hashes differ (native %s vs verified %s): R2 violated",
            reg.name, hex(before):sub(1, 16), reg.name, a0_native, a0_uarch, hex(h_native):sub(1, 16), hex(rh):sub(1, 16)))
    end
end

if failures > 0 then
    print(string.format("R11-FAMMASK-1: native interpreter and uarch/verifiers disagree on %d of 3 machine-ID CSRs "
        .. "(native returns build constants, uarch reads the hashed shadow word)", failures))
    os.exit(1)
end
print("R11-FAMMASK-1: native and uarch paths agree on all machine-ID CSR reads")
os.exit(0)
