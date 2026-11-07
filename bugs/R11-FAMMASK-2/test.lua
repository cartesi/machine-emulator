#!/usr/bin/env lua5.4
-- R11-FAMMASK-2: config mvendorid/marchid/mimpid are never checked when a machine is created.
--
-- The manual (doc/README.md, "processor" entry of machine_config) says users set mvendorid, mimpid and marchid in
-- the config, "which the emulator checks at instantiation to ensure the configuration matches the running emulator
-- version", that -1 makes the emulator accept any value, and that production code should hard-code them.
-- This is the documented way for the honest operator to detect and refuse a build/deployment version mismatch (R13).
--
-- On feature/prt-audit, machine_config::adjust_defaults only replaces -1, machine::init_processor never copies these
-- three config fields into the shadow (which keeps the build's constants), and validate_processor_shadow compares the
-- shadow with the build constants, which always passes. The config's values are compared with nothing; they survive
-- in get_initial_config() and in the config.json written by store(), while read_reg and the hashed state hold the
-- build's values.
--
-- The test creates fresh machines from configs whose version IDs do not match this build (one field at a time) and
-- asserts that creation is refused, as the manual requires. It also checks that a config with the matching IDs and
-- with -1 is accepted (sanity), and reports the inconsistent state left behind when creation succeeds.
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local function cfg(regs)
    return { ram = { length = 0x10000 }, processor = { registers = regs } }
end

-- Sanity: matching IDs and wildcard -1 must be accepted (otherwise harness error, exit 2).
local ok, err = pcall(cartesi.machine, cfg({
    marchid = cartesi.MARCHID, mvendorid = cartesi.MVENDORID, mimpid = cartesi.MIMPID }))
if not ok then io.stderr:write("harness error: matching IDs rejected: ", tostring(err), "\n") os.exit(2) end
ok, err = pcall(cartesi.machine, cfg({ marchid = -1, mvendorid = -1, mimpid = -1 }))
if not ok then io.stderr:write("harness error: -1 IDs rejected: ", tostring(err), "\n") os.exit(2) end

local failures = {}
local cases = {
    { name = "marchid", value = cartesi.MARCHID + 12345 },
    { name = "mvendorid", value = cartesi.MVENDORID + 7 },
    { name = "mimpid", value = cartesi.MIMPID + 99 },
}

for _, c in ipairs(cases) do
    local mok, m = pcall(cartesi.machine, cfg({ [c.name] = c.value }))
    if mok then
        local initial = m:get_initial_config().processor.registers[c.name]
        local live = m:read_reg(c.name)
        local build = cartesi[c.name:upper()]
        -- Persist and reload: the stored config keeps advertising the mismatching ID and reloads fine.
        local dir = assert(io.popen("mktemp -u"):read("l"), "harness error: mktemp failed")
        m:store(dir)
        local f = assert(io.open(dir .. "/config.json"), "harness error: no config.json")
        local json = f:read("a")
        f:close()
        local stored = json:match('"' .. c.name .. '"%s*:%s*"?(%w+)"?')
        local rok = pcall(cartesi.machine, dir)
        os.execute("rm -rf '" .. dir .. "'")
        failures[#failures + 1] = string.format(
            "%s=%d (build %d) accepted at creation: get_initial_config=%d, read_reg=%d, config.json=%s, reload %s",
            c.name, c.value, build, initial, live, tostring(stored), rok and "succeeded" or "failed")
    else
        print(string.format("ok: %s=%d refused: %s", c.name, c.value, tostring(m)))
    end
end

if #failures > 0 then
    for _, l in ipairs(failures) do print("  " .. l) end
    print("FAIL: cartesi.machine(config) accepts mvendorid/marchid/mimpid that do not match the build; the manual says "
        .. "they are checked at instantiation (R13 version-mismatch detection lost)")
    os.exit(1)
end
print("OK: mismatching version IDs are refused at creation")
