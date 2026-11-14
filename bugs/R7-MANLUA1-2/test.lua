-- R7-MANLUA1-2: get_initial_config() of a machine loaded from a stored directory must report the register values
-- the machine had when it was stored (doc/README.md, "Persistent machines": "Likewise, the values of all registers
-- will reflect the values as they were when stored."). This test compares, for a set of registers, the value in
-- get_initial_config().processor.registers of the reloaded machine with read_reg() of the same machine.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local tmp = os.getenv("TMPDIR") or "/tmp"
    local ok, out = harness.sh("mktemp -d " .. tmp .. "/r7-manlua1-2.XXXXXX")
    if not ok then harness.setup_error("mktemp failed") end
    local dir = out:gsub("%s+$", "")
    local function cleanup() os.execute("rm -rf '" .. dir .. "'") end

    -- read a register value from a config.processor.registers table, by read_reg name
    local function cfg_reg(regs, name)
        local f = name:match("^iflags_(%a)$")
        if f then
            local v = regs.iflags and regs.iflags[f]
            if type(v) == "boolean" then v = v and 1 or 0 end
            return v
        end
        return regs[name]
    end

    local mismatches = 0
    local function compare(label, m, names)
        local regs = m:get_initial_config().processor.registers
        for _, name in ipairs(names) do
            local cv, rv = cfg_reg(regs, name), m:read_reg(name)
            if cv ~= rv then
                mismatches = mismatches + 1
                io.stderr:write(string.format("  %s: %-10s get_initial_config()=0x%x  read_reg()=0x%x\n", label, name,
                    cv or -1, rv))
            else
                io.stderr:write(string.format("  %s: %-10s 0x%x (agree)\n", label, name, rv))
            end
        end
    end

    local res, err = pcall(function()
        -- Case A: create from a configuration, run 1000 cycles, store, reload.
        local cfg = harness.config("baremetal-minimal")
        do
            local m <close> = harness.machine(cfg)
            m:run(1000)
            m:store(dir .. "/a")
        end
        do
            local m <close> = harness.machine(dir .. "/a")
            compare("A (create, run 1000, store, load)", m, { "mcycle", "pc" })
        end

        -- Case B: a template waiting at a manual yield (emit-output.bin) receives an advance-state input with
        -- send_cmio_response, which sets imcyclemax and clears iflags_Y; store, reload.
        do
            local m <close> = harness.machine(harness.config_dir("baremetal-template") .. "/machine")
            if m:read_reg("iflags_Y") ~= 1 then harness.setup_error("baremetal-template not at a manual yield") end
            m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "hello", m:get_root_hash())
            m:store(dir .. "/b")
        end
        do
            local m <close> = harness.machine(dir .. "/b")
            compare("B (template, deliver input, store, load)", m, { "mcycle", "pc", "imcyclemax", "iflags_Y" })
        end
    end)
    cleanup()
    if not res then error(err, 0) end

    return harness.expect(mismatches == 0, string.format(
        "manual: for a loaded machine, get_initial_config() register values reflect the values as they were " ..
            "when stored (%d register(s) differ from read_reg)", mismatches))
end)
