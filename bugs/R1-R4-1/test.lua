-- R1-R4-1: machine creation accepts reproducible Keccak-256 configurations whose uarch is not pristine
-- (uarch RAM image from uarch.ram.backing_store.data_filename, uarch processor registers), and the honest
-- operator then cannot compute the uarch-level claim or a uarch step log, while native interpretation runs.
--
-- Requirement (THREAT_MODEL.md R4): "Every reproducible configuration that the emulator accepts, using the
-- deployment's hash function and holding only register values that the RISC-V specification and the manual
-- allow, yields a machine on which this rule holds. A configuration that would not is rejected when the machine
-- is created."
--
-- For each configuration the test requires: either cartesi.machine(config) raises, or, on the created machine,
-- (1) collect_uarch_cycle_root_hashes(1) succeeds, (2) its final hash equals the native run(1) root hash, and
-- (3) log_step_uarch() at mcycle 0 succeeds.  Exit 1 if some configuration is accepted and fails one of them.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local ram_image = harness.baremetal("accept")

    -- 4 KiB uarch RAM image of 0xff bytes, generated in a temp file
    local junk = os.tmpname()
    do
        local f = assert(io.open(junk, "wb"))
        f:write(string.rep("\255", 4096))
        f:close()
    end

    local function base()
        return {
            ram = { length = 64 << 20, backing_store = { data_filename = ram_image } },
            hash_tree = { hash_function = "keccak256" },
        }
    end

    local zero = string.rep("\0", cartesi.HASH_SIZE)
    local revert_tail = { zero, zero } -- revert root hash of a fresh machine is zero

    -- Returns true when the requirement holds for cfg, plus a description.
    local function check(name, make_cfg)
        local ok, m = pcall(cartesi.machine, make_cfg())
        if not ok then return true, name .. ": rejected at creation (" .. tostring(m) .. ")" end
        local cfg0 = m:get_initial_config()
        if cfg0.processor.registers.iunrep ~= 0 or cfg0.hash_tree.hash_function ~= "keccak256" then
            harness.setup_error(name .. ": configuration is not reproducible Keccak-256")
        end
        local pristine = m:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)
            == cartesi.UARCH_PRISTINE_STATE_HASH
        local okc, res = pcall(m.collect_uarch_cycle_root_hashes, m, 1, 0, revert_tail)
        m:destroy()
        -- native interpretation on a fresh machine from the same configuration
        local n <close> = cartesi.machine(make_cfg())
        local okn, errn = pcall(n.run, n, 1)
        local native = okn and n:get_root_hash() or nil
        local native_mcycle = n:read_reg("mcycle")
        -- uarch step log at mcycle 0, uarch cycle 0
        local s <close> = cartesi.machine(make_cfg())
        local oks, errs = pcall(s.log_step_uarch, s)
        local desc = string.format(
            "%s: accepted (uarch node pristine=%s); native run(1): %s (mcycle %d); "
                .. "collect_uarch_cycle_root_hashes(1): %s; log_step_uarch: %s",
            name, tostring(pristine), okn and "ok" or ("error: " .. tostring(errn)), native_mcycle,
            okc and "ok" or ("error: " .. tostring(res)), oks and "ok" or ("error: " .. tostring(errs)))
        if not (okc and oks and okn) then return false, desc end
        if res.hashes[#res.hashes] ~= native then
            return false, desc .. "; uarch-path hash at mcycle 1 differs from native"
        end
        return true, desc .. "; uarch path agrees with native at mcycle 1"
    end

    -- control: default (pristine) uarch must satisfy the requirement, else the harness is broken
    local okc, dc = check("control (default uarch)", base)
    io.stderr:write(dc, "\n")
    if not okc then
        os.remove(junk)
        harness.setup_error("control configuration does not satisfy the requirement")
    end

    local cases = {
        { "uarch.ram.backing_store.data_filename = 4 KiB of 0xff", function()
            local c = base()
            c.uarch = { ram = { backing_store = { data_filename = junk } } }
            return c
        end },
        { "uarch.processor.registers.pc = 0x600004 (aligned, inside uarch RAM)", function()
            local c = base()
            c.uarch = { processor = { registers = { pc = cartesi.UARCH_RAM_START_ADDRESS + 4 } } }
            return c
        end },
    }
    local all = true
    for _, cs in ipairs(cases) do
        local ok, d = check(cs[1], cs[2])
        all = harness.expect(ok, "R4 configuration clause: " .. d) and all
    end
    os.remove(junk)
    return all
end)
