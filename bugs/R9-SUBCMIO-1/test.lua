-- R9-SUBCMIO-1: machine creation accepts a reproducible Keccak-256 configuration whose processor registers put the
-- machine at a manual yield with the rx-rejected reason (iflags.Y = 1, htif.tohost = manual yield, reason
-- rx-rejected), while the revert root hash, which no configuration field sets, is 32 zero bytes. The rejection
-- exception then makes the canonical hash at the next mcycle boundary 0x00..00, which is the content hash of no
-- state: no later uarch trajectory, node or step proof can be produced from it.
--
-- Requirement (THREAT_MODEL.md R4): "Every reproducible configuration that the emulator accepts, using the
-- deployment's hash function and holding only register values that the RISC-V specification and the manual
-- allow, yields a machine on which this rule holds. A configuration that would not is rejected when the machine
-- is created."
--
-- The test requires: either cartesi.machine(config) raises, or on the created machine the hash that the honest
-- operator's mcycle-level collector commits to at the next mcycle boundary, and the after-hash of the uarch reset
-- that closes that mcycle (log_reset_uarch / verify_reset_uarch), are not the all-zero hash. Exit 1 otherwise.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local zero = string.rep("\0", cartesi.HASH_SIZE)

    local function manual_yield_tohost(reason)
        return (cartesi.HTIF_DEV_YIELD << 56) | (cartesi.HTIF_YIELD_CMD_MANUAL << 48) | (reason << 32)
    end

    local function config(reason)
        return {
            ram = { length = 1 << 20 },
            hash_tree = { hash_function = "keccak256" },
            processor = { registers = { iflags = { Y = 1 }, htif = { tohost = manual_yield_tohost(reason) } } },
        }
    end

    -- Returns ok (requirement holds), description, and the observed hashes.
    local function check(name, reason)
        local okm, m = pcall(cartesi.machine, config(reason))
        if not okm then return true, name .. ": rejected at creation (" .. tostring(m) .. ")" end
        local ic = m:get_initial_config()
        if ic.processor.registers.iunrep ~= 0 or ic.hash_tree.hash_function ~= "keccak256" then
            harness.setup_error(name .. ": configuration is not reproducible Keccak-256")
        end
        local root = m:get_root_hash()
        local revert = m:read_revert_root_hash()
        -- mcycle-level claim: the leaf at the next mcycle boundary (fixed point, so the collector stops there)
        local res = m:collect_mcycle_root_hashes(m:read_reg("mcycle") + 4, 0, 0, 0)
        local leaf = res.hashes[1]
        -- the uarch trajectory of that mcycle, closed by the reset
        while m:run_uarch(m:read_reg("uarch_cycle") + 1) ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED do
        end
        local before_reset = m:get_root_hash()
        local log = m:log_reset_uarch()
        local after_reset = cartesi.machine:verify_reset_uarch(before_reset, log)
        -- does the uarch-level collector accept a made-up tail ending at the zero revert root hash?
        -- (only meaningful at a rejected yield, where the collector consumes the tail)
        local oku = nil
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            local made_up = { string.rep("\x5a", cartesi.HASH_SIZE), revert }
            local m2 <close> = cartesi.machine(config(reason))
            oku = pcall(m2.collect_uarch_cycle_root_hashes, m2, m2:read_reg("mcycle") + 1, 0, made_up)
        end
        m:destroy()
        local desc = string.format(
            "%s: accepted; root %s; revert root hash %s; collect_mcycle_root_hashes leaf %s (%d leaves); "
                .. "verify_reset_uarch after-hash %s; collect_uarch_cycle_root_hashes with made-up tail: %s",
            name, harness.hex(root):sub(1, 16), harness.hex(revert):sub(1, 16), harness.hex(leaf):sub(1, 16),
            #res.hashes, harness.hex(after_reset):sub(1, 16), oku == nil and "n/a" or (oku and "accepted" or "refused"))
        return leaf ~= zero and after_reset ~= zero, desc, leaf, root, after_reset
    end

    -- control: a manual yield with the accepted reason must give a nonzero leaf equal to the machine's root hash
    local okc, dc, leafc, rootc, resetc = check("control (manual yield, accepted)",
        cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    io.stderr:write(dc, "\n")
    if not okc or leafc ~= rootc or resetc ~= rootc then
        harness.setup_error("control configuration does not behave as expected")
    end

    local ok, d = check("iflags.Y=1, tohost = manual yield rx-rejected", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    if not ok then
        io.stderr:write("VIOLATED: R4 configuration clause: ", d,
            "; the canonical hash at the next mcycle boundary is 32 zero bytes, the hash of no state\n")
    else
        io.stderr:write(d, "\n")
    end
    return harness.expect(ok, "R4: a configuration whose machine cannot satisfy R4 must be rejected at creation")
end)
