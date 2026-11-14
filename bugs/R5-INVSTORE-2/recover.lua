-- Applies the documented crash-recovery rule of --revert-mode=stored to what a killed cartesi-machine left in
-- <work>, and checks that it yields a loadable directory holding a committed state.
--   lua5.4 recover.lua <template-dir> <work-dir> <input-0> <input-1>
-- Exit 0: the rule recovers a committed state; 1: it does not; 2: setup error (harness.main).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local fs = require("cartesi.filesystem")
    local template, work, input0, input1 = arg[1], arg[2], arg[3], arg[4]
    if not (template and work and input0 and input1) then harness.setup_error("usage: recover.lua tpl work in0 in1") end
    local machine_dir = work .. "/machine"
    local backup = machine_dir .. ".revert"
    local tmp = backup .. ".tmp"
    local recovered = work .. "/recovered"
    local ADV = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE

    -- Committed states computed independently from the template: after input 0 and after input 1. The kill
    -- happens inside the commit of input 0, after machine and machine.revert.tmp were synced with it, so the
    -- recovered state must be one of these (rolling back to the template would lose the committed input 0).
    local committed = {}
    do
        local m <close> = cartesi.machine(template .. "/machine", {})
        for i, f in ipairs({ input0, input1 }) do
            m:send_cmio_response(ADV, harness.read_file(f), m:get_root_hash())
            -- the guest emits an output and a report (automatic yields) and then accepts (manual yield)
            local br = m:run(math.maxinteger)
            while br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY do
                br = m:run(math.maxinteger)
            end
            local _, reason = m:receive_cmio_request()
            if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY or reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                harness.setup_error("input " .. (i - 1) .. " was not accepted by the template")
            end
            committed[m:get_root_hash()] = "after input " .. (i - 1)
        end
    end
    for h, what in pairs(committed) do
        print(string.format("committed state %-13s %s", what .. ":", harness.hex(h)))
    end

    local function describe(dir)
        if not fs.exists(dir) then return "absent" end
        local ok, m = pcall(cartesi.machine, dir, { clear_hash_tree = true })
        if not ok then return "present, does not load: " .. tostring(m) end
        local h = m:get_root_hash()
        m:destroy()
        return "present, rebuilt root " .. harness.hex(h) .. " (" .. (committed[h] or "not a committed state") .. ")"
    end
    print("left on disk after the kill:")
    print("  machine:            " .. describe(machine_dir))
    print("  machine.revert:     " .. describe(backup))
    print("  machine.revert.tmp: " .. describe(tmp))

    -- The documented rule (doc/README.md "Rolling Cartesi Machines directly from storage", CLI --help):
    -- "If machine.revert exists, it holds that state, so discard machine and machine.revert.tmp and clone
    -- machine.revert back to machine. If machine.revert is missing but machine.revert.tmp exists, ... machine
    -- holds that state and machine.revert.tmp can be discarded. If neither exists, the command stopped before its
    -- first commit, and the run starts over."
    -- The test does not discard anything (it only reports what the rule would discard), and clones instead of
    -- replacing machine, so the evidence stays on disk.
    local resume_dir, why
    if fs.exists(backup) then
        print("rule: machine.revert exists -> discard machine and machine.revert.tmp, clone machine.revert to machine")
        local ok, err = pcall(cartesi.machine.clone_stored, cartesi.machine, backup, recovered)
        if not ok then
            return harness.expect(false, "R4/O2: the documented rule resumes from machine.revert, which cannot be "
                .. "cloned: " .. tostring(err) .. "; the rule discards machine and machine.revert.tmp, the synced "
                .. "copies of the last committed state")
        end
        resume_dir, why = recovered, "clone of machine.revert"
    elseif fs.exists(tmp) then
        print("rule: only machine.revert.tmp exists -> machine holds the committed state")
        resume_dir, why = machine_dir, "machine"
    else
        return harness.expect(false, "R4: the rule says nothing was committed, although input 0 was committed")
    end

    local ok, m = pcall(cartesi.machine, resume_dir, {})
    if not ok then return harness.expect(false, "R4/O2: the directory the rule resumes from does not load: " .. m) end
    local cached = m:get_root_hash()
    m:destroy()
    local r <close> = cartesi.machine(resume_dir, { clear_hash_tree = true })
    local rebuilt = r:get_root_hash()
    print(string.format("resumed from %s: cached root %s, rebuilt root %s", why, harness.hex(cached),
        harness.hex(rebuilt)))
    return harness.expect(cached == rebuilt and committed[rebuilt] ~= nil,
        "R4/O2: the directory the documented rule resumes from must hold the last committed state")
end)
