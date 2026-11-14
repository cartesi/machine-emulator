-- Checks what `cartesi-machine --revert-mode=stored` left on disk after a host I/O fault, or a SIGINT, inside the
-- commit of input 0 (the process saw the error and ran its own cleanup; it was not killed).
--   lua5.4 check.lua <template-dir> <run-dir> <input-0> <input-1>
-- Exit 0: a committed state survived; 1: the CLI's own cleanup destroyed it; 2: setup error (harness.main).
--
-- When the fault hits, `machine` has been synced after the machine using it was destroyed, so O2 guarantees it,
-- and it holds the state after input 0. THREAT_MODEL section 4: a host fault "may stop the honest operator, but
-- the emulator must never turn one into a wrong hash, a wrong proof, or a directory that O2 guarantees but that
-- later loads as a different state"; section 5: "O1 and O2 bind the emulator too. The tools and reference
-- implementations that ship with it must follow them ... A defect ... that damages a directory while O2
-- guarantees it, is not excused by them"; R4: "After a stop, it restarts from a directory that O2 guarantees".
-- The test passes if EITHER the guaranteed `machine` still loads with the state after input 0 (or the later
-- committed state after input 1, if the run went on), OR the manual's
-- recovery rule, applied to the names left on disk, selects a directory holding a committed state (after input 0,
-- or a state committed before it).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local fs = require("cartesi.filesystem")
    local template, work, input0, input1 = arg[1], arg[2], arg[3], arg[4]
    if not (template and work and input0 and input1) then harness.setup_error("usage: check.lua tpl work in0 in1") end
    local machine_dir = work .. "/machine"
    local backup = machine_dir .. ".revert"
    local tmp = backup .. ".tmp"
    local ADV = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE

    -- Committed states computed independently from the template: the initial fixed point (committed before
    -- input 0), after input 0 and after input 1.
    local committed = {}
    local order = {}
    local after = {}
    do
        local m <close> = cartesi.machine(template .. "/machine", {})
        local function run_to_manual_yield(what)
            local br = m:run(math.maxinteger)
            while br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY do
                br = m:run(math.maxinteger)
            end
            local _, reason = m:receive_cmio_request()
            if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY or reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                harness.setup_error(what .. " did not end at an rx-accepted manual yield")
            end
        end
        run_to_manual_yield("the template")
        committed[m:get_root_hash()] = "initial (before input 0)"
        order[#order + 1] = m:get_root_hash()
        for i, f in ipairs({ input0, input1 }) do
            m:send_cmio_response(ADV, harness.read_file(f), m:get_root_hash())
            run_to_manual_yield("input " .. (i - 1))
            committed[m:get_root_hash()] = "after input " .. (i - 1)
            order[#order + 1] = m:get_root_hash()
            after[m:get_root_hash()] = true
        end
    end
    for _, h in ipairs(order) do
        print(string.format("  committed state %-26s %s", committed[h] .. ":", harness.hex(h)))
    end

    -- Root of a directory after rebuilding its cached hash-tree data, and whether the cached root agreed
    local function inspect(dir)
        if not fs.exists(dir) then return nil, "absent" end
        local ok, m = pcall(cartesi.machine, dir, {})
        if not ok then return nil, "present, does not load: " .. tostring(m) end
        local cached = m:get_root_hash()
        m:destroy()
        local ok2, r = pcall(cartesi.machine, dir, { clear_hash_tree = true })
        if not ok2 then return nil, "present, does not load with a rebuilt hash tree: " .. tostring(r) end
        local rebuilt = r:get_root_hash()
        r:destroy()
        if cached ~= rebuilt then return nil, "present, cached root differs from rebuilt root" end
        return rebuilt, "present, root " .. harness.hex(rebuilt) .. " (" .. (committed[rebuilt] or "not committed") .. ")"
    end
    local machine_root, machine_desc = inspect(machine_dir)
    local _, backup_desc = inspect(backup)
    local _, tmp_desc = inspect(tmp)
    print("  left on disk:")
    print("    machine:            " .. machine_desc)
    print("    machine.revert:     " .. backup_desc)
    print("    machine.revert.tmp: " .. tmp_desc)

    -- (a) The directory O2 guaranteed when the fault hit: it must still hold the state after input 0 (or, if the
    -- run went on, the later committed state after input 1)
    local machine_survived = machine_root ~= nil and after[machine_root] == true
    print("  machine (O2-guaranteed with the state after input 0 when the fault hit) survived: "
        .. tostring(machine_survived))

    -- (b) The documented recovery rule (doc/README.md "Rolling Cartesi Machines directly from storage"):
    -- "If machine.revert exists, it holds that state ... clone machine.revert back to machine. If machine.revert is
    -- missing but machine.revert.tmp exists ... machine holds that state ... If neither exists, the command stopped
    -- before its first commit, and the run starts over."
    local rule_dir, rule_what
    if fs.exists(backup) then
        rule_dir, rule_what = backup, "machine.revert exists -> resume from machine.revert"
    elseif fs.exists(tmp) then
        rule_dir, rule_what = machine_dir, "only machine.revert.tmp exists -> resume from machine"
    else
        rule_what = "neither machine.revert nor machine.revert.tmp exists -> start over from the template"
    end
    local rule_ok = false
    if rule_dir then
        local root = inspect(rule_dir)
        rule_ok = root ~= nil and committed[root] ~= nil
    end
    print("  recovery rule: " .. rule_what .. "; yields a committed state: " .. tostring(rule_ok))

    return harness.expect(machine_survived or rule_ok,
        "O2/R4 (THREAT_MODEL sections 4 and 5): a fault (host I/O error or SIGINT) inside the commit of input 0 made the CLI's own "
            .. "error-path revert delete the O2-guaranteed `machine` directory, and no committed state is left "
            .. "that the documented recovery rule can resume from")
end)
