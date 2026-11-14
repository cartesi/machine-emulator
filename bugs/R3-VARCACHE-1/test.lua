-- R3-VARCACHE-1: machine:replace_memory_range on a machine that shares its stored directory D (SHARING_ALL)
-- swaps the range's backing store only in memory. It neither refuses the call nor records the replacement in D.
-- After the machine runs, is destroyed without a crash, and D is synced (D is then a directory O2 guarantees),
-- D reloads to a state the machine never had: post-run registers with the pre-replacement RAM contents.
--
-- Required (THREAT_MODEL.md):
--   section 8, How to rate, step 1: "A wrong hash after documented operations, destroying the machine, and a
--     sync is not" out of scope;
--   R2: "Every way of copying, persisting, restoring, or sharing a machine" must agree on the hash;
--   R9 / section 8 Medium: an API operation that "used as documented, leaves ... a stored directory inconsistent
--     with the machine's contents";
--   manual (doc/README.md): "A directory used by a machine with sharing holds a valid machine only after that
--     machine was destroyed without a crash and the directory was synced."
--
-- Pass (exit 0) if any of these holds: replace_memory_range refuses a machine that shares its directory, the
-- sync of D refuses (D then is not guaranteed), or D reloads (with an O1 rebuild) to the machine's last root hash.
-- Exit 1 if D reloads to a different root hash. Exit 2 on setup errors, or if the control (same sequence without
-- the replacement) does not round-trip.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local src = harness.config_dir("baremetal-template") .. "/machine"
    local ram_bin = "0000000080000000-4000000.bin"
    local probe_off = 0x3000000 -- 48 MiB into RAM, far from the guest's code, data, bss and stack
    if not io.open(src .. "/" .. ram_bin, "rb") then
        harness.setup_error("missing " .. src .. " (run bugs/harness/configs/make-configs.sh)")
    end

    local p = io.popen("mktemp -d \"${TMPDIR:-/tmp}/r3-varcache-1.XXXXXX\"")
    local tmp = p:read("l")
    p:close()
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function setup_error(msg) error({ setup = msg }) end

    -- Runs the scenario on a fresh clone of the template. With replace=true, .ram is replaced by an image that
    -- differs from the template's RAM in one byte at probe_off. Returns a table of observations.
    local function scenario(name, replace)
        local D = tmp .. "/" .. name
        cartesi.machine:clone_stored(src, D)
        cartesi.machine:sync_stored(D)
        local r = {}
        local m = cartesi.new()
        m:load(D, { clear_hash_tree = true }, cartesi.SHARING_ALL)
        r.template = m:get_root_hash()
        if replace then
            local img = tmp .. "/" .. name .. "-ram.img"
            local ram = harness.read_file(src .. "/" .. ram_bin)
            if ram:byte(probe_off + 1) ~= 0 then setup_error("probe byte of the template RAM is not zero") end
            ram = ram:sub(1, probe_off) .. "\x5a" .. ram:sub(probe_off + 2)
            local f = assert(io.open(img, "wb"))
            f:write(ram)
            f:close()
            ram = nil
            local ok, err = pcall(m.replace_memory_range, m, {
                label = ".ram",
                backing_store = { data_filename = img },
            })
            if not ok then
                m:destroy()
                r.refused = "replace_memory_range: " .. tostring(err)
                return r
            end
            r.after_replace = m:get_root_hash()
            if r.after_replace == r.template then setup_error("replacement did not change the root hash") end
        end
        -- one advance input, run to the next yield
        m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, harness.encode_advance({ payload = "hello" }),
            m:get_root_hash())
        -- the guest emits an output and a report (automatic yields) before it accepts (manual yield)
        local n = 0
        repeat
            r.break_reason = m:run(1 << 40)
            n = n + 1
        until r.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY or n > 16
        if r.break_reason ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
            setup_error(name .. ": run did not stop at a manual yield (break reason " .. tostring(r.break_reason) .. ")")
        end
        r.mcycle = m:read_reg("mcycle")
        r.final = m:get_root_hash()
        r.probe = m:read_memory(0x80000000 + probe_off, 1):byte()
        m:destroy()
        local ok, err = pcall(cartesi.machine.sync_stored, cartesi.machine, D)
        if not ok then
            r.refused = "sync_stored: " .. tostring(err)
            return r
        end
        -- reload the guaranteed directory, rebuilding its cached hash-tree data (O1)
        local rm <close> = cartesi.machine(D, { clear_hash_tree = true })
        r.reloaded = rm:get_root_hash()
        r.reloaded_mcycle = rm:read_reg("mcycle")
        r.reloaded_probe = rm:read_memory(0x80000000 + probe_off, 1):byte()
        return r
    end

    local ok, res = pcall(function()
        local control = scenario("control", false)
        local test = scenario("D", true)
        return { control = control, test = test }
    end)
    os.execute("rm -rf '" .. tmp .. "'")
    if not ok then
        if type(res) == "table" and res.setup then harness.setup_error(res.setup) end
        error(res, 0)
    end

    local c, t = res.control, res.test
    local hx = cartesi.tohex
    print("control (no replacement): final " .. hx(c.final) .. " mcycle " .. c.mcycle)
    print("control reloaded:         root  " .. hx(c.reloaded) .. " mcycle " .. c.reloaded_mcycle)
    if c.reloaded ~= c.final then
        harness.setup_error("control: sharing + destroy + sync + reload does not round-trip even without replacement")
    end
    if t.refused then
        print("refused: " .. t.refused)
        return harness.expect(true, "the API refuses to leave a shared, synced directory inconsistent")
    end
    print("template root:            " .. hx(t.template))
    print("after replace .ram:       " .. hx(t.after_replace))
    print(string.format("machine after input:      %s mcycle %d, RAM byte at probe 0x%02x", hx(t.final), t.mcycle,
        t.probe))
    print(string.format("D reloaded (O1 rebuild):  %s mcycle %d, RAM byte at probe 0x%02x", hx(t.reloaded),
        t.reloaded_mcycle, t.reloaded_probe))
    local known = { [t.template] = "template", [t.after_replace] = "after replace", [t.final] = "machine's final" }
    print("D's reloaded root equals: " .. (known[t.reloaded] or "none of the machine's root hashes"))
    return harness.expect(t.reloaded == t.final,
        "a directory shared by a machine, destroyed without a crash and synced (O2-guaranteed) must reload to "
            .. "the machine's state (R2, R9, section 8 step 1)")
end)
