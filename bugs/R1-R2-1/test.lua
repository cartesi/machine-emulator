-- R1-R2-1: the unreproducible mode has two sources of truth. write_reg("iunrep", ...) changes the hashed
-- register (shadow state), while every guarded path (log_step_uarch, collect_*, store, ...) reads the copy in
-- the machine's config, and only create/load compare the two. On a reproducible machine, write_reg("iunrep", 1)
-- succeeds; the root hash then commits to an unreproducible machine, the uarch still logs steps, store still
-- writes a directory, and that directory refuses to load ("iunrep mismatch between shadow state and config").
--
-- Asserted (THREAT_MODEL R2 "Every register and every configuration value that affects a transition has one
-- source of truth in the hashed state, and every path reads it from there"; R14 "The unreproducible mode is fixed
-- at creation and recorded in the hashed state"; R9 / section 8 Medium "a stored directory inconsistent with the
-- machine's contents"; manual: iunrep is "a creation-time mode"):
--   either write_reg("iunrep", 1) on a reproducible machine is refused, or, once it succeeds, the machine
--   follows the hashed register: log_step_uarch refuses (unreproducible machines cannot use the uarch) and store
--   either refuses or writes a directory that loads back with the same root hash and iunrep.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local cfg_path = harness.config_dir("baremetal-minimal") .. "/config.lua"
    local ok_cfg, cfg = pcall(dofile, cfg_path)
    if not ok_cfg or type(cfg) ~= "table" then harness.setup_error("cannot load " .. cfg_path) end

    local ok_tmp, tmp = harness.sh("mktemp -d /tmp/r1-r2-1.XXXXXX")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok_tmp or not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end

    local violations = {}
    local function violation(msg)
        violations[#violations + 1] = msg
        print("VIOLATION: " .. msg)
    end

    local ok_run, err = pcall(function()
        local m <close> = cartesi.machine(cfg, {})
        if m:read_reg("iunrep") ~= 0 then harness.setup_error("baremetal-minimal is not reproducible") end
        local hash0 = m:get_root_hash()

        -- control: a reproducible machine can log a uarch step (on a clone of the state, so m is untouched)
        local okc, errc = pcall(function()
            local c <close> = cartesi.machine(cfg, {})
            c:log_step_uarch()
        end)
        if not okc then harness.setup_error("control log_step_uarch failed: " .. tostring(errc)) end

        local okw, errw = pcall(function() m:write_reg("iunrep", 1) end)
        if not okw then
            print("write_reg('iunrep', 1) refused: " .. tostring(errw))
            return
        end
        local hash1 = m:get_root_hash()
        print(string.format("write_reg('iunrep', 1) accepted; read_reg('iunrep') = %d; root hash changed: %s",
            m:read_reg("iunrep"), tostring(hash0 ~= hash1)))
        if m:read_reg("iunrep") == 0 then
            violation("write_reg('iunrep', 1) succeeded but read_reg('iunrep') still returns 0")
        end

        -- the hashed state now says unreproducible: the uarch must refuse, as on any unreproducible machine
        local okl, errl = pcall(function() return m:log_step_uarch() end)
        if okl then
            violation("log_step_uarch succeeded on a machine whose hashed iunrep is 1 "
                .. "(the guard reads the config copy, not the hashed register)")
        else
            print("log_step_uarch refused: " .. tostring(errl))
        end

        -- store: must refuse, or write a directory that loads back as the same machine
        local dir = tmp .. "/stored"
        local oks, errs = pcall(function() m:store(dir) end)
        if not oks then
            print("store refused: " .. tostring(errs))
        else
            print("store succeeded")
            local okld, res = pcall(function()
                local m2 <close> = cartesi.machine(dir, {})
                return { hash = m2:get_root_hash(), iunrep = m2:read_reg("iunrep") }
            end)
            if not okld then
                violation("store wrote a directory that refuses to load: " .. tostring(res))
            elseif res.hash ~= m:get_root_hash() or res.iunrep ~= m:read_reg("iunrep") then
                violation("stored directory loads as a different machine")
            else
                print("stored directory loads back with the same root hash and iunrep")
            end
        end
    end)
    cleanup()
    if not ok_run then error(err, 0) end

    return harness.expect(#violations == 0,
        "R2/R14: iunrep must have one source of truth in the hashed state (write refused, or every path follows it)")
end)
