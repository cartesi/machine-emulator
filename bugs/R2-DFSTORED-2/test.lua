-- R2-DFSTORED-2: machine:clone_stored copies a valid template's file attributes that lie outside the hashed state
-- (permission bits, backing-file length) into the clone: it hard-links every file without write permission bits and
-- clones a trimmed backing file at its short length. A shared-write load of the clone (clone + SHARING_ALL +
-- clear_hash_tree, as the PRT stored player and `cartesi-machine --load=<dir>,clone:<src>` adopt a template) then
-- refuses the clone, although the template meets every valid-template condition and loads unshared with the
-- committed hash.
--
-- Asserted (THREAT_MODEL section 8, out-of-scope note on snapshots: "Once a snapshot meets them, nothing it carries
-- outside the hashed state may affect any transition (R1), crash the honest operator, or corrupt its memory";
-- R4; section 2 "Honest operator's path": "Obtaining its valid template", "Storing and reloading the machine"):
--   for each variant of the template (A: every file read-only; B: RAM backing file trimmed after its last non-zero
--   page) whose unshared clear_hash_tree load gives the reference content hash,
--   clone_stored(template, clone) followed by load(clone, {clear_hash_tree=true}, SHARING_ALL) succeeds, gives the
--   reference hash, can deliver an input and run, and leaves the template's contents untouched.
-- A control (the unmodified template) must pass the same procedure, or the test is a setup error (exit 2).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local src = harness.config_dir("baremetal-template") .. "/machine"
    if not io.open(src .. "/config.json", "rb") then harness.setup_error("missing stored machine " .. src) end

    local ok_tmp, tmp = harness.sh("mktemp -d /tmp/r2-dfstored-2.XXXXXX")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok_tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("chmod -R u+w '" .. tmp .. "' 2>/dev/null; rm -rf '" .. tmp .. "'") end
    local function fail_setup(msg)
        cleanup()
        harness.setup_error(msg)
    end
    local function sh(cmd)
        if not os.execute(cmd) then fail_setup("command failed: " .. cmd) end
    end

    local RAM = "0000000080000000-4000000.bin"

    -- Reference content hash, rebuilt from the contents of the untouched template.
    local function rebuilt_hash(dir)
        local m <close> = cartesi.machine(dir, { clear_hash_tree = true }, cartesi.SHARING_NONE)
        return m:get_root_hash()
    end
    local ok_ref, ref = pcall(rebuilt_hash, src)
    if not ok_ref then fail_setup("cannot load template: " .. tostring(ref)) end
    print("reference content hash: 0x" .. harness.hex(ref))

    -- Length of the RAM backing file trimmed after its last non-zero 4 KiB page.
    local function trimmed_length(path)
        local f = assert(io.open(path, "rb"))
        local data = f:read("a")
        f:close()
        local last = #data
        while last > 0 and data:byte(last) == 0 do
            last = last - 1
        end
        local len = ((last + 4095) // 4096) * 4096
        return len, #data
    end

    local variants = {
        { name = "control: unmodified template", control = true, prepare = function() end },
        {
            name = "A: template files read-only (chmod a-w, as tar/OCI packaging or a protected store leaves them)",
            prepare = function(dir) sh("chmod a-w '" .. dir .. "'/*") end,
        },
        {
            name = "B: RAM backing file trimmed after its last non-zero page (same contents, same hash)",
            prepare = function(dir)
                local len, full = trimmed_length(dir .. "/" .. RAM)
                if len >= full then fail_setup("RAM file has no trailing zero page to trim") end
                print(string.format("  trimming %s from %d to %d bytes", RAM, full, len))
                sh(string.format("truncate -s %d '%s/%s'", len, dir, RAM))
            end,
        },
    }

    local all_ok = true
    for i, v in ipairs(variants) do
        print(v.name)
        local tmpl = tmp .. "/tmpl" .. i
        local clone = tmp .. "/clone" .. i
        sh("cp -a --sparse=always '" .. src .. "' '" .. tmpl .. "'")
        v.prepare(tmpl)

        -- Precondition: the variant is the same valid template (unshared O1 load gives the reference hash).
        local ok_pre, h = pcall(rebuilt_hash, tmpl)
        if not ok_pre then fail_setup("variant does not load unshared: " .. tostring(h)) end
        if h ~= ref then fail_setup("variant changes the content hash: 0x" .. harness.hex(h)) end
        print("  unshared load with clear_hash_tree: hash equals reference")

        -- Adoption: clone, then load the clone with sharing and rebuild, as the PRT stored player does.
        local ok_adopt, err = pcall(function()
            cartesi.machine:clone_stored(tmpl, clone)
            local m <close> = cartesi.new()
            m:load(clone, { clear_hash_tree = true }, cartesi.SHARING_ALL)
            local hh = m:get_root_hash()
            if hh ~= ref then error("shared load of the clone gives 0x" .. harness.hex(hh)) end
            -- Use the adopted machine: deliver an input and run to the next yield.
            m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "hello", hh)
            local target = m:read_reg("mcycle") + 100000000
            local br
            repeat
                br = m:run(target) -- automatic yields (output, report) resume
            until br ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then error("guest did not yield manually after the input") end
        end)
        if ok_adopt then
            -- The run on the clone must not have reached the template's contents.
            local ok_after, h2 = pcall(rebuilt_hash, tmpl)
            if not ok_after or h2 ~= ref then
                ok_adopt, err = false, "running the clone changed the template: " .. tostring(ok_after and
                    ("0x" .. harness.hex(h2)) or h2)
            end
        end
        if ok_adopt then
            print("  clone_stored + SHARING_ALL load + run: OK, template untouched")
        else
            print("  clone_stored + SHARING_ALL load + run FAILED: " .. tostring(err))
            if v.control then fail_setup("control variant fails: " .. tostring(err)) end
            -- Informational only (not asserted): the documented workaround, unshared load then store with sharing.
            local stored = tmp .. "/stored" .. i
            local ok_w, err_w = pcall(function()
                do
                    local m <close> = cartesi.machine(tmpl, { clear_hash_tree = true }, cartesi.SHARING_NONE)
                    m:store(stored, cartesi.SHARING_ALL)
                end
                local m <close> = cartesi.new()
                m:load(stored, { clear_hash_tree = true }, cartesi.SHARING_ALL)
                if m:get_root_hash() ~= ref then error("wrong hash") end
            end)
            print("  (info) unshared load + store(SHARING_ALL) + shared load instead: "
                .. (ok_w and "works" or ("fails: " .. tostring(err_w))))
            harness.expect(false, v.name .. ": a valid template must be adoptable by clone + shared load")
            all_ok = false
        end
    end

    cleanup()
    return harness.expect(all_ok,
        "section 8 / R4: attributes outside the hashed state (file mode, file length) of a valid template must not "
            .. "stop the honest operator from adopting it by clone_stored + shared load")
end)
