-- R3-VARSHADOW-1: the guard that keeps HTIF console input (the hashed htif_iconsole GETCHAR bit, or a non-null
-- console input source) out of reproducible machines runs only at create/load (machine::init_console).
-- write_reg("htif_iconsole", ...), the full-shadow write_memory and set_runtime_config{console={input_source=...}}
-- are accepted afterwards on a reproducible machine. Then a GETCHAR request makes the native interpreter put a host
-- byte in fromhost, while the uarch and collect_mcycle_root_hashes (non-interactive state accesses) put 0; host
-- console input reaches the hashed state; and store writes a directory that load refuses.
--
-- Asserted (THREAT_MODEL R2: native interpretation, the uarch plus reset and the computation-hash builders "must
-- agree on its canonical hash", and "Every register and every configuration value that affects a transition has one
-- source of truth in the hashed state, and every path reads it from there"; R14: "In a reproducible machine, the host
-- reaches the state only through deliveries and deliberate changes through the machine API. That rules out host
-- devices, any other host input"; R9 / section 8 Medium: "a stored directory inconsistent with the machine's
-- contents"). For each trigger: either it is refused on a reproducible machine, or, once accepted,
--   (a) native run, run_uarch+reset_uarch and collect_mcycle_root_hashes reach the same root hash at the halt,
--   (b) bytes given with write_console_input do not change the hashed state,
--   (c) store refuses, or writes a directory that loads back with the same root hash.
local harness = require("harness")

-- getchar.S assembled (rv64): tohost <- console GETCHAR; a0 <- fromhost; tohost <- halt(0); j .
local GUEST = harness.unhex("b78200401303100013138303" .. "23b06200" .. "03b58200" .. "13031000" .. "23b06200" .. "6f000000")

harness.main(function()
    local cartesi = require("cartesi")
    local GETCHAR = 1 << cartesi.HTIF_CONSOLE_CMD_GETCHAR

    local ok_tmp, tmp = harness.sh("mktemp -d /tmp/r3-varshadow-1.XXXXXX")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok_tmp or not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local f = io.open(tmp .. "/getchar.bin", "wb")
    if not f then cleanup(); harness.setup_error("cannot write guest") end
    f:write(GUEST); f:close()

    local cfg = { ram = { length = 4 << 20, backing_store = { data_filename = tmp .. "/getchar.bin" } } }

    local violations = {}
    local function violation(msg)
        violations[#violations + 1] = msg
        print("VIOLATION: " .. msg)
    end

    -- the three API operations that set the GETCHAR bit / an input source after creation
    local function trig_write_reg(m)
        m:write_reg("htif_iconsole", m:read_reg("htif_iconsole") | GETCHAR)
    end
    local function trig_write_memory(m)
        local shadow = m:read_memory(cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_STATE_LENGTH)
        local off = m:get_reg_address("htif_iconsole") - cartesi.AR_SHADOW_STATE_START
        local v = string.unpack("<I8", shadow, off + 1) | GETCHAR
        shadow = shadow:sub(1, off) .. string.pack("<I8", v) .. shadow:sub(off + 9)
        m:write_memory(cartesi.AR_SHADOW_STATE_START, shadow)
    end

    local function run_native(m)
        m:run(1000)
        return m
    end
    local function run_uarch(m)
        for _ = 1, 100 do
            if m:read_reg("iflags_H") ~= 0 then break end
            m:run_uarch(cartesi.UARCH_CYCLE_MAX)
            m:reset_uarch()
        end
        return m
    end
    local function run_collect(m)
        m:collect_mcycle_root_hashes(1000, 1, 0, 0)
        return m
    end

    -- run the guest to its halt along one path, after an optional trigger; returns root hash and fromhost
    local function reach_halt(trigger, path)
        local m <close> = cartesi.machine(cfg, {})
        if trigger then trigger(m) end
        path(m)
        if m:read_reg("iflags_H") == 0 then harness.setup_error("guest did not halt") end
        return m:get_root_hash(), m:read_reg("htif_fromhost")
    end

    local ok_run, err = pcall(function()
        -- preconditions: the guard exists at creation, the machine is reproducible, and all paths agree without
        -- a trigger
        local okc, errc = pcall(function()
            local m <close> = cartesi.machine({ ram = cfg.ram,
                processor = { registers = { htif = { iconsole = GETCHAR } } } }, {})
        end)
        print("create reproducible machine with GETCHAR enabled: " .. (okc and "accepted" or ("refused: " .. tostring(errc))))
        do
            local m <close> = cartesi.machine(cfg, {})
            if m:read_reg("iunrep") ~= 0 then harness.setup_error("machine is not reproducible") end
        end
        local hn, hu, hc = reach_halt(nil, run_native), reach_halt(nil, run_uarch), reach_halt(nil, run_collect)
        if hn ~= hu or hn ~= hc then harness.setup_error("control: paths disagree without any trigger") end
        print("control (no trigger): native == uarch == collect at the halt")

        for _, t in ipairs({ { "write_reg('htif_iconsole', iconsole|GETCHAR)", trig_write_reg },
                             { "write_memory(full shadow with iconsole|GETCHAR)", trig_write_memory } }) do
            local name, trig = t[1], t[2]
            local okt, errt = pcall(function()
                local m <close> = cartesi.machine(cfg, {})
                trig(m)
            end)
            if not okt then
                print(name .. ": refused: " .. tostring(errt))
            else
                print(name .. ": accepted on a reproducible machine")
                local rn, fn = reach_halt(trig, run_native)
                local ru, fu = reach_halt(trig, run_uarch)
                local rc, fc = reach_halt(trig, run_collect)
                print(string.format("  fromhost at halt: native 0x%016x, uarch 0x%016x, collect 0x%016x", fn, fu, fc))
                if rn ~= ru then violation(name .. ": native and uarch+reset root hashes differ at the halt (R2)") end
                if rn ~= rc then violation(name .. ": native and collect_mcycle_root_hashes differ at the halt (R2)") end
                -- (c) store / load
                local dir = tmp .. "/stored"
                os.execute("rm -rf '" .. dir .. "'")
                local m <close> = cartesi.machine(cfg, {})
                trig(m)
                local h = m:get_root_hash()
                local oks, errs = pcall(function() m:store(dir) end)
                if not oks then
                    print("  store refused: " .. tostring(errs))
                else
                    local okl, hl = pcall(function()
                        local l <close> = cartesi.machine(dir, {})
                        return l:get_root_hash()
                    end)
                    if not okl then
                        print("  store succeeded; load refused: " .. tostring(hl))
                        violation(name .. ": store wrote a directory that load refuses (R9)")
                    elseif hl ~= h then
                        violation(name .. ": stored directory loads with a different root hash (R9)")
                    else
                        print("  store/load round trip keeps the root hash")
                    end
                end
                os.execute("rm -rf '" .. dir .. "'")
            end
        end

        -- (b) host console input on a reproducible machine
        local okr, errr = pcall(function()
            local m <close> = cartesi.machine(cfg, {})
            m:set_runtime_config({ console = { input_source = "from_buffer" } })
        end)
        if not okr then
            print("set_runtime_config{console={input_source='from_buffer'}}: refused: " .. tostring(errr))
        else
            print("set_runtime_config{console={input_source='from_buffer'}}: accepted on a reproducible machine")
            local function with_input(bytes)
                local m <close> = cartesi.machine(cfg, {})
                m:set_runtime_config({ console = { input_source = "from_buffer" } })
                pcall(trig_write_reg, m) -- may be refused by a fix; then no getchar can happen
                pcall(function() m:write_console_input(bytes) end)
                for _ = 1, 5 do -- resume after console-input breaks, up to the halt
                    m:run(1000)
                    if m:read_reg("iflags_H") ~= 0 then break end
                end
                return m:get_root_hash(), m:read_reg("htif_fromhost"), m:read_reg("iflags_H")
            end
            local ra, fa, ha = with_input("A")
            local rz, fz, hz = with_input("Z")
            print(string.format("  fromhost after host input 'A': 0x%016x (H=%d); after 'Z': 0x%016x (H=%d)", fa, ha, fz, hz))
            if ra ~= rz then
                violation("host console input reaches the hashed state of a reproducible machine (R14)")
            end
        end
    end)
    cleanup()
    if not ok_run then error(err, 0) end
    if #violations > 0 then
        print(string.format("%d violation(s)", #violations))
        return false
    end
    print("no violation: console input is refused or kept out of the reproducible machine on every path")
    return true
end)
