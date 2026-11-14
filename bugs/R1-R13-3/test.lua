-- R1-R13-3: can the machine-identification registers of this build be confused with those of a released
-- version whose state transition function differs?
--
-- R13: "Every version that changes the state transition function changes the machine-identification registers
-- in the hashed state. The honest operator must be able to detect and refuse a mismatch between its build and a
-- deployment. The check must refuse every pairing of its build with a deployment of another released version."
--
-- The released versions are taken from the records available to this audit:
--   * the pinned machine-solidity-step history (Dave's machine/step clone, v0.16.0 with history), which pins one
--     released emulator tag per commit and carries its generated UARCH_PRISTINE_STATE_HASH (and CM_MARCHID from
--     v0.21.0 on);
--   * machine-solidity-step v0.17.0-test1 (released, generated for emulator v0.23.0-test2);
--   * this branch's CHANGELOG.md ("Bumped MARCHID version to N" once per minor release).
-- A different pristine uarch hash means a different uarch program, which R13 lists as part of the STF.
--
-- Asserted (exit 1 if violated): for every released version on record whose pristine hash differs from this
-- build's, this build's (mvendorid, marchid, mimpid) differ from every value that version can carry, and the
-- emulator refuses to create a machine carrying that version's registers.
-- Reported, not asserted: pairs of released versions (other than this build) that share registers while their
-- STF differs. No change to audit/prt2 can alter those past releases.

local harness = require("harness")

local function sh(cmd)
    local p = assert(io.popen(cmd .. " 2>/dev/null"))
    local out = p:read("a")
    local ok = p:close()
    return ok and out or nil
end

harness.main(function()
    local cartesi = require("cartesi")
    local work = os.getenv("HARNESS_WORK") or harness.setup_error("HARNESS_WORK not set")
    local mss = work .. "/dave/src/machine/step" -- pinned machine-solidity-step clone with history
    local mss_rel = work .. "/solidity-step/released" -- v0.17.0-test1, untouched

    -- Read one released record: the emulator tag a machine-solidity-step tree pins, its pristine hash and marchid.
    local function record_from(text_mk, text_consts, source)
        local ver = text_mk:match("\nEMULATOR_VERSION %?= (%S+)")
        local tag = text_mk:match("\nEMULATOR_TAG %?=[ \t]*([^\n]*)") or ""
        local hash = text_consts:match("UARCH_PRISTINE_STATE_HASH =%s*0x(%x+)")
        local marchid = text_consts:match("CM_MARCHID = (%d+)")
        if not (ver and hash) then harness.setup_error("cannot parse record from " .. source) end
        return { version = ver .. tag, hash = hash, marchid = marchid and tonumber(marchid), source = source }
    end

    local records, seen = {}, {}
    local revs = sh("git -C '" .. mss .. "' rev-list --reverse c87c24c^..fb00a32 -- Makefile src/EmulatorConstants.sol")
    if not revs then harness.setup_error("pinned machine-solidity-step history not found at " .. mss) end
    for c in revs:gmatch("%x+") do
        local mk = sh("git -C '" .. mss .. "' show " .. c .. ":Makefile")
        local k = sh("git -C '" .. mss .. "' show " .. c .. ":src/EmulatorConstants.sol")
        if not (mk and k) then harness.setup_error("cannot read " .. c) end
        local r = record_from(mk, k, "machine-solidity-step " .. c:sub(1, 7))
        -- keep the record of the commit that switched to the tag (regenerated against that release); a later
        -- commit on the same tag only contributes CM_MARCHID when its pristine hash is the same
        local i = seen[r.version]
        if not i then
            records[#records + 1] = r
            seen[r.version] = #records
        elseif records[i].hash == r.hash and r.marchid then
            records[i].marchid = r.marchid
            records[i].source = records[i].source .. "+" .. r.source:sub(-7)
        end
    end
    local r17 = record_from(harness.read_file(mss_rel .. "/Makefile"),
        harness.read_file(mss_rel .. "/src/EmulatorConstants.sol"), "machine-solidity-step v0.17.0-test1")
    records[#records + 1] = r17

    -- MARCHID per minor from CHANGELOG.md: "Bumped MARCHID version to N" inside "## [0.N.0]".
    local changelog = harness.read_file(os.getenv("REPO") .. "/CHANGELOG.md")
    local bumped = {}
    local cur
    for line in changelog:gmatch("[^\n]+") do
        local v = line:match("^## %[(%d+%.%d+)%.%d+%]")
        if v then cur = v end
        local n = line:match("Bumped MARCHID version to (%d+)")
        if n and cur then bumped[cur] = tonumber(n) end
    end

    -- Possible register values of a released version: mvendorid is constant, mimpid = major*1000+minor
    -- (CHANGELOG 0.15.2: the patch no longer affects the root hash; the label is never encoded).
    -- marchid: the record's CM_MARCHID when it publishes one; otherwise, for a pre-release of minor N, any value
    -- between the marchid of release N-1 and the one release N bumped to.
    local function possible(r)
        local maj, min = r.version:match("^v(%d+)%.(%d+)%.")
        maj, min = tonumber(maj), tonumber(min)
        local mimpid = maj * 1000 + min
        local lo, hi
        if r.marchid then lo, hi = r.marchid, r.marchid else
            lo = bumped[maj .. "." .. (min - 1)] or 0
            hi = bumped[maj .. "." .. min] or math.huge
        end
        return mimpid, lo, hi
    end

    local mine = { mvendorid = cartesi.MVENDORID, marchid = cartesi.MARCHID, mimpid = cartesi.MIMPID,
        hash = harness.hex(cartesi.UARCH_PRISTINE_STATE_HASH), version = cartesi.VERSION }
    print(string.format("this build: %s marchid=%d mimpid=%d pristine=0x%s", mine.version, mine.marchid,
        mine.mimpid, mine.hash))

    local violations = {}
    for _, r in ipairs(records) do
        local mimpid, lo, hi = possible(r)
        local differs = r.hash ~= mine.hash
        local collide = mimpid == mine.mimpid and lo <= mine.marchid and mine.marchid <= hi
        print(string.format("released %-14s pristine=0x%s.. mimpid=%d marchid in [%s,%s]  (%s)%s", r.version,
            r.hash:sub(1, 8), mimpid, lo, hi, r.source,
            differs and (collide and "  <-- SAME REGISTERS, DIFFERENT STF" or "") or "  (same uarch program)"))
        if differs and collide then violations[#violations + 1] = r.version end
        -- the emulator must refuse a machine carrying this version's registers (create checks them)
        if differs and (mimpid ~= mine.mimpid or lo ~= mine.marchid or hi ~= mine.marchid) then
            local regs = { mimpid = mimpid }
            if mimpid == mine.mimpid then regs.marchid = (lo ~= mine.marchid) and lo or hi end
            local ok = pcall(function()
                local m <close> = cartesi.machine({ processor = { registers = regs }, ram = { length = 1 << 20 } })
            end)
            if ok then violations[#violations + 1] = r.version .. " (registers accepted at creation)" end
        end
    end

    -- Informational: released versions other than this build that share registers while their STF differs.
    local hist = {}
    for i = 1, #records do
        for j = i + 1, #records do
            local a, b = records[i], records[j]
            local ma, la, ha = possible(a)
            local mb, lb, hb = possible(b)
            if a.hash ~= b.hash and ma == mb and math.max(la, lb) <= math.min(ha, hb) then
                hist[#hist + 1] = a.version .. "/" .. b.version
            end
        end
    end
    -- Pigeonhole over each minor: more distinct uarch programs than possible marchid values forces a collision.
    local by_minor = {}
    for _, r in ipairs(records) do
        local mimpid, lo, hi = possible(r)
        local g = by_minor[mimpid] or { hashes = {}, n = 0, lo = lo, hi = hi }
        by_minor[mimpid] = g
        if not g.hashes[r.hash] then g.hashes[r.hash], g.n = true, g.n + 1 end
        g.lo, g.hi = math.min(g.lo, lo), math.max(g.hi, hi)
    end
    for mimpid, g in pairs(by_minor) do
        if g.hi - g.lo + 1 < g.n then
            print(string.format("note: %d released uarch programs with mimpid %d but marchid only in [%d,%d]: at " ..
                "least two released versions with different STF share all identification registers", g.n, mimpid,
                g.lo, g.hi))
        end
    end
    if #hist > 0 then
        print("note: released pairs whose registers may coincide although their uarch programs differ (marchid of a")
        print("      pre-release is not published; past releases, not a property of this build): " ..
            table.concat(hist, ", "))
    end

    return harness.expect(#violations == 0,
        "R13: this build's identification registers must differ from those of every released version with a " ..
        "different STF, and creation must refuse them" .. (#violations > 0 and (": " ..
        table.concat(violations, ", ")) or ""))
end)
