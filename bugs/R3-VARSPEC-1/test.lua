-- R3-VARSPEC-1: the bit layout of the first PMA word that the manual documents does not match the encoding the
-- emulator writes into the guest-readable PMA array.
--
-- Requirement (THREAT_MODEL.md R7): "The emulator implements the RISC-V specification and the devices as the
-- manual documents them, departing only where the manual documents a deviation." (area "Address translation and
-- memory permissions"); R13 lists "The state layout" as part of the transition function; section 8: "A
-- contradiction between the manual and the behavior on a security-relevant point is a defect in one of the two."
-- The manual (doc/README.md, "PMAs") documents the first PMA word, "readable both internally and externally", as
--   bits 63-12 start | 11-8 DID | 7 IW | 6 IR | 5 X | 4 W | 3 R | 2 E | 1 IO | 0 M
-- with "The M, IO, and E bits are mutually exclusive", and the DID values PMA_MEMORY_DID = 1,
-- PMA_FLASH_DRIVE_DID = 3, PMA_CMIO_RX_BUFFER_DID = 7, ...
--
-- Asserted: an M-mode guest that loads each PMA istart word from the PMA array (0x10000), natively and through
-- the uarch, and decodes it with the manual's table, finds
--   * no entry with more than one of M, IO, E set;
--   * RAM (0x80000000): M=1, E=0, R=W=X=1, DID=PMA_MEMORY_DID (1);
--   * the read-only flash drive (0x100000000): M=1, R=1, W=0, X=0, DID=PMA_FLASH_DRIVE_DID (3);
--   * the cmio rx buffer (0x60000000): M=1, R=1, W=0, X=0, DID=PMA_CMIO_RX_BUFFER_DID (7).
-- Exit 1 if any fails (today: the emulator packs M=0 IO=1 R=2 W=3 X=4 IR=5 IW=6 DID=7..11, no E bit),
-- 0 once code and manual agree, 2 on setup errors (including native/uarch/read_word disagreement).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local FLASH = 0x100000000
    local RX = 0x60000000
    local NENT = 12 -- entries the guest reads (array ends with a zero entry well before this)
    local PMAS = cartesi.AR_PMAS_START
    if PMAS ~= 0x10000 then harness.setup_error(string.format("AR_PMAS_START=0x%x, manual says 0x10000", PMAS)) end

    -- guest: lui x5, 0x10 ; ld x(6+i), 16*i(x5) for i = 0..NENT-1 ; j .
    local function ld(rd, rs1, imm) return (imm << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03 end
    local words = { (0x10 << 12) | (5 << 7) | 0x37 }
    for i = 0, NENT - 1 do words[#words + 1] = ld(6 + i, 5, 16 * i) end
    words[#words + 1] = 0x0000006f
    local prog = string.pack("<" .. string.rep("I4", #words), table.unpack(words))
    local nsteps = 1 + NENT

    local function guest_read(use_uarch)
        local m <close> = cartesi.machine({
            ram = { length = 1 << 20 },
            flash_drive = { { start = FLASH, length = 1 << 20, read_only = true } },
        })
        m:write_memory(RAM, prog)
        m:write_reg("mtvec", RAM + 4 * (#words - 1)) -- any trap parks on the final loop
        local mc = m:read_reg("mcycle")
        if use_uarch then
            for _ = 1, nsteps do
                if m:run_uarch() ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
                    harness.setup_error("uarch did not halt")
                end
                m:reset_uarch()
            end
        else
            m:run(mc + nsteps)
        end
        if m:read_reg("mcycle") ~= mc + nsteps then harness.setup_error("did not complete the guest's mcycles") end
        if m:read_reg("mcause") ~= 0 then
            harness.setup_error(string.format("guest trapped reading the PMA array (mcause=%d)", m:read_reg("mcause")))
        end
        local vals = {}
        for i = 0, NENT - 1 do
            local v = m:read_reg("x" .. (6 + i))
            if v ~= m:read_word(PMAS + 16 * i) then
                harness.setup_error(string.format("guest load of entry %d differs from read_word", i))
            end
            vals[i] = v
        end
        return vals
    end

    local native = guest_read(false)
    local uarch = guest_read(true)
    for i = 0, NENT - 1 do
        if native[i] ~= uarch[i] then harness.setup_error("native and uarch guest reads differ at entry " .. i) end
    end

    -- decode with the manual's table, parsed from doc/README.md ("PMAs", first word), so that a fix of either the
    -- code or the manual makes the test pass
    local layout = {} -- field -> { lo, hi }
    do
        -- MANUAL_OVERRIDE: path of an alternative manual, only to check that a manual fix makes the test pass
        local doc = harness.read_file(os.getenv("MANUAL_OVERRIDE") or (harness.REPO .. "/doc/README.md"))
        local lines = {}
        for l in doc:gmatch("[^\n]*") do lines[#lines + 1] = l end
        local function cells(l)
            local t = {}
            for c in l:gmatch("|([^|]*)") do
                c = c:gsub("^%s+", ""):gsub("%s+$", ""):gsub("`", "")
                if c ~= "" then t[#t + 1] = c end
            end
            return t
        end
        for i = 1, #lines - 2 do
            if lines[i]:match("^| Bits") and lines[i + 2]:match("^| Field") and lines[i + 2]:match("`DID`")
                and lines[i + 2]:match("`start`") then
                local bits, fields = cells(lines[i]), cells(lines[i + 2])
                if #bits ~= #fields then harness.setup_error("malformed PMA table in the manual") end
                for k = 2, #bits do
                    local hi, lo = bits[k]:match("^(%d+)%-(%d+)$")
                    if not hi then hi = bits[k]:match("^(%d+)$"); lo = hi end
                    if not hi then harness.setup_error("cannot parse PMA table bits '" .. bits[k] .. "'") end
                    layout[fields[k]] = { tonumber(lo), tonumber(hi) }
                end
                break
            end
        end
        for _, f in ipairs({ "start", "DID", "M", "IO", "R", "W", "X" }) do
            if not layout[f] then harness.setup_error("manual's PMA table has no field " .. f) end
        end
        local desc = {}
        for f, r in pairs(layout) do desc[#desc + 1] = string.format("%s=%d-%d", f, r[2], r[1]) end
        table.sort(desc)
        print("manual PMA first-word layout: " .. table.concat(desc, " "))
    end
    local function manual(w)
        local d = {}
        for f, r in pairs(layout) do
            local width = r[2] - r[1] + 1
            d[f] = (w >> r[1]) & ((1 << width) - 1)
        end
        d.start = w & ~0xfff
        d.E = d.E or 0 -- a layout without an E bit has no excluded ranges
        d.IR = d.IR or 0
        d.IW = d.IW or 0
        return d
    end

    local ok = true
    local function check(cond, what)
        if not cond then ok = false end
        harness.expect(cond, what)
    end
    local by_start = {}
    for i = 0, NENT - 1 do
        local w = native[i]
        if w == 0 then break end
        local d = manual(w)
        by_start[d.start] = d
        print(string.format("entry %2d istart=0x%016x  manual decode: M=%d IO=%d E=%d R=%d W=%d X=%d IR=%d IW=%d DID=%d",
            i, w, d.M, d.IO, d.E, d.R, d.W, d.X, d.IR, d.IW, d.DID))
        check(d.M + d.IO + d.E <= 1,
            string.format("entry %d (start 0x%x): manual says M, IO and E are mutually exclusive", i, d.start))
    end
    local function expect_range(name, start, want)
        local d = by_start[start]
        if not d then harness.setup_error(string.format("no PMA entry starts at 0x%x (%s)", start, name)) end
        for _, f in ipairs({ "M", "IO", "E", "R", "W", "X", "DID" }) do
            if want[f] ~= nil then
                check(d[f] == want[f], string.format("%s: manual-decoded %s=%d, required %d", name, f, d[f], want[f]))
            end
        end
    end
    expect_range("RAM", RAM, { M = 1, IO = 0, E = 0, R = 1, W = 1, X = 1, DID = 1 })
    expect_range("read-only flash drive", FLASH, { M = 1, IO = 0, E = 0, R = 1, W = 0, X = 0, DID = 3 })
    expect_range("cmio rx buffer", RX, { M = 1, IO = 0, E = 0, R = 1, W = 0, X = 0, DID = 7 })

    return harness.expect(ok, "R7/R13: the PMA words the guest reads follow the manual's documented layout")
end)
