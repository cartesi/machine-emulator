-- R1-R14-2: the manual does not state the host requirement that output channels such as the console
-- accept every write the emulator makes, blocking if needed.
--
-- THREAT_MODEL.md section 4 ("The operator's host is provisioned"): "Host output channels, such as the
-- console, accept every write the emulator makes, blocking if needed, and the manual must state this
-- requirement."
--
-- Assertion (decides the exit status): doc/README.md has a paragraph that speaks of the console or of a host
-- output channel, of blocking, and of writes. Exit 1 when no such paragraph exists, 0 once one does.
--
-- Context (printed, never decides the exit status): why the statement matters. A bare-metal guest that prints
-- 262144 line feeds runs to its halt with the console to_null, but with the console wired (to_fd) to a
-- non-blocking pipe that nobody reads, machine:run() raises "console output flush failed" once the pipe fills.
-- The threat model allows a host fault to stop the honest operator, so this is not asserted; it only shows that
-- the emulator relies on the undocumented requirement.

local harness = require("harness")

local function manual_paragraphs(path)
    local text = harness.read_file(path)
    text = text:gsub("\r", "")
    -- strip blockquote markers so quoted paragraphs read as plain ones
    text = ("\n" .. text):gsub("\n[ \t]*>[ \t]?", "\n")
    local paras = {}
    for para in (text .. "\n\n"):gmatch("(.-)\n[ \t]*\n") do
        local p = para:gsub("%s+", " "):lower()
        if p:match("%S") then
            paras[#paras + 1] = p
        end
    end
    return paras
end

local function any(s, pats)
    for _, pat in ipairs(pats) do
        if s:find(pat) then
            return true
        end
    end
    return false
end

-- A paragraph states the requirement when it names the console or a host output channel, speaks of blocking,
-- and speaks of the writes the emulator makes.
local function states_requirement(p)
    local channel = any(p, { "console", "output channel", "output destination", "output_destination" })
    -- remove the unrelated uses of "block" before looking for blocking
    local q = p:gsub("blockchains?", ""):gsub("block[ _-]?device", ""):gsub("block[ _-]?size", "")
    q = q:gsub("block[ _-]?number", ""):gsub("block[ _-]?timestamp", ""):gsub("blocks? of", "")
    local blocking = any(q, { "%f[%a]block%f[%A]", "%f[%a]blocks%f[%A]", "%f[%a]blocking", "%f[%a]blocked",
        "non%-?blocking" })
    local writes = any(p, { "%f[%a]writ" })
    return channel and blocking and writes
end

-- Hand-assembled RV64 guest: print '\n' 262144 times through HTIF putchar, then halt.
local function putchar_guest()
    local function u32(x) return string.pack("<I4", x & 0xffffffff) end
    local function itype(op, rd, f3, rs1, imm)
        return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
    end
    local function utype(op, rd, imm20) return (imm20 << 12) | (rd << 7) | op end
    local function stype(rs1, rs2, f3, imm)
        return (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 0x1f) << 7) | 0x23
    end
    local function btype(rs1, rs2, f3, imm)
        imm = imm & 0x1fff
        return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12)
            | (((imm >> 1) & 0xf) << 8) | (((imm >> 11) & 1) << 7) | 0x63
    end
    return table.concat({
        u32(utype(0x37, 5, 0x40008)), -- lui  t0, 0x40008        (HTIF tohost, AR_HTIF_START)
        u32(itype(0x13, 6, 0, 0, 0x101)), -- addi t1, x0, 0x101
        u32(itype(0x13, 6, 1, 6, 48)), -- slli t1, t1, 48         (dev console, cmd putchar)
        u32(itype(0x13, 6, 0, 6, 10)), -- addi t1, t1, '\n'
        u32(utype(0x37, 7, 0x40)), -- lui  t2, 0x40           (262144 iterations)
        u32(stype(5, 6, 3, 0)), -- loop: sd t1, 0(t0)
        u32(itype(0x13, 7, 0, 7, -1)), -- addi t2, t2, -1
        u32(btype(7, 0, 1, -8)), -- bne  t2, x0, loop
        u32(itype(0x13, 28, 0, 0, 1)), -- addi t3, x0, 1
        u32(stype(5, 28, 3, 0)), -- sd   t3, 0(t0)          (halt)
        u32(0x6f), -- j .
    })
end

local function context_demo()
    local cartesi = require("cartesi")
    local ok_u, unistd = pcall(require, "posix.unistd")
    local ok_f, fcntl = pcall(require, "posix.fcntl")
    local code = putchar_guest()
    local function run_with(console)
        local m <close> = cartesi.machine({ ram = { length = 0x400000 } }, { console = console })
        m:write_memory(cartesi.AR_RAM_START or 0x80000000, code)
        local ok, res = pcall(m.run, m, math.maxinteger)
        local halted = m:read_reg("iflags_H")
        return ok, res, halted, m:read_reg("mcycle")
    end
    local ok, res, halted, mcycle = run_with({ output_destination = "to_null" })
    print(string.format("context: console to_null: run ok=%s break_reason=%s halted=%s mcycle=%s", tostring(ok),
        tostring(res), tostring(halted), tostring(mcycle)))
    if not (ok_u and ok_f) then
        print("context: lua-posix not available, non-blocking pipe demonstration skipped")
        return
    end
    local rfd, wfd = unistd.pipe()
    if not rfd then
        print("context: pipe() failed, demonstration skipped")
        return
    end
    fcntl.fcntl(wfd, fcntl.F_SETFL, fcntl.O_NONBLOCK)
    local ok2, res2, halted2, mcycle2 = run_with({ output_destination = "to_fd", output_fd = wfd })
    unistd.close(wfd)
    unistd.close(rfd)
    print(string.format(
        "context: console to_fd on a non-blocking pipe nobody reads: run ok=%s result=%s halted=%s mcycle=%s",
        tostring(ok2), tostring(res2), tostring(halted2), tostring(mcycle2)))
end

harness.main(function()
    -- detector sanity: the threat model's own sentence must count as a statement, and an unrelated one must not
    local sample = "host output channels, such as the console, accept every write the emulator makes, " ..
        "blocking if needed."
    if not states_requirement(sample) or states_requirement("the console prints to the blockchain block number") then
        harness.setup_error("requirement detector self-check failed")
    end
    -- R1_R14_2_MANUAL lets a reviewer point the check at an edited copy of the manual
    local manual = os.getenv("R1_R14_2_MANUAL") or ((os.getenv("REPO") or "../..") .. "/doc/README.md")
    local paras = manual_paragraphs(manual)
    if #paras < 100 then
        harness.setup_error("could not read the manual " .. manual)
    end

    local ok, err = pcall(context_demo)
    if not ok then
        print("context: demonstration failed to run (ignored): " .. tostring(err))
    end

    local hits = {}
    for i, p in ipairs(paras) do
        if states_requirement(p) then
            hits[#hits + 1] = i
        end
    end
    print(string.format("manual: %d paragraphs scanned, %d state the host output-channel requirement", #paras,
        #hits))
    for _, i in ipairs(hits) do
        print("  paragraph " .. i .. ": " .. paras[i]:sub(1, 200))
    end
    return harness.expect(#hits > 0,
        "THREAT_MODEL section 4: host output channels, such as the console, accept every write the emulator " ..
            "makes, blocking if needed, and the manual must state this requirement (doc/README.md must state it)")
end)
