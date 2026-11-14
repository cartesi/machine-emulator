-- R2-DFINPUT-1: the manual's /dev/cmio section and the emulator disagree on where the host puts the request
-- type when it resumes a guest from an rx-accepted manual yield.
--
-- doc/README.md, "The /dev/cmio device": for HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED "the host sets the `data` field on
-- resume to HTIF_YIELD_REASON_ADVANCE_STATE or HTIF_YIELD_REASON_INSPECT_STATE to indicate the type of the freshly
-- loaded input in the receive buffer".
-- doc/README.md, HTIF yield section: "The `REASON` field in `fromhost` carries the request type, and the `DATA`
-- field carries the request length in bytes."
--
-- The test boots Linux with the pinned machine-guest-tools rootfs and runs, as the entrypoint, the guest-tools
-- `yield` utility (a direct wrapper of IOCTL_CMIO_YIELD on /dev/cmio) with CMT_DEBUG=1, so that libcmt prints the
-- `struct cmio_yield` fields the guest gets back from the ioctl. The host delivers one advance-state input of
-- L bytes (L != 0) through the machine API. The test then asserts that what the guest sees on /dev/cmio, and the
-- fromhost register, satisfy every statement of the manual about that response (R7: "The emulator implements ...
-- the devices as the manual documents them"; the yield interface's "contents, lengths, and reason encoding").
-- Each statement is checked only while the manual still makes it, so the test passes once the manual and the
-- behavior agree (e.g. the /dev/cmio sentence is corrected) and fails while they contradict each other.
local harness = require("harness")

local REPO = os.getenv("REPO") or "../.."
-- R2_DFINPUT_1_MANUAL overrides the manual path (only to check the test against a corrected copy)
local MANUAL = os.getenv("R2_DFINPUT_1_MANUAL") or (REPO .. "/doc/README.md")

-- Normalize the manual text so that line wrapping does not matter.
local function manual_text()
    local ok, s = pcall(harness.read_file, MANUAL)
    if not ok then harness.setup_error("cannot read " .. MANUAL) end
    return (s:gsub("%s+", " "))
end

harness.main(function()
    local cartesi = require("cartesi")
    local manual = manual_text()

    -- The manual statements under test (whitespace-normalized, plain substring search).
    local stmt_devcmio = "the host sets the `data` field on resume to `HTIF_YIELD_REASON_ADVANCE_STATE` or "
        .. "`HTIF_YIELD_REASON_INSPECT_STATE` to indicate the type of the freshly loaded input"
    local stmt_htif = "The `REASON` field in `fromhost` carries the request type, and the `DATA` field carries the "
        .. "request length in bytes"
    local has_devcmio = manual:find(stmt_devcmio, 1, true) ~= nil
    local has_htif = manual:find(stmt_htif, 1, true) ~= nil
    io.stderr:write(string.format("manual: /dev/cmio statement present=%s, HTIF statement present=%s\n",
        tostring(has_devcmio), tostring(has_htif)))
    if not has_devcmio and not has_htif then
        harness.setup_error("neither manual statement found in doc/README.md: the manual was reworded, update the test")
    end

    -- Linux + guest-tools rootfs; the entrypoint performs one manual rx-accepted yield on /dev/cmio and prints
    -- (libcmt debug) the struct it gets back from the ioctl.
    local cfg = harness.config("linux-rootfs")
    cfg.dtb.entrypoint = "CMT_DEBUG=1 yield manual rx-accepted 0"
    local m <close> = harness.machine(cfg, { console = { output_destination = "to_buffer" } })

    local MAX = 2000000000
    local console = {}
    -- Run until a break other than console output (drained into `console`) or a soft/automatic yield.
    local function run()
        while true do
            local br = m:run(MAX)
            console[#console + 1] = m:read_console_output()
            if br ~= cartesi.BREAK_REASON_CONSOLE_OUTPUT and br ~= cartesi.BREAK_REASON_YIELDED_SOFTLY
                and br ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                return br
            end
        end
    end
    local br = run()
    if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
        io.stderr:write(table.concat(console), "\n")
        harness.setup_error("guest did not reach the manual yield (break reason " .. tostring(br) .. ")")
    end
    local tohost = m:read_reg("htif_tohost")
    local reason = (tohost >> 32) & 0xffff
    if reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
        harness.setup_error(string.format("unexpected manual yield reason %d", reason))
    end

    -- One advance-state input, as the host delivers it (any bytes; an EvmAdvance-encoded one for realism).
    local input = harness.encode_advance({ index = 0, payload = string.rep("\x5a", 20) })
    local L = #input
    assert(L ~= cartesi.HTIF_YIELD_REASON_ADVANCE_STATE)
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, m:get_root_hash())
    local fromhost = m:read_reg("htif_fromhost")
    local fh_reason, fh_data = (fromhost >> 32) & 0xffff, fromhost & 0xffffffff
    io.stderr:write(string.format("delivered advance-state input of L=%d bytes; fromhost=0x%016x (REASON=%d DATA=%d)\n",
        L, fromhost, fh_reason, fh_data))

    br = run()
    if br ~= cartesi.BREAK_REASON_HALTED then
        harness.setup_error("guest did not halt after the yield returned (break reason " .. tostring(br) .. ")")
    end
    console = table.concat(console)
    local block = console:match("fromhost%s*{(.-)}")
    if not block then
        io.stderr:write(console, "\n")
        harness.setup_error("libcmt debug output (fromhost struct) not found on the console")
    end
    local g_reason = tonumber(block:match("%.reason%s*=%s*(%-?%d+)"))
    local g_data = tonumber(block:match("%.data%s*=%s*(%-?%d+)"))
    if not (g_reason and g_data) then harness.setup_error("cannot parse the fromhost struct: " .. block) end
    io.stderr:write(string.format("guest /dev/cmio struct cmio_yield after resume: .reason=%d .data=%d\n",
        g_reason, g_data))

    local pass = true
    if has_htif then
        pass = harness.expect(fh_reason == cartesi.HTIF_YIELD_REASON_ADVANCE_STATE and fh_data == L
                and g_reason == cartesi.HTIF_YIELD_REASON_ADVANCE_STATE and g_data == L,
            string.format("manual HTIF section: REASON = request type (%d) and DATA = request length (%d); "
                    .. "observed fromhost REASON=%d DATA=%d, guest .reason=%d .data=%d",
                cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, L, fh_reason, fh_data, g_reason, g_data)) and pass
    end
    if has_devcmio then
        pass = harness.expect(g_data == cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            string.format("manual /dev/cmio section: on resume from rx-accepted the host sets the `data` field to "
                    .. "the request type (HTIF_YIELD_REASON_ADVANCE_STATE = %d); observed guest .data=%d "
                    .. "(the input length), .reason=%d",
                cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, g_data, g_reason)) and pass
    end
    if not pass then
        io.stderr:write("R7 / section 8: the yield interface's reason encoding as the manual documents it does not "
            .. "match what the emulator delivers (the manual contradicts itself and the behavior)\n")
    end
    return pass
end)
