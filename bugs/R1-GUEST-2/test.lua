-- R1-GUEST-2: the machine-guest-tools `rollup` CLI (v0.18.1-test1, the rootfs pinned by the harness) in
-- `--utf8-payload` mode cannot represent an advance-state payload that is not valid UTF-8. `rollup accept`
-- (likewise reject/finish) first yields manually with the accepted reason and receives the next input, and only
-- then builds its JSON output: nlohmann::json::dump (strict error handler) throws type_error.316, the tool prints
-- the exception to stderr, prints NO request on stdout and exits 1. The input has been delivered and is gone, but
-- the application never sees it and cannot tell this failure from a failed yield.
--
-- Requirement (THREAT_MODEL.md, section 2, "Correctly designed application"): "On every input sequence, its guest
-- follows the rollup interface that the manual specifies. After each input, it yields manually with the accepted or
-- the rejected reason." Section 3, Guest software: "A defect that lets an input make such an application deviate
-- from the rollup interface is Critical, as an R7 deviation in the rx buffer, the tx buffer and the yield
-- interface." `rollup --help` documents, for every command and in every payload encoding, that "<data> contains
-- arbitrary data in the selected payload encoding", and that `finish`/`accept`/`reject` "print the next request
-- to stdout"; the manual's calculator (doc/README.md) uses `rollup --utf8-payload`. (The manual's
-- cartesi-rollup-data.lua section advises hex/base64 "when payloads contain arbitrary binary data rather than
-- text": recorded in README.md; it decides severity, not reproduction.)
--
-- The test boots Linux with the pinned guest-tools rootfs (harness config `linux-rootfs`) and runs, as the
-- entrypoint, an echo application that uses only documented `rollup --utf8-payload` commands and checks their exit
-- status: it prints each request, emits its payload as a notice and accepts; if `rollup accept/reject` does not
-- give it the next request, it stops (exit 3, cartesi-init then halts the machine).
-- Inputs: (1) "hello" (control), (2) "h\xc3\xa9llo" (valid non-ASCII UTF-8, control), (3) "h\xffllo" (invalid
-- UTF-8: any input sender may send it), (4) "bye" if the machine still waits.
-- Asserted: after each delivered input the machine reaches a manual yield with the accepted or the rejected
-- reason (not a halt), i.e. the application keeps following the rollup interface.
--
-- A second run (informative, not asserted) uses the alternative error handling (retry `rollup accept` when it
-- fails) and shows that the tool then accepts input 3 without the application ever seeing it (no notice).
--
-- Exit 1: the machine halts after input 3; the console shows the tool's type_error.316 (bug present).
-- Exit 0: every input ends at an accepted/rejected manual yield.
-- Exit 2: setup error (the controls are not accepted with one notice each, boot fails, ...).
local harness = require("harness")

local APP_STOP = [[
s=accept
while :; do
    if ! rollup --utf8-payload "$s" > /tmp/req; then
        echo "app: rollup --utf8-payload $s failed: no request obtained, stopping"
        exit 3
    fi
    echo "app: got request payload $(jq -c .data.payload /tmp/req)"
    s=reject
    jq -c '{payload: .data.payload}' /tmp/req | rollup --utf8-payload notice > /dev/null && s=accept
done
]]

local APP_RETRY = [[
s=accept
while :; do
    until rollup --utf8-payload "$s" > /tmp/req; do
        echo "app: rollup --utf8-payload $s failed: no request obtained, retrying"
    done
    echo "app: got request payload $(jq -c .data.payload /tmp/req)"
    s=reject
    jq -c '{payload: .data.payload}' /tmp/req | rollup --utf8-payload notice > /dev/null && s=accept
done
]]

local PAYLOADS = { "hello", "h\xc3\xa9llo", "h\xffllo", "bye" }
local BAD = 3

harness.main(function()
    local cartesi = require("cartesi")
    local MAX = math.maxinteger

    local function run_app(app, tag)
        local cfg = harness.config("linux-rootfs")
        cfg.dtb.entrypoint = app
        local m <close> = harness.machine(cfg, { console = { output_destination = "to_buffer" } })
        local console = {}
        local outputs
        local function run()
            while true do
                local br = m:run(MAX)
                console[#console + 1] = m:read_console_output()
                if br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                    local _, reason, data = m:receive_cmio_request()
                    if reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then outputs[#outputs + 1] = data end
                elseif br ~= cartesi.BREAK_REASON_CONSOLE_OUTPUT and br ~= cartesi.BREAK_REASON_YIELDED_SOFTLY then
                    return br
                end
            end
        end
        local results = {}
        for step = 0, #PAYLOADS do
            if step > 0 then
                m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
                    harness.encode_advance({ index = step - 1, payload = PAYLOADS[step] }), m:get_root_hash())
            end
            outputs = {}
            local br = run()
            local r = { step = step, noutputs = #outputs }
            if br == cartesi.BREAK_REASON_HALTED then
                r.what = "halted"
            elseif br == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                local _, reason = m:receive_cmio_request()
                if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                    r.what = "accepted"
                elseif reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
                    r.what = "rejected"
                else
                    r.what = "manual yield reason " .. reason
                end
            else
                r.what = "break reason " .. br
            end
            results[step] = r
            io.stderr:write(string.format("%s %s: %s, %d output(s) emitted\n", tag,
                step == 0 and "template" or string.format("input %d (payload %q)", step, PAYLOADS[step]), r.what,
                r.noutputs))
            if step == 0 and r.what ~= "accepted" then
                io.stderr:write(table.concat(console), "\n")
                harness.setup_error(tag .. " boot did not reach an rx-accepted manual yield")
            end
            if r.what ~= "accepted" and r.what ~= "rejected" then break end
        end
        local text = table.concat(console)
        for line in text:gmatch("[^\r\n]+") do
            if line:find("app: ", 1, true) or line:find("json.exception", 1, true) then
                io.stderr:write(tag, " guest console: ", line, "\n")
            end
        end
        return results, text
    end

    -- controls in the asserted run: inputs 1 and 2 (valid UTF-8) must be accepted with one notice each
    local res, text = run_app(APP_STOP, "[stop on failure]")
    for i = 1, BAD - 1 do
        if not (res[i] and res[i].what == "accepted" and res[i].noutputs == 1) then
            harness.setup_error("control input " .. i .. " (valid UTF-8) was not accepted with one notice")
        end
    end
    local bad = res[BAD]
    local ok = bad ~= nil and (bad.what == "accepted" or bad.what == "rejected")
    if ok then
        for i = BAD + 1, #PAYLOADS do
            ok = ok and res[i] ~= nil and (res[i].what == "accepted" or res[i].what == "rejected")
        end
    end
    if not ok then
        io.stderr:write(string.format("VIOLATION: after input %d (payload %q, not valid UTF-8) the machine %s "
            .. "instead of yielding manually with the accepted or the rejected reason\n", BAD, PAYLOADS[BAD],
            bad and bad.what or "?"))
        if text:find("type_error.316", 1, true) then
            io.stderr:write("  cause: `rollup --utf8-payload accept` received the input (its accept yield returned) "
                .. "and then failed to print it: nlohmann type_error.316 (invalid UTF-8), exit 1, empty stdout\n")
        end
    end

    -- informative: the alternative error handling (retry) accepts the bad input without the app seeing it
    local res2 = run_app(APP_RETRY, "[retry on failure]")
    local b2 = res2[BAD]
    if b2 and b2.what == "accepted" and b2.noutputs == 0 then
        io.stderr:write(string.format("INFO: with retry, input %d was ACCEPTED with no notice: the application "
            .. "never saw it\n", BAD))
    end

    return harness.expect(ok,
        "section 2 'Correctly designed application' / section 3 Guest software: an application using `rollup "
            .. "--utf8-payload` as documented must yield manually with the accepted or the rejected reason after "
            .. "each input")
end)
