-- R7-MANARCH-1: the manual's description of an advance-state delivery omits state writes that every
-- delivery path makes (imcyclemax, zero padding of the rx buffer), so the documented delivery and the
-- implemented one reach different state hashes.
--
-- Required (THREAT_MODEL.md): "The emulator's user manual is the specification it refers to"; section 2,
-- state transition function: "The manual's documented semantics define it on every state"; R7: "The emulator
-- implements ... the devices as the manual documents them, departing only where the manual documents a
-- deviation" (incl. "The rx buffer ... (contents, lengths ...)"); section 8: "A contradiction between the
-- manual and the behavior on a security-relevant point is a defect in one of the two."
--
-- The test performs, on a valid template at an rx-accepted manual yield, (A) machine:send_cmio_response and
-- (B) exactly the state changes the manual's delivery description lists (doc/README.md, "#### Rollup" host
-- loop, the prose after it, and the send_cmio_response API text):
--   Write the current state hash to the state at AR_SHADOW_REVERT_ROOT_HASH_START
--   Write ABI-encoded EvmAdvance(...) to CMIO RX buffer
--   Write HTIF_YIELD_REASON_ADVANCE_STATE to REASON and length as DATA in fromhost
--   Reset register iflags_Y to 0
-- For each extra effect of (A) the test passes if the two states agree, or if the manual documents that
-- effect of a delivery (a paragraph or list item that names it together with the delivery).
-- Exit 1: some extra effect is undocumented and changes the state hash. Exit 0: fixed. Exit 2: setup error.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local ADV = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local template = harness.config_dir("baremetal-template") .. "/machine"
    local function load() return harness.machine(template) end
    local hex = harness.hex

    -- The manual's documented delivery, done literally with the low-level API.
    local function manual_delivery(m, input, revert_root)
        m:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, revert_root)
        m:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, input)
        m:write_reg("htif_fromhost", (ADV << 32) | #input)
        m:write_reg("iflags_Y", 0)
    end

    local function run_to_manual_yield(m)
        for _ = 1, 1000 do
            local br = m:run(math.maxinteger)
            if br == cartesi.BREAK_REASON_YIELDED_MANUALLY then return end
            if br ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                harness.setup_error("guest did not reach a manual yield, break reason " .. tostring(br))
            end
        end
        harness.setup_error("too many automatic yields")
    end

    local function at_rx_accepted(m)
        local tohost = m:read_reg("htif_tohost")
        return m:read_reg("iflags_Y") ~= 0 and ((tohost >> 32) & 0xffff) == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
    end

    -- Does the manual document this effect of a delivery? Look for one paragraph or list item of
    -- doc/README.md that names the effect together with the delivery.
    local manual = harness.read_file(harness.REPO .. "/doc/README.md")
    local units = {}
    for para in (manual .. "\n\n"):gmatch("(.-)\n%s*\n") do
        local start = 1
        for i in para:gmatch("()\n[-*] ") do
            units[#units + 1] = para:sub(start, i - 1)
            start = i + 1
        end
        units[#units + 1] = para:sub(start)
    end
    local function mentions_delivery(u)
        local l = u:lower()
        return l:find("send_cmio_response", 1, true) or l:find("deliver", 1, true)
            or l:find("advance-state", 1, true) or l:find("ar_shadow_revert_root_hash", 1, true)
    end
    local function documented(pred)
        for _, u in ipairs(units) do
            if mentions_delivery(u) and pred(u:lower()) then return u end
        end
        return nil
    end
    local doc_imcyclemax = documented(function(l) return l:find("imcyclemax", 1, true) end)
    local doc_padding = documented(function(l)
        return (l:find("rx buffer", 1, true) or l:find("rx_buffer", 1, true))
            and (l:find("zero", 1, true) or l:find("pad", 1, true))
    end)

    local failures = {}

    -- Case 1: delivery to the template itself (rx buffer still zero, so only imcyclemax can differ).
    do
        local a <close> = load()
        local b <close> = load()
        if not at_rx_accepted(a) then harness.setup_error("template is not at an rx-accepted manual yield") end
        local input = harness.encode_advance({ payload = "hello" })
        local root = a:get_root_hash()
        local imax_before = a:read_reg("imcyclemax")
        a:send_cmio_response(ADV, input, root)
        manual_delivery(b, input, root)
        local ra, rb = a:get_root_hash(), b:get_root_hash()
        print(string.format("case 1: mcycle %d, imcyclemax before 0x%x", a:read_reg("mcycle"), imax_before))
        print(string.format("  send_cmio_response : imcyclemax 0x%x fromhost 0x%x iflags_Y %d root %s",
            a:read_reg("imcyclemax"), a:read_reg("htif_fromhost"), a:read_reg("iflags_Y"), hex(ra)))
        print(string.format("  manual's 4 writes  : imcyclemax 0x%x fromhost 0x%x iflags_Y %d root %s",
            b:read_reg("imcyclemax"), b:read_reg("htif_fromhost"), b:read_reg("iflags_Y"), hex(rb)))
        -- Which written address does the manual not account for? The access log of the same delivery.
        local c <close> = load()
        local log = c:log_send_cmio_response(ADV, input, root)
        local imc_addr = c:get_reg_address("imcyclemax")
        local logged_imc = false
        for _, acc in ipairs(log.accesses) do
            if acc.type == "write" and acc.address == imc_addr then logged_imc = true end
        end
        print(string.format("  log_send_cmio_response writes imcyclemax (0x%x): %s", imc_addr, tostring(logged_imc)))
        print("  manual documents that a delivery writes imcyclemax: " .. (doc_imcyclemax and "yes" or "no"))
        if ra ~= rb then
            b:write_reg("imcyclemax", a:read_reg("imcyclemax"))
            local only_imc = b:get_root_hash() == ra
            print("  roots equal once imcyclemax is copied from (A): " .. tostring(only_imc))
            if not doc_imcyclemax then
                failures[#failures + 1] = "delivery sets imcyclemax (0x" .. string.format("%x", a:read_reg("imcyclemax"))
                    .. ") but the manual's delivery lists no such write; root hashes differ"
            end
        end
    end

    -- Case 2: an earlier, longer input left bytes in the rx buffer past the end of the next, shorter one.
    do
        local long = harness.encode_advance({ payload = string.rep("L", 1000) })
        -- The same deterministic state twice: the template after accepting the long input.
        local function after_long()
            local m = load()
            m:send_cmio_response(ADV, long, m:get_root_hash())
            run_to_manual_yield(m)
            if not at_rx_accepted(m) then harness.setup_error("guest did not accept the first input") end
            return m
        end
        do
            local a <close> = after_long()
            local b <close> = after_long()
            if a:get_root_hash() ~= b:get_root_hash() then harness.setup_error("nondeterministic setup") end
            local input = harness.encode_advance({ payload = "hello" })
            local root = a:get_root_hash()
            a:send_cmio_response(ADV, input, root)
            manual_delivery(b, input, root)
            -- Align imcyclemax so that only the rx buffer contents can differ in this case.
            b:write_reg("imcyclemax", a:read_reg("imcyclemax"))
            local ra, rb = a:get_root_hash(), b:get_root_hash()
            local span = 2048
            local ma = a:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, span)
            local mb = b:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, span)
            local first, last
            for i = 1, span do
                if ma:byte(i) ~= mb:byte(i) then
                    first = first or i - 1
                    last = i - 1
                end
            end
            print(string.format("case 2: previous input %d bytes, new input %d bytes", #long, #input))
            print(string.format("  root (A) %s\n  root (B) %s (B with imcyclemax copied from A)", hex(ra), hex(rb)))
            if first then
                print(string.format("  rx buffer differs at offsets [0x%x, 0x%x]: (A) zero, (B) previous input's bytes",
                    first, last))
            end
            print("  manual documents zero padding of the rx buffer by a delivery: " .. (doc_padding and "yes" or "no"))
            if ra ~= rb and not doc_padding then
                failures[#failures + 1] = string.format("delivery zero-fills the rx buffer past the input "
                    .. "(offsets 0x%x-0x%x) but the manual's delivery only writes the input; root hashes differ",
                    first or -1, last or -1)
            end
        end
    end

    for _, f in ipairs(failures) do io.stderr:write("  - ", f, "\n") end
    return harness.expect(#failures == 0,
        "an advance-state delivery changes the state exactly as the manual documents it (THREAT_MODEL section 2: "
            .. "'The manual's documented semantics define it'; R7; section 8 manual contradiction)")
end)
