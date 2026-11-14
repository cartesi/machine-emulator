-- R1-GUEST-1: the machine-guest-tools `rollup` CLI (v0.18.1-test1, the rootfs pinned by the harness) keeps the
-- outputs Merkle tree that links its invocations in an undocumented file, /tmp/merkle.dat, and ignores every
-- failure to load or save it. When the file is gone, the next `rollup notice` silently starts from the empty tree
-- (index 0 again) and the next `rollup accept` writes to the tx buffer an outputs Merkle root that omits the
-- outputs accepted before, while every command exits 0.
--
-- Requirement (THREAT_MODEL.md, section 2, "Correctly designed application"): "When it accepts, it leaves in the
-- tx buffer the outputs Merkle root of every output it accepted. That includes the outputs its template already
-- commits to, and the outputs emitted while processing the inputs it accepted." Section 3, Guest software: "A
-- defect that lets an input make such an application deviate from the rollup interface is Critical, as an R7
-- deviation in the rx buffer, the tx buffer and the yield interface."
--
-- The test boots Linux with the pinned guest-tools rootfs and runs, as the entrypoint, a shell application that
-- uses only the documented `rollup` commands (accept/reject, notice) and checks every exit status (a failing
-- command makes it reject the input). After reading each request it clears its scratch directory /tmp (the trigger
-- modeled: the application treats /tmp, a tmpfs that cartesi-init mounts for everyone, as its own scratch space;
-- neither `rollup --help` nor the manual reserves any file there). Two advance-state inputs are delivered. The
-- host keeps its own outputs tree from the outputs the guest emitted (as `cartesi-machine` does with
-- check_outputs_merkle_root) and the test asserts: whenever the guest accepts, the tx-buffer root equals the root
-- of every output accepted so far. A control run of the same application without the /tmp cleanup must satisfy
-- the assertion (otherwise the test is broken: exit 2).
--
-- Exit 1: the guest accepted input 2 with a root that commits only to input 2's notice (bug present).
-- Exit 0: every accept carried the right root (tree kept elsewhere), or the tool failed loudly and the application
--         rejected the input.
local harness = require("harness")

local APP = [[
s=accept
while :; do
    rollup "$s" > /tmp/req || exit 1
    s=reject
    p=$(jq -c '{payload: .data.payload}' /tmp/req) || continue
    if [ "$CLEAN_TMP" = 1 ]; then rm -rf /tmp/* /tmp/.[!.]* 2> /dev/null; fi
    idx=$(echo "$p" | rollup notice) || continue
    echo "app: notice index $(echo "$idx" | jq -c .index)"
    s=accept
done
]]

harness.main(function()
    local cartesi = require("cartesi")
    local hash_tree = require("cartesi.hash-tree")
    local MAX = math.maxinteger

    local function run_app(clean)
        local cfg = harness.config("linux-rootfs")
        cfg.dtb.entrypoint = "export CLEAN_TMP=" .. (clean and "1" or "0") .. "\n" .. APP
        local m <close> = harness.machine(cfg, { console = { output_destination = "to_buffer" } })
        local console = {}
        local outputs = {}
        -- run until a manual yield (or failure); collect tx outputs emitted on the way
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
        local tag = clean and "[app clears /tmp]" or "[control]"
        local frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
        local results = {}
        -- genesis (template) + two inputs
        for step = 0, 2 do
            if step > 0 then
                m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
                    harness.encode_advance({ index = step - 1, payload = string.char(step) }), m:get_root_hash())
            end
            outputs = {}
            local br = run()
            if br ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
                io.stderr:write(table.concat(console), "\n")
                harness.setup_error(string.format("%s step %d: no manual yield (break reason %d)", tag, step, br))
            end
            local _, reason, data = m:receive_cmio_request()
            local r = { step = step, reason = reason, noutputs = #outputs, outputs = outputs }
            if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                for _, o in ipairs(outputs) do hash_tree.frontier_push_back(frontier, cartesi.keccak256(o)) end
                r.accepted = true
                r.guest_root = data
                r.host_root = hash_tree.frontier_get_root_hash(frontier)
                r.count = hash_tree.frontier_get_leaf_count(frontier)
            elseif reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
                harness.setup_error(string.format("%s step %d: manual yield reason %d", tag, step, reason))
            end
            results[#results + 1] = r
            io.stderr:write(string.format("%s %s: %s, %d output(s) emitted%s\n", tag,
                step == 0 and "template" or ("input " .. step), r.accepted and "accepted" or "rejected", r.noutputs,
                r.accepted and string.format(", guest root %s, host root over %d accepted output(s) %s",
                    cartesi.tohex(r.guest_root), r.count, cartesi.tohex(r.host_root)) or ""))
        end
        local text = table.concat(console)
        for line in text:gmatch("app: [^\r\n]*") do io.stderr:write(tag, " guest console: ", line, "\n") end
        return results
    end

    local function violations(results)
        local bad = {}
        for _, r in ipairs(results) do
            if r.accepted and r.guest_root ~= r.host_root then bad[#bad + 1] = r end
        end
        return bad
    end

    -- control: same app, /tmp untouched; must accept both inputs with correct roots
    local control = run_app(false)
    if #violations(control) > 0 or not (control[2].accepted and control[3].accepted)
        or control[3].count ~= 2 then
        harness.setup_error("control run does not accept both inputs with the right outputs root")
    end

    local results = run_app(true)
    local bad = violations(results)
    for _, r in ipairs(bad) do
        io.stderr:write(string.format("VIOLATION at %s: tx-buffer root %s is not the root %s of the %d output(s) "
            .. "accepted so far\n", r.step == 0 and "template" or ("input " .. r.step), cartesi.tohex(r.guest_root),
            cartesi.tohex(r.host_root), r.count))
        -- what the guest root commits to instead: only the outputs emitted while processing this input?
        local f = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
        for _, o in ipairs(r.outputs) do hash_tree.frontier_push_back(f, cartesi.keccak256(o)) end
        if hash_tree.frontier_get_root_hash(f) == r.guest_root then
            io.stderr:write(string.format("  the tx-buffer root is the root of only the %d output(s) of this input: "
                .. "the earlier accepted outputs were dropped from the guest's outputs tree\n", #r.outputs))
        end
    end
    return harness.expect(#bad == 0,
        "section 2 'Correctly designed application' / section 3 Guest software: an application using the rollup "
            .. "CLI as documented must leave in the tx buffer, when it accepts, the outputs Merkle root of every "
            .. "output it accepted")
end)
