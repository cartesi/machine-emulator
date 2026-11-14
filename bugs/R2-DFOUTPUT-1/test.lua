-- R2-DFOUTPUT-1: the stored PRT player cannot start on a valid template whose tx buffer already commits to
-- outputs (a non-genesis template). prt.store_first_epoch_checkpoint, the only way the recipe creates the
-- epoch-0 checkpoint that crisium.lua and prt-demo.lua require, asserts that the template's tx buffer holds
-- the root of the EMPTY outputs tree.
--
-- The test builds a valid template from the harness bare-metal rollup guest (emit-output.bin): it loads the
-- `baremetal-template` configuration (stored at its first rx-accepted yield), delivers one advance-state input,
-- and runs it to its next rx-accepted manual yield. The guest emitted one output and wrote the outputs Merkle
-- root of that output to the tx buffer. The state is stored as the template. It then requires that the player
-- stores the epoch-0 checkpoint for it, that the checkpoint commits to the template and to its output history,
-- and that a stored player started from it seals an empty epoch 0 and computes the claim. Whether the
-- checkpoint carries the template's output history, and whether an outputs root mismatch is reported, are
-- printed as notes only (reviewer repair: they do not bear on R4).
--
-- Exit: 0 = the player defends the template (fixed), 1 = refused with "template machine has an output history"
-- (bug present), 2 = setup error.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local hash_tree = require("cartesi.hash-tree")
    local prt = require("prt")

    local ok_tmp, tmp = harness.sh("mktemp -d")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok_tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local _ <close> = setmetatable({}, {
        __close = function() os.execute("rm -rf '" .. tmp .. "'") end,
    })

    local TX = cartesi.AR_CMIO_TX_BUFFER_START or 0x60800000
    local LOG2 = cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT
    local empty_root = hash_tree.frontier_get_root_hash(hash_tree.frontier(LOG2, "keccak256"))

    -- 1. Build the non-genesis template: deliver one input to the genesis template and run to rx-accepted.
    local template_dir = tmp .. "/template"
    local template_hash, history_root
    local history = hash_tree.frontier(LOG2, "keccak256")
    do
        local m <close> = harness.machine(harness.config_dir("baremetal-template") .. "/machine")
        if m:read_memory(TX, 32) ~= empty_root then harness.setup_error("baremetal-template is not a genesis template") end
        m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            harness.encode_advance({ payload = "an output accepted before the template" }), m:get_root_hash())
        local outputs = 0
        for _ = 1, 100 do
            local br = m:run(math.maxinteger)
            if br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                local cmd, reason, data = m:receive_cmio_request()
                if cmd == cartesi.HTIF_YIELD_CMD_AUTOMATIC and reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
                    hash_tree.frontier_push_back(history, cartesi.keccak256(data))
                    outputs = outputs + 1
                end
            elseif br == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                break
            else
                harness.setup_error("guest stopped with break reason " .. tostring(br))
            end
        end
        local cmd, reason = m:receive_cmio_request()
        if cmd ~= cartesi.HTIF_YIELD_CMD_MANUAL or reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            harness.setup_error("guest did not accept the input")
        end
        history_root = hash_tree.frontier_get_root_hash(history)
        if outputs ~= 1 or m:read_memory(TX, 32) ~= history_root or history_root == empty_root then
            harness.setup_error("tx buffer does not hold the outputs root of the emitted output")
        end
        if m:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)
            ~= cartesi.UARCH_PRISTINE_STATE_HASH then
            harness.setup_error("uarch not pristine")
        end
        template_hash = m:get_root_hash()
        m:store(template_dir)
    end
    io.stderr:write("template ", harness.hex(template_hash), " commits to 1 earlier output, outputs root ",
        harness.hex(history_root), "\n")

    -- 2. The honest operator's path: store the epoch-0 checkpoint for this template. A fix may take the
    -- template's outputs frontier as an extra argument; the current function ignores it.
    local checkpoint_dir = tmp .. "/checkpoints/epoch-0"
    os.execute("mkdir -p '" .. tmp .. "/checkpoints' '" .. tmp .. "/state/epoch-0'")
    local stored, err = pcall(prt.store_first_epoch_checkpoint, template_dir, prt.new_geometry(11), checkpoint_dir,
        hash_tree.frontier_copy(history))
    if not stored then
        if tostring(err):find("template machine has an output history", 1, true) then
            io.stderr:write("store_first_epoch_checkpoint raised: ", tostring(err), "\n")
            return harness.expect(false, "valid template (tx buffer holds the outputs root of every output accepted "
                .. "before it): the honest operator must obtain it and compute the epoch-0 claim (R4)")
        end
        error("store_first_epoch_checkpoint failed for another reason: " .. tostring(err))
    end

    -- 3. Fixed path: the checkpoint commits to the template and its output history, and a stored player computes
    -- the epoch-0 claim from it.
    local dapp, frontier, manifest = prt.load_epoch_checkpoint(checkpoint_dir)
    local ok = harness.expect(manifest.final_state_hash:lower():gsub("^0x", "") == harness.hex(template_hash),
        "epoch-0 checkpoint is the template")
    -- Informational only (reviewer repair): the output history and the anomaly reports matter for output
    -- proofs and diagnostics, not for computing claims (R4), so they do not decide the exit status.
    io.stderr:write("note: epoch-0 checkpoint carries the template's output history: ",
        tostring(hash_tree.frontier_get_root_hash(frontier) == history_root
            and hash_tree.frontier_get_leaf_count(frontier) == 1), "\n")
    local reports = {}
    local stderr = io.stderr
    io.stderr = { write = function(_, ...) for _, s in ipairs({ ... }) do reports[#reports + 1] = tostring(s) end end }
    local started, player = pcall(prt.new_stored_player, dapp, "honest", frontier, tmp .. "/state/epoch-0",
        tmp .. "/checkpoints/epoch-1")
    local sealed, serr
    if started then
        player.anomaly_handler = function(kind, message) reports[#reports + 1] = kind .. ": " .. tostring(message) end
        sealed, serr = pcall(player.event_handler.epoch_sealed, player, 0)
    end
    io.stderr = stderr
    ok = harness.expect(started, "stored player starts from the checkpoint: " .. tostring(not started and player or ""))
        and ok
    if started then
        ok = harness.expect(sealed and player.final_state_hash == template_hash and player.mcycle_forest ~= nil,
            "stored player seals the empty epoch 0 at the template: " .. tostring(serr or "")) and ok
        local built, tree = false, nil
        if sealed then built, tree = pcall(player.new_mcycle_tree, player) end
        ok = harness.expect(built and tree ~= nil, "stored player computes the epoch-0 claim: "
            .. tostring(not built and tree or "")) and ok
        getmetatable(player).__close(player)
    end
    io.stderr:write("note: outputs root mismatch reported: ",
        tostring(table.concat(reports):find("outputs_merkle_root_mismatch", 1, true) ~= nil), " ",
        table.concat(reports), "\n")
    return ok
end)
