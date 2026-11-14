-- R1-A3-1: the PRT player's epoch listener misses the input backlog that DaveConsensus defers past the
-- per-epoch input limit.
--
-- DaveConsensus seals epoch N with [lo, lo + min(pending, 2^24)) and leaves the rest pending for epoch N+1
-- (_nextInputIndexUpperBound). Those deferred inputs were added to the InputBox BEFORE epoch N's seal block.
-- crisium.lua opens epoch N+1's listener (prt-epoch.lua) with first_input_block = the block of epoch N's
-- EpochSealed log, and the listener fetches InputAdded logs only from that block on.
--
-- This test drives the real prt-epoch.lua listener on a fake chain, with first_input_block computed by the
-- expression crisium.lua passes (extracted from its source), and asserts what R4 requires: the listener of
-- epoch N+1 delivers every input the referee assigns to that epoch, in order, and accepts the epoch's seal.
-- A control run with first_input_block = first_block checks that the fake chain is consistent (setup).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local eth = require("prt-ethereum")

    -- The dispute bridge is outside the defect: record its creation instead of building one.
    local bridges = {}
    package.loaded["prt-bridge"] = {
        new = function(args)
            bridges[#bridges + 1] = args
            return { fake_bridge = true }
        end,
        new_sentinel = function(args)
            bridges[#bridges + 1] = args
            return { fake_bridge = true }
        end,
    }
    local epoch = require("prt-epoch")

    -- Premise: the pinned DaveConsensus caps each seal at MAX_INPUTS_PER_EPOCH and leaves the rest pending.
    local consensus_src = os.getenv("HARNESS_WORK") .. "/dave/released/cartesi-rollups/contracts/src/DaveConsensus.sol"
    local okc, csrc = pcall(harness.read_file, consensus_src)
    if not okc then
        harness.setup_error("pinned DaveConsensus.sol not found: " .. consensus_src)
    end
    if
        not csrc:find("return lowerBound + pendingInputs.min(MAX_INPUTS_PER_EPOCH);", 1, true)
        or not csrc:find("_inputIndexUpperBound = _nextInputIndexUpperBound(_inputIndexLowerBound);", 1, true)
    then
        harness.setup_error("pinned DaveConsensus no longer seals min(pending, MAX_INPUTS_PER_EPOCH) inputs")
    end
    print("premise: pinned DaveConsensus seals [lo, lo + min(pending, 2^"
        .. cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH .. ")) and defers the rest to the next epoch")

    local MAX = 1 << cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
    local INPUT_BOX = "0x" .. string.rep("11", 20)
    local CONSENSUS = "0x" .. string.rep("22", 20)
    local APP = "0x" .. string.rep("33", 20)
    local FIRST_BLOCK = 1 -- consensus deployment block (crisium's first_block)
    local SEAL0_BLOCK = 100 -- block of epoch 0's EpochSealed
    local HEAD = 200

    local function q(n)
        return string.format("0x%x", n)
    end

    -- Extract the first_input_block expression that crisium.lua passes to prt-epoch.new.
    local crisium_path = os.getenv("RECIPES_DIR") .. "/crisium.lua"
    local src = harness.read_file(crisium_path)
    local call = src:match("listeners%[#listeners %+ 1%] = epoch%.new%((%b{})%)")
    if not call then
        harness.setup_error("cannot find the epoch.new call of open_epochs in " .. crisium_path)
    end
    local expr = call:match("\n%s*first_input_block%s*=%s*(.-),%s*\n")
    local function crisium_first_input_block(previous_seal, next_epoch)
        if not expr then
            return nil -- crisium passes none: prt-epoch defaults to first_block
        end
        local env = setmetatable({
            previous_seal = previous_seal,
            next_epoch = next_epoch,
            first_block = FIRST_BLOCK,
            eth = eth,
            math = math,
        }, {
            __index = function(_, name)
                error("crisium's first_input_block expression uses an unknown name: " .. tostring(name), 0)
            end,
        })
        local chunk, err = load("return " .. expr, "=crisium first_input_block", "t", env)
        if not chunk then
            error(err, 0)
        end
        return chunk()
    end

    local scenarios = {
        {
            name = "backlog input + one input after the seal",
            -- Index MAX was added at block 50 (before epoch 0's seal), when MAX + 1 inputs were pending,
            -- so the consensus sealed epoch 0 as [0, MAX) and deferred index MAX to epoch 1.
            inputs = { { block = 50, index = MAX }, { block = 120, index = MAX + 1 } },
            seal1 = { block = 150, lower = MAX, upper = MAX + 2 },
        },
        {
            name = "backlog input only",
            inputs = { { block = 50, index = MAX } },
            seal1 = { block = 150, lower = MAX, upper = MAX + 1 },
        },
    }

    local function make_chain(scenario)
        local logs = {}
        local function add(address, block, logindex, event)
            local log = {
                address = address,
                removed = false,
                blockNumber = q(block),
                logIndex = q(logindex),
                blockHash = string.format("0x%064x", block),
                topics = {},
                event = event,
            }
            event.log = log
            logs[#logs + 1] = log
            return log
        end
        for i, input in ipairs(scenario.inputs) do
            add(INPUT_BOX, input.block, i, {
                name = "InputAdded",
                appContract = APP,
                index = q(input.index),
                input = string.format("0x%016x", input.index),
            })
        end
        local seal0 = add(CONSENSUS, SEAL0_BLOCK, 0, {
            name = "EpochSealed",
            epochNumber = q(0),
            inputIndexLowerBound = q(0),
            inputIndexUpperBound = q(MAX), -- capped: MAX + 1 inputs were pending at block SEAL0_BLOCK
            initialMachineStateHash = "0xaa",
            outputsMerkleRoot = "0xbb",
            tournament = "0x" .. string.rep("44", 20),
        }).event
        add(CONSENSUS, scenario.seal1.block, 0, {
            name = "EpochSealed",
            epochNumber = q(1),
            inputIndexLowerBound = q(scenario.seal1.lower),
            inputIndexUpperBound = q(scenario.seal1.upper),
            initialMachineStateHash = "0xcc",
            outputsMerkleRoot = "0xdd",
            tournament = "0x" .. string.rep("55", 20),
        })
        local chain = {
            fetched_from = {},
            head = function()
                return HEAD, string.format("0x%064x", HEAD)
            end,
            is_canonical = function()
                return true
            end,
            logs = function(self, selected, last, from)
                self.fetched_from[#self.fetched_from + 1] = from
                local out = {}
                for _, l in ipairs(logs) do
                    local b = eth.small(l.blockNumber)
                    if l.address == selected and b >= from and b <= last then
                        out[#out + 1] = l
                    end
                end
                return out
            end,
        }
        return chain, seal0
    end

    local abi = {
        topics = function()
            return {}
        end,
        event = function(_, log)
            return log.event
        end,
    }

    -- Runs epoch 1's listener once; returns ok/err, delivered offsets, sealed counts, fetch blocks.
    local function run(scenario, first_input_block_of)
        local chain, seal0 = make_chain(scenario)
        local delivered, sealed = {}, {}
        local player = {
            event_handler = {
                input_added = function(_, offset, path)
                    local f = assert(io.open(path, "rb"))
                    f:close()
                    delivered[#delivered + 1] = offset
                end,
                epoch_sealed = function(_, count)
                    sealed[#sealed + 1] = count
                end,
            },
        }
        bridges = {}
        local listener = epoch.new({
            chain = chain,
            abi = abi,
            app = APP,
            input_box = INPUT_BOX,
            consensus = CONSENSUS,
            player = player,
            label = "honest",
            sentinel = true,
            geometry = {},
            epoch = 1,
            -- as crisium.lua: input_begin = previous seal's inputIndexUpperBound
            input_begin = eth.small(seal0.inputIndexUpperBound),
            initial_hash = "0xcc",
            previous_outputs_root = "0xdd",
            input_policy = 0,
            dispute_policy = 0,
            first_block = FIRST_BLOCK,
            first_input_block = first_input_block_of(seal0),
        })
        local ok, dispute = pcall(listener.poll, listener)
        return ok, dispute, delivered, sealed, chain.fetched_from
    end

    local function expected_ok(scenario, ok, dispute, delivered, sealed)
        if not ok or not dispute then
            return false
        end
        local n = scenario.seal1.upper - scenario.seal1.lower
        if #delivered ~= n or #sealed ~= 1 or sealed[1] ~= n or #bridges ~= 1 then
            return false
        end
        for i = 1, n do
            if delivered[i] ~= i - 1 then
                return false
            end
        end
        return true
    end

    local all_ok = true
    for _, scenario in ipairs(scenarios) do
        -- Control: a listener that fetches from the consensus deployment block sees every input.
        local cok, cdispute, cdelivered, csealed = run(scenario, function()
            return FIRST_BLOCK
        end)
        if not expected_ok(scenario, cok, cdispute, cdelivered, csealed) then
            harness.setup_error(
                "control run failed for '"
                    .. scenario.name
                    .. "' (fake chain inconsistent): "
                    .. tostring(cok and "delivered " .. table.concat(cdelivered, ",") or cdispute)
            )
        end
        -- As crisium.lua opens it.
        local first_of_crisium
        local ok, dispute, delivered, sealed, fetched = run(scenario, function(seal0)
            local ok_expr, value = pcall(crisium_first_input_block, seal0, 1)
            if not ok_expr then
                harness.setup_error("cannot evaluate crisium's first_input_block: " .. tostring(value))
            end
            first_of_crisium = value
            return value
        end)
        local good = expected_ok(scenario, ok, dispute, delivered, sealed)
        print(string.format("[%s] crisium first_input_block = %s (epoch 0 sealed at block %d, deferred input %d added at block %d)",
            scenario.name, tostring(first_of_crisium), SEAL0_BLOCK, MAX, scenario.inputs[1].block))
        print(string.format("[%s] fetched InputAdded/EpochSealed from block(s) %s; poll ok=%s%s; delivered offsets {%s}; epoch_sealed {%s}",
            scenario.name, table.concat(fetched, ","), tostring(ok), ok and "" or (" error: " .. tostring(dispute)),
            table.concat(delivered, ","), table.concat(sealed, ",")))
        if not good then
            print(string.format("[%s] VIOLATION: epoch 1's listener does not deliver inputs [%d, %d) that the referee assigns to epoch 1",
                scenario.name, scenario.seal1.lower, scenario.seal1.upper))
            all_ok = false
        end
    end
    return harness.expect(
        all_ok,
        "R4: 'It assigns inputs to epochs exactly as the referee does, including the input limit per epoch (A3)' "
            .. "- epoch N+1's listener must deliver the inputs the consensus deferred past epoch N's input limit"
    )
end)
