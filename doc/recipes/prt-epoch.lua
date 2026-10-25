-- One accumulating epoch, followed by its sealed dispute. Input and seal logs
-- share one ordered stream, so an input after the seal belongs to the next player.
local fs = require("cartesi.filesystem")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local bridge = require("prt-bridge")
local log_history = require("prt-log-history")
local M = {}
local methods = {}

local function key(log)
    return log.blockHash .. ":" .. log.logIndex
end

local function less(a, b)
    local an, bn = eth.small(a.blockNumber), eth.small(b.blockNumber)
    return an < bn or (an == bn and eth.small(a.logIndex) < eth.small(b.logIndex))
end

function methods:poll()
    if self.dispute then
        assert(self.chain:is_canonical(self.seal_block, self.seal_hash), "stable epoch seal was reorganized")
        return self.dispute
    end
    local head, hash = self.chain:head(self.input_policy)
    -- Logs come from the history, which fetches only the blocks it has not seen. A rejected
    -- observation resets it, so the next one fetches everything again.
    local history = self.history
    history:observe(head, hash)
    local logs = {}
    for _, address in ipairs({ self.input_box, self.consensus }) do
        for _, log in ipairs(history:get_logs(address, self.first_block)) do
            assert(log.address == address and type(log.removed) == "boolean", "invalid epoch log")
            if log.removed then
                history:reset()
                return nil
            end
            assert(eth.small(log.blockNumber) <= head, "epoch log past sampled head")
            logs[#logs + 1] = log
        end
    end
    table.sort(logs, less)
    if not self.chain:is_canonical(head, hash) then
        history:reset()
        return nil
    end
    assert(#logs >= #self.applied, "epoch log history was truncated")
    local positions, blocks = {}, {}
    for i, log in ipairs(logs) do
        local identity = key(log)
        assert(not positions[identity], "duplicate epoch log")
        positions[identity] = true
        if blocks[log.blockNumber] and blocks[log.blockNumber] ~= log.blockHash then
            history:reset()
            return nil
        end
        blocks[log.blockNumber] = log.blockHash
        if self.applied[i] then
            assert(self.applied[i] == identity, "epoch history changed; restart from a matching checkpoint")
        end
    end
    for i = #self.applied + 1, #logs do
        local log = logs[i]
        local event = self.abi:event(log)
        if event and event.name == "InputAdded" and log.address == self.input_box and event.appContract == self.app then
            local index = eth.small(event.index)
            if not self.dispute and index >= self.input_begin then
                assert(index == self.input_begin + #self.inputs, "input stream has a gap or duplicate")
                -- The player reads the input from a file that lasts only for its event. The listener
                -- keeps the chain's bytes, which proofs must encode.
                local data = assert(eth.raw(event.input))
                local file <close>, path = fs.write_scope_temp_file(data) -- luacheck: ignore 211
                local player = self.player
                player.event_handler.input_added(player, index - self.input_begin, path)
                self.inputs[#self.inputs + 1] = data
                io.stderr:write("Epoch ", self.epoch, ": processed confirmed InputAdded ", index, ".\n")
            end
        elseif
            event
            and event.name == "EpochSealed"
            and log.address == self.consensus
            and eth.small(event.epochNumber) == self.epoch
        then
            assert(not self.dispute, "epoch sealed twice")
            assert(event.initialMachineStateHash == self.initial_hash, "sealed initial state differs from checkpoint")
            assert(
                event.outputsMerkleRoot == self.previous_outputs_root,
                "sealed output history differs from checkpoint"
            )
            assert(eth.small(event.inputIndexLowerBound) == self.input_begin, "sealed lower input bound mismatch")
            assert(
                eth.small(event.inputIndexUpperBound) == self.input_begin + #self.inputs,
                "sealed input count mismatch"
            )
            local player = self.player
            player.event_handler.epoch_sealed(player, #self.inputs, self.checkpoint_directory)
            self.seal = event
            self.seal_block, self.seal_hash = eth.small(log.blockNumber), log.blockHash
            self.dispute = bridge.new({
                chain = self.chain,
                transactions = self.transactions,
                abi = self.abi,
                root = event.tournament,
                epoch = event.epochNumber,
                initial_hash = self.initial_hash,
                factory = self.factory,
                consensus = self.consensus,
                player = self.player,
                signer = self.signer,
                label = self.label,
                cleanup = self.cleanup,
                geometry = self.geometry,
                inputs = self.inputs,
                claim_staging_period = self.claim_staging_period,
                observation_policy = self.dispute_policy,
                seal_block = self.seal_block,
                seal_hash = self.seal_hash,
                first_block = self.first_block,
            })
        end
        self.applied[i] = key(log)
    end
    return self.dispute
end

function M.new(args)
    assert(args.chain and args.abi and args.app and args.input_box and args.consensus)
    assert(args.player and args.signer and args.label and args.initial_hash)
    assert(args.geometry, "missing factory geometry")
    local input_policy = cast.policy(args.input_policy or "finalized")
    local dispute_policy = cast.policy(args.dispute_policy or 4)
    return setmetatable({
        chain = args.chain,
        transactions = args.transactions,
        abi = args.abi,
        app = args.app,
        input_box = args.input_box,
        consensus = args.consensus,
        factory = args.factory,
        epoch = args.epoch,
        input_begin = args.input_begin,
        initial_hash = args.initial_hash,
        previous_outputs_root = args.previous_outputs_root,
        geometry = args.geometry,
        player = args.player,
        signer = args.signer,
        label = args.label,
        checkpoint_directory = args.checkpoint_directory,
        cleanup = args.cleanup,
        claim_staging_period = args.claim_staging_period,
        first_block = args.first_block,
        input_policy = input_policy,
        dispute_policy = dispute_policy,
        inputs = {},
        applied = {},
        history = log_history.new(args.chain),
    }, { __index = methods })
end

return M
