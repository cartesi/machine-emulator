-- One accumulating epoch, followed by its sealed dispute. Input and seal logs
-- share one ordered stream, so an input after the seal belongs to the next player.
local cartesi = require("cartesi")
local util = require("cartesi.util")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local bridge = require("prt-bridge")
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
    local head, hash, tip = self.chain:head(self.input_policy)
    local logs = {}
    for _, address in ipairs({ self.input_box, self.consensus }) do
        for _, log in ipairs(self.chain:logs(address, head)) do
            assert(log.address == address and type(log.removed) == "boolean", "invalid epoch log")
            if log.removed then
                return nil
            end
            assert(eth.small(log.blockNumber) <= head, "epoch log past sampled head")
            logs[#logs + 1] = log
        end
    end
    table.sort(logs, less)
    if not self.chain:is_canonical(head, hash) then
        return nil
    end
    assert(#logs >= #self.applied, "epoch log history was truncated")
    local positions, blocks = {}, {}
    for i, log in ipairs(logs) do
        local identity = key(log)
        assert(not positions[identity], "duplicate epoch log")
        positions[identity] = true
        if blocks[log.blockNumber] and blocks[log.blockNumber] ~= log.blockHash then
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
                assert(index == self.input_begin + #self.input_paths, "input stream has a gap or duplicate")
                local path = self.directory .. "/input-" .. index .. ".bin"
                util.write_file(assert(eth.raw(event.input)), path)
                for _, actor in ipairs(self.actors) do
                    actor.player.event_handler.input_added(actor.player, index - self.input_begin, path)
                end
                self.input_paths[#self.input_paths + 1] = path
                self.inputs[#self.inputs + 1] = {
                    index = index,
                    block = eth.small(log.blockNumber),
                    observation_block = head,
                    processed_at = tip,
                }
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
                eth.small(event.inputIndexUpperBound) == self.input_begin + #self.input_paths,
                "sealed input count mismatch"
            )
            for _, actor in ipairs(self.actors) do
                actor.player.event_handler.epoch_sealed(actor.player, #self.input_paths, actor.checkpoint_directory)
            end
            self.seal = event
            self.seal_block, self.seal_hash = eth.small(log.blockNumber), log.blockHash
            self.dispute = bridge.new({
                chain = self.chain,
                abi = self.abi,
                root = event.tournament,
                epoch = event.epochNumber,
                initial_hash = self.initial_hash,
                factory = self.factory,
                consensus = self.consensus,
                actors = self.actors,
                cleaner = self.cleaner,
                input_paths = self.input_paths,
                directory = self.directory,
                claim_staging_period = self.claim_staging_period,
                observation_policy = self.dispute_policy,
                seal_block = self.seal_block,
                seal_hash = self.seal_hash,
            })
            util.write_file(cartesi.tojson({
                epoch = self.epoch,
                input_begin = self.input_begin,
                input_end = self.input_begin + #self.input_paths,
                initial_hash = self.initial_hash,
                root = event.tournament,
                seal_block = eth.small(log.blockNumber),
                seal_hash = log.blockHash,
                seal_processed_at = tip,
                input_policy = self.input_policy,
                dispute_policy = self.dispute_policy,
                inputs = self.inputs,
            }, 2) .. "\n", self.directory .. "/epoch.json")
        end
        self.applied[i] = key(log)
    end
    return self.dispute
end

function M.new(args)
    assert(args.chain and args.abi and args.app and args.input_box and args.consensus)
    assert(args.actors and #args.actors > 0 and args.directory and args.initial_hash)
    args.input_policy = cast.policy(args.input_policy or "finalized")
    args.dispute_policy = cast.policy(args.dispute_policy or 4)
    cast.run({ "mkdir", "-p", args.directory })
    args.input_paths, args.inputs, args.applied = {}, {}, {}
    return setmetatable(args, { __index = methods })
end

return M
