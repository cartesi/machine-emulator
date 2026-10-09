-- Event-driven adapter for the doc/recipes players.
-- Contracts own pairing, clocks, and results. Only local claims survive a tick.
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")
local json = require("dkjson")
local util = require("cartesi.util")
local M = {}
local methods = {}

local function event_key(event)
    return event.log.blockHash .. ":" .. event.log.logIndex
end

local function match_key(event)
    return event.address .. ":" .. event.matchIdHash
end

local function block_number(value)
    return eth.small(evmu.bint(value))
end

local function log_less(a, b)
    if a.blockNumber ~= b.blockNumber then
        return block_number(a.blockNumber) < block_number(b.blockNumber)
    end
    return block_number(a.logIndex) < block_number(b.logIndex)
end

function methods:observe()
    local head, hash = self.chain:head()
    local addresses = { self.factory, self.consensus, self.root }
    local fetched, logs, contexts, order = {}, {}, {}, {}
    local index = 1
    while addresses[index] do
        local address = addresses[index]
        index = index + 1
        if not fetched[address] then
            fetched[address] = true
            for _, log in ipairs(self.chain:logs(address, head)) do
                assert(log.address == address and log.removed == false, "invalid log stream")
                assert(block_number(log.blockNumber) <= head, "log is past sampled head")
                logs[#logs + 1] = log
                local event = self.abi:event(log)
                if event and event.name == "NewInnerTournament" then
                    addresses[#addresses + 1] = event.childTournament
                end
            end
        end
    end
    table.sort(logs, log_less)
    local matches, deleted, recovered, events, staged, sealed = {}, {}, {}, {}, false, false
    local staged_event, settled
    local blocks, seen = {}, {}
    for _, log in ipairs(logs) do
        assert(not blocks[log.blockNumber] or blocks[log.blockNumber] == log.blockHash, "inconsistent block hashes")
        blocks[log.blockNumber] = log.blockHash
        local key = log.blockHash .. ":" .. log.logIndex
        assert(not seen[key], "duplicate log position")
        seen[key] = true
        local event = self.abi:event(log)
        if event then
            events[#events + 1] = event
            local name = event.name
            if name == "TournamentCreated" or name == "NewInnerTournament" then
                local address = event.tournament or event.childTournament
                if name == "NewInnerTournament" or address == self.root then
                    assert(not contexts[address], "duplicate tournament creation")
                    if name == "TournamentCreated" then
                        assert(event.address == self.factory, "root was not created by the configured factory")
                        assert(
                            event.descriptor.initialHash == self.initial_hash
                                and event.descriptor.baseCycle == evmu.bint(0),
                            "root computation mismatch"
                        )
                    end
                    local context = {
                        address = address,
                        creation = event,
                        descriptor = event.descriptor,
                        bond = event.bondValue,
                        joined = {},
                    }
                    if name == "NewInnerTournament" then
                        assert(contexts[event.address], "child has no observed parent")
                        context.parent = event.address
                        context.parent_match = match_key(event)
                        matches[context.parent_match] = nil
                    end
                    contexts[address] = context
                    order[#order + 1] = context
                end
            elseif name == "EpochSealed" then
                if event.tournament == self.root then
                    assert(event.address == self.consensus and event.epochNumber == self.epoch, "epoch mismatch")
                    assert(event.initialMachineStateHash == self.initial_hash, "epoch initial hash mismatch")
                    sealed = true
                elseif event.address == self.consensus and event.epochNumber == self.epoch + 1 then
                    settled = event
                end
            elseif name == "MatchCreated" or name == "MatchAdvanced" or name == "LeafMatchSealed" then
                matches[match_key(event)] = event
            elseif name == "MatchDeleted" then
                matches[match_key(event)], deleted[match_key(event)] = nil, true
            elseif name == "StandingChanged" then
                assert(contexts[event.address], "standing without creation").standing = event
            elseif name == "CommitmentJoined" then
                assert(contexts[event.address], "join without creation").joined[event.commitment] = event
            elseif name == "BondRecovered" then
                recovered[event.address] = true
            elseif name == "EpochStaged" and event.address == self.consensus and event.epochNumber == self.epoch then
                staged, staged_event = true, event
            end
        end
    end
    local canonical = assert(self.chain:rpc("eth_getBlockByNumber", { string.format("0x%x", head), false }))
    assert(canonical.hash == hash, "sampled head changed during observation")
    assert(contexts[self.root], "root creation was not observed")
    assert(sealed, "epoch seal was not observed")
    return {
        head = head,
        hash = hash,
        contexts = contexts,
        order = order,
        matches = matches,
        deleted = deleted,
        recovered = recovered,
        events = events,
        logs = logs,
        staged = staged,
        staged_event = staged_event,
        settled = settled,
    }
end

local function holds(actor, address, root)
    local claim = actor.claims and actor.claims[address]
    return claim and claim.root == root and claim or nil
end

local function build_claim(actor, context)
    local address = context.address
    if actor.claims[address] then
        return actor.claims[address]
    end
    local descriptor, response = context.descriptor
    local height = eth.small(descriptor.height)
    if not context.parent then
        assert(
            height == 62 and eth.small(descriptor.log2Stride) == 30 and eth.small(descriptor.level) == 0,
            "root does not match recipe geometry"
        )
        response = actor.player.event_handler.commit_mcycle_claim(actor.player)
    else
        assert(
            height == 30 and eth.small(descriptor.log2Stride) == 0 and eth.small(descriptor.level) == 1,
            "child does not match recipe geometry"
        )
        local input, period, offset = eth.coordinates(descriptor.baseCycle)
        assert(offset == 0, "child starts inside a period")
        response = actor.player.event_handler.commit_uarch_claim(actor.player, input, period)
    end
    local claim = eth.claim(response, height)
    if context.parent then
        local event = context.creation
        assert(
            claim.final_state == event.contestedFinalStateOne or claim.final_state == event.contestedFinalStateTwo,
            "child claim does not defend a contested state"
        )
    end
    actor.claims[address] = claim
    local file <close> = assert(io.open((actor.directory or ".") .. "/" .. actor.label .. "-claims.json", "w"))
    assert(file:write(json.encode(actor.claims, { indent = true })))
    return claim
end

function methods:jobs(snapshot)
    local jobs = {}
    local function add(kind, context, event, actor, first, last, root)
        local key = event_key(event) .. ":" .. kind .. ":" .. (actor and actor.label or "cleanup")
        if not self.rejected[key] then
            jobs[#jobs + 1] = {
                key = key,
                kind = kind,
                context = context,
                event = event,
                actor = actor or self.cleaner,
                first = first or 0,
                last = last or math.maxinteger,
                root = root,
            }
        end
    end
    for _, context in ipairs(snapshot.order) do
        local event, d = context.creation, context.descriptor
        local close = eth.small(d.startInstant) + eth.small(d.allowance)
        if not context.parent_match or not snapshot.deleted[context.parent_match] then
            for _, actor in ipairs(self.actors) do
                local eligible = not context.parent
                    or (
                        not actor.player.done
                        and (holds(actor, context.parent, event.one) or holds(actor, context.parent, event.two))
                    )
                if eligible and snapshot.head + 1 < close then
                    local claim = build_claim(actor, context)
                    if not context.joined[claim.root] then
                        add("joinTournament", context, event, actor, 0, close, claim.root)
                    end
                end
            end
        end
    end
    for _, event in ipairs(snapshot.events) do
        if event.matchIdHash and snapshot.matches[match_key(event)] == event then
            local context = assert(snapshot.contexts[event.address])
            local first_timeout
            local eliminable = eth.small(event.eliminableAt)
            local timeout_root
            if event.name == "LeafMatchSealed" then
                local d1, d2 = eth.small(event.deadlineOne), eth.small(event.deadlineTwo)
                first_timeout = math.min(d1, d2)
                timeout_root = d1 > d2 and event.one or event.two
                for _, actor in ipairs(self.actors) do
                    local claim = holds(actor, context.address, event.one) or holds(actor, context.address, event.two)
                    if claim and not actor.player.done then
                        add("winLeafMatch", context, event, actor, 0, first_timeout, claim.root)
                    end
                end
            else
                local height = event.currentHeight and eth.small(event.currentHeight)
                    or eth.small(context.descriptor.height)
                local one_responds = (eth.small(context.descriptor.height) - height) % 2 == 0
                local responder = one_responds and event.one or event.two
                timeout_root = one_responds and event.two or event.one
                first_timeout = eth.small(event.responderDeadline)
                for _, actor in ipairs(self.actors) do
                    if holds(actor, context.address, responder) and not actor.player.done then
                        local kind = height > 1 and "advanceMatch"
                            or (
                                eth.small(context.descriptor.kind) == 0 and "sealLeafMatch"
                                or "sealInnerMatchAndCreateInnerTournament"
                            )
                        add(kind, context, event, actor, 0, first_timeout, responder)
                    end
                end
            end
            for _, actor in ipairs(self.actors) do
                if holds(actor, context.address, timeout_root) and not actor.player.done then
                    add("winMatchByTimeout", context, event, actor, first_timeout, eliminable, timeout_root)
                end
            end
            add("eliminateMatchByTimeout", context, event, nil, eliminable)
        end
    end
    for _, context in ipairs(snapshot.order) do
        local standing, d = context.standing, context.descriptor
        if not standing or eth.small(standing.matchCount) == 0 then
            local event = standing or context.creation
            local result_at = standing and eth.small(standing.resultAt)
                or eth.small(d.startInstant) + eth.small(d.allowance)
            local candidate = standing and standing.dangling or eth.zero
            if context.parent and not snapshot.deleted[context.parent_match] then
                local expires = candidate ~= eth.zero and eth.small(standing.winnerExpiresAt) or result_at
                if candidate ~= eth.zero then
                    for _, actor in ipairs(self.actors) do
                        if holds(actor, context.parent, standing.parentCommitment) and not actor.player.done then
                            add(
                                "winInnerTournament",
                                context,
                                event,
                                actor,
                                result_at,
                                expires,
                                standing.parentCommitment
                            )
                        end
                    end
                end
                add("eliminateInnerTournament", context, event, nil, expires)
            end
            for _, actor in ipairs(self.actors) do
                local claim = holds(actor, context.address, candidate)
                if claim and not actor.player.done then
                    if not context.parent and not snapshot.staged then
                        add("stageTournamentResult", context, event, actor, result_at, nil, candidate)
                    end
                    local joined = context.joined[candidate]
                    if
                        joined
                        and joined.submitter == actor.signer.address
                        and not snapshot.recovered[context.address]
                    then
                        add("tryRecoveringBond", context, event, actor, result_at, nil, candidate)
                    end
                end
            end
        end
    end
    if snapshot.staged and not snapshot.settled and self.claim_staging_period then
        add(
            "acceptStagedTournamentResult",
            snapshot.contexts[self.root],
            snapshot.staged_event,
            nil,
            block_number(snapshot.staged_event.log.blockNumber) + self.claim_staging_period
        )
    end
    return jobs
end

function methods:prepare(job)
    local context, event, actor = job.context, job.event, job.actor
    local player, kind = actor.player, job.kind
    local id, address, args, value = { event.one, event.two }, context.address, {}, nil
    local claim = actor.claims and actor.claims[address]
    local proof_check
    if kind == "joinTournament" then
        args = { claim.final_state, claim.proof, claim.children[1], claim.children[2] }
        value = tostring(context.bond)
    elseif kind == "advanceMatch" then
        local response = player.event_handler.reveal_bisection(
            player,
            assert(eth.raw(job.root)),
            event.segmentStartPosition and eth.small(event.segmentStartPosition) or 0,
            event.currentHeight and eth.small(event.currentHeight) or eth.small(context.descriptor.height),
            assert(eth.raw(event.leftNode or event.leftOfTwo))
        )
        args = {
            id,
            eth.hex(response.turn_left_node),
            eth.hex(response.turn_right_node),
            eth.hex(response.turn_next_left_node),
            eth.hex(response.turn_next_right_node),
        }
    elseif kind == "sealLeafMatch" or kind == "sealInnerMatchAndCreateInnerTournament" then
        local response = player.event_handler.seal_divergence(
            player,
            assert(eth.raw(job.root)),
            event.segmentStartPosition and eth.small(event.segmentStartPosition) or 0,
            assert(eth.raw(event.leftNode or event.leftOfTwo))
        )
        local proof = response.agreed_state_hash_proof
        args = {
            id,
            eth.hex(response.turn_left_node),
            eth.hex(response.turn_right_node),
            proof and eth.hex(proof.target_hash) or context.descriptor.initialHash,
            proof and eth.siblings(proof) or {},
        }
    elseif kind == "winLeafMatch" then
        local cycle = context.descriptor.baseCycle
            + (event.divergencePosition << eth.small(context.descriptor.log2Stride))
        local input, period, offset = eth.coordinates(cycle)
        local response = player.event_handler.prove_state_transition(player, input, period, offset)
        local path = self.input_paths[input + 1]
        local input_data = path and util.read_file(path)
        local proof = eth.transition_proof(response, cycle, input_data)
        local ok, obtained = pcall(eth.verify_transition, response, cycle, input_data, event.agreeState)
        local expected = claim.root == event.one and event.finalStateOne or event.finalStateTwo
        proof_check = { valid = ok and obtained == expected, obtained = tostring(obtained), expected = expected }
        args = { id, claim.children[1], claim.children[2], proof }
    elseif kind == "winMatchByTimeout" then
        args = { id, claim.children[1], claim.children[2] }
    elseif kind == "eliminateMatchByTimeout" then
        args = { id }
    elseif kind == "winInnerTournament" then
        claim = assert(actor.claims[context.parent])
        address, args = context.parent, { context.address, claim.children[1], claim.children[2] }
    elseif kind == "eliminateInnerTournament" then
        address, args = context.parent, { context.address }
    elseif kind == "acceptStagedTournamentResult" then
        address, args = self.consensus, { self.epoch }
    elseif kind == "stageTournamentResult" then
        local response = player.event_handler.prove_outputs_merkle_root(player)
        local ok, proof = pcall(eth.validity_proof, response, claim.final_state)
        if not ok then
            self.terminal = "Winning machine state cannot be staged: " .. tostring(proof)
            self.rejected[job.key] = self.terminal
            return nil
        end
        address, args = self.consensus, { self.epoch, proof }
    else
        assert(kind == "tryRecoveringBond", "unknown bridge action")
    end
    return {
        signer = actor.signer,
        to = address,
        data = self.abi:calldata(kind, args),
        value = value,
        proof_check = proof_check,
    }
end

function methods:tick()
    local snapshot = self:observe()
    local jobs = self:jobs(snapshot)
    local next_block
    for _, job in ipairs(jobs) do
        local inclusion = snapshot.head + 1
        if inclusion >= job.first and inclusion < job.last then
            local transaction = self:prepare(job)
            if transaction then
                local _, head_hash = self.chain:head()
                if head_hash ~= snapshot.hash then
                    return snapshot, true
                end
                local receipt, failure =
                    self.chain:send(transaction.signer, transaction.to, transaction.data, transaction.value)
                local file <close> = assert(io.open((self.directory or ".") .. "/transactions.jsonl", "a"))
                assert(file:write(
                    json.encode({
                        action = job.kind,
                        actor = job.actor.label,
                        receipt = receipt,
                        rejected = failure,
                        data = transaction.data,
                        to = transaction.to,
                        proof_check = transaction.proof_check,
                    }),
                    "\n"
                ))
                if transaction.proof_check then
                    assert(
                        transaction.proof_check.valid == (failure == nil),
                        "native and Solidity transition verification disagree; see transactions.jsonl"
                    )
                end
                if failure then
                    self.rejected[job.key] = failure
                    io.stderr:write(job.actor.label, ": ", job.kind, " rejected: ", failure.message, "\n")
                end
                return snapshot, true
            end
        elseif inclusion < job.first and job.first < job.last then
            next_block = math.min(next_block or job.first, job.first)
        end
    end
    return snapshot, false, next_block
end

function M.new(args)
    assert(args.chain and args.abi and args.root and args.factory and args.consensus)
    assert(args.actors and #args.actors > 0)
    args.cleaner = assert(args.cleaner)
    args.rejected = {}
    return setmetatable(args, { __index = methods })
end

return M
