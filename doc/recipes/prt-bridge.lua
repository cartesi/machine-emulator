-- Event-driven adapter for the doc/recipes players.
-- Contracts own pairing, clocks, and results. Claims and prepared proofs survive
-- observations; the shared transaction journal owns account nonces and fees.
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")
local json = require("dkjson")
local util = require("cartesi.util")
local cast = require("prt-cast")
local M = {}
local methods = {}

local function event_key(event)
    return event.log.blockHash .. ":" .. event.log.logIndex
end

local function match_key(event)
    return event.address .. ":" .. event.matchIdHash
end

local function log_less(a, b)
    if a.blockNumber ~= b.blockNumber then
        return eth.small(a.blockNumber) < eth.small(b.blockNumber)
    end
    return eth.small(a.logIndex) < eth.small(b.logIndex)
end

function methods:observe()
    local head, hash, tip, tip_hash = self.chain:head(self.observation_policy)
    if self.seal_block then
        assert(self.chain:is_canonical(self.seal_block, self.seal_hash), "stable epoch seal was reorganized")
    end
    local addresses = { self.factory, self.consensus, self.root }
    local fetched, logs, contexts, order = {}, {}, {}, {}
    local index = 1
    while addresses[index] do
        local address = addresses[index]
        index = index + 1
        if not fetched[address] then
            fetched[address] = true
            for _, log in ipairs(self.chain:logs(address, head)) do
                assert(log.address == address, "invalid log address")
                assert(type(log.removed) == "boolean", "log lacks removed flag")
                if log.removed then
                    return nil
                end
                assert(eth.small(log.blockNumber) <= head, "log is past sampled head")
                logs[#logs + 1] = log
                local event = self.abi:event(log)
                if event and event.name == "NewInnerTournament" then
                    addresses[#addresses + 1] = event.childTournament
                end
            end
        end
    end
    if not self.chain:is_canonical(head, hash) then
        return nil
    end
    table.sort(logs, log_less)
    local matches, deleted, recovered, events, sealed = {}, {}, {}, {}, false
    local staged, settled
    local blocks, seen = {}, {}
    for _, log in ipairs(logs) do
        if blocks[log.blockNumber] and blocks[log.blockNumber] ~= log.blockHash then
            return nil
        end
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
                staged = event
            end
        end
    end
    if not self.chain:is_canonical(head, hash) then
        return nil
    end
    if not self.seal_block or head >= self.seal_block then
        assert(contexts[self.root], "root creation was not observed")
        assert(sealed, "epoch seal was not observed")
    end
    return {
        head = head,
        hash = hash,
        tip = tip,
        tip_hash = tip_hash,
        ready = sealed,
        contexts = contexts,
        order = order,
        matches = matches,
        deleted = deleted,
        recovered = recovered,
        events = events,
        logs = logs,
        staged = staged,
        settled = settled,
    }
end

local function holds(actor, address, root)
    local claim = actor.claims and actor.claims[address]
    return claim and claim.root == root and claim or nil
end

local function build_claim(actor, context)
    local descriptor, response = context.descriptor
    local height = eth.small(descriptor.height)
    local key = table.concat({
        tostring(descriptor.initialHash),
        tostring(descriptor.baseCycle),
        tostring(descriptor.height),
        tostring(descriptor.log2Stride),
        tostring(descriptor.level),
        tostring(descriptor.kind),
    }, ":")
    actor.computations = actor.computations or {}
    local claim = actor.computations[key]
    if not context.parent then
        assert(
            height == 62 and eth.small(descriptor.log2Stride) == 30 and eth.small(descriptor.level) == 0,
            "root does not match recipe geometry"
        )
        if not claim then
            response = actor.player.event_handler.commit_mcycle_claim(actor.player)
        end
    else
        assert(
            height == 30 and eth.small(descriptor.log2Stride) == 0 and eth.small(descriptor.level) == 1,
            "child does not match recipe geometry"
        )
        local input, period, offset = eth.coordinates(descriptor.baseCycle)
        assert(offset == 0, "child starts inside a period")
        if not claim then
            response = actor.player.event_handler.commit_uarch_claim(actor.player, input, period)
        end
    end
    claim = claim or eth.claim(response, height)
    if context.parent then
        local event = context.creation
        assert(
            claim.final_state == event.contestedFinalStateOne or claim.final_state == event.contestedFinalStateTwo,
            "child claim does not defend a contested state"
        )
    end
    actor.computations[key] = claim
    return claim, response ~= nil
end

local function bind_claim(actor, address, claim)
    if actor.claims[address] == claim then
        return
    end
    actor.claims[address] = claim
    local file <close> = assert(io.open((actor.directory or ".") .. "/" .. actor.label .. "-claims.json", "w"))
    assert(file:write(json.encode(actor.claims, { indent = true })))
end

local function can_join(actor, context, snapshot)
    local event, d = context.creation, context.descriptor
    return snapshot.tip + 1 < eth.small(d.startInstant) + eth.small(d.allowance)
        and not snapshot.deleted[context.parent_match]
        and (
            not context.parent
            or (
                not actor.player.done
                and (holds(actor, context.parent, event.one) or holds(actor, context.parent, event.two))
            )
        )
end

-- Claims belong to computations; tournament addresses are only associations
-- reconstructed from the current branch. Keep computation out of job queries.
function methods:update_claims(snapshot)
    local computed = false
    for _, context in ipairs(snapshot.order) do
        local event = context.creation
        for _, actor in ipairs(self.actors) do
            local bound_child = context.parent and actor.claims[context.address]
            if
                bound_child and not (holds(actor, context.parent, event.one) or holds(actor, context.parent, event.two))
            then
                bind_claim(actor, context.address, nil)
                bound_child = nil
            end
            if bound_child or can_join(actor, context, snapshot) then
                local claim, built = build_claim(actor, context)
                bind_claim(actor, context.address, claim)
                computed = computed or built
            end
        end
    end
    return computed
end

-- Player computation can take many blocks. Refresh before scheduling ANY
-- transaction, including cancellation, until claims match a fresh observation.
function methods:refresh()
    while true do
        local snapshot = self:observe()
        if not snapshot or not snapshot.ready or not self:update_claims(snapshot) then
            return snapshot
        end
    end
end

function methods:jobs(snapshot)
    local jobs = {}
    local function add(kind, context, event, actor, first, last, root)
        local key = event_key(event) .. ":" .. kind .. ":" .. (actor and actor.label or "cleanup")
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
    for _, context in ipairs(snapshot.order) do
        local event, d = context.creation, context.descriptor
        local close = eth.small(d.startInstant) + eth.small(d.allowance)
        for _, actor in ipairs(self.actors) do
            local claim = actor.claims[context.address]
            if claim and can_join(actor, context, snapshot) and not context.joined[claim.root] then
                add("joinTournament", context, event, actor, 0, close, claim.root)
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
            snapshot.staged,
            nil,
            eth.small(snapshot.staged.log.blockNumber) + self.claim_staging_period
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

-- Receipts suppress duplicate publication while their events are still behind
-- the observation policy. An orphaned receipt never completes or suppresses work.
function methods:awaiting_observation(job, snapshot)
    local receipt = self.transactions:receipt(job.key)
    if receipt then
        local number = eth.small(receipt.blockNumber)
        return snapshot.head < number, receipt
    end
    return false
end

function methods:record_attempt(job, transaction, result, snapshot)
    local file <close> = assert(io.open((self.directory or ".") .. "/transactions.jsonl", "a"))
    local candidate = result.candidate
    assert(file:write(
        json.encode({
            action = job.kind,
            actor = job.actor.label,
            hash = candidate and candidate.hash,
            nonce = candidate and candidate.nonce,
            max_fee = candidate and candidate.max_fee,
            priority_fee = candidate and candidate.priority_fee,
            rejected = result.rejected,
            publication_error = result.publication_error,
            rebroadcast = result.rebroadcast,
            data = transaction and transaction.data,
            to = transaction and transaction.to,
            proof_check = transaction and transaction.proof_check,
            observation_block = snapshot.head,
            observation_hash = snapshot.hash,
        }),
        "\n"
    ))
end

function methods:report_blocked(actor, result)
    if result.blocked and self.blocked[actor.label] ~= result.blocked then
        io.stderr:write(actor.label, ": transaction waiting at ", result.blocked, "; observing continues.\n")
    end
    self.blocked[actor.label] = result.blocked
end

-- A nil result means the observation or job changed: the scheduler must
-- start over. Otherwise return the transaction outcome and next retry block.
function methods:attempt(job, snapshot)
    local transaction = self.prepared[job.key] or self:prepare(job)
    self.prepared[job.key] = transaction
    if not transaction then
        return snapshot, { waiting = true }, snapshot.tip + 1
    end
    -- Computation may take many blocks. Rebuild eligibility at
    -- the configured observation head, then use the real tip
    -- for the inclusion window, never observation.head + 1.
    local refreshed = self:refresh()
    if not refreshed or not refreshed.ready then
        return refreshed, nil
    end
    local current
    for _, candidate in ipairs(self:jobs(refreshed)) do
        if candidate.key == job.key and candidate.root == job.root then
            current = candidate
            break
        end
    end
    if not current or refreshed.tip + 1 < current.first or refreshed.tip + 1 >= current.last then
        return refreshed, nil, refreshed.tip + 1
    end
    snapshot = refreshed
    -- Verify the proof against the observed leaf event. A
    -- later execution-state revert can mean that someone else
    -- already answered; it is not evidence of a bad proof.
    local proof_failure
    if transaction.proof_check then
        local _, failure = self.chain:simulate(
            transaction.signer,
            transaction.to,
            transaction.data,
            transaction.value,
            { blockHash = snapshot.hash, requireCanonical = true }
        )
        if not self.chain:is_canonical(snapshot.head, snapshot.hash) then
            return nil, nil
        end
        assert(not failure or failure.code == 3, "proof simulation RPC failure")
        assert(
            transaction.proof_check.valid == (failure == nil),
            "native and Solidity transition verification disagree"
        )
        if not transaction.proof_check.valid then
            self.invalid[job.key] = true
            proof_failure = failure
        end
    end
    local tip = self.chain:head()
    if
        tip + 1 < current.first
        or tip + 1 >= current.last
        or not self.chain:is_canonical(snapshot.head, snapshot.hash)
    then
        return snapshot, nil, tip + 1
    end
    local result
    if proof_failure then
        result = { rejected = proof_failure }
    else
        result = self.transactions:submit(transaction.signer, {
            key = job.key,
            kind = job.kind,
            first = current.first,
            last = current.last,
            to = transaction.to,
            data = transaction.data,
            value = transaction.value,
            context = {
                epoch = tostring(self.epoch),
                root = self.root,
                claim = job.root,
                tournament = job.context.address,
                event = event_key(job.event),
            },
        }, snapshot)
    end
    self:report_blocked(job.actor, result)
    if result.published or result.rejected then
        self:record_attempt(job, transaction, result, snapshot)
    end
    if result.rejected then
        self.rejected[job.key] = snapshot.tip_hash
        io.stderr:write(job.actor.label, ": ", job.kind, " preflight reverted.\n")
    end
    return snapshot, result, tip + 1
end

function methods:cancel(actor, snapshot)
    local result = self.transactions:submit(actor.signer, nil, snapshot)
    self:report_blocked(actor, result)
    if result.published then
        self:record_attempt({ kind = "cancel", actor = actor }, nil, result, snapshot)
    end
    return result
end

function methods:tick()
    local snapshot = self:refresh()
    if not snapshot then
        return nil, false
    end
    local next_block
    if not snapshot.ready then
        return snapshot, false, snapshot.tip + 1
    end
    local jobs = self:jobs(snapshot)
    local due, preferred, obsolete = {}, {}, {}
    for _, job in ipairs(jobs) do
        if snapshot.tip + 1 >= job.first and snapshot.tip + 1 < job.last and not self.invalid[job.key] then
            local address = job.actor.signer.address
            due[address] = due[address] or {}
            table.insert(due[address], job)
        end
    end
    local actors = { self.cleaner, table.unpack(self.actors) }
    for _, actor in ipairs(actors) do
        local candidate = self.transactions:pending(actor.signer.address)
        if candidate then
            next_block = snapshot.tip + 1
            local eligible = due[actor.signer.address] or {}
            local selected = eligible[1]
            for _, job in ipairs(eligible) do
                if job.key == candidate.job then
                    selected = job
                    break
                end
            end
            if selected then
                -- Keep working on a useful pending action. Do not oscillate
                -- between two eligible actions belonging to the same account.
                preferred[actor.signer.address] = selected.key
                if selected.key ~= candidate.job then
                    obsolete[#obsolete + 1] = actor
                end
            elseif self:cancel(actor, snapshot).published then
                return snapshot, true
            end
        end
    end
    for _, job in ipairs(jobs) do
        local inclusion = snapshot.tip + 1
        if inclusion >= job.first and inclusion < job.last then
            local rejected = self.rejected[job.key]
            local awaiting, receipt = self:awaiting_observation(job, snapshot)
            if awaiting or rejected == snapshot.tip_hash then
                local observable = snapshot.tip + 1
                if awaiting and type(self.observation_policy) == "number" then
                    observable = eth.small(receipt.blockNumber) + self.observation_policy
                end
                next_block = math.min(next_block or observable, observable)
            end
            local selected = preferred[job.actor.signer.address]
            if
                not self.invalid[job.key]
                and rejected ~= snapshot.tip_hash
                and not awaiting
                and (not selected or selected == job.key)
            then
                local refreshed, result, retry_at = self:attempt(job, snapshot)
                if not result then
                    return refreshed, false, retry_at
                end
                if result.published or result.rejected then
                    return refreshed, true
                end
                if refreshed.hash ~= snapshot.hash or refreshed.tip_hash ~= snapshot.tip_hash then
                    -- Pending-job preference and cancellation decisions belong
                    -- to the original view. Recompute them after a head change.
                    return refreshed, false, retry_at
                end
                next_block = math.min(next_block or retry_at, retry_at)
            end
        elseif inclusion < job.first and job.first < job.last then
            next_block = math.min(next_block or job.first - 1, job.first - 1)
        end
    end
    -- A due replacement can become unusable during preparation or preflight.
    -- Its predecessor is still obsolete; do not leave that candidate unattended.
    for _, actor in ipairs(obsolete) do
        if self:cancel(actor, snapshot).published then
            return snapshot, true
        end
    end
    return snapshot, false, next_block
end

function M.new(args)
    assert(args.chain and args.abi and args.root and args.factory and args.consensus)
    assert(args.transactions, "missing shared transaction journal")
    assert(args.actors and #args.actors > 0)
    return setmetatable({
        chain = args.chain,
        abi = args.abi,
        root = args.root,
        factory = args.factory,
        consensus = args.consensus,
        transactions = args.transactions,
        actors = args.actors,
        cleaner = assert(args.cleaner),
        epoch = args.epoch,
        initial_hash = args.initial_hash,
        input_paths = args.input_paths,
        directory = args.directory,
        claim_staging_period = args.claim_staging_period,
        observation_policy = cast.policy(args.observation_policy or 4),
        seal_block = args.seal_block,
        seal_hash = args.seal_hash,
        rejected = {},
        invalid = {},
        prepared = {},
        blocked = {},
    }, { __index = methods })
end

return M
