-- Event-driven adapter for the doc/recipes players.
-- Contracts own pairing, clocks, and results. Claims and prepared proofs survive
-- observations; the player's transaction journal owns its account's nonces and fees.
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local log_history = require("prt-log-history")
local cartesi = require("cartesi")
local prt = require("prt")
local M = {}
local methods = {}

local function event_key(event)
    return event.log.blockHash .. ":" .. event.log.logIndex
end

local function match_key(event)
    return event.address .. ":" .. event.matchIdHash
end

-- The history accepts only canonical quantities, which order by length and then as strings.
local function quantity_less(a, b)
    return #a < #b or (#a == #b and a < b)
end

local function log_less(a, b)
    if a.blockNumber ~= b.blockNumber then
        return quantity_less(a.blockNumber, b.blockNumber)
    end
    return quantity_less(a.logIndex, b.logIndex)
end

-- The event of a log, decoded once. Logs without an event in the ABI are remembered as false.
local function decode(self, log)
    local event = self.decoded[log]
    if event == nil then
        event = self.abi:event(log) or false
        self.decoded[log] = event
    end
    return event or nil
end

function methods:observe()
    local head, hash, tip, tip_hash = self.chain:head(self.observation_policy)
    if self.seal_block then
        assert(self.chain:is_canonical(self.seal_block, self.seal_hash), "stable epoch seal was reorganized")
    end
    -- Logs come from the history, which fetches only the blocks it has not seen. A rejected
    -- observation resets it, so the next one fetches everything again.
    local history = self.history
    history:observe(head, hash)
    local addresses, first_blocks = { self.factory, self.consensus, self.root }, {}
    local fetched, logs, contexts, order = {}, {}, {}, {}
    local index = 1
    while addresses[index] do
        local address = addresses[index]
        index = index + 1
        if not fetched[address] then
            fetched[address] = true
            for _, log in ipairs(history:get_logs(address, first_blocks[address] or self.first_block)) do
                assert(log.address == address, "invalid log address")
                assert(type(log.removed) == "boolean", "log lacks removed flag")
                if log.removed then
                    history:reset()
                    return nil
                end
                assert(eth.small(log.blockNumber) <= head, "log is past sampled head")
                logs[#logs + 1] = log
                local event = decode(self, log)
                if event and event.name == "NewInnerTournament" then
                    addresses[#addresses + 1] = event.childTournament
                    first_blocks[event.childTournament] = eth.small(log.blockNumber)
                end
            end
        end
    end
    if not self.chain:is_canonical(head, hash) then
        history:reset()
        return nil
    end
    table.sort(logs, log_less)
    local matches, deleted, recovered, events, sealed = {}, {}, {}, {}, false
    local staged, settled
    local blocks, seen = {}, {}
    for _, log in ipairs(logs) do
        if blocks[log.blockNumber] and blocks[log.blockNumber] ~= log.blockHash then
            history:reset()
            return nil
        end
        blocks[log.blockNumber] = log.blockHash
        local key = log.blockHash .. ":" .. log.logIndex
        assert(not seen[key], "duplicate log position")
        seen[key] = true
        local event = decode(self, log)
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
        history:reset()
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

-- A handler answers with a payload, "nothing" when it has no payload to give, or "done" when its
-- player leaves the game. The bridge then stops all of its jobs.
local function payload(self, response)
    if response == "done" then
        self.done = true
        return nil
    elseif response == "nothing" then
        return nil
    end
    assert(type(response) ~= "string", "a handler returned an unknown string")
    return response
end

local function holds(self, address, root)
    local claim = self.claims and self.claims[address]
    return claim and claim.root == root and claim or nil
end

local function build_claim(self, context)
    local geometry = self.geometry
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
    local claim = self.computations[key]
    if not context.parent then
        assert(
            height == geometry.mcycle_height
                and eth.small(descriptor.log2Stride) == geometry.uarch_height
                and eth.small(descriptor.level) == 0,
            "root does not match the factory geometry"
        )
        if not claim then
            response = payload(self, self.player.event_handler.commit_mcycle_claim(self.player))
            if not response then
                return nil, false
            end
        end
    else
        assert(
            height == geometry.uarch_height
                and eth.small(descriptor.log2Stride) == 0
                and eth.small(descriptor.level) == 1,
            "child does not match the factory geometry"
        )
        local input, period, offset = eth.coordinates(descriptor.baseCycle, geometry)
        assert(offset == 0, "child starts inside a period")
        if not claim then
            response = payload(self, self.player.event_handler.commit_uarch_claim(self.player, input, period))
            if not response then
                return nil, false
            end
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
    self.computations[key] = claim
    return claim, response ~= nil
end

local function bind_claim(self, address, claim)
    if self.claims[address] == claim then
        return
    end
    self.claims[address] = claim
end

local function can_join(self, context, snapshot)
    local event, d = context.creation, context.descriptor
    return snapshot.tip + 1 < eth.small(d.startInstant) + eth.small(d.allowance)
        and not snapshot.deleted[context.parent_match]
        and (
            not context.parent
            or (not self.done and (holds(self, context.parent, event.one) or holds(self, context.parent, event.two)))
        )
end

-- Whether the bridge's signer joined a tournament, which binds the player's claim there after its
-- joining window closes, so a restarted bridge derives the same bindings from the chain.
local function joined_by(self, context)
    for _, joined in pairs(context.joined) do
        if joined.submitter == self.signer.address then
            return true
        end
    end
    return false
end

-- Claims belong to computations; tournament addresses are only associations
-- reconstructed from the current branch. Keep computation out of job queries.
function methods:update_claims(snapshot)
    local computed = false
    for _, context in ipairs(snapshot.order) do
        local event = context.creation
        local holds_parent = not context.parent
            or holds(self, context.parent, event.one)
            or holds(self, context.parent, event.two)
        local bound_child = context.parent and self.claims[context.address]
        if bound_child and not holds_parent then
            bind_claim(self, context.address, nil)
            bound_child = nil
        end
        local rejoined = holds_parent and not self.done and joined_by(self, context)
        if bound_child or can_join(self, context, snapshot) or rejoined then
            local claim, built = build_claim(self, context)
            if claim then
                bind_claim(self, context.address, claim)
            end
            computed = computed or built
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

-- Every job belongs to the bridge's player, and none remains once it leaves. The permissionless
-- cleanup jobs are derived unless the bridge was created without cleanup.
function methods:jobs(snapshot)
    local jobs = {}
    if self.done then
        return jobs
    end
    local function add(kind, context, event, first, last, root)
        local key = event_key(event) .. ":" .. kind .. ":" .. self.label
        jobs[#jobs + 1] = {
            key = key,
            kind = kind,
            context = context,
            event = event,
            first = first or 0,
            last = last or math.maxinteger,
            root = root,
        }
    end
    for _, context in ipairs(snapshot.order) do
        local event, d = context.creation, context.descriptor
        local close = eth.small(d.startInstant) + eth.small(d.allowance)
        local claim = self.claims[context.address]
        if claim and can_join(self, context, snapshot) and not context.joined[claim.root] then
            add("joinTournament", context, event, 0, close, claim.root)
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
                local claim = holds(self, context.address, event.one) or holds(self, context.address, event.two)
                if claim and not self.done then
                    add("winLeafMatch", context, event, 0, first_timeout, claim.root)
                end
            else
                local height = event.currentHeight and eth.small(event.currentHeight)
                    or eth.small(context.descriptor.height)
                local one_responds = (eth.small(context.descriptor.height) - height) % 2 == 0
                local responder = one_responds and event.one or event.two
                timeout_root = one_responds and event.two or event.one
                first_timeout = eth.small(event.responderDeadline)
                if holds(self, context.address, responder) and not self.done then
                    local kind = height > 1 and "advanceMatch"
                        or (
                            eth.small(context.descriptor.kind) == 0 and "sealLeafMatch"
                            or "sealInnerMatchAndCreateInnerTournament"
                        )
                    add(kind, context, event, 0, first_timeout, responder)
                end
            end
            if holds(self, context.address, timeout_root) and not self.done then
                add("winMatchByTimeout", context, event, first_timeout, eliminable, timeout_root)
            end
            if self.cleanup then
                add("eliminateMatchByTimeout", context, event, eliminable)
            end
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
                    if holds(self, context.parent, standing.parentCommitment) and not self.done then
                        add("winInnerTournament", context, event, result_at, expires, standing.parentCommitment)
                    end
                end
                if self.cleanup then
                    add("eliminateInnerTournament", context, event, expires)
                end
            end
            local claim = holds(self, context.address, candidate)
            if claim and not self.done then
                if not context.parent and not snapshot.staged then
                    add("stageTournamentResult", context, event, result_at, nil, candidate)
                end
                local joined = context.joined[candidate]
                if joined and joined.submitter == self.signer.address and not snapshot.recovered[context.address] then
                    add("tryRecoveringBond", context, event, result_at, nil, candidate)
                end
            end
        end
    end
    if self.cleanup and snapshot.staged and not snapshot.settled and self.claim_staging_period then
        add(
            "acceptStagedTournamentResult",
            snapshot.contexts[self.root],
            snapshot.staged,
            eth.small(snapshot.staged.log.blockNumber) + self.claim_staging_period
        )
    end
    return jobs
end

function methods:prepare(job)
    local context, event = job.context, job.event
    local player, kind = self.player, job.kind
    local id, address, args, value = { event.one, event.two }, context.address, {}, nil
    local claim = self.claims and self.claims[address]
    local proof_check
    if kind == "joinTournament" then
        args = { claim.final_state, claim.proof, claim.children[1], claim.children[2] }
        value = tostring(context.bond)
    elseif kind == "advanceMatch" then
        local response = payload(
            self,
            player.event_handler.reveal_bisection(
                player,
                assert(eth.raw(job.root)),
                event.segmentStartPosition and eth.small(event.segmentStartPosition) or 0,
                event.currentHeight and eth.small(event.currentHeight) or eth.small(context.descriptor.height),
                assert(eth.raw(event.leftNode or event.leftOfTwo))
            )
        )
        if not response then
            return nil
        end
        args = {
            id,
            eth.hex(response.turn_left_node),
            eth.hex(response.turn_right_node),
            eth.hex(response.turn_next_left_node),
            eth.hex(response.turn_next_right_node),
        }
    elseif kind == "sealLeafMatch" or kind == "sealInnerMatchAndCreateInnerTournament" then
        local response = payload(
            self,
            player.event_handler.seal_divergence(
                player,
                assert(eth.raw(job.root)),
                event.segmentStartPosition and eth.small(event.segmentStartPosition) or 0,
                assert(eth.raw(event.leftNode or event.leftOfTwo))
            )
        )
        if not response then
            return nil
        end
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
        local input, period, offset = eth.coordinates(cycle, self.geometry)
        local response = payload(self, player.event_handler.prove_state_transition(player, input, period, offset))
        if not response then
            return nil
        end
        local input_data = self.inputs[input + 1]
        local proof = eth.transition_proof(response, cycle, input_data)
        local ok, obtained = pcall(eth.verify_transition, response, cycle, input_data, event.agreeState)
        local expected = claim.root == event.one and event.finalStateOne or event.finalStateTwo
        proof_check = { valid = ok and obtained == expected, obtained = tostring(obtained), expected = expected }
        args = { id, claim.children[1], claim.children[2], proof }
    elseif kind == "winMatchByTimeout" then
        local response = payload(self, player.event_handler.win_match_by_timeout(player, assert(eth.raw(job.root))))
        if not response then
            return nil
        end
        args = { id, eth.hex(response.computation_hash_left), eth.hex(response.computation_hash_right) }
    elseif kind == "eliminateMatchByTimeout" then
        args = { id }
    elseif kind == "winInnerTournament" then
        claim = assert(self.claims[context.parent])
        address, args = context.parent, { context.address, claim.children[1], claim.children[2] }
    elseif kind == "eliminateInnerTournament" then
        address, args = context.parent, { context.address }
    elseif kind == "acceptStagedTournamentResult" then
        address, args = self.consensus, { self.epoch }
    elseif kind == "stageTournamentResult" then
        local response = payload(self, player.event_handler.prove_outputs_merkle_root(player))
        if not response then
            return nil
        end
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
        signer = self.signer,
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

function methods:report_blocked(result)
    if result.blocked and self.blocked[self.label] ~= result.blocked then
        io.stderr:write(self.label, ": transaction waiting at ", result.blocked, "; observing continues.\n")
    end
    self.blocked[self.label] = result.blocked
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
    self:report_blocked(result)
    if result.rejected then
        self.rejected[job.key] = snapshot.tip_hash
        io.stderr:write(self.label, ": ", job.kind, " preflight reverted.\n")
    end
    return snapshot, result, tip + 1
end

function methods:cancel(snapshot)
    local result = self.transactions:submit(self.signer, nil, snapshot)
    self:report_blocked(result)
    return result
end

-- Jobs are attempted in order of expiry, earliest first, and by key on equal expiry.
local function job_less(a, b)
    if a.last ~= b.last then
        return a.last < b.last
    end
    return a.key < b.key
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
    table.sort(jobs, job_less)
    local due, preferred, obsolete = {}, {}, false
    for _, job in ipairs(jobs) do
        if snapshot.tip + 1 >= job.first and snapshot.tip + 1 < job.last and not self.invalid[job.key] then
            local address = self.signer.address
            due[address] = due[address] or {}
            table.insert(due[address], job)
        end
    end
    local candidate = self.transactions:pending(self.signer.address)
    if candidate then
        next_block = snapshot.tip + 1
        local eligible = due[self.signer.address] or {}
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
            preferred[self.signer.address] = selected.key
            if selected.key ~= candidate.job then
                obsolete = true
            end
        elseif self:cancel(snapshot).published then
            return snapshot, true
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
            local selected = preferred[self.signer.address]
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
    if obsolete and self:cancel(snapshot).published then
        return snapshot, true
    end
    return snapshot, false, next_block
end

-- Reads the claim geometry from the tournament factory. Level 0 is the mcycle claim, whose stride
-- is one period of uarch cycles, and level 1 the uarch claim, whose stride is one uarch cycle.
function M.read_geometry(chain, abi, factory)
    local function view(name, arguments, types)
        return evmu.decode_abi(types, assert(eth.raw(assert(chain:call(factory, abi:calldata(name, arguments))))))
    end
    local level_count = eth.small(view("tournamentLevelCount", {}, "(uint64)")[1])
    assert(level_count == 2, "the factory does not have two tournament levels")
    local levels = {}
    for level = 0, 1 do
        local parameters = view("tournamentParameters", { level }, "(uint64,uint64,uint64,uint64,uint64,uint64)")
        levels[level] = { log2step = eth.small(parameters[2]), height = eth.small(parameters[3]) }
    end
    local geometry = prt.new_geometry(levels[1].height - cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE)
    assert(
        levels[0].height == geometry.mcycle_height
            and levels[0].log2step == geometry.uarch_height
            and levels[1].height == geometry.uarch_height
            and levels[1].log2step == 0,
        "the factory geometry is not a PRT geometry"
    )
    return geometry
end

local function new(args)
    assert(args.chain and args.abi and args.root and args.factory and args.consensus)
    return setmetatable({
        chain = args.chain,
        abi = args.abi,
        root = args.root,
        factory = args.factory,
        consensus = args.consensus,
        transactions = args.transactions,
        player = args.player,
        signer = args.signer,
        label = args.label,
        claims = {},
        computations = {},
        cleanup = args.cleanup ~= false,
        epoch = args.epoch,
        initial_hash = args.initial_hash,
        geometry = args.geometry,
        inputs = args.inputs,
        claim_staging_period = args.claim_staging_period,
        observation_policy = cast.policy(args.observation_policy or 4),
        seal_block = args.seal_block,
        seal_hash = args.seal_hash,
        -- Logs are fetched from this block, except a child's, which start at its creation.
        first_block = args.first_block,
        history = log_history.new(args.chain),
        -- Weak keys drop an event when the history drops its log.
        decoded = setmetatable({}, { __mode = "k" }),
        rejected = {},
        invalid = {},
        prepared = {},
        blocked = {},
    }, { __index = methods })
end

function M.new(args)
    assert(args.geometry, "missing factory geometry")
    assert(args.transactions, "missing transaction journal")
    assert(args.player and args.signer and args.label, "missing player, signer, or label")
    return new(args)
end

-- A bridge with no player, signer, or journal. It only observes, so it is never ticked.
function M.new_observer(args)
    return new(args)
end

return M
