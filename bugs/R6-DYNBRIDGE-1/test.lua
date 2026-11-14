-- R6-DYNBRIDGE-1: the PRT bridge retires a settled epoch on a 'latest'-nonce check. A reorg shallower than
-- both policies brings that epoch's last transaction back as the journal's pending candidate; no bridge owns
-- it any more, and the live epoch's bridge defers to it, so the live epoch's deadline-bound move is never sent.
--
-- Real code under test: doc/recipes/prt-bridge.lua (tick, attempt, cancel, awaiting_observation) and
-- doc/recipes/prt-transactions.lua (the file-backed journal: nonces, pending, submit, fees, forget_settled),
-- over doc/recipes/prt-rpc.lua's chain methods (head, is_canonical, simulate, publish). Only the bridge's
-- refresh/jobs/prepare (its view of the contracts) are scripted, and the node is the in-process fake of
-- fakechain.lua (per-block nonce and state, base fee, mempool with replacement rules, reorgs).
--
-- Required (THREAT_MODEL.md R4): "The honest operator observes the chain and submits its transactions within
-- the dispute clocks" and "defends every epoch whose dispute is open". Asserted: epoch 2's move, due in the
-- inclusion window [40, 60), is mined inside that window.
local harness = require("harness")

harness.main(function()
    local here = arg[0]:match("^(.*)/") or "."
    package.path = here .. "/?.lua;" .. package.path
    local fake = require("fakechain")
    local transactions = require("prt-transactions")
    local bridge = require("prt-bridge")
    local hx = fake.hx

    local SENDER = "0x00000000000000000000000000000000000000aa"
    local CONTRACT = "0x00000000000000000000000000000000000000cc"
    local GWEI = 1000000000
    local D, I, F = 4, 8, 12 -- dispute policy (crisium default 4), input policy (demo's 8), finalized depth
    local WINDOW_FIRST, WINDOW_LAST, END = 40, 60, 70

    local tmp = assert(io.popen("mktemp -d"):read("l"), "mktemp failed")
    local function cleanup()
        os.execute("rm -rf '" .. tmp .. "'")
    end

    -- variant: "control" (the node re-injects the reorged transaction at a payable fee),
    -- "drop" (the node does not re-inject it), "fee" (re-injected, but the replacing branch's full blocks
    -- raise the base fee 12.5% per block above its max fee, where it stays).
    local function scenario(variant)
        local log = {}
        local function say(fmt, ...)
            log[#log + 1] = string.format(fmt, ...)
        end
        local jobs = {}
        local node = fake.new({
            rng = function()
                return 0.5
            end,
            finality = F,
            jobs = jobs,
            sender = SENDER,
            drop_on_reorg = variant == "drop" and 1 or 0,
        })
        local signer = node:signer(SENDER)
        local path = tmp .. "/journal-" .. variant .. ".json"
        os.remove(path)
        local chain = node:client()
        local journal = transactions.new({ chain = chain, path = path })
        -- Epoch 1: settled at block 5; one permissionless post-settlement job (a bond recovery or cleanup that
        -- anyone may perform) eligible from block 9, open-ended.
        -- Epoch 2: the live dispute; one deadline-bound move whose inclusion window is [40, 60).
        local epochs = {
            { number = 1, settle = 5, jobs = { { key = "e1-recover", appear = 9, first = 9, last = math.maxinteger } } },
            {
                number = 2,
                settle = 1 << 40,
                jobs = { { key = "e2-move", appear = WINDOW_FIRST, first = WINDOW_FIRST, last = WINDOW_LAST } },
            },
        }
        for _, ep in ipairs(epochs) do
            for _, j in ipairs(ep.jobs) do
                j.data = "job:" .. j.key
                jobs[j.data] = j
            end
        end
        local function make_bridge(ep)
            local b = bridge.new({
                chain = chain,
                abi = {},
                root = "0xr" .. ep.number,
                factory = "0xf",
                consensus = "0xc",
                transactions = journal,
                player = { report_anomaly = function() end },
                signer = signer,
                label = "honest",
                geometry = {},
                epoch = ep.number,
                observation_policy = D,
                retirement_policy = I, -- prt-epoch.lua: retirement_policy = input_policy
            })
            function b:refresh()
                local head, hash, tip, tip_hash = self.chain:head(D)
                return {
                    head = head,
                    hash = hash,
                    tip = tip,
                    tip_hash = tip_hash,
                    ready = true,
                    settled = ep.settle <= head and { log = { blockNumber = hx(ep.settle) } } or nil,
                }
            end
            -- A job exists while its effect is not in the state at the observation head
            function b:jobs(snapshot)
                local out, hb = {}, node:block(snapshot.head)
                for _, job in ipairs(ep.jobs) do
                    if job.appear <= snapshot.head and not hb.done[job.data] then
                        out[#out + 1] = {
                            key = job.key,
                            kind = "move",
                            context = { address = "0xt" },
                            event = { log = { blockHash = "0xb", logIndex = "0x0" } },
                            first = job.first,
                            last = job.last,
                            root = "r",
                        }
                    end
                end
                return out
            end
            function b:prepare(job)
                return { signer = signer, to = CONTRACT, data = "job:" .. job.key }
            end
            return b
        end
        local bridges = { make_bridge(epochs[1]), make_bridge(epochs[2]) }
        -- crisium.lua pass(): newest epoch ticks first; finished bridges are dropped; pass again after a publish
        local function pass()
            for _ = 1, 4 do
                local again = false
                for i = #bridges, 1, -1 do
                    local _, published = bridges[i]:tick()
                    again = again or published
                end
                for i = #bridges, 1, -1 do
                    if bridges[i].finished then
                        say("tip %d: epoch %d bridge finished and dropped (crisium pass)", node.tip, bridges[i].epoch)
                        table.remove(bridges, i)
                    end
                end
                if not again then
                    return
                end
            end
        end
        local function status()
            local p = journal:pending(SENDER)
            return p and string.format("%s(epoch %s)@nonce %d", p.job or "cancel", p.context and p.context.epoch or "-", p.nonce)
                or "none"
        end
        -- Blocks 1..13: the epoch-1 job becomes due at observation head 9; the honest copy C is published.
        for _ = 1, 13 do
            node:mine(GWEI)
            pass()
        end
        say("tip %d: pending %s", node.tip, status())
        -- Block 14: another party's identical permissionless call is included; C does not fit (full block).
        local b14 = node:mine(GWEI, { empty = true })
        b14.done["job:e1-recover"] = b14.number
        pass()
        -- Block 15: C is mined (after the other call, so it is a no-op for the contract).
        node:mine(GWEI)
        pass()
        local blk = node:block(15)
        say("block 15 holds %d honest tx (C)", #blk.txs)
        -- Blocks 16..18: at tip 18 the observation head (tip-4) reaches block 14, epoch 1 has no jobs, the
        -- 'latest' nonce is past C, and settlement block 5 <= tip-8: the bridge of epoch 1 retires.
        for _ = 1, 3 do
            node:mine(GWEI)
            pass()
        end
        say("tip %d: %d bridge(s) left, pending %s", node.tip, #bridges, status())
        -- A 4-block reorg replaces blocks 15..18 (observation head 14 untouched, finality 12 deep, input policy
        -- 8 deep: within both policies). The replacing branch does not hold C.
        local base = GWEI
        local function next_base(full)
            if variant == "fee" and full then
                base = base * 9 // 8 -- EIP-1559: a full block raises the base fee by 12.5%
            end
            return base
        end
        local tip = node.tip
        node:reorg(4, 0)
        for _ = 1, 4 do
            if variant == "fee" then
                node:mine(next_base(true), { empty = true }) -- blocks full of other parties' transactions
            else
                node:mine(GWEI)
            end
        end
        assert(node.tip == tip)
        say("after reorg, tip %d: pending %s, C in node pool: %s", node.tip, status(), tostring(node.pool[0] ~= nil))
        local c_max_fee = node.pool[0] and node.pool[0].max_fee
        for _ = node.tip + 1, END do
            if variant == "fee" and base <= (c_max_fee or 0) then
                node:mine(next_base(true), { empty = true }) -- full blocks until the base fee passes C's max fee
            else
                node:mine(variant == "fee" and base or GWEI) -- then the base fee holds (half-full blocks)
            end
            pass()
        end
        local done
        for n = 1, node.tip do
            done = done or node:block(n).done["job:e2-move"]
        end
        say("tip %d: base fee %.3f gwei, epoch-2 move window [%d,%d) mined at block %s, pending %s, bridges %d",
            node.tip, base / GWEI, WINDOW_FIRST, WINDOW_LAST, tostring(done), status(), #bridges)
        local ok = done ~= nil and done >= WINDOW_FIRST and done < WINDOW_LAST
        return ok, table.concat(log, "\n  ")
    end

    local results = {}
    for _, variant in ipairs({ "control", "drop", "fee" }) do
        local ok, res, text = pcall(scenario, variant)
        if not ok then
            cleanup()
            error(res)
        end
        results[variant] = res
        io.stderr:write("[", variant, "]\n  ", text, "\n")
    end
    cleanup()
    if not results.control then
        harness.setup_error("control: the epoch-2 move was not mined in its window even when the reorged transaction is re-mined")
    end
    local held = true
    held = harness.expect(results.drop, "R4 (node drops the reorged epoch-1 transaction): the live epoch's move is mined within its window [40,60)") and held
    held = harness.expect(results.fee, "R4 (reorged epoch-1 transaction re-injected but priced out): the live epoch's move is mined within its window [40,60)") and held
    return held
end)
