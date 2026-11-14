-- R1-A8-2: one leaf match whose native and Solidity proof checks disagree (or whose proof simulation
-- gets a non-revert RPC error) must not stop the PRT bridge from processing any other match.
--
-- Threat model, A8: "Failing to process one match's data, for any reason, must not stop, delay or
-- decide any other match." R4: "After a stop, it restarts ... and keeps defending its claim."
--
-- The bridge (doc/recipes/prt-bridge.lua) is used unchanged, with its real job derivation (jobs), its
-- real scheduler (tick) and its real attempt(). Only what lies outside it is mocked, in the style of
-- doc/recipes/prt-bridge-test.lua: the chain observation (observe), the chain RPC (head, is_canonical,
-- simulate), the transaction journal (submit) and the computation of the transactions (prepare).
--
-- One tournament holds two matches:
--   * "leaf": a LeafMatchSealed match of the bridge's own commitment, so winLeafMatch is due and
--     carries a proof check;
--   * "other": a match between two other commitments whose elimination is due (permissionless cleanup,
--     needed for the tournament to finish).
-- In each scenario the leaf proof's checks disagree, or its simulation fails with an RPC error. The
-- bridge is ticked a few times, the way crisium.lua's main loop does (which calls tick() with no
-- protection). Required: no tick raises, and the other match's job is submitted.
local harness = require("harness")

harness.main(function()
    local bridge = require("prt-bridge")
    local prt = require("prt")
    local geometry = prt.new_geometry(10)

    local TICKS = 6

    -- Runs one scenario on a fresh bridge (a fresh bridge is also what a restarted player builds).
    -- simulate_leaf(): the (result, failure) the RPC gives for the leaf proof's simulation.
    local function run(native_valid, simulate_leaf)
        local signer = { address = "alice" }
        local context = {
            address = "root",
            creation = { log = { blockHash = "block0", logIndex = "0x0" } },
            descriptor = { height = geometry.mcycle_height, kind = 0, startInstant = 0, allowance = 1 },
            joined = { one = { submitter = "alice" } },
            standing = { matchCount = 2 },
        }
        local leaf = {
            name = "LeafMatchSealed",
            address = "root",
            matchIdHash = "leaf",
            one = "one",
            two = "rival",
            deadlineOne = 20,
            deadlineTwo = 30,
            eliminableAt = 40,
            log = { blockHash = "block2", logIndex = "0x0" },
        }
        local other = {
            name = "MatchCreated",
            address = "root",
            matchIdHash = "other",
            one = "a",
            two = "b",
            responderDeadline = 3,
            eliminableAt = 5,
            log = { blockHash = "block1", logIndex = "0x0" },
        }
        local observed = {
            head = 4,
            hash = "block4",
            tip = 8,
            tip_hash = "block8",
            ready = true,
            order = { context },
            contexts = { root = context },
            events = { other, leaf },
            matches = { ["root:leaf"] = leaf, ["root:other"] = other },
            deleted = {},
            recovered = {},
        }
        local submitted, simulations, anomalies = {}, 0, {}
        local chain = {
            head = function()
                return observed.tip, observed.tip_hash
            end,
            is_canonical = function()
                return true
            end,
            simulate = function(_, _, _, data)
                if data == "leaf-proof" then
                    simulations = simulations + 1
                    return simulate_leaf()
                end
                return "0x", nil
            end,
        }
        local journal = {
            receipt = function() end,
            pending = function() end,
            submit = function(_, _, request)
                submitted[#submitted + 1] = request.kind .. "@" .. request.context.event
                return { published = true }
            end,
        }
        local player = {
            report_anomaly = function(_, kind)
                anomalies[#anomalies + 1] = kind
            end,
        }
        local client = bridge.new({
            geometry = geometry,
            chain = chain,
            transactions = journal,
            abi = {},
            root = "root",
            factory = "factory",
            consensus = "consensus",
            player = player,
            signer = signer,
            label = "honest",
            cleanup = true,
        })
        client.claims = { root = { root = "one", children = { "c1", "c2" } } }
        function client.observe()
            return observed
        end
        function client.prepare(_, job)
            if job.kind == "winLeafMatch" then
                return {
                    signer = signer,
                    to = "root",
                    data = "leaf-proof",
                    proof_check = { valid = native_valid, obtained = "x", expected = "x" },
                }
            end
            return { signer = signer, to = "root", data = job.kind }
        end

        -- Sanity of the fixture: the real job derivation yields both jobs, both due at the next block.
        local due = {}
        for _, job in ipairs(client:jobs(observed)) do
            if observed.tip + 1 >= job.first and observed.tip + 1 < job.last then
                due[#due + 1] = job.kind .. "@" .. job.event.matchIdHash
            end
        end
        table.sort(due)
        if table.concat(due, ",") ~= "eliminateMatchByTimeout@other,winLeafMatch@leaf" then
            harness.setup_error("fixture does not derive the expected due jobs: " .. table.concat(due, ","))
        end

        local errors = {}
        for _ = 1, TICKS do
            local ok, err = pcall(client.tick, client)
            if not ok then
                errors[#errors + 1] = tostring(err)
            end
        end
        local other_done = false
        for _, s in ipairs(submitted) do
            if s == "eliminateMatchByTimeout@block1:0x0" then
                other_done = true
            end
        end
        return {
            errors = errors,
            other_done = other_done,
            submitted = submitted,
            simulations = simulations,
            anomalies = anomalies,
        }
    end

    local scenarios = {
        {
            name = "native accepts, Solidity simulation reverts (code 3)",
            native_valid = true,
            simulate = function()
                return nil, { code = 3, message = "execution reverted" }
            end,
        },
        {
            name = "native rejects, Solidity simulation accepts",
            native_valid = false,
            simulate = function()
                return "0x", nil
            end,
        },
        {
            name = "proof simulation answered by a non-revert RPC error",
            native_valid = true,
            simulate = function()
                return nil, { code = -32000, message = "header not found" }
            end,
        },
    }

    local all_ok = true
    for _, scenario in ipairs(scenarios) do
        local r = run(scenario.native_valid, scenario.simulate)
        -- A second fresh bridge over the same chain state stands for the relaunched player.
        local again = run(scenario.native_valid, scenario.simulate)
        local ok = #r.errors == 0 and r.other_done
        all_ok = all_ok and ok
        print(string.format("scenario: %s", scenario.name))
        print(
            string.format(
                "  ticks: %d, raised: %d, leaf simulations: %d, submitted: [%s], anomalies: [%s]",
                TICKS,
                #r.errors,
                r.simulations,
                table.concat(r.submitted, ", "),
                table.concat(r.anomalies, ", ")
            )
        )
        if #r.errors > 0 then
            print("  first error: " .. r.errors[1])
        end
        print(
            string.format(
                "  other match's elimination submitted: %s; after a restart (fresh bridge): raised %d, submitted %s",
                tostring(r.other_done),
                #again.errors,
                tostring(again.other_done)
            )
        )
        print("  " .. (ok and "OK" or "VIOLATION"))
    end
    return harness.expect(
        all_ok,
        "A8: failing to process one match's leaf proof must not stop the bridge from processing another match"
    )
end)
