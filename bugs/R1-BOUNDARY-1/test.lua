-- R1-BOUNDARY-1: the PRT bridge's chain observation must not grow with chain activity that does not
-- belong to the application (THREAT_MODEL.md R12, adversary capability of section 7).
--
-- A bridge observer (doc/recipes/prt-bridge.lua, as prt-epoch.lua starts it: first_block = seal_block)
-- watches a mock chain in the style of the pruning fixture of prt-bridge-test.lua. The application's
-- own history is fixed: the root's TournamentCreated (factory) and EpochSealed (consensus) in the seal
-- block, and a few events of the root tournament. After the seal, K TournamentCreated logs that do not
-- belong to the application are emitted by the shared, permissionless tournament factory (anyone may call
-- MultiLevelTournamentFactory.instantiate; every Dave application uses the same factory).
--
-- The same observation sequence is run twice, with K = 0 (control) and K = FOREIGN, and four counts are
-- compared. Each must not depend on K:
--   fetched   log records the chain handed to the bridge over all observations
--   logs      #snapshot.logs of the last observation (records kept and walked per observation)
--   events    #snapshot.events of the last observation (walked again by jobs/report_lost_matches)
--   reads     field reads on log records during the observations after the first one, in which no
--             new log appears (deterministic measure of per-observation work: sort + walk)
local harness = require("harness")

local FOREIGN = tonumber(arg[1] or "") or 3000
local PER_BLOCK = 50
local MARGIN = 64 -- slack per count for a fixed bridge that does a constant amount of extra work

local function run(foreign)
    local evmu = require("cartesi.evmu")
    local bridge = require("prt-bridge")
    local prt = require("prt")
    local hash = "0x" .. string.rep("ab", 32)
    local raw = setmetatable({}, { __mode = "k" }) -- proxy -> raw record
    local reads, counting = 0, false
    local logs = { factory = {}, consensus = {}, root = {} }
    local function add(address, block, index, event)
        local item = {
            address = address,
            blockNumber = string.format("0x%x", block),
            blockHash = "b" .. block,
            logIndex = string.format("0x%x", index),
            removed = false,
        }
        local proxy = setmetatable({}, {
            __index = function(_, key)
                if counting then
                    reads = reads + 1
                end
                return item[key]
            end,
            __newindex = function()
                error("the bridge wrote into a log record")
            end,
        })
        event.address, event.log = address, proxy
        raw[proxy] = { item = item, event = event }
        table.insert(logs[address], proxy)
    end
    -- The application's own history: seal block 1
    add("factory", 1, 0, {
        name = "TournamentCreated",
        tournament = "root",
        bondValue = 1,
        descriptor = { initialHash = hash, baseCycle = evmu.bint(0) },
    })
    add("consensus", 1, 1, {
        name = "EpochSealed",
        tournament = "root",
        initialMachineStateHash = hash,
        epochNumber = evmu.bint(0),
    })
    add("root", 2, 0, { name = "CommitmentJoined", commitment = "c1" })
    add("root", 2, 1, { name = "CommitmentJoined", commitment = "c2" })
    add("root", 3, 0, { name = "MatchCreated", matchIdHash = "m", one = "c1", two = "c2" })
    -- Chain activity that does not belong to the application: other root tournaments created through the
    -- shared factory after the seal (other applications' epochs, or anyone calling instantiate)
    for i = 1, foreign do
        add("factory", 3 + (i - 1) // PER_BLOCK, 1 + (i - 1) % PER_BLOCK, {
            name = "TournamentCreated",
            tournament = "foreign" .. i,
            bondValue = 1,
            descriptor = { initialHash = "0x" .. string.rep("cd", 32), baseCycle = evmu.bint(0) },
        })
    end
    local head = 4 + foreign // PER_BLOCK
    local fetched = 0
    local args = {
        geometry = prt.new_geometry(10),
        chain = {
            head = function()
                return head, "h" .. head, head, "h" .. head
            end,
            logs = function(_, addresses, last_block, first_block)
                local result = {}
                for _, address in ipairs(type(addresses) == "table" and addresses or { addresses }) do
                    for _, proxy in ipairs(logs[address] or {}) do
                        local number = tonumber(raw[proxy].item.blockNumber)
                        if number >= (first_block or 0) and number <= last_block then
                            result[#result + 1] = proxy
                            fetched = fetched + 1
                        end
                    end
                end
                return result
            end,
            is_canonical = function()
                return true
            end,
        },
        abi = {
            event = function(_, proxy)
                local r = raw[proxy]
                return r and r.event
            end,
        },
        root = "root",
        factory = "factory",
        consensus = "consensus",
        epoch = evmu.bint(0),
        initial_hash = hash,
        seal_block = 1,
        seal_hash = "b1",
        first_block = 1,
    }
    local observer = bridge.new_observer(args)
    local view = assert(observer:observe(), "first observation was rejected")
    assert(view.contexts.root and view.ready, "the root tournament or the seal was not observed")
    -- Later observations, as a player makes several per tick, while the head advances with no new log
    counting = true
    for _ = 1, 4 do
        head = head + 1
        view = assert(observer:observe(), "observation was rejected")
    end
    counting = false
    assert(view.contexts.root and view.ready and view.contexts.root.joined.c1, "the application's state was lost")
    return { fetched = fetched, logs = #view.logs, events = #view.events, reads = reads }
end

harness.main(function()
    local ok_c, control = pcall(run, 0)
    if not ok_c then
        harness.setup_error("control run failed: " .. tostring(control))
    end
    local ok_s, spam = pcall(run, FOREIGN)
    if not ok_s then
        harness.setup_error("run with foreign logs failed: " .. tostring(spam))
    end
    local ok = true
    for _, name in ipairs({ "fetched", "logs", "events", "reads" }) do
        local c, s = control[name], spam[name]
        local good = s <= c + MARGIN
        io.stderr:write(
            string.format(
                "%-8s control (K=0) = %-7d  with K=%d foreign factory logs = %-7d  %s\n",
                name,
                c,
                FOREIGN,
                s,
                good and "independent of K" or "grows with K"
            )
        )
        ok = ok and good
    end
    return harness.expect(
        ok,
        "R12: the honest operator's chain observation 'must not grow ... with chain activity that does not "
            .. "belong to the application' (foreign TournamentCreated logs of the shared tournament factory)"
    )
end)
