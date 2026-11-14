-- R1-R12-3: the PRT epoch listener (prt-epoch.lua poll) and the PRT bridge (prt-bridge.lua observe)
-- re-copy, re-sort and re-scan every log they have already processed on every observation.
--
-- R12: "The honest operator's own work outside the emulator, such as observing the chain, ... has a
-- bounded cost per input, per yield, and per match, and its total grows only with the inputs, yields,
-- and matches of the epochs still open."
--
-- The test drives the real recipe modules against an in-memory chain. Every log handed to them is a
-- proxy whose field reads are counted. After K logs have been observed and processed, one more log
-- (one more input, or one more Sybil commitment) is appended and the component observes once more.
-- The work of that observation on the K logs it already processed must not grow with K: the test
-- requires that going from K1 to K2 = 10*K1 at most doubles it (plus a small constant), which leaves
-- room for an incremental implementation with logarithmic lookups. Today it grows ~K log K.
local harness = require("harness")

harness.main(function()
    local evmu = require("cartesi.evmu")
    local eth = require("prt-ethereum")
    local epoch = require("prt-epoch")
    local bridge = require("prt-bridge")
    local prt = require("prt")
    local geometry = prt.new_geometry(10)
    local hash = "0x" .. string.rep("ab", 32)

    -- Counted reads of the fields of logs that were already processed before the measured observation.
    local old_reads = 0
    local function new_stream_set(addresses)
        local streams = {}
        for _, address in ipairs(addresses) do
            streams[address] = {}
        end
        return streams
    end
    -- A log as the chain returns it: a proxy over raw fields. raw.old marks it processed.
    local function make_log(raw)
        local proxy = setmetatable({}, {
            __index = function(_, k)
                if raw.old then
                    old_reads = old_reads + 1
                end
                return raw[k]
            end,
            __newindex = function()
                error("recipe wrote into a chain log")
            end,
        })
        return proxy, raw
    end
    -- In-memory chain. Block n has hash "block<n>"; the mock reads raw fields only, so its own cost
    -- is not counted.
    local function new_chain(streams)
        local chain = { tip = 0 }
        function chain:head()
            return self.tip, "block" .. self.tip, self.tip, "block" .. self.tip
        end
        function chain:is_canonical(number, block_hash)
            return number ~= nil and number <= self.tip and block_hash == "block" .. number
        end
        function chain:logs(addresses, last_block, first_block)
            local result = {}
            for _, address in ipairs(type(addresses) == "table" and addresses or { addresses }) do
                for _, entry in ipairs(streams[address]) do
                    local n = entry.number
                    if n >= (first_block or 0) and n <= last_block then
                        result[#result + 1] = entry.proxy
                    end
                end
            end
            return result
        end
        return chain
    end
    local function append(chain, streams, events, address, event)
        chain.tip = chain.tip + 1
        local block = chain.tip
        local proxy, raw = make_log({
            address = address,
            blockNumber = string.format("0x%x", block),
            blockHash = "block" .. block,
            logIndex = "0x0",
            removed = false,
        })
        event.address, event.log = address, proxy
        events[proxy] = event
        local entry = { number = block, proxy = proxy, raw = raw }
        local stream = streams[address]
        stream[#stream + 1] = entry
        return entry
    end
    local function mark_all_old(streams)
        for _, stream in pairs(streams) do
            for _, entry in ipairs(stream) do
                entry.raw.old = true
            end
        end
    end

    -- Epoch listener: K InputAdded logs of the application already delivered, then one more input.
    local function epoch_reads(k)
        local streams = new_stream_set({ "inputbox", "consensus" })
        local events = {}
        local chain = new_chain(streams)
        local delivered = 0
        local player = {
            event_handler = {
                input_added = function(_, index)
                    assert(index == delivered, "input delivered out of order")
                    delivered = delivered + 1
                end,
                epoch_sealed = function() end,
            },
        }
        local session = epoch.new({
            geometry = geometry,
            transactions = {},
            chain = chain,
            input_policy = 0,
            abi = {
                event = function(_, log)
                    return events[log]
                end,
                topics = function(_, name, ...)
                    return { name, ... }
                end,
            },
            app = "app",
            input_box = "inputbox",
            consensus = "consensus",
            factory = "factory",
            epoch = 0,
            input_begin = 0,
            initial_hash = hash,
            previous_outputs_root = hash,
            player = player,
            signer = {},
            label = "r1-r12-3",
            first_input_block = 0,
        })
        local function input(index)
            append(chain, streams, events, "inputbox", {
                name = "InputAdded",
                appContract = "app",
                index = index,
                input = eth.hex("x"),
            })
        end
        for i = 0, k - 1 do
            input(i)
        end
        assert(not session:poll(), "unexpected seal")
        assert(delivered == k, "setup: not every input was delivered")
        mark_all_old(streams)
        input(k)
        old_reads = 0
        assert(not session:poll(), "unexpected seal")
        assert(delivered == k + 1, "the new input was not delivered")
        return old_reads
    end

    -- Bridge: the root tournament holds K commitments (Sybil joins) already observed, then one more.
    local function bridge_reads(k)
        local streams = new_stream_set({ "factory", "consensus", "root" })
        local events = {}
        local chain = new_chain(streams)
        local created = append(chain, streams, events, "factory", {
            name = "TournamentCreated",
            tournament = "root",
            bondValue = 1,
            descriptor = { initialHash = hash, baseCycle = evmu.bint(0) },
        })
        append(chain, streams, events, "consensus", {
            name = "EpochSealed",
            tournament = "root",
            initialMachineStateHash = hash,
            epochNumber = evmu.bint(0),
        })
        local reader = bridge.new({
            geometry = geometry,
            transactions = {},
            chain = chain,
            abi = {
                event = function(_, log)
                    return events[log]
                end,
            },
            root = "root",
            factory = "factory",
            consensus = "consensus",
            epoch = evmu.bint(0),
            initial_hash = hash,
            player = {},
            signer = {},
            label = "r1-r12-3",
            seal_block = 2,
            seal_hash = "block2",
            first_block = created.number,
        })
        local function join(i)
            append(chain, streams, events, "root", {
                name = "CommitmentJoined",
                commitment = string.format("0x%064x", i),
            })
        end
        for i = 1, k do
            join(i)
        end
        local snapshot = assert(reader:observe(), "setup: observation rejected")
        local joined = 0
        for _ in pairs(snapshot.contexts.root.joined) do
            joined = joined + 1
        end
        assert(joined == k, "setup: not every commitment was observed")
        mark_all_old(streams)
        join(k + 1)
        old_reads = 0
        snapshot = assert(reader:observe(), "observation rejected")
        assert(snapshot.contexts.root.joined[string.format("0x%064x", k + 1)], "the new commitment was not observed")
        return old_reads
    end

    local K1, K2 = 300, 3000
    local ok = true
    local function check(what, f)
        local r1, r2 = f(K1), f(K2)
        io.stderr:write(
            string.format(
                "%s: field reads of already-processed logs in one observation after one new log: K=%d -> %d, K=%d -> %d (x%.1f)\n",
                what,
                K1,
                r1,
                K2,
                r2,
                r2 / math.max(r1, 1)
            )
        )
        ok = harness.expect(
            r2 <= 2 * r1 + 64,
            what
                .. ": R12 bounded cost per input/match: the work of one observation on logs already "
                .. "processed must not grow with their number"
        ) and ok
    end
    -- The listener reports every delivered input on stderr; keep the test output short.
    local real_stderr = io.stderr
    local function quiet(f)
        return function(k)
            io.stderr = {
                write = function(self, ...)
                    local line = table.concat({ ... })
                    if not line:find("processed confirmed InputAdded", 1, true) then
                        real_stderr:write(line)
                    end
                    return self
                end,
            }
            local ok_call, result = pcall(f, k)
            io.stderr = real_stderr
            if not ok_call then
                error(result, 0)
            end
            return result
        end
    end
    epoch_reads = quiet(epoch_reads)
    check("prt-epoch poll (K inputs)", epoch_reads)
    check("prt-bridge observe (K commitments)", bridge_reads)
    return ok
end)
