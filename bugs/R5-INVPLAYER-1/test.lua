-- R5-INVPLAYER-1: a one-time host fault while the PRT player builds a uarch claim becomes a permanent refusal
-- to build that claim (doc/recipes/prt.lua event_handler.commit_uarch_claim, failed_uarch_periods).
--
-- A stored player (as crisium runs it) on the bare-metal template takes one input and seals the epoch. While it
-- builds the uarch claim of (input 0, period 0), the soft RLIMIT_NOFILE is lowered to the descriptors already
-- open, so the build hits a real EMFILE ("Too many open files"). The limit is then restored. The bridge calls
-- commit_uarch_claim again on every tick while the inner tournament is joinable; the test does the same.
--
-- Required (THREAT_MODEL R4, section 4): a host fault may stop the honest operator, which then restarts and keeps
-- defending its claim. So once the fault is gone, either the first call raised (the supervisor relaunches the
-- player) or a later call in the same process returns the uarch claim. Exit 1 if the first call swallowed the
-- error and every later call returns "nothing" although the build itself now succeeds (control).

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local fs = require("cartesi.filesystem")
    local prt = require("prt")
    local ok_res, res = pcall(require, "posix.sys.resource")
    if not ok_res then
        harness.setup_error("lua-posix (posix.sys.resource) is required: " .. tostring(res))
    end

    local config_dir = harness.config_dir("baremetal-template")
    local root_hex = harness.read_file(config_dir .. "/root-hash.txt"):match("0x%x+")
    if not root_hex then
        harness.setup_error("missing baremetal-template root hash (bugs/harness/configs/make-configs.sh)")
    end
    local contract = {
        initial_state_hash = cartesi.fromhex(root_hex),
        machine_directory = config_dir .. "/machine",
        geometry = prt.new_geometry(10),
    }

    local tmp = fs.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "r5-invplayer-1-")
    local epoch = tmp .. "/epoch"
    local player
    local _ <close> = setmetatable({}, {
        __close = function()
            if player then
                pcall(getmetatable(player).__close, player)
            end
            if fs.exists(epoch) then
                pcall(prt.remove_epoch_directory, epoch)
            end
            os.remove(tmp .. "/input-0.bin")
            pcall(fs.remove_directory, tmp)
        end,
    })

    local input = tmp .. "/input-0.bin"
    local f = assert(io.open(input, "wb"))
    f:write("hello")
    f:close()
    fs.create_directory(epoch)

    -- The honest stored player takes the epoch's one input and seals it.
    player = prt.new_stored_player(contract, "honest", nil, epoch)
    local anomalies = {}
    player.anomaly_handler = function(kind, message)
        anomalies[#anomalies + 1] = kind .. " " .. message
    end
    player.event_handler.input_added(player, 0, input)
    repeat
    until not player.event_handler.idle(player)
    player.event_handler.epoch_sealed(player, 1)
    io.stderr:write("sealed: final state ", cartesi.tohex(player.final_state_hash), "\n")

    -- First build of the uarch claim under a transient EMFILE.
    local open_fds = 0
    for _ in pairs(fs.list_directory("/proc/self/fd")) do
        open_fds = open_fds + 1
    end
    local limit = res.getrlimit(res.RLIMIT_NOFILE)
    assert(res.setrlimit(res.RLIMIT_NOFILE, { rlim_cur = open_fds, rlim_max = limit.rlim_max }))
    local first_ok, first = pcall(player.event_handler.commit_uarch_claim, player, 0, 0)
    assert(res.setrlimit(res.RLIMIT_NOFILE, { rlim_cur = limit.rlim_cur, rlim_max = limit.rlim_max }))
    io.stderr:write("first call (EMFILE injected): ", first_ok and tostring(first) or ("raised: " .. tostring(first)),
        "\n")
    for _, a in ipairs(anomalies) do
        io.stderr:write("  anomaly: ", a, "\n")
    end
    if not first_ok then
        -- The fault stopped the player; the supervisor relaunches it from its stored state.
        return harness.expect(true, "the transient fault raised, so the supervisor relaunches the player")
    end
    if first ~= "nothing" then
        harness.setup_error("the injected EMFILE did not reach the uarch claim build (first call returned a claim)")
    end
    if not (anomalies[1] or ""):find("Too many open files", 1, true) then
        harness.setup_error("the first build failed for another reason than the injected EMFILE")
    end

    -- The fault is gone. The bridge calls again on later ticks while the tournament is joinable.
    local later
    for attempt = 1, 3 do
        later = player.event_handler.commit_uarch_claim(player, 0, 0)
        io.stderr:write("later call ", attempt, " (fault cleared): ", type(later) == "table" and "claim" or tostring(later),
            "\n")
        if later ~= "nothing" then
            break
        end
    end

    -- Control: with the fault gone, the same player builds the claim when asked directly.
    local tree = player:new_uarch_tree(0, 0)
    local left, right = tree:get_child_hashes(player, 0, tree.height)
    io.stderr:write("control: direct build succeeds, uarch claim root ", cartesi.tohex(tree:get_root_hash()), "\n")

    if type(later) == "table" then
        return harness.expect(
            later.computation_hash_left == left and later.computation_hash_right == right,
            "R4: after the transient fault clears, the player returns the honest uarch claim"
        )
    end
    return harness.expect(
        false,
        "R4/section 4: a transient host fault (EMFILE) during the uarch claim build must stop the player or be "
            .. "retried; instead commit_uarch_claim keeps returning \"nothing\" for (input 0, period 0) for the life "
            .. "of the process, although the build now succeeds, so the honest uarch claim never joins"
    )
end)
