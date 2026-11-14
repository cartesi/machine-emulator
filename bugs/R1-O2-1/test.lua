-- R1-O2-1: after a power loss right after an input is recorded, the PRT stored player restarts from the unsynced
-- backup clone (machine.revert) and trusts its cached hash tree, so it records root hashes that are not the
-- content hashes of its machine.
--
-- Required (THREAT_MODEL.md, O2): "A process that stops (crash, kill, or power loss) leaves every stored directory
-- it was writing or sharing in an unspecified state. The operator discards those directories and resumes from a
-- guaranteed one". R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its
-- claim." Section 5: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it
-- must follow them".
--
-- The test runs doc/recipes/prt.lua's stored player (unchanged, loaded as a module) in child processes:
--   control:  inputs 0 and 1, no stop                                  -> root hash R (state.json)
--   crashed:  input 0, power loss modelled at the sync of the backup clone (player.lua "crash"), then a relaunch
--             on the same epoch directory that is delivered inputs 0 and 1 again, as a restarted listener does
--                                                                       -> root hash R' (state.json)
-- It asserts R' == R: the relaunched player must defend the same state as an uninterrupted one. On audit/prt2
-- R' differs, while the relaunched player's machine contents, rehashed with clear_hash_tree, hash to R.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local template = harness.config_dir("baremetal-template") .. "/machine"
    if not io.open(template .. "/config.json", "rb") then
        harness.setup_error("missing " .. template .. " (run bugs/harness/configs/make-configs.sh)")
    end
    local p = assert(io.popen("mktemp -d -t r1-o2-1.XXXXXX"))
    local tmp = p:read("l")
    p:close()
    assert(tmp and #tmp > 0, "mktemp failed")
    local function cleanup()
        os.execute("rm -rf '" .. tmp .. "'")
    end

    local ok, result = xpcall(function()
        local inputs = {}
        for i = 0, 1 do
            local path = tmp .. "/input-" .. i .. ".bin"
            local f = assert(io.open(path, "wb"))
            f:write(harness.encode_advance({ index = i, payload = "input " .. i .. string.rep("x", 100) }))
            f:close()
            inputs[#inputs + 1] = "'" .. path .. "'"
        end
        local function player(mode, directory, input_list)
            assert(os.execute("mkdir -p '" .. directory .. "'"))
            local command = string.format(
                "lua5.4 player.lua %s '%s' '%s' %s 2>&1",
                mode,
                directory,
                template,
                table.concat(input_list, " ")
            )
            local pipe = assert(io.popen(command))
            local output = pipe:read("a")
            local _, _, status = pipe:close()
            io.stderr:write(string.format("[%s %s] exit %s\n%s", mode, directory:match("[^/]+$"), status, output))
            return status, output:match("ROOT (0x%x+)")
        end

        local control_status, control_root = player("run", tmp .. "/control", inputs)
        if control_status ~= 0 or not control_root then
            error("setup: the uninterrupted stored player failed")
        end

        local crash_status = player("crash", tmp .. "/crashed", { inputs[1] })
        if crash_status ~= 99 and crash_status ~= 3 then
            error("setup: the crash run ended unexpectedly")
        end
        if crash_status == 3 then
            io.stderr:write("note: the player never synced an unsynced clone of its epoch machine; nothing to lose\n")
        end

        local relaunch_status, relaunch_root = player("run", tmp .. "/crashed", inputs)
        local content_root
        do
            local loaded, m = pcall(cartesi.machine, tmp .. "/crashed/machine", { clear_hash_tree = true })
            if loaded then
                content_root = cartesi.tohex(m:get_root_hash())
                m:destroy()
            end
        end
        io.stderr:write("uninterrupted player, root after input 1:          ", control_root, "\n")
        io.stderr:write("relaunched player, root it records after input 1:  ", tostring(relaunch_root), "\n")
        io.stderr:write("relaunched player's machine, contents rehashed:    ", tostring(content_root), "\n")
        if relaunch_status ~= 0 or not relaunch_root then
            return harness.expect(false, "R4/O2: after a power loss the stored player must relaunch and keep "
                .. "defending its claim (the relaunch failed)")
        end
        return harness.expect(
            relaunch_root == control_root,
            "R4/O2: after a power loss the stored player must resume from a guaranteed directory and record the "
                .. "same root hash as an uninterrupted player (relaunched "
                .. relaunch_root
                .. ", uninterrupted "
                .. control_root
                .. ")"
        )
    end, debug.traceback)
    cleanup()
    if not ok then
        error(result, 0)
    end
    return result
end)
