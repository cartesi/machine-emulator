-- R1-O2-2: after a stop between the sealed state.json commit and the removal of machine.revert, the PRT stored
-- player's restart (reopen_epoch_directory) replaces the synced epoch machine with an UNSYNCED clone of
-- machine.revert and then removes machine.revert. From then on the epoch directory holds no stored machine that
-- O2 guarantees, and the next restart requires one.
--
-- Requirement (THREAT_MODEL.md): O2 "The operator discards those directories and resumes from a guaranteed one";
-- "The emulator guarantees a stored directory only when it was synced after the last change to its contents";
-- section 5 "The tools and reference implementations that ship with it must follow them"; R4 "After a stop, it
-- restarts from a directory that O2 guarantees and keeps defending its claim".
--
-- Steps (each player run is its own process, as a relaunch is):
--   1. player.lua seal-crash: open an epoch on the bare-metal template, run one input, seal; the process stops
--      (os.exit without cleanup, like kill -9) right after the sealed state.json commit, before machine.revert is
--      removed.
--   2. player.lua reopen under strace: the relaunch. The trace records every change to files and directory
--      entries and every fsync.
--   3. (A) After the relaunch, the epoch directory must hold a machine directory (machine or machine.revert) that
--      matches state.json's root hash and was synced after the last change to its contents (files and entries).
--   4. (B) Power loss: the data of every file of those directories that the relaunch changed and did not sync is
--      discarded (the file becomes a hole of the same size: O2 leaves it unspecified). Then the next relaunch must
--      reopen the sealed epoch.
--   Control (same run): the same steps with a reopen whose clones are synced (stand-in for a fix) must pass A and
--   B, otherwise the test reports a harness error.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local here = harness.REPO .. "/bugs/R1-O2-2"
    local template = harness.config_dir("baremetal-template")
    local template_machine = template .. "/machine"
    local root_hex = harness.read_file(template .. "/root-hash.txt"):match("0x%x+")
    if not root_hex then
        harness.setup_error("missing " .. template .. "/root-hash.txt (bugs/harness/configs/make-configs.sh)")
    end
    if not harness.sh("command -v strace >/dev/null") then
        harness.setup_error("strace is required")
    end

    local ok_tmp, tmp = harness.sh("mktemp -d \"${TMPDIR:-/tmp}/r1-o2-2.XXXXXX\"")
    tmp = ok_tmp and tmp:match("[^\n]+")
    if not tmp then
        harness.setup_error("mktemp failed")
    end

    local function q(s)
        return "'" .. s:gsub("'", "'\\''") .. "'"
    end

    local function run(cmd)
        local _, how, code = os.execute(cmd)
        if how ~= "exit" then
            return 128 + (code or 0)
        end
        return code
    end

    local function player(mode, epoch, extra, prefix)
        return run(
            (prefix or "")
                .. "lua5.4 "
                .. q(here .. "/player.lua")
                .. " "
                .. mode
                .. " "
                .. q(epoch)
                .. " "
                .. q(template_machine)
                .. " "
                .. root_hex
                .. (extra and (" " .. q(extra)) or "")
        )
    end

    local function exists(path)
        return run("test -e " .. q(path)) == 0
    end

    local function list(dir)
        local names = {}
        local p = io.popen("ls -1A " .. q(dir) .. " 2>/dev/null")
        for name in p:lines() do
            names[#names + 1] = name
        end
        p:close()
        table.sort(names)
        return names
    end

    local function parent(path)
        return (path:gsub("/[^/]*$", ""))
    end

    -- Parses an strace -f -y log into, per path, the index of its last change and of its last fsync. Changes are
    -- file data (open for writing, write, truncate, clone) and directory entries (create, link, unlink, rename,
    -- mkdir, rmdir) of the parent. A global sync/syncfs syncs everything.
    local function analyze(log, cwd)
        local last_change, last_sync, made_dirs = {}, {}, {}
        local global_sync = 0
        local index = 0
        local function abs(p)
            if p:sub(1, 1) == "/" then
                return p
            end
            return cwd .. "/" .. p
        end
        local function change(p, i)
            last_change[p] = i
        end
        for line in io.lines(log) do
            index = index + 1
            local call, args, result = line:match("^%d+%s+([%w_]+)%((.*)%)%s+=%s+(%S+)")
            if call and not result:match("^%-") then
                local fd_path = args:match("^%d+<([^>]*)>")
                local strings = {}
                for s in args:gmatch('"([^"]*)"') do
                    strings[#strings + 1] = abs(s)
                end
                if call == "openat" or call == "open" or call == "creat" then
                    local opened = result:match("^%d+<([^>]*)>")
                    if opened and (call == "creat" or args:match("O_WRONLY") or args:match("O_RDWR")
                        or args:match("O_CREAT") or args:match("O_TRUNC")) then
                        change(opened, index)
                        if call == "creat" or args:match("O_CREAT") then
                            change(parent(opened), index)
                        end
                    end
                elseif call == "write" or call == "pwrite64" or call == "writev" or call == "pwritev"
                    or call == "pwritev2" or call == "ftruncate" or call == "fallocate" then
                    if fd_path then
                        change(fd_path, index)
                    end
                elseif call == "sendfile" then
                    if fd_path then
                        change(fd_path, index)
                    end
                elseif call == "copy_file_range" then
                    local out = args:match("^%d+<[^>]*>,%s*[^,]+,%s*%d+<([^>]*)>")
                    if out then
                        change(out, index)
                    end
                elseif call == "ioctl" then
                    if fd_path and args:match("FICLONE") then
                        change(fd_path, index)
                    end
                elseif call == "mkdir" or call == "mkdirat" then
                    local p = strings[#strings]
                    if p then
                        made_dirs[p] = index
                        change(parent(p), index)
                    end
                elseif call == "link" or call == "linkat" or call == "symlink" or call == "symlinkat" then
                    local p = strings[#strings]
                    if p then
                        change(parent(p), index)
                    end
                elseif call == "unlink" or call == "unlinkat" or call == "rmdir" then
                    local p = strings[#strings]
                    if p then
                        change(parent(p), index)
                    end
                elseif call == "rename" or call == "renameat" or call == "renameat2" then
                    for _, p in ipairs(strings) do
                        change(parent(p), index)
                    end
                elseif call == "fsync" or call == "fdatasync" then
                    if fd_path then
                        last_sync[fd_path] = index
                    end
                elseif call == "sync" or call == "syncfs" then
                    global_sync = index
                end
            end
        end
        local function synced_after(p, i)
            return math.max(last_sync[p] or 0, global_sync) > i
        end
        -- Files of dir changed after their last sync, and whether the directory's own entries are durable
        local function unsynced(dir)
            local files = {}
            for _, name in ipairs(list(dir)) do
                local p = dir .. "/" .. name
                if last_change[p] and not synced_after(p, last_change[p]) then
                    files[#files + 1] = p
                end
            end
            local entries_ok = not last_change[dir] or synced_after(dir, last_change[dir])
            local made_ok = not made_dirs[dir] or synced_after(parent(dir), made_dirs[dir])
            return files, entries_ok and made_ok
        end
        return unsynced
    end

    local function rehash(dir)
        local ok, machine = pcall(cartesi.machine, dir, { clear_hash_tree = true })
        if not ok then
            return nil
        end
        local hash = machine:get_root_hash()
        machine:destroy()
        return hash
    end

    -- One scenario. reopen_mode is "reopen" (the player as shipped) or "reopen-synced-clone" (control).
    local function scenario(name, reopen_mode)
        local base = tmp .. "/" .. name
        local epoch = base .. "/epoch"
        assert(run("mkdir -p " .. q(epoch)) == 0)
        local input = base .. "/input.bin"
        local f = assert(io.open(input, "wb"))
        f:write("R1-O2-2 input")
        f:close()

        local status = player("seal-crash", epoch, input)
        if status ~= 17 then
            harness.setup_error(name .. ": seal-crash run did not stop at the injection point (status " .. status .. ")")
        end
        local state = cartesi.fromjson(harness.read_file(epoch .. "/state.json"))
        if not (state.mcycle_forest and not state.epoch_builder) then
            harness.setup_error(name .. ": state.json is not sealed after the stop")
        end
        local root = cartesi.fromhex(state.root_hash)
        if not exists(epoch .. "/machine.revert") or rehash(epoch .. "/machine.revert") ~= root
            or rehash(epoch .. "/machine") ~= root then
            harness.setup_error(name .. ": the stop did not leave machine and machine.revert at the sealed state")
        end
        io.stderr:write(name, ": stopped with the sealed state.json committed, machine and machine.revert both at ",
            state.root_hash, "\n")

        local log = base .. "/reopen.strace"
        status = player(reopen_mode, epoch, nil, "strace -f -y -qq -s 4096 -o " .. q(log) .. " -e trace="
            .. "open,openat,creat,mkdir,mkdirat,link,linkat,symlink,symlinkat,unlink,unlinkat,rmdir,rename,"
            .. "renameat,renameat2,write,pwrite64,writev,pwritev,pwritev2,ftruncate,fallocate,sendfile,"
            .. "copy_file_range,ioctl,fsync,fdatasync,sync,syncfs ")
        if status ~= 0 then
            harness.setup_error(name .. ": the first relaunch failed (status " .. status .. ")")
        end
        local unsynced = analyze(log, here)
        os.remove(log)

        -- (A) a guaranteed machine directory at the sealed state remains
        local guaranteed = {}
        local lost = {}
        for _, dir in ipairs({ epoch .. "/machine", epoch .. "/machine.revert" }) do
            if exists(dir) then
                local files, entries_ok = unsynced(dir)
                local matches = rehash(dir) == root
                local leaf = dir:match("[^/]+$")
                io.stderr:write(string.format("%s: after the relaunch, %s: matches state.json=%s, files changed and "
                    .. "not synced=%d, entries synced=%s\n", name, leaf, tostring(matches), #files,
                    tostring(entries_ok)))
                if matches and #files == 0 and entries_ok then
                    guaranteed[#guaranteed + 1] = leaf
                end
                for _, p in ipairs(files) do
                    lost[#lost + 1] = p
                end
            else
                io.stderr:write(string.format("%s: after the relaunch, %s does not exist\n", name,
                    dir:match("[^/]+$")))
            end
        end
        local a = #guaranteed > 0

        -- (B) power loss: unsynced file data is gone (hole of the same size; the old inode is unlinked, so hard
        -- links to other files are never written), then the next relaunch
        for _, p in ipairs(lost) do
            local fh = assert(io.open(p, "rb"))
            local size = fh:seek("end")
            fh:close()
            assert(os.remove(p))
            assert(run("truncate -s " .. size .. " " .. q(p)) == 0)
        end
        io.stderr:write(string.format("%s: power loss discarded the data of %d unsynced file(s)\n", name, #lost))
        status = player("reopen", epoch)
        local b = status == 0
        io.stderr:write(string.format("%s: relaunch after the power loss: status %d\n", name, status))
        return a, b
    end

    local results = {}
    local ok, err = pcall(function()
        results.control_a, results.control_b = scenario("control", "reopen-synced-clone")
        results.a, results.b = scenario("player", "reopen")
    end)
    run("rm -rf " .. q(tmp))
    if not ok then
        error(err, 0)
    end
    if not (results.control_a and results.control_b) then
        harness.setup_error("control (clones synced) did not pass: the test cannot tell a fixed player apart")
    end
    io.stderr:write("control (reopen with synced clones): A and B hold\n")
    local a = harness.expect(results.a, "O2/R4: after relaunching a sealed epoch, its directory keeps a machine "
        .. "directory at state.json's root hash that was synced after its last change")
    local b = harness.expect(results.b, "O2/R4: after a power loss that follows that relaunch, the next relaunch "
        .. "reopens the sealed epoch")
    return a and b
end)
