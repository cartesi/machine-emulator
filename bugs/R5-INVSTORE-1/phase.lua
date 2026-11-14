-- Phases of the R5-INVSTORE-1 test (run by test.sh). Exit status of each phase is interpreted by test.sh.
--   clone  <src> <dir>      clone_stored + sync_stored                       (0 ok, 2 setup error)
--   dirty  <dir> <hashfile> [label [filler]]  load with SHARING_ALL, write 2048 RAM pages, record the root hash,
--                           destroy, sync_stored                             (0 sync ok, 3 sync failed, 2 error)
--                           with <filler>: the first sync must fail (else 4); then <filler> is removed and the same
--                           process calls sync_stored again                  (0 second sync ok, 3 it failed)
--   check  <dir> <hashfile> reload (no rebuild) and compare with the recorded root
--                           (0 equal, 1 differ, 4 the load itself failed loudly, 2 error)
local ok_load, cartesi = pcall(require, "cartesi")
if not ok_load then
    io.stderr:write(tostring(cartesi), "\n")
    os.exit(2)
end
local phase = arg[1]

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function sync(dir, label)
    local ok, err = pcall(function() cartesi.machine:sync_stored(dir) end)
    print(string.format("%-40s %s", label, ok and "SUCCESS" or ("FAILED: " .. tostring(err))))
    return ok
end

local status = 2
local ok, err = pcall(function()
    if phase == "clone" then
        cartesi.machine:clone_stored(arg[2], arg[3])
        cartesi.machine:sync_stored(arg[3])
        status = 0
    elseif phase == "dirty" then
        local dir, hashfile = arg[2], arg[3]
        local m = cartesi.machine(dir, {}, cartesi.SHARING_ALL)
        -- change 8 MiB of RAM pages that are holes in the sparse RAM file (new blocks must be allocated)
        for i = 0, 2047 do
            m:write_memory(0x80000000 + (32 << 20) + (i << 12), string.rep(string.char(1 + i % 250), 4096))
        end
        local root = m:get_root_hash()
        local f <close> = assert(io.open(hashfile, "wb"))
        f:write(root)
        print("root hash of the machine before destroy: " .. hex(root))
        m:destroy()
        local filler = arg[5]
        if not filler then
            status = sync(dir, arg[4] or "first sync_stored (storage full):") and 0 or 3
        else
            -- Same process: the first sync must fail (host fault), then the space is freed and the
            -- process syncs the same directory again
            if sync(dir, arg[4] or "first sync_stored (storage full):") then
                status = 4
            else
                assert(os.remove(filler))
                status = sync(dir, "second sync_stored (space freed):") and 0 or 3
            end
        end
    elseif phase == "sync" then
        status = sync(arg[2], "second sync_stored (space freed):") and 0 or 3
    elseif phase == "check" then
        local dir, hashfile = arg[2], arg[3]
        local f <close> = assert(io.open(hashfile, "rb"))
        local expected = f:read("a")
        local cached, rebuilt
        local loaded, load_err = pcall(function()
            local m <close> = cartesi.machine(dir, {})
            cached = m:get_root_hash()
        end)
        if not loaded then
            -- A loud refusal to load the directory (e.g. a fix that invalidates it after a failed sync)
            print("loading the directory failed: " .. tostring(load_err))
            status = 4
            return
        end
        do
            local m <close> = cartesi.machine(dir, { clear_hash_tree = true })
            rebuilt = m:get_root_hash()
        end
        print("expected (machine before destroy):  " .. hex(expected))
        print("root after reload (cached tree):    " .. hex(cached))
        print("root rebuilt from the contents:     " .. hex(rebuilt))
        status = (cached == expected and rebuilt == expected) and 0 or 1
    else
        error("unknown phase " .. tostring(phase))
    end
end)
if not ok then
    io.stderr:write("phase ", tostring(phase), " error: ", tostring(err), "\n")
    os.exit(2)
end
os.exit(status)
