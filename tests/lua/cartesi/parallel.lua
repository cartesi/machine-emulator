-- module to run things in parallel via fork + join
local M = {}

-- for each row in `list`, run `fn(row)` in its own process, limited to `jobs`
-- parallel executions.
local function parallel(list, jobs, fn)
    local unistd = require("posix.unistd")
    local syswait = require("posix.sys.wait")

    local running = 0
    local failures = 0

    -- fork fn(row) into a separate process
    local function spawn_run_one(row)
        local pid, err = unistd.fork()
        if pid == nil then
            error(err)
        elseif pid == 0 then
            os.exit(fn(row))
        end
        return pid
    end

    -- opt is either "WNOHANG" or nil
    -- "WNOHANG" : process only the completed children
    --    nil    : process all children (including the ones still running)
    local function drain(opt)
        local any_children = -1
        local num_errors = 0
        local pid, reason, rc = syswait.wait(any_children)
        while pid and pid ~= (opt and 0) do
            if reason == "exited" or reason == "killed" then -- ignore 'stopped'
                if rc ~= 0 then num_errors = num_errors + 1 end
                running = running - 1
            end
            pid, reason, rc = syswait.wait(any_children, syswait[opt])
        end
        return num_errors
    end

    local iter, _, i = ipairs(list)
    local row
    while true do
        while running < jobs do
            i, row = iter(list, i)
            if not row then goto done end
            spawn_run_one(row)
            running = running + 1
        end
        failures = failures + drain("WNOHANG")
    end
    ::done::
    return failures + drain()
end

M.run = function(list, jobs, fn)
    assert(list, "expected at least one entry")
    assert(jobs >= 1, "expected at least one job at a time")
    assert((fn ~= nil) and (type(fn) == "function"), "expected a function")

    if jobs > 1 then
        return parallel(list, jobs, fn)
    else -- special case that doesn't need the `posix` library
        local failures = 0
        for _, row in ipairs(list) do
            -- change traceback to debug for a shell instead
            local ok, err = xpcall(fn, require("debug").traceback, row)
            if not ok then
                failures = failures + 1
                print(err)
            end
        end
        return failures
    end
end

return M
