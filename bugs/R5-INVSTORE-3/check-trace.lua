-- usage: lua5.4 check-trace.lua <strace -f -y output> <stored directory>
-- Exit 0 when the traced process made <stored directory> durable after creating it: every file of the directory,
-- the directory itself and its parent were fsync()ed or fdatasync()ed after the file was created (or a sync() or
-- syncfs() was called after the last creation). Exit 1 otherwise, listing what was never synced. Exit 2 on error.
local trace_name, dir = arg[1], arg[2]
local function realpath(p)
    local f = assert(io.popen("realpath -e '" .. p .. "'"))
    local r = f:read("l")
    f:close()
    return r
end
local ok, err = pcall(function()
    dir = assert(realpath(dir), "cannot resolve " .. tostring(dir))
    local parent = assert(realpath(dir .. "/.."))
    local required = { [dir] = true, [parent] = true }
    local p = assert(io.popen("ls -A '" .. dir .. "'"))
    local nfiles = 0
    for name in p:lines() do
        required[dir .. "/" .. name] = true
        nfiles = nfiles + 1
    end
    p:close()
    assert(nfiles > 0, "empty stored directory")
    local created, synced, global_sync, last_create = {}, {}, nil, 0
    local lineno = 0
    for line in io.lines(trace_name) do
        lineno = lineno + 1
        -- openat(..., "<path>", ...O_CREAT...) = N</resolved path>
        local path = line:match("^%d*%s*open[a-z]*%(.-O_CREAT.-%) = %d+<(.-)>%s*$")
        if path then
            created[path] = lineno
            last_create = lineno
        end
        local spath = line:match("^%d*%s*f[datas]*ync%(%d+<(.-)>%) = 0")
        if spath and not synced[spath] then synced[spath] = {} end
        if spath then table.insert(synced[spath], lineno) end
        if line:match("^%d*%s*syncfs%(.-%) = 0") or line:match("^%d*%s*sync%(%) = 0") then global_sync = lineno end
    end
    local missing = {}
    local names = {}
    for path in pairs(required) do
        names[#names + 1] = path
    end
    table.sort(names)
    for _, path in ipairs(names) do
        local c = created[path] or 0
        local done = global_sync and global_sync > math.max(c, last_create)
        for _, l in ipairs(synced[path] or {}) do
            if l > c then done = true end
        end
        if not done then missing[#missing + 1] = path end
    end
    print(string.format("  %d files in the stored directory; %d of %d required paths (files, directory, parent) " ..
        "never synced after creation", nfiles, #missing, #names))
    for i = 1, math.min(#missing, 5) do
        print("    not synced: " .. missing[i])
    end
    if #missing > 5 then print("    ...") end
    os.exit(#missing == 0 and 0 or 1)
end)
if not ok then
    io.stderr:write("check-trace.lua: ", tostring(err), "\n")
    os.exit(2)
end
