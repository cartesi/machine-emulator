-- Runs external commands for the PRT recipe, such as cast.
local fs = require("cartesi.filesystem")

local M = {}

local function quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

-- A temporary file holding a command's input, if it has one.
local function new_input_file(input)
    if input then
        return fs.write_scope_temp_file(input)
    end
end

-- Runs a command and returns its output. An input, if given, is read from a temporary file, since the
-- size of a single command argument is limited.
function M.run(arguments, input)
    local command = {}
    for i, value in ipairs(arguments) do
        assert(not tostring(value):find("\0", 1, true), "NUL in command argument")
        command[i] = quote(value)
    end
    local input_file <close>, input_path = new_input_file(input) -- luacheck: ignore 211
    if input_path then
        command[#command + 1] = "< " .. quote(input_path)
    end
    local pipe = assert(io.popen(table.concat(command, " ") .. " 2>/dev/null", "r"))
    local output = pipe:read("a")
    local ok, why, status = pipe:close()
    -- Tool diagnostics may contain endpoints, signer paths, or credentials.
    assert(ok, string.format("%s failed (%s %s)", arguments[1], why, status))
    return output
end

return M
