-- usage: lua5.4 reload.lua <stored directory> <expected root hash (0x...)>
-- Exit 0 when the directory loads, and both its cached root hash and its root hash rebuilt from the contents
-- (clear_hash_tree) equal the expected hash. Exit 1 otherwise (directory missing, load fails, or a root differs).
local cartesi = require("cartesi")
local dir, expected = arg[1], arg[2]
local good = true
for _, rt in ipairs({ {}, { clear_hash_tree = true } }) do
    local what = rt.clear_hash_tree and "rebuilt root" or "cached root "
    local ok, m = pcall(cartesi.machine, dir, rt)
    if not ok then
        print(string.format("    %s: load failed: %s", what, tostring(m)))
        good = false
    else
        local root = cartesi.tohex(m:get_root_hash())
        m:destroy()
        print(string.format("    %s: %s%s", what, root, root == expected and "" or "  (expected " .. expected .. ")"))
        if root ~= expected then good = false end
    end
end
os.exit(good and 0 or 1)
