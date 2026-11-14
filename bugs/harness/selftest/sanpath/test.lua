-- Self-test: exit 0 iff the cartesi module comes from the sanitizer build (run with HARNESS_SANITIZE=1).
local harness = require("harness")
harness.main(function()
    local p = package.searchpath("cartesi", package.cpath)
    return harness.expect(p ~= nil and p:find("/sanitizer/") ~= nil, "cartesi from the sanitizer build: " .. tostring(p))
end)
