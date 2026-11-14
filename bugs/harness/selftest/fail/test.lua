-- Self-test of the runner: must exit 1.
local harness = require("harness")
harness.main(function() return harness.expect(false, "deliberately violated") end)
