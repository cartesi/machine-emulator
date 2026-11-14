-- Self-test of the runner: setup error must exit 2.
local harness = require("harness")
harness.main(function() error("deliberate setup failure") end)
