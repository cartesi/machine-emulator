-- Self-test of the runner: must exit 0.
local harness = require("harness")
harness.main(function()
    local cartesi = require("cartesi")
    return harness.expect(#cartesi.UARCH_PRISTINE_STATE_HASH == 32, "cartesi module loads")
end)
