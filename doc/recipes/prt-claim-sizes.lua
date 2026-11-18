-- Estimates the storage of the claims of an epoch, written one value per file.
--   prt-claim-sizes.lua <log2-period> <sampled-periods-per-input> <machine> <input> [<machine> <input> ...]
-- Each machine waits for its input. Stored trees hold about two hashes per distinct leaf.
local cartesi = require("cartesi")
local fs = require("cartesi.filesystem")

local HASH_SIZE = 32
local LOG2_HASH_SIZE = 5
local LOG2_BUNDLE_MCYCLE_COUNT = 4

local log2_period = assert(tonumber(arg[1]), "missing log2 period")
local sampled_periods_per_input = assert(tonumber(arg[2]), "missing sampled periods per input")
local period = 1 << log2_period
local log2_mcycle_leaves = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
    + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
    - log2_period
local log2_uarch_leaves = log2_period + cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE

local function format_size(log2_bytes, bytes)
    local units = { "bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" }
    local unit = math.min(log2_bytes // 10, #units - 1)
    local scaled = bytes and bytes / (1 << (10 * unit)) or (1 << (log2_bytes - 10 * unit))
    return string.format(scaled < 10 and "%.1f %s" or "%.0f %s", scaled, units[unit + 1])
end

local function format_bytes(bytes)
    local log2_bytes = 0
    while (1 << (log2_bytes + 1)) <= bytes do
        log2_bytes = log2_bytes + 1
    end
    return format_size(log2_bytes, bytes)
end

local function new_input_machine(machine_path, input_path)
    local machine = cartesi.machine(machine_path)
    machine:send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        fs.read_file(input_path),
        machine:get_root_hash()
    )
    return machine
end

local function run_to(machine, mcycle)
    while math.ult(machine:read_reg("mcycle"), mcycle) do
        if machine:run(mcycle) ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            break
        end
    end
end

-- Distinct leaves of a uarch claim: the uarch cycles of each mcycle and its reset
local function count_uarch_leaves(machine)
    local leaves = 0
    for _ = 1, period do
        if machine:read_reg("iflags_Y") ~= 0 or machine:read_reg("iflags_H") ~= 0 then
            break
        end
        machine:run_uarch(cartesi.UARCH_CYCLE_MAX)
        leaves = leaves + machine:read_reg("uarch_cycle") + 1
        machine:reset_uarch()
    end
    return leaves
end

math.randomseed(42)
local mcycle_leaves, mcycle_bundles = 0, 0
local uarch_leaves, sampled_periods = 0, 0
for i = 3, #arg, 2 do
    local machine_path, input_path = arg[i], assert(arg[i + 1], "missing input")
    local mcycles
    do
        local machine <close> = new_input_machine(machine_path, input_path)
        local mcycle_begin = machine:read_reg("mcycle")
        run_to(machine, cartesi.MCYCLE_MAX)
        mcycles = machine:read_reg("mcycle") - mcycle_begin
    end
    local leaves = mcycles // period + 1
    mcycle_leaves = mcycle_leaves + leaves
    mcycle_bundles = mcycle_bundles + (leaves + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1) // (1 << LOG2_BUNDLE_MCYCLE_COUNT)
    local periods = {}
    for j = 1, sampled_periods_per_input do
        periods[j] = math.random(0, mcycles // period - 1)
    end
    table.sort(periods)
    local machine <close> = new_input_machine(machine_path, input_path)
    local mcycle_begin = machine:read_reg("mcycle")
    for _, period_index in ipairs(periods) do
        run_to(machine, mcycle_begin + period_index * period)
        uarch_leaves = uarch_leaves + count_uarch_leaves(machine)
        sampled_periods = sampled_periods + 1
    end
end
local mean_uarch_leaves = uarch_leaves // sampled_periods

fs.write_file(tostring(sampled_periods), "sampled_periods")
fs.write_file(string.format("%.0f", mcycle_leaves / 1000), "mcycle_distinct_leaves_thousands")
fs.write_file(tostring(mcycle_bundles), "mcycle_bundles")
fs.write_file(string.format("%.0f", mean_uarch_leaves / 1000), "uarch_distinct_leaves_thousands")
fs.write_file(format_size(log2_mcycle_leaves + 1 + LOG2_HASH_SIZE), "mcycle_full_tree_size")
fs.write_file(format_size(log2_uarch_leaves + 1 + LOG2_HASH_SIZE), "uarch_full_tree_size")
fs.write_file(format_bytes(2 * mcycle_leaves * HASH_SIZE), "mcycle_leaf_forest_size")
fs.write_file(format_bytes(2 * mean_uarch_leaves * HASH_SIZE), "uarch_leaf_forest_size")
fs.write_file(format_bytes(2 * mcycle_bundles * HASH_SIZE), "mcycle_bundle_forest_size")
fs.write_file(format_bytes(2 * period * HASH_SIZE), "uarch_bundle_forest_size")
