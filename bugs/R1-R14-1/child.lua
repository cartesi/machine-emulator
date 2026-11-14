-- Child process of test.lua: runs one measured case on the putchar-loop guest and prints one result line on
-- stdout:  cpu=<seconds> mcycle=<n> calls=<collect calls> hashes=<keccak of all collected hashes> final=<root hash>
-- usage: lua5.4 child.lua <guest.bin> <case>
--   roots-null   collect_mcycle_root_hashes loop, console to_null
--   roots-file   collect_mcycle_root_hashes loop, console to_file /dev/null, every_line (flushed inside the call)
--   roots-buffer collect_mcycle_root_hashes loop, console to_buffer, every_line, caller drains after each break
--   run-buffer   (information) the same loop over run() instead of a collection, to_buffer, every_line, drained
--   bundle-null   collect_mcycle_bundle(0, 10, 4) repeated until the halt, console to_null
--   bundle-file   the same, console to_file /dev/null, every_line (flushed inside the call)
--   bundle-buffer the same, console to_buffer, when_full (the call cannot drain the buffer itself)
-- Geometry of the PRT recipes (doc/recipes/prt.lua: new_geometry(10), LOG2_BUNDLE_MCYCLE_COUNT = 4).
local cartesi = require("cartesi")
local guest, case = arg[1], arg[2]
local LOG2_PERIOD, LOG2_BUNDLE = 10, 4

local consoles = {
    ["roots-null"] = { output_destination = "to_null" },
    ["roots-file"] = { output_destination = "to_file", output_filename = "/dev/null", output_flush_mode = "every_line" },
    ["roots-buffer"] = { output_destination = "to_buffer", output_flush_mode = "every_line" },
    ["run-buffer"] = { output_destination = "to_buffer", output_flush_mode = "every_line" },
    ["bundle-null"] = { output_destination = "to_null" },
    ["bundle-file"] = { output_destination = "to_file", output_filename = "/dev/null", output_flush_mode = "every_line" },
    ["bundle-buffer"] = { output_destination = "to_buffer", output_flush_mode = "when_full" },
}
local console = assert(consoles[case], "unknown case " .. tostring(case))
local m <close> = cartesi.machine({ ram = { length = 64 << 20, backing_store = { data_filename = guest } } },
    { console = console })

-- Hash the initial contents before timing, so the one-off hash of the whole RAM is outside the measurement
m:get_root_hash()
local all, calls = {}, 0
local t0 = os.clock()
if case == "run-buffer" then
    while true do
        calls = calls + 1
        if m:run(cartesi.MCYCLE_MAX) ~= cartesi.BREAK_REASON_CONSOLE_OUTPUT then break end
        m:read_console_output()
    end
    all[1] = m:get_root_hash()
elseif case:match("^roots") then
    local phase, pb = 0, nil
    while true do
        calls = calls + 1
        local r = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, LOG2_PERIOD, phase, LOG2_BUNDLE, pb)
        for _, h in ipairs(r.hashes) do all[#all + 1] = h end
        phase, pb = r.mcycle_phase, r.partial_bundle
        if r.break_reason == cartesi.BREAK_REASON_CONSOLE_OUTPUT then
            if console.output_destination == "to_buffer" then m:read_console_output() end
        else
            break
        end
    end
else
    while m:read_reg("iflags_H") == 0 do
        calls = calls + 1
        local hs = m:collect_mcycle_bundle(0, LOG2_PERIOD, LOG2_BUNDLE)
        for _, h in ipairs(hs) do all[#all + 1] = h end
    end
end
local cpu = os.clock() - t0
assert(m:read_reg("iflags_H") ~= 0, "guest did not halt")
print(string.format("cpu=%.6f mcycle=%d calls=%d nhashes=%d hashes=%s final=%s", cpu, m:read_reg("mcycle"), calls,
    #all, cartesi.tohex(cartesi.keccak256(table.concat(all))), cartesi.tohex(m:get_root_hash())))
