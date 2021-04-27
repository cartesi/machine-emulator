local cartesi = require"cartesi"

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

local tests_path = adjust_images_path(os.getenv('CARTESI_TESTS_PATH'))

-- Config yields 5 times with progress
local config =  {
  processor = {
    mvendorid = -1,
    mimpid = -1,
    marchid = -1,
  },
  ram = {
    image_filename = tests_path .. "htif_devices.bin",
    length = 0x4000000,
  },
  rom = {
    image_filename = tests_path .. "bootstrap.bin"
  },
}

local yields = {
    { mcycle = 26, data = 10, cmd = cartesi.machine.HTIF_YIELD_PROGRESS},
    { mcycle = 52, data = 20, cmd = cartesi.machine.HTIF_YIELD_PROGRESS},
    { mcycle = 78, data = 30, cmd = cartesi.machine.HTIF_YIELD_PROGRESS},
    { mcycle = 104, data = 45, cmd = cartesi.machine.HTIF_YIELD_ROLLUP},
    { mcycle = 130, data = 55, cmd = cartesi.machine.HTIF_YIELD_ROLLUP},
    { mcycle = 156, data = 65, cmd = cartesi.machine.HTIF_YIELD_ROLLUP},
}

local function stderr(...)
    io.stderr:write(string.format(...))
end

local final_mcycle = 432
local exit_payload = 42

function test(config, progress_enable, rollup_enable)
    stderr("  testing progress:%s rollup:%s\n",
        progress_enable and "on" or "off",
        rollup_enable and "on" or "off"
    )
    config.htif = {
        yield_progress = progress_enable,
        yield_rollup = rollup_enable,
    }
    local machine = cartesi.machine(config)
    for i, v in ipairs(yields) do
        if v.cmd == cartesi.machine.HTIF_YIELD_PROGRESS and progress_enable or
           v.cmd == cartesi.machine.HTIF_YIELD_ROLLUP and rollup_enable then
            while not machine:read_iflags_Y() and not machine:read_iflags_H() do
                machine:run(math.maxinteger)
            end
            -- when it stops, iflags.Y should be set
            assert(machine:read_iflags_Y())
            -- mcycle should be as expected
            local mcycle = machine:read_mcycle()
            assert(mcycle == v.mcycle)
            -- data should be as expected
            assert(machine:read_htif_tohost_data() == v.data)
            -- cmd should be as expected
            assert(machine:read_htif_tohost_cmd() == v.cmd)
            -- trying to run it without resetting iflags.Y should not advance
            machine:run(math.maxinteger)
            assert(mcycle == machine:read_mcycle())
            assert(machine:read_iflags_Y())
            -- now reset it so the machine can be advanced
            machine:reset_iflags_Y()
        end
    end
    -- finally run to completion
    while not machine:read_iflags_Y() and not machine:read_iflags_H() do
        machine:run(math.maxinteger)
    end
    -- should be halted
    assert(machine:read_iflags_H())
    -- at the expected mcycle
    assert(machine:read_mcycle() == final_mcycle, machine:read_mcycle())
    -- with the expected payload
    assert((machine:read_htif_tohost_data() >> 1) == exit_payload)
    stderr("    passed\n")
end

stderr("testing yield sink\n")

test(config, true, true)
test(config, true, false)
test(config, false, true)
test(config, false, false)
