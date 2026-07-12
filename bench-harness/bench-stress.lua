#!/usr/bin/env lua5.4
package.cpath = '../src/?.so;'..package.cpath

local argparse = require("argparse")
local cartesi  = require("cartesi")

-- ---------------------------------------------------------------------------
--  Argument parsing
-- ---------------------------------------------------------------------------
local command = argparse("bench-stress", "Stress benchmarks for Cartesi RISC-V emulator")
command:flag("   -q --quiet",         "Only print section averages"):init(false)
command:option("   -f --filter PATTERN", "Only benchmark stressors matching PATTERN (Lua pattern)")
command:argument():args("*"):target("names")("   names", "Explicit list of benchmark names to run (overrides --filter)")

local opts = command:parse()

-- ---------------------------------------------------------------------------
--  Benchmarks (stress-ng tests exercising different CPU/memory paths)
-- ---------------------------------------------------------------------------
local benchs = {
  {name='nop',            desc='NO-OP CPU instruction'},
  {name='regs',           desc='CPU registers stressor'},
  {name='cpu',            desc='CPU stressor'},
  {name='fp',             desc='Floating point operations stressor'},
  {name='crypt',          desc='Crypt'},
  {name='memcpy',         desc='Memory copy (memcpy) stressor'},
  {name='branch',         desc='Branch stressor'},
  {name='heapsort',       desc='BSD heapsort'},
  {name='tsearch',        desc='Binary tree'},
  {name='matrix-3d',      desc='3D Matrix'},
  {name='tree',           desc='Tree data structures'},
  {name='malloc',         desc='Memory allocation'},
  {name='randlist',       desc='Random list'},
}

-- ---------------------------------------------------------------------------
--  Configuration
-- ---------------------------------------------------------------------------
local images_dir = '/usr/share/cartesi-machine/images'
local boot_mcycle   = 256 * 1024 * 1024  -- skip Linux boot
local compute_mcycle = 1 << 30            -- 1 Gi mcycles to benchmark
local ram_length     = 512 * 1024 * 1024  -- 512 MiB

-- ---------------------------------------------------------------------------
--  Filtering
-- ---------------------------------------------------------------------------
local function filter_benchs()
  -- Explicit name list (positional arguments) — highest priority
  if opts.names and #opts.names > 0 then
    local name_set = {}
    for _, name in ipairs(opts.names) do
      name_set[name] = true
    end
    local filtered = {}
    for _, bench in ipairs(benchs) do
      if name_set[bench.name] then
        table.insert(filtered, bench)
      end
    end
    return filtered
  end

  -- Name pattern filter
  if opts.filter then
    local filtered = {}
    for _, bench in ipairs(benchs) do
      if bench.name:match(opts.filter) then
        table.insert(filtered, bench)
      end
    end
    return filtered
  end

  -- No filter — return all benchmarks
  return benchs
end

-- ---------------------------------------------------------------------------
--  Helpers
-- ---------------------------------------------------------------------------
local function human(n)
  if n >= 1000 * 1000 then return string.format('%.2fM', n / (1000 * 1000)) end
  if n >= 1000           then return string.format('%.2fK', n / 1000)       end
  return n
end

-- ---------------------------------------------------------------------------
--  Main
-- ---------------------------------------------------------------------------
local benchs = filter_benchs()

if #benchs == 0 then
  print("No benchmarks matched the given filter.")
  return
end

print('| benchmark        | MIPS     |')
print('|------------------|----------|')

for _, bench in ipairs(benchs) do
  local machine <close> = cartesi.machine({
    ram = {
      length = ram_length,
      backing_store = {
        data_filename = images_dir .. "/linux.bin",
      },
    },
    dtb = {
      init       = bench.asroot and "USER=root" or '',
      entrypoint = "stress-ng --no-rand-seed --" .. bench.name .. " 1 --timeout 1m >> /dev/null",
    },
    flash_drive = {
      {
        backing_store = {
          data_filename = images_dir .. "/rootfs.ext2",
        },
      },
    },
  })

  -- Boot into the benchmark
  machine:run(boot_mcycle)

  -- Measure emulation speed
  local target = boot_mcycle + compute_mcycle
  local start  = os.clock()
  local reason = machine:run(target)
  local elapsed = os.clock() - start

  if reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
    io.stderr:write(string.format("Warning: %s ended early (reason=%d)\n", bench.name, reason))
  end

  local mips = compute_mcycle / (elapsed * 1e6)
  print(string.format('| %-16s | %9.1f |', bench.name, mips))
end
