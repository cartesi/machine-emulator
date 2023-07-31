local cartesi = require("cartesi")
local merkle = require("cartesi.merkle")
local keccak = cartesi.keccak

local function get_machine_metatable()
    local machine <close> = cartesi.machine({ ram = { length = 0x1000 } })
    return getmetatable(machine)
end

local machine_methods = get_machine_metatable().__index

function machine_methods:get_pmas(dump_memory)
    -- TODO(edubart): implement this function as a C/C++ API instead
    local config = self:get_initial_config()
    local pmas = {
        { start = cartesi.PMA_SHADOW_STATE_START, length = cartesi.PMA_SHADOW_STATE_LENGTH }, -- shadow state
        { start = cartesi.PMA_SHADOW_PMAS_START, length = cartesi.PMA_SHADOW_PMAS_LENGTH }, -- shadow pmas
        { start = cartesi.PMA_SHADOW_TLB_START, length = cartesi.PMA_SHADOW_TLB_LENGTH }, -- shadow tlb
        { start = cartesi.PMA_CLINT_START, length = cartesi.PMA_CLINT_LENGTH }, -- clint
        { start = cartesi.PMA_HTIF_START, length = cartesi.PMA_HTIF_LENGTH }, -- htif
        { start = cartesi.PMA_DTB_START, length = cartesi.PMA_DTB_LENGTH }, -- dtb
    }
    -- uarch ram
    if config.uarch.ram.length > 0 then
        table.insert(pmas, { start = cartesi.PMA_UARCH_RAM_START, length = config.uarch.ram.length })
    end
    -- ram
    table.insert(pmas, { start = cartesi.PMA_RAM_START, length = config.ram.length })
    -- flash drives
    for _, flash in ipairs(config.flash_drive) do
        table.insert(pmas, { start = flash.start, length = flash.length })
    end
    -- sort by start
    table.sort(pmas, function(a, b) return a.start < b.start end)
    -- dump memory
    if dump_memory then
        for _, pma in ipairs(pmas) do
            pma.data = self:read_memory(pma.start, pma.length)
        end
    end
    return pmas
end

function machine_methods:dump_pmas_and_get_root_hash()
    -- we intentionally dump pmas to a file instead using machine read memory,
    -- to exercise bin files dumping
    local pmas = self:get_pmas()
    self:dump_pmas()
    -- remove pma files on scope end
    local _ <close> = setmetatable({}, {
        __close = function()
            for _, pma in ipairs(pmas) do
                local filename = string.format("%016x--%016x.bin", pma.start, pma.length)
                os.remove(filename)
            end
        end,
    })
    for _, pma in ipairs(pmas) do
        local filename = string.format("%016x--%016x.bin", pma.start, pma.length)
        local file <close> = assert(io.open(filename, "rb"))
        pma.data = assert(file:read("a"))
    end
    local hlen = 1 << 63
    local left, it = merkle.keccak_chunks(pmas, 0, hlen, 1)
    local right = merkle.keccak_chunks(pmas, hlen, hlen, it)
    return keccak(left, right)
end

return machine_methods
