#!/usr/bin/env luapp5.3

local cartesi = require"cartesi"

local tests = {
  {"rv64mi-p-access.bin", 110},
  {"rv64mi-p-breakpoint.bin", 61},
  {"rv64mi-p-csr.bin", 173},
  {"rv64mi-p-illegal.bin", 410},
  {"rv64mi-p-ma_addr.bin", 682},
  {"rv64mi-p-ma_fetch.bin", 196},
  {"rv64mi-p-mcsr.bin", 69},
  {"rv64mi-p-sbreak.bin", 74},
  {"rv64mi-p-scall.bin", 63},
  {"rv64si-p-csr.bin", 126},
  {"rv64si-p-dirty.bin", 143},
  {"rv64si-p-ma_fetch.bin", 154},
  {"rv64si-p-sbreak.bin", 69},
  {"rv64si-p-scall.bin", 76},
  {"rv64si-p-wfi.bin", 57},
  {"rv64ua-p-amoadd_d.bin", 74},
  {"rv64ua-p-amoadd_w.bin", 71},
  {"rv64ua-p-amoand_d.bin", 71},
  {"rv64ua-p-amoand_w.bin", 70},
  {"rv64ua-p-amomax_d.bin", 70},
  {"rv64ua-p-amomax_w.bin", 70},
  {"rv64ua-p-amomaxu_d.bin", 70},
  {"rv64ua-p-amomaxu_w.bin", 70},
  {"rv64ua-p-amomin_d.bin", 70},
  {"rv64ua-p-amomin_w.bin", 70},
  {"rv64ua-p-amominu_d.bin", 70},
  {"rv64ua-p-amominu_w.bin", 70},
  {"rv64ua-p-amoor_d.bin", 69},
  {"rv64ua-p-amoor_w.bin", 69},
  {"rv64ua-p-amoswap_d.bin", 71},
  {"rv64ua-p-amoswap_w.bin", 70},
  {"rv64ua-p-amoxor_d.bin", 72},
  {"rv64ua-p-amoxor_w.bin", 74},
  {"rv64ua-p-lrsc.bin", 6246},
  {"rv64ua-v-amoadd_d.bin", 10678},
  {"rv64ua-v-amoadd_w.bin", 10675},
  {"rv64ua-v-amoand_d.bin", 10687},
  {"rv64ua-v-amoand_w.bin", 10686},
  {"rv64ua-v-amomax_d.bin", 10668},
  {"rv64ua-v-amomax_w.bin", 10668},
  {"rv64ua-v-amomaxu_d.bin", 10668},
  {"rv64ua-v-amomaxu_w.bin", 10668},
  {"rv64ua-v-amomin_d.bin", 10668},
  {"rv64ua-v-amomin_w.bin", 10668},
  {"rv64ua-v-amominu_d.bin", 11162},
  {"rv64ua-v-amominu_w.bin", 11162},
  {"rv64ua-v-amoor_d.bin", 10667},
  {"rv64ua-v-amoor_w.bin", 10667},
  {"rv64ua-v-amoswap_d.bin", 10687},
  {"rv64ua-v-amoswap_w.bin", 10686},
  {"rv64ua-v-amoxor_d.bin", 10670},
  {"rv64ua-v-amoxor_w.bin", 10672},
  {"rv64ua-v-lrsc.bin", 16842},
  {"rv64ui-p-add.bin", 475},
  {"rv64ui-p-addi.bin", 250},
  {"rv64ui-p-addiw.bin", 247},
  {"rv64ui-p-addw.bin", 470},
  {"rv64ui-p-and.bin", 550},
  {"rv64ui-p-andi.bin", 221},
  {"rv64ui-p-auipc.bin", 64},
  {"rv64ui-p-beq.bin", 296},
  {"rv64ui-p-bge.bin", 314},
  {"rv64ui-p-bgeu.bin", 404},
  {"rv64ui-p-blt.bin", 296},
  {"rv64ui-p-bltu.bin", 382},
  {"rv64ui-p-bne.bin", 296},
  {"rv64ui-p-fence_i.bin", 299},
  {"rv64ui-p-jal.bin", 60},
  {"rv64ui-p-jalr.bin", 113},
  {"rv64ui-p-lb.bin", 250},
  {"rv64ui-p-lbu.bin", 250},
  {"rv64ui-p-ld.bin", 384},
  {"rv64ui-p-lh.bin", 262},
  {"rv64ui-p-lhu.bin", 269},
  {"rv64ui-p-lui.bin", 70},
  {"rv64ui-p-lw.bin", 272},
  {"rv64ui-p-lwu.bin", 298},
  {"rv64ui-p-or.bin", 583},
  {"rv64ui-p-ori.bin", 214},
  {"rv64ui-p-sb.bin", 435},
  {"rv64ui-p-sh.bin", 488},
  {"rv64ui-p-sw.bin", 495},
  {"rv64ui-p-sd.bin", 607},
  {"rv64ui-p-simple.bin", 46},
  {"rv64ui-p-sll.bin", 545},
  {"rv64ui-p-slli.bin", 275},
  {"rv64ui-p-slliw.bin", 246},
  {"rv64ui-p-sllw.bin", 505},
  {"rv64ui-p-slt.bin", 464},
  {"rv64ui-p-slti.bin", 242},
  {"rv64ui-p-sltiu.bin", 242},
  {"rv64ui-p-sltu.bin", 481},
  {"rv64ui-p-sra.bin", 517},
  {"rv64ui-p-srai.bin", 263},
  {"rv64ui-p-sraiw.bin", 273},
  {"rv64ui-p-sraw.bin", 517},
  {"rv64ui-p-srl.bin", 559},
  {"rv64ui-p-srli.bin", 284},
  {"rv64ui-p-srliw.bin", 255},
  {"rv64ui-p-srlw.bin", 511},
  {"rv64ui-p-sub.bin", 466},
  {"rv64ui-p-subw.bin", 462},
  {"rv64ui-p-xor.bin", 578},
  {"rv64ui-p-xori.bin", 212},
  {"rv64ui-v-add.bin", 11565},
  {"rv64ui-v-addi.bin", 6637},
  {"rv64ui-v-addiw.bin", 6634},
  {"rv64ui-v-addw.bin", 11560},
  {"rv64ui-v-and.bin", 11640},
  {"rv64ui-v-andi.bin", 6608},
  {"rv64ui-v-auipc.bin", 6450},
  {"rv64ui-v-beq.bin", 6683},
  {"rv64ui-v-bge.bin", 6701},
  {"rv64ui-v-bgeu.bin", 6791},
  {"rv64ui-v-blt.bin", 6683},
  {"rv64ui-v-bltu.bin", 6769},
  {"rv64ui-v-bne.bin", 6683},
  {"rv64ui-v-fence_i.bin", 13155},
  {"rv64ui-v-jal.bin", 6447},
  {"rv64ui-v-jalr.bin", 6500},
  {"rv64ui-v-lb.bin", 11340},
  {"rv64ui-v-lbu.bin", 11340},
  {"rv64ui-v-ld.bin", 11474},
  {"rv64ui-v-lh.bin", 11352},
  {"rv64ui-v-lhu.bin", 11359},
  {"rv64ui-v-lui.bin", 6457},
  {"rv64ui-v-lw.bin", 11362},
  {"rv64ui-v-lwu.bin", 11388},
  {"rv64ui-v-or.bin", 11673},
  {"rv64ui-v-ori.bin", 6601},
  {"rv64ui-v-sb.bin", 11033},
  {"rv64ui-v-sd.bin", 15908},
  {"rv64ui-v-sh.bin", 11086},
  {"rv64ui-v-simple.bin", 6433},
  {"rv64ui-v-sll.bin", 11635},
  {"rv64ui-v-slli.bin", 6662},
  {"rv64ui-v-slliw.bin", 6633},
  {"rv64ui-v-sllw.bin", 11595},
  {"rv64ui-v-slt.bin", 11554},
  {"rv64ui-v-slti.bin", 6629},
  {"rv64ui-v-sltiu.bin", 6629},
  {"rv64ui-v-sltu.bin", 11571},
  {"rv64ui-v-sra.bin", 11607},
  {"rv64ui-v-srai.bin", 6650},
  {"rv64ui-v-sraiw.bin", 6660},
  {"rv64ui-v-sraw.bin", 11607},
  {"rv64ui-v-srl.bin", 11649},
  {"rv64ui-v-srli.bin", 6671},
  {"rv64ui-v-srliw.bin", 6642},
  {"rv64ui-v-srlw.bin", 11601},
  {"rv64ui-v-sub.bin", 11556},
  {"rv64ui-v-subw.bin", 11552},
  {"rv64ui-v-sw.bin", 11093},
  {"rv64ui-v-xor.bin", 11668},
  {"rv64ui-v-xori.bin", 6599},
  {"rv64um-p-div.bin", 106},
  {"rv64um-p-divu.bin", 112},
  {"rv64um-p-divuw.bin", 104},
  {"rv64um-p-divw.bin", 101},
  {"rv64um-p-mul.bin", 465},
  {"rv64um-p-mulh.bin", 473},
  {"rv64um-p-mulhsu.bin", 473},
  {"rv64um-p-mulhu.bin", 505},
  {"rv64um-p-mulw.bin", 404},
  {"rv64um-p-rem.bin", 105},
  {"rv64um-p-remu.bin", 106},
  {"rv64um-p-remuw.bin", 101},
  {"rv64um-p-remw.bin", 107},
  {"rv64um-v-div.bin", 6493},
  {"rv64um-v-divu.bin", 6499},
  {"rv64um-v-divuw.bin", 6491},
  {"rv64um-v-divw.bin", 6488},
  {"rv64um-v-mul.bin", 11555},
  {"rv64um-v-mulh.bin", 6860},
  {"rv64um-v-mulhsu.bin", 6860},
  {"rv64um-v-mulhu.bin", 11595},
  {"rv64um-v-mulw.bin", 6791},
  {"rv64um-v-rem.bin", 6492},
  {"rv64um-v-remu.bin", 6493},
  {"rv64um-v-remuw.bin", 6488},
  {"rv64um-v-remw.bin", 6494},
-- regression tests
  {"sd_pma_overflow.bin", 16},
}

local function run(machine)
    local step = 500000
    local cycles_end = step
    while true do
        machine:run(cycles_end)
        if machine:read_iflags_H() then
            break
        end
        cycles_end = cycles_end + step
    end
    local payload = (machine:read_tohost() & (~1 >> 16)) >> 1
    local cycles = machine:read_mcycle()
    return cycles, payload
end

local errors = {}

for _, test in ipairs(tests) do
    local ram_image = test[1]
    local expected_cycles = test[2]
    io.write(ram_image, " ")
    local machine = cartesi.machine{
        machine = cartesi.get_name(),
        rom = {
            backing = "../tests/bootstrap.bin"
        },
        ram = {
            length = 128 << 20,
            backing = "../tests/" .. ram_image
        }
    }
    local cycles, payload = run(machine)
    if payload ~= 0 then
        local e = string.format("%s returned non-zero payload %d", ram_image, payload)
        errors[#errors+1] = e
        print(e)
    elseif cycles ~= expected_cycles then
        local e = string.format("%s terminated with mcycle = %d, expected %d", ram_image, cycles, expected_cycles)
        errors[#errors+1] = e
        print(e)
    else
        print(" passed")
    end
    machine:destroy()
end

if #errors > 0 then
    io.write(string.format("FAILED %d tests\n", #errors))
    for i, e in ipairs(errors) do
        io.write("\t", e, "\n")
    end
    os.exit(1, true)
else
    print("passed all tests")
    os.exit(0, true)
end
