local emu = require"emu"

local tests = {
  {"rv64mi-p-access.bin", 111},
  {"rv64mi-p-breakpoint.bin", 62},
  {"rv64mi-p-csr.bin", 174},
  {"rv64mi-p-illegal.bin", 411},
  {"rv64mi-p-ma_addr.bin", 366},
  {"rv64mi-p-ma_fetch.bin", 197},
  {"rv64mi-p-mcsr.bin", 70},
  {"rv64mi-p-sbreak.bin", 75},
  {"rv64mi-p-scall.bin", 64},
  {"rv64si-p-csr.bin", 127},
  {"rv64si-p-dirty.bin", 144},
  {"rv64si-p-ma_fetch.bin", 155},
  {"rv64si-p-sbreak.bin", 70},
  {"rv64si-p-scall.bin", 77},
  {"rv64si-p-wfi.bin", 58},
  {"rv64ua-p-amoadd_d.bin", 75},
  {"rv64ua-p-amoadd_w.bin", 72},
  {"rv64ua-p-amoand_d.bin", 72},
  {"rv64ua-p-amoand_w.bin", 71},
  {"rv64ua-p-amomax_d.bin", 71},
  {"rv64ua-p-amomax_w.bin", 71},
  {"rv64ua-p-amomaxu_d.bin", 71},
  {"rv64ua-p-amomaxu_w.bin", 71},
  {"rv64ua-p-amomin_d.bin", 71},
  {"rv64ua-p-amomin_w.bin", 71},
  {"rv64ua-p-amominu_d.bin", 71},
  {"rv64ua-p-amominu_w.bin", 71},
  {"rv64ua-p-amoor_d.bin", 70},
  {"rv64ua-p-amoor_w.bin", 70},
  {"rv64ua-p-amoswap_d.bin", 72},
  {"rv64ua-p-amoswap_w.bin", 71},
  {"rv64ua-p-amoxor_d.bin", 73},
  {"rv64ua-p-amoxor_w.bin", 75},
  {"rv64ua-p-lrsc.bin", 6237},
  {"rv64ua-v-amoadd_d.bin", 10677},
  {"rv64ua-v-amoadd_w.bin", 10674},
  {"rv64ua-v-amoand_d.bin", 10686},
  {"rv64ua-v-amoand_w.bin", 10685},
  {"rv64ua-v-amomax_d.bin", 10667},
  {"rv64ua-v-amomax_w.bin", 10667},
  {"rv64ua-v-amomaxu_d.bin", 10667},
  {"rv64ua-v-amomaxu_w.bin", 10667},
  {"rv64ua-v-amomin_d.bin", 10667},
  {"rv64ua-v-amomin_w.bin", 10667},
  {"rv64ua-v-amominu_d.bin", 11158},
  {"rv64ua-v-amominu_w.bin", 11158},
  {"rv64ua-v-amoor_d.bin", 10666},
  {"rv64ua-v-amoor_w.bin", 10666},
  {"rv64ua-v-amoswap_d.bin", 10686},
  {"rv64ua-v-amoswap_w.bin", 10685},
  {"rv64ua-v-amoxor_d.bin", 10669},
  {"rv64ua-v-amoxor_w.bin", 10671},
  {"rv64ua-v-lrsc.bin", 16831},
  {"rv64ui-p-add.bin", 476},
  {"rv64ui-p-addi.bin", 251},
  {"rv64ui-p-addiw.bin", 248},
  {"rv64ui-p-addw.bin", 471},
  {"rv64ui-p-and.bin", 551},
  {"rv64ui-p-andi.bin", 222},
  {"rv64ui-p-auipc.bin", 65},
  {"rv64ui-p-beq.bin", 297},
  {"rv64ui-p-bge.bin", 315},
  {"rv64ui-p-bgeu.bin", 405},
  {"rv64ui-p-blt.bin", 297},
  {"rv64ui-p-bltu.bin", 383},
  {"rv64ui-p-bne.bin", 297},
  {"rv64ui-p-fence_i.bin", 300},
  {"rv64ui-p-jal.bin", 61},
  {"rv64ui-p-jalr.bin", 114},
  {"rv64ui-p-lb.bin", 251},
  {"rv64ui-p-lbu.bin", 251},
  {"rv64ui-p-ld.bin", 385},
  {"rv64ui-p-lh.bin", 263},
  {"rv64ui-p-lhu.bin", 270},
  {"rv64ui-p-lui.bin", 71},
  {"rv64ui-p-lw.bin", 273},
  {"rv64ui-p-lwu.bin", 299},
  {"rv64ui-p-or.bin", 584},
  {"rv64ui-p-ori.bin", 215},
  {"rv64ui-p-sb.bin", 436},
  {"rv64ui-p-sh.bin", 489},
  {"rv64ui-p-sw.bin", 496},
  {"rv64ui-p-sd.bin", 608},
  {"rv64ui-p-simple.bin", 47},
  {"rv64ui-p-sll.bin", 546},
  {"rv64ui-p-slli.bin", 279},
  {"rv64ui-p-slliw.bin", 247},
  {"rv64ui-p-sllw.bin", 506},
  {"rv64ui-p-slt.bin", 465},
  {"rv64ui-p-slti.bin", 243},
  {"rv64ui-p-sltiu.bin", 243},
  {"rv64ui-p-sltu.bin", 482},
  {"rv64ui-p-sra.bin", 518},
  {"rv64ui-p-srai.bin", 264},
  {"rv64ui-p-sraiw.bin", 274},
  {"rv64ui-p-sraw.bin", 518},
  {"rv64ui-p-srl.bin", 560},
  {"rv64ui-p-srli.bin", 285},
  {"rv64ui-p-srliw.bin", 256},
  {"rv64ui-p-srlw.bin", 512},
  {"rv64ui-p-sub.bin", 467},
  {"rv64ui-p-subw.bin", 463},
  {"rv64ui-p-xor.bin", 579},
  {"rv64ui-p-xori.bin", 213},
  {"rv64ui-v-add.bin", 11561},
  {"rv64ui-v-addi.bin", 6636},
  {"rv64ui-v-addiw.bin", 6633},
  {"rv64ui-v-addw.bin", 11556},
  {"rv64ui-v-and.bin", 11636},
  {"rv64ui-v-andi.bin", 6607},
  {"rv64ui-v-auipc.bin", 6449},
  {"rv64ui-v-beq.bin", 6682},
  {"rv64ui-v-bge.bin", 6700},
  {"rv64ui-v-bgeu.bin", 6790},
  {"rv64ui-v-blt.bin", 6682},
  {"rv64ui-v-bltu.bin", 6768},
  {"rv64ui-v-bne.bin", 6682},
  {"rv64ui-v-fence_i.bin", 13150},
  {"rv64ui-v-jal.bin", 6446},
  {"rv64ui-v-jalr.bin", 6499},
  {"rv64ui-v-lb.bin", 11336},
  {"rv64ui-v-lbu.bin", 11336},
  {"rv64ui-v-ld.bin", 11470},
  {"rv64ui-v-lh.bin", 11348},
  {"rv64ui-v-lhu.bin", 11355},
  {"rv64ui-v-lui.bin", 6456},
  {"rv64ui-v-lw.bin", 11358},
  {"rv64ui-v-lwu.bin", 11384},
  {"rv64ui-v-or.bin", 11669},
  {"rv64ui-v-ori.bin", 6600},
  {"rv64ui-v-sb.bin", 11032},
  {"rv64ui-v-sd.bin", 15904},
  {"rv64ui-v-sh.bin", 11085},
  {"rv64ui-v-simple.bin", 6432},
  {"rv64ui-v-sll.bin", 11631},
  {"rv64ui-v-slli.bin", 6664},
  {"rv64ui-v-slliw.bin", 6632},
  {"rv64ui-v-sllw.bin", 11591},
  {"rv64ui-v-slt.bin", 6850},
  {"rv64ui-v-slti.bin", 6628},
  {"rv64ui-v-sltiu.bin", 6628},
  {"rv64ui-v-sltu.bin", 11567},
  {"rv64ui-v-sra.bin", 11603},
  {"rv64ui-v-srai.bin", 6649},
  {"rv64ui-v-sraiw.bin", 6659},
  {"rv64ui-v-sraw.bin", 11603},
  {"rv64ui-v-srl.bin", 11645},
  {"rv64ui-v-srli.bin", 6670},
  {"rv64ui-v-srliw.bin", 6641},
  {"rv64ui-v-srlw.bin", 11597},
  {"rv64ui-v-sub.bin", 11552},
  {"rv64ui-v-subw.bin", 6848},
  {"rv64ui-v-sw.bin", 11092},
  {"rv64ui-v-xor.bin", 11664},
  {"rv64ui-v-xori.bin", 6598},
  {"rv64um-p-div.bin", 107},
  {"rv64um-p-divu.bin", 113},
  {"rv64um-p-divuw.bin", 105},
  {"rv64um-p-divw.bin", 102},
  {"rv64um-p-mul.bin", 466},
  {"rv64um-p-mulh.bin", 474},
  {"rv64um-p-mulhsu.bin", 474},
  {"rv64um-p-mulhu.bin", 506},
  {"rv64um-p-mulw.bin", 405},
  {"rv64um-p-rem.bin", 106},
  {"rv64um-p-remu.bin", 107},
  {"rv64um-p-remuw.bin", 102},
  {"rv64um-p-remw.bin", 108},
  {"rv64um-v-div.bin", 6492},
  {"rv64um-v-divu.bin", 6498},
  {"rv64um-v-divuw.bin", 6490},
  {"rv64um-v-divw.bin", 6487},
  {"rv64um-v-mul.bin", 11551},
  {"rv64um-v-mulh.bin", 6859},
  {"rv64um-v-mulhsu.bin", 6859},
  {"rv64um-v-mulhu.bin", 11591},
  {"rv64um-v-mulw.bin", 6790},
  {"rv64um-v-rem.bin", 6491},
  {"rv64um-v-remu.bin", 6492},
  {"rv64um-v-remuw.bin", 6487},
  {"rv64um-v-remw.bin", 6493},
}

local function run(machine)
    local step = 500000
    local cycles_end = step
    local cycles, success, payload
    while true do
        cycles, not_halted, payload = machine:run(cycles_end)
        if not_halted then
            cycles_end = cycles_end + step
        else
            break
        end
    end
    return cycles, payload
end

local errors = {}

for _, test in ipairs(tests) do
    local ram_image = test[1]
    local expected_cycles = test[2]
    io.write(ram_image, " ")
    local machine = emu.create{
        version = 1,
        machine = "riscv64",
        memory_size = 128,
        ram_image = "tests/" .. ram_image
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
else
    print("passed all tests")
end
