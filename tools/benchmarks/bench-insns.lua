local cartesi = require("cartesi")

local function bench(insn_iters, detailed)
    local TEXT_ADDR = 0x80000000
    local DATA_ADDR = 0x80010000
    local FS_2 = 0xffffffff40000000
    local FD_2 = 0x4000000000000000
    local FS_3 = 0xffffffff40400000
    local FD_3 = 0x4008000000000000
    local FS_5 = 0xffffffff40a00000
    local FD_5 = 0x4014000000000000
    local MSTATUS_FS_DIRTY = 3 << 13

    -- stylua: ignore
    local insn_sections = {
        {
            title="RISC-V Privileged Memory-management",
            {name='sfence.vma', opcode=0x12000073--[[sfence.vma]]},
        },
        {
            title="RISC-V Privileged Interrupt-management",
            {name='wfi',        opcode=0x10500073--[[wfi]]},
        },
        {
            title="RV64I - Base integer instruction set",
            {name='lui',        opcode=0x00001537--[[lui   a0,1]]},
            {name='auipc',      opcode=0x00000517--[[auipc a0,0]]},
            -- Jumping
            {name='jal',        opcode=0x000000ef--[[1: jal ra,1b ]]},
            {name='jalr',       opcode=0x000580e7--[[jalr ra,0(a1)]], a1=TEXT_ADDR},
            -- Branching
            {name='beq',          opcode=0x00c58263--[[1: beq  a1,a2,1f]],  a1=2, a2=3},
            {name='bne',          opcode=0x00c59263--[[1: bne  a1,a2,1f]],  a1=2, a2=2},
            {name='blt',          opcode=0x00c5c263--[[1: blt  a1,a2,1f]],  a1=2, a2=2},
            {name='bge',          opcode=0x00c5d263--[[1: bge  a1,a2,1f]],  a1=2, a2=3},
            {name='bltu',         opcode=0x00c5e263--[[1: bltu a1,a2,1f]],  a1=2, a2=2},
            {name='bgeu',         opcode=0x00c5f263--[[1: bgeu a1,a2,1f]],  a1=2, a2=3},
            {name='beq (taken)',  opcode=0x00c58263--[[1: beq  a1,a2,1f]],  a1=2, a2=2},
            {name='bne (taken)',  opcode=0x00c59263--[[1: bne  a1,a2,1f]],  a1=2, a2=3},
            {name='blt (taken)',  opcode=0x00c5c263--[[1: blt  a1,a2,1f]],  a1=2, a2=3},
            {name='bge (taken)',  opcode=0x00c5d263--[[1: bge  a1,a2,1f]],  a1=2, a2=2},
            {name='bltu (taken)', opcode=0x00c5e263--[[1: bltu a1,a2,1f]],  a1=2, a2=3},
            {name='bgeu (taken)', opcode=0x00c5f263--[[1: bgeu a1,a2,1f]],  a1=2, a2=2},
            -- Integer computation
            {name='addi',       opcode=0x00358513--[[addi  a0,a1,3]], a1=2},
            {name='addiw',      opcode=0x0035851b--[[addiw a0,a1,3]], a1=2},
            {name='slti',       opcode=0x0035a513--[[slti  a0,a1,3]], a1=2},
            {name='sltiu',      opcode=0x0035b513--[[sltiu a0,a1,3]], a1=2},
            {name='xori',       opcode=0x0035c513--[[xori  a0,a1,3]], a1=2},
            {name='ori',        opcode=0x0035e513--[[ori   a0,a1,3]], a1=2},
            {name='andi',       opcode=0x0035f513--[[andi  a0,a1,3]], a1=2},
            {name='slli',       opcode=0x00359513--[[slli  a0,a1,3]], a1=2},
            {name='slliw',      opcode=0x0035951b--[[slliw a0,a1,3]], a1=2},
            {name='srli',       opcode=0x0035d513--[[srli  a0,a1,3]], a1=2},
            {name='srliw',      opcode=0x0035d51b--[[srliw a0,a1,3]], a1=2},
            {name='srai',       opcode=0x4035d513--[[srai  a0,a1,3]], a1=2},
            {name='sraiw',      opcode=0x4035d51b--[[sraiw a0,a1,3]], a1=2},
            {name='add',        opcode=0x00c58533--[[add  a0,a1,a2]], a1=2, a2=3},
            {name='addw',       opcode=0x00c5853b--[[addw a0,a1,a2]], a1=2, a2=3},
            {name='sub',        opcode=0x40c58533--[[sub  a0,a1,a2]], a1=2, a2=3},
            {name='subw',       opcode=0x40c5853b--[[subw a0,a1,a2]], a1=2, a2=3},
            {name='sll',        opcode=0x00c59533--[[sll  a0,a1,a2]], a1=2, a2=3},
            {name='sllw',       opcode=0x00c5953b--[[sllw a0,a1,a2]], a1=2, a2=3},
            {name='slt',        opcode=0x00c5a533--[[slt  a0,a1,a2]], a1=2, a2=3},
            {name='sltu',       opcode=0x00c5b533--[[sltu a0,a1,a2]], a1=2, a2=3},
            {name='xor',        opcode=0x00c5c533--[[xor  a0,a1,a2]], a1=2, a2=3},
            {name='srl',        opcode=0x00c5d533--[[srl  a0,a1,a2]], a1=2, a2=3},
            {name='srlw',       opcode=0x00c5d53b--[[srlw a0,a1,a2]], a1=2, a2=3},
            {name='sra',        opcode=0x40c5d533--[[sra  a0,a1,a2]], a1=2, a2=3},
            {name='sraw',       opcode=0x40c5d53b--[[sraw a0,a1,a2]], a1=2, a2=3},
            {name='or',         opcode=0x00c5e533--[[or   a0,a1,a2]], a1=2, a2=3},
            {name='and',        opcode=0x00c5f533--[[and  a0,a1,a2]], a1=2, a2=3},
            -- Memory load and store
            {name="lb",         opcode=0x00058503--[[lb  a0, 0(a1)]], a1=DATA_ADDR},
            {name="lbu",        opcode=0x0005c503--[[lbu a0, 0(a1)]], a1=DATA_ADDR},
            {name="lh",         opcode=0x00059503--[[lh  a0, 0(a1)]], a1=DATA_ADDR},
            {name="lhu",        opcode=0x0005d503--[[lhu a0, 0(a1)]], a1=DATA_ADDR},
            {name="lw",         opcode=0x0005a503--[[lw  a0, 0(a1)]], a1=DATA_ADDR},
            {name="lwu",        opcode=0x0005e503--[[lwu a0, 0(a1)]], a1=DATA_ADDR},
            {name="ld",         opcode=0x0005b503--[[ld  a0, 0(a1)]], a1=DATA_ADDR},
            {name="sb",         opcode=0x00a58023--[[sb  a0, 0(a1)]], a1=DATA_ADDR},
            {name="sh",         opcode=0x00a59023--[[sh  a0, 0(a1)]], a1=DATA_ADDR},
            {name="sw",         opcode=0x00a5a023--[[sw  a0, 0(a1)]], a1=DATA_ADDR},
            {name="sd",         opcode=0x00a5b023--[[sd  a0, 0(a1)]], a1=DATA_ADDR},
            -- Memory ordering
            {name='fence',      opcode=0x0ff0000f--[[fence  ]]},
            -- Environment calls
            {name='ecall',      opcode=0x00000073--[[ecall ]]},
            {name='ebreak',     opcode=0x00100073--[[ebreak]]},
        },
        {
            title="RV64M - Integer multiplication and division",
            {name='mul',        opcode=0x02c58533--[[mul    a0,a1,a2]],  a1=2, a2=3},
            {name='mulw',       opcode=0x02c5853b--[[mulw   a0,a1,a2]],  a1=2, a2=3},
            {name='mulh',       opcode=0x02c59533--[[mulh   a0,a1,a2]],  a1=2, a2=3},
            {name='mulhsu',     opcode=0x02c5a533--[[mulhsu a0,a1,a2]],  a1=2, a2=3},
            {name='mulhu',      opcode=0x02c5b533--[[mulhu  a0,a1,a2]],  a1=2, a2=3},
            {name='div',        opcode=0x02c5c533--[[div    a0,a1,a2]],  a1=3, a2=2},
            {name='divw',       opcode=0x02c5c53b--[[divw   a0,a1,a2]],  a1=3, a2=2},
            {name='divu',       opcode=0x02c5d533--[[divu   a0,a1,a2]],  a1=3, a2=2},
            {name='divuw',      opcode=0x02c5d53b--[[divuw  a0,a1,a2]],  a1=3, a2=2},
            {name='rem',        opcode=0x02c5e533--[[rem    a0,a1,a2]],  a1=3, a2=2},
            {name='remw',       opcode=0x02c5e53b--[[remw   a0,a1,a2]],  a1=3, a2=2},
            {name='remu',       opcode=0x02c5f533--[[remu   a0,a1,a2]],  a1=3, a2=2},
            {name='remuw',      opcode=0x02c5f53b--[[remuw  a0,a1,a2]],  a1=3, a2=2},
        },
        {
            title="RV64A - Atomic instructions",
            {name="lr.w",       opcode=0x1005a52f--[[lr.w      a0,(a1)   ]],  a1=DATA_ADDR, data=0},
            {name="lr.d",       opcode=0x1005b52f--[[lr.d      a0,(a1)   ]],  a1=DATA_ADDR, data=0},
            {name="sc.w",       opcode=0x18b6252f--[[sc.w      a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=0},
            {name="sc.d",       opcode=0x18b6352f--[[sc.d      a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=0},
            {name="amoswap.w",  opcode=0x08b6252f--[[amoswap.w a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoswap.d",  opcode=0x08b6352f--[[amoswap.d a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoadd.w",   opcode=0x00b6252f--[[amoadd.w  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoadd.d",   opcode=0x00b6352f--[[amoadd.d  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoxor.w",   opcode=0x20b6252f--[[amoxor.w  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoxor.d",   opcode=0x20b6352f--[[amoxor.d  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoand.w",   opcode=0x60b6252f--[[amoand.w  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoand.d",   opcode=0x60b6352f--[[amoand.d  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoor.w",    opcode=0x40b6252f--[[amoor.w   a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amoor.d",    opcode=0x40b6352f--[[amoor.d   a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amomin.w",   opcode=0x80b6252f--[[amomin.w  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amomin.d",   opcode=0x80b6352f--[[amomin.d  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amomax.w",   opcode=0xa0b6252f--[[amomax.w  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amomax.d",   opcode=0xa0b6352f--[[amomax.d  a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amominu.w",  opcode=0xc0b6252f--[[amominu.w a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amominu.d",  opcode=0xc0b6352f--[[amominu.d a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amomaxu.w",  opcode=0xe0b6252f--[[amomaxu.w a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
            {name="amomaxu.d",  opcode=0xe0b6352f--[[amomaxu.d a0,a1,(a2)]],  a1=2, a2=DATA_ADDR, data=3},
        },
        {
            title="RV64F - Single-precision floating-point",
            {name="flw",        opcode=0x0005a507--[[flw       fa0,0(a1)      ]], a1=DATA_ADDR, data=FS_2},
            {name="fsw",        opcode=0x00a5a027--[[fsw       fa0,0(a1)      ]], a1=DATA_ADDR},
            {name="fmadd.s",    opcode=0x68c5f543--[[fmadd.s   fa0,fa1,fa2,fa3]], fa1=FS_2, fa2=FS_3, fa3=FS_5},
            {name="fmsub.s",    opcode=0x68c5f547--[[fmsub.s   fa0,fa1,fa2,fa3]], fa1=FS_2, fa2=FS_3, fa3=FS_5},
            {name="fnmsub.s",   opcode=0x68c5f54b--[[fnmsub.s  fa0,fa1,fa2,fa3]], fa1=FS_2, fa2=FS_3, fa3=FS_5},
            {name="fnmadd.s",   opcode=0x68c5f54f--[[fnmadd.s  fa0,fa1,fa2,fa3]], fa1=FS_2, fa2=FS_3, fa3=FS_5},
            {name="fadd.s",     opcode=0x00c5f553--[[fadd.s    fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fsub.s",     opcode=0x08c5f553--[[fsub.s    fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fmul.s",     opcode=0x10c5f553--[[fmul.s    fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fdiv.s",     opcode=0x18c5f553--[[fdiv.s    fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fsgnj.s",    opcode=0x20c58553--[[fsgnj.s   fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fsgnjn.s",   opcode=0x20c59553--[[fsgnjn.s  fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fsgnjx.s",   opcode=0x20c5a553--[[fsgnjx.s  fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fmin.s",     opcode=0x28c58553--[[fmin.s    fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="fmax.s",     opcode=0x28c59553--[[fmax.s    fa0,fa1,fa2    ]], fa1=FS_2, fa2=FS_3},
            {name="feq.s",      opcode=0xa0c5a553--[[feq.s     a0,fa1,fa2     ]], fa1=FS_2, fa2=FS_3},
            {name="flt.s",      opcode=0xa0c59553--[[flt.s     a0,fa1,fa2     ]], fa1=FS_2, fa2=FS_3},
            {name="fle.s",      opcode=0xa0c58553--[[fle.s     a0,fa1,fa2     ]], fa1=FS_2, fa2=FS_3},
            {name="fsqrt.s",    opcode=0x5805f553--[[fsqrt.s   fa0,fa1        ]], fa1=FS_2},
            {name="fclass.s",   opcode=0xe0059553--[[fclass.s  a0,fa1         ]], fa1=FS_2},
            {name="fcvt.w.s",   opcode=0xc005f553--[[fcvt.w.s  a0,fa1         ]], fa1=FS_2},
            {name="fcvt.wu.s",  opcode=0xc015f553--[[fcvt.wu.s a0,fa1         ]], fa1=FS_2},
            {name="fcvt.l.s",   opcode=0xc025f553--[[fcvt.l.s  a0,fa1         ]], fa1=FS_2},
            {name="fcvt.lu.s",  opcode=0xc035f553--[[fcvt.lu.s a0,fa1         ]], fa1=FS_2},
            {name="fmv.x.w",    opcode=0xe0058553--[[fmv.x.w   a0,fa1         ]], fa1=FS_2},
            {name="fcvt.s.w",   opcode=0xd005f553--[[fcvt.s.w  fa0,a1         ]], a1=2},
            {name="fcvt.s.wu",  opcode=0xd015f553--[[fcvt.s.wu fa0,a1         ]], a1=2},
            {name="fcvt.s.l",   opcode=0xd025f553--[[fcvt.s.l  fa0,a1         ]], a1=2},
            {name="fcvt.s.lu",  opcode=0xd035f553--[[fcvt.s.lu fa0,a1         ]], a1=2},
            {name="fmv.w.x",    opcode=0xf0058553--[[fmv.w.x   fa0,a1         ]], a1=FS_2},
        },
        {
            title="RV64D - Double-precision floating-point",
            {name="fld",        opcode=0x0005b507--[[fld       fa0,0(a1)      ]], a1=DATA_ADDR, data=FD_2},
            {name="fsd",        opcode=0x00a5b027--[[fsd       fa0,0(a1)      ]], a1=DATA_ADDR},
            {name="fmadd.d",    opcode=0x6ac5f543--[[fmadd.d   fa0,fa1,fa2,fa3]], fa1=FD_2, fa2=FD_3, fa3=FD_5},
            {name="fmsub.d",    opcode=0x6ac5f547--[[fmsub.d   fa0,fa1,fa2,fa3]], fa1=FD_2, fa2=FD_3, fa3=FD_5},
            {name="fnmsub.d",   opcode=0x6ac5f54b--[[fnmsub.d  fa0,fa1,fa2,fa3]], fa1=FD_2, fa2=FD_3, fa3=FD_5},
            {name="fnmadd.d",   opcode=0x6ac5f54f--[[fnmadd.d  fa0,fa1,fa2,fa3]], fa1=FD_2, fa2=FD_3, fa3=FD_5},
            {name="fadd.d",     opcode=0x02c5f553--[[fadd.d    fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fsub.d",     opcode=0x0ac5f553--[[fsub.d    fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fmul.d",     opcode=0x12c5f553--[[fmul.d    fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fdiv.d",     opcode=0x1ac5f553--[[fdiv.d    fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fsgnj.d",    opcode=0x22c58553--[[fsgnj.d   fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fsgnjn.d",   opcode=0x22c59553--[[fsgnjn.d  fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fsgnjx.d",   opcode=0x22c5a553--[[fsgnjx.d  fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fmin.d",     opcode=0x2ac58553--[[fmin.d    fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="fmax.d",     opcode=0x2ac59553--[[fmax.d    fa0,fa1,fa2    ]], fa1=FD_2, fa2=FD_3},
            {name="feq.d",      opcode=0xa2c5a553--[[feq.d     a0,fa1,fa2     ]], fa1=FD_2, fa2=FD_3},
            {name="flt.d",      opcode=0xa2c59553--[[flt.d     a0,fa1,fa2     ]], fa1=FD_2, fa2=FD_3},
            {name="fle.d",      opcode=0xa2c58553--[[fle.d     a0,fa1,fa2     ]], fa1=FD_2, fa2=FD_3},
            {name="fsqrt.d",    opcode=0x5a05f553--[[fsqrt.d   fa0,fa1        ]], fa1=FD_2},
            {name="fcvt.s.d",   opcode=0x4015f553--[[fcvt.s.d  fa0,fa1        ]], fa1=FD_2},
            {name="fcvt.d.s",   opcode=0x42058553--[[fcvt.d.s  fa0,fa1        ]], fa1=FS_2},
            {name="fclass.d",   opcode=0xe2059553--[[fclass.d  a0,fa1         ]], fa1=FD_2},
            {name="fcvt.w.d",   opcode=0xc205f553--[[fcvt.w.d  a0,fa1         ]], fa1=FD_2},
            {name="fcvt.wu.d",  opcode=0xc215f553--[[fcvt.wu.d a0,fa1         ]], fa1=FD_2},
            {name="fcvt.l.d",   opcode=0xc225f553--[[fcvt.l.d  a0,fa1         ]], fa1=FD_2},
            {name="fcvt.lu.d",  opcode=0xc235f553--[[fcvt.lu.d a0,fa1         ]], fa1=FD_2},
            {name="fmv.x.d",    opcode=0xe2058553--[[fmv.x.d   a0,fa1         ]], fa1=FD_2},
            {name="fcvt.d.w",   opcode=0xd2058553--[[fcvt.d.w  fa0,a1         ]], a1=2},
            {name="fcvt.d.wu",  opcode=0xd2158553--[[fcvt.d.wu fa0,a1         ]], a1=2},
            {name="fcvt.d.l",   opcode=0xd225f553--[[fcvt.d.l  fa0,a1         ]], a1=2},
            {name="fcvt.d.lu",  opcode=0xd235f553--[[fcvt.d.lu fa0,a1         ]], a1=2},
            {name="fmv.d.x",    opcode=0xf2058553--[[fmv.d.x   fa0,a1         ]], a1=FD_2},
        },
        -- TODO: C extension
        {
            title="RV64Zicsr - Control and status registers",
            {name="csrrw",      opcode=0x34359573--[[csrrw  a0,mtval,a1]], a1=2},
            {name="csrrs",      opcode=0x3435a573--[[csrrs  a0,mtval,a1]], a1=2},
            {name="csrrc",      opcode=0x3435b573--[[csrrc  a0,mtval,a1]], a1=2},
            {name="csrrwi",     opcode=0x34315573--[[csrrwi a0,mtval,2 ]]},
            {name="csrrsi",     opcode=0x34316573--[[csrrsi a0,mtval,2 ]]},
            {name="csrrci",     opcode=0x34317573--[[csrrci a0,mtval,2 ]]},
        },
        {
            title="RV64Zicntr - Base counters and timers",
            {name='rdcycle',    opcode=0xc0002573--[[rdcycle]]},
            {name='rdtime',     opcode=0xc0102573--[[rdtime]]},
            {name='rdinstret',  opcode=0xc0202573--[[rdinstret]]},
        },
        {
            title="RV64Zifence - Instruction fetch fence",
            {name='fence.i',    opcode=0x0000100f--[[fence.i]]},
        },
    }

    local function bench_insn(machine, insn, iters)
        local unroll_count = 4096
        local jump = 0x00018067 -- jalr zero,0(gp)
        local prog = string.pack("<I4", insn.opcode):rep(unroll_count) .. string.pack("<I4", jump)
        -- init machine memory
        machine:write_mstatus(machine:read_mstatus() | MSTATUS_FS_DIRTY) -- enable floating-point
        machine:write_pc(TEXT_ADDR)
        machine:write_mtvec(TEXT_ADDR) -- set trap handler (for ecall/ebreak)
        machine:write_x(3, TEXT_ADDR) -- gp
        machine:write_x(1, 0) -- ra
        machine:write_x(10, insn.a0 or 0) -- a0
        machine:write_x(11, insn.a1 or 0) -- a1
        machine:write_x(12, insn.a2 or 0) -- a2
        machine:write_x(13, insn.a3 or 0) -- a3
        machine:write_f(10, insn.fa0 or 0) -- fa0
        machine:write_f(11, insn.fa1 or 0) -- fa1
        machine:write_f(12, insn.fa2 or 0) -- fa2
        machine:write_f(13, insn.fa3 or 0) -- fa3
        machine:write_memory(TEXT_ADDR, prog)
        machine:write_memory(DATA_ADDR, string.pack("<I8", insn.data or 0))
        -- warmup
        machine:run(machine:read_mcycle() + (iters // 4) * (unroll_count+1))
        assert(machine:read_pc() == TEXT_ADDR)
        -- benchmark
        local cycles = iters * (unroll_count+1)
        local max_mcycle = machine:read_mcycle() + cycles
        local start = os.clock()
        machine:run(max_mcycle)
        local elapsed = os.clock() - start
        local mips = cycles / (elapsed * 1000000)
        -- uarch
        assert(machine:read_pc() == TEXT_ADDR)
        assert(machine:run_uarch() == cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
        local ucycles = machine:read_uarch_cycle()
        machine:reset_uarch()
        return mips, ucycles
    end
    if detailed then
        print("-- Instruction speed --")
    end
    local machine = cartesi.machine({ ram = { length = 0x8000000 } })
    for _, section in ipairs(insn_sections) do
        local mips_sum = 0
        local ucycles_sum = 0
        for _, insn in ipairs(section) do
            local mips, ucycles = bench_insn(machine, insn, insn_iters)
            if detailed then
                print(string.format("%-44s%9.3f MIPS%9d ucycles", insn.name, mips, ucycles))
            end
            mips_sum = mips_sum + mips
            ucycles_sum = ucycles_sum + ucycles
        end
        section.mips = mips_sum / #section
        section.ucycles = ucycles_sum / #section
    end
    print("-- Average instruction set speed --")
    for _, section in ipairs(insn_sections) do
        print(string.format("%-44s%9.3f MIPS%9.1f ucycles", section.title, section.mips, section.ucycles))
    end
end

bench(256, true)
