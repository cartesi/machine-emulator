// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef RISCV_CONSTANTS_H
#define RISCV_CONSTANTS_H

#include <cstdint>

/// \file
/// \brief RISC-V constants

namespace cartesi {

/// \brief Global RISC-V constants
enum RISCV_constants {
    XLEN = 64       ///< Maximum XLEN
};

/// \brief Register counts
enum REG_COUNT {
    X_REG_COUNT = 32,
    DHD_H_REG_COUNT = 4
};

/// \brief MIP shifts
enum MIP_shifts {
    MIP_USIP_SHIFT = 0,
    MIP_SSIP_SHIFT = 1,
    MIP_MSIP_SHIFT = 3,
    MIP_UTIP_SHIFT = 4,
    MIP_STIP_SHIFT = 5,
    MIP_MTIP_SHIFT = 7,
    MIP_UEIP_SHIFT = 8,
    MIP_SEIP_SHIFT = 9,
    MIP_MEIP_SHIFT = 11
};

/// \brief MIP masks
enum MIP_masks: uint64_t {
    MIP_USIP_MASK = UINT64_C(1) << MIP_USIP_SHIFT,  ///< User software interrupt
    MIP_SSIP_MASK = UINT64_C(1) << MIP_SSIP_SHIFT,  ///< Supervisor software interrupt
    MIP_MSIP_MASK = UINT64_C(1) << MIP_MSIP_SHIFT,  ///< Machine software interrupt
    MIP_UTIP_MASK = UINT64_C(1) << MIP_UTIP_SHIFT,  ///< User timer interrupt
    MIP_STIP_MASK = UINT64_C(1) << MIP_STIP_SHIFT,  ///< Supervisor timer interrupt
    MIP_MTIP_MASK = UINT64_C(1) << MIP_MTIP_SHIFT,  ///< Machine timer interrupt
    MIP_UEIP_MASK = UINT64_C(1) << MIP_UEIP_SHIFT,  ///< User external interrupt
    MIP_SEIP_MASK = UINT64_C(1) << MIP_SEIP_SHIFT,  ///< Supervisor external interrupt
    MIP_MEIP_MASK = UINT64_C(1) << MIP_MEIP_SHIFT   ///< Machine external interrupt
};

/// \brief mcause for exceptions
enum MCAUSE_constants: uint64_t {
    MCAUSE_INSN_ADDRESS_MISALIGNED      = 0x0, ///< Instruction address misaligned
    MCAUSE_INSN_ACCESS_FAULT            = 0x1, ///< Instruction access fault
    MCAUSE_ILLEGAL_INSN                 = 0x2, ///< Illegal instruction
    MCAUSE_BREAKPOINT                   = 0x3, ///< Breakpoint
    MCAUSE_LOAD_ADDRESS_MISALIGNED      = 0x4, ///< Load address misaligned
    MCAUSE_LOAD_ACCESS_FAULT            = 0x5, ///< Load access fault
    MCAUSE_STORE_AMO_ADDRESS_MISALIGNED = 0x6, ///< Store/AMO address misaligned
    MCAUSE_STORE_AMO_ACCESS_FAULT       = 0x7, ///< Store/AMO access fault
    MCAUSE_ECALL_BASE                   = 0x8, ///< Environment call (+0: from U-mode, +1: from S-mode, +3: from M-mode)
    MCAUSE_FETCH_PAGE_FAULT             = 0xc, ///< Instruction page fault
    MCAUSE_LOAD_PAGE_FAULT              = 0xd, ///< Load page fault
    MCAUSE_STORE_AMO_PAGE_FAULT         = 0xf, ///< Store/AMO page fault

    MCAUSE_INTERRUPT_FLAG               = UINT64_C(1) << (XLEN-1) ///< Interrupt flag
};

/// \brief Privilege modes
enum PRV_constants: uint8_t {
    PRV_U = 0,  ///< User mode
    PRV_S = 1,  ///< Supervisor mode
    PRV_H = 2,  ///< Reserved
    PRV_M = 3   ///< Machine mode
};

/// \brief misa shifts
enum MISA_shifts {
    MISA_EXT_S_SHIFT = ('S' - 'A'),
    MISA_EXT_U_SHIFT = ('U' - 'A'),
    MISA_EXT_I_SHIFT = ('I' - 'A'),
    MISA_EXT_M_SHIFT = ('M' - 'A'),
    MISA_EXT_A_SHIFT = ('A' - 'A'),
    MISA_EXT_F_SHIFT = ('F' - 'A'),
    MISA_EXT_D_SHIFT = ('D' - 'A'),
    MISA_EXT_C_SHIFT = ('C' - 'A'),

    MISA_MXL_SHIFT = (XLEN-2)
};

/// \brief misa masks
enum MISA_masks: uint64_t {
    MISA_EXT_S_MASK = UINT64_C(1) << MISA_EXT_S_SHIFT, ///< Supervisor mode implemented
    MISA_EXT_U_MASK = UINT64_C(1) << MISA_EXT_U_SHIFT, ///< User mode implemented
    MISA_EXT_I_MASK = UINT64_C(1) << MISA_EXT_I_SHIFT, ///< RV32I/64I/128I base ISA
    MISA_EXT_M_MASK = UINT64_C(1) << MISA_EXT_M_SHIFT, ///< Integer Multiply/Divide extension
    MISA_EXT_A_MASK = UINT64_C(1) << MISA_EXT_A_SHIFT, ///< Atomic extension
    MISA_EXT_F_MASK = UINT64_C(1) << MISA_EXT_F_SHIFT, ///< Single-precision floating-point extension
    MISA_EXT_D_MASK = UINT64_C(1) << MISA_EXT_D_SHIFT, ///< Double-precision floating-point extension
    MISA_EXT_C_MASK = UINT64_C(1) << MISA_EXT_C_SHIFT, ///< Compressed extension
};

/// \brief misa constants
enum MISA_constants: uint64_t {
    MISA_MXL_VALUE = UINT64_C(2)
};

/// \brief mstatus shifts
enum MSTATUS_shifts {
    MSTATUS_UIE_SHIFT  = 0,
    MSTATUS_SIE_SHIFT  = 1,
    MSTATUS_MIE_SHIFT  = 3,
    MSTATUS_UPIE_SHIFT = 4,
    MSTATUS_SPIE_SHIFT = 5,
    MSTATUS_MPIE_SHIFT = 7,
    MSTATUS_SPP_SHIFT  = 8,
    MSTATUS_MPP_SHIFT  = 11,
    MSTATUS_FS_SHIFT   = 13,
    MSTATUS_XS_SHIFT   = 15,
    MSTATUS_MPRV_SHIFT = 17,
    MSTATUS_SUM_SHIFT  = 18,
    MSTATUS_MXR_SHIFT  = 19,
    MSTATUS_TVM_SHIFT  = 20,
    MSTATUS_TW_SHIFT   = 21,
    MSTATUS_TSR_SHIFT  = 22,

    MSTATUS_UXL_SHIFT  = 32,
    MSTATUS_SXL_SHIFT  = 34,
    MSTATUS_SD_SHIFT   = XLEN-1
};

/// \brief mstatus masks
enum MSTATUS_masks: uint64_t {
    MSTATUS_UIE_MASK  = UINT64_C(1) << MSTATUS_UIE_SHIFT,
    MSTATUS_SIE_MASK  = UINT64_C(1) << MSTATUS_SIE_SHIFT,
    MSTATUS_MIE_MASK  = UINT64_C(1) << MSTATUS_MIE_SHIFT,
    MSTATUS_UPIE_MASK = UINT64_C(1) << MSTATUS_UPIE_SHIFT,
    MSTATUS_SPIE_MASK = UINT64_C(1) << MSTATUS_SPIE_SHIFT,
    MSTATUS_MPIE_MASK = UINT64_C(1) << MSTATUS_MPIE_SHIFT,
    MSTATUS_SPP_MASK  = UINT64_C(1) << MSTATUS_SPP_SHIFT,
    MSTATUS_MPP_MASK  = UINT64_C(3) << MSTATUS_MPP_SHIFT,
    MSTATUS_FS_MASK   = UINT64_C(3) << MSTATUS_FS_SHIFT,
    MSTATUS_XS_MASK   = UINT64_C(3) << MSTATUS_XS_SHIFT,
    MSTATUS_MPRV_MASK = UINT64_C(1) << MSTATUS_MPRV_SHIFT,
    MSTATUS_SUM_MASK  = UINT64_C(1) << MSTATUS_SUM_SHIFT,
    MSTATUS_MXR_MASK  = UINT64_C(1) << MSTATUS_MXR_SHIFT,
    MSTATUS_TVM_MASK  = UINT64_C(1) << MSTATUS_TVM_SHIFT,
    MSTATUS_TW_MASK   = UINT64_C(1) << MSTATUS_TW_SHIFT,
    MSTATUS_TSR_MASK  = UINT64_C(1) << MSTATUS_TSR_SHIFT,

    MSTATUS_UXL_MASK  = UINT64_C(3) << MSTATUS_UXL_SHIFT,
    MSTATUS_SXL_MASK  = UINT64_C(3) << MSTATUS_SXL_SHIFT,
    MSTATUS_SD_MASK   = UINT64_C(1) << MSTATUS_SD_SHIFT
};

/// \brief mstatus read-write masks
enum MSTATUS_RW_masks: uint64_t {
    MSTATUS_W_MASK = (
        MSTATUS_UIE_MASK  |
        MSTATUS_SIE_MASK  |
        MSTATUS_MIE_MASK  |
        MSTATUS_UPIE_MASK |
        MSTATUS_SPIE_MASK |
        MSTATUS_MPIE_MASK |
        MSTATUS_SPP_MASK  |
        MSTATUS_MPP_MASK  |
        MSTATUS_FS_MASK   |
        MSTATUS_MPRV_MASK |
        MSTATUS_SUM_MASK  |
        MSTATUS_MXR_MASK  |
        MSTATUS_TVM_MASK  |
        MSTATUS_TW_MASK   |
        MSTATUS_TSR_MASK), ///< Write mask for mstatus
    MSTATUS_R_MASK = (
        MSTATUS_UIE_MASK  |
        MSTATUS_SIE_MASK  |
        MSTATUS_MIE_MASK  |
        MSTATUS_UPIE_MASK |
        MSTATUS_SPIE_MASK |
        MSTATUS_MPIE_MASK |
        MSTATUS_SPP_MASK  |
        MSTATUS_MPP_MASK  |
        MSTATUS_FS_MASK   |
        MSTATUS_MPRV_MASK |
        MSTATUS_SUM_MASK  |
        MSTATUS_MXR_MASK  |
        MSTATUS_TVM_MASK  |
        MSTATUS_TW_MASK   |
        MSTATUS_TSR_MASK  |
        MSTATUS_UXL_MASK  |
        MSTATUS_SXL_MASK  |
        MSTATUS_SD_MASK) ///< Read mask for mstatus
};

/// \brief sstatus read/write masks
enum SSTATUS_rw_masks: uint64_t {
    SSTATUS_W_MASK = (
        MSTATUS_UIE_MASK  |
        MSTATUS_SIE_MASK  |
        MSTATUS_UPIE_MASK |
        MSTATUS_SPIE_MASK |
        MSTATUS_SPP_MASK  |
        MSTATUS_FS_MASK   |
        MSTATUS_SUM_MASK  |
        MSTATUS_MXR_MASK ), ///< Write mask for sstatus
    SSTATUS_R_MASK = (
        MSTATUS_UIE_MASK  |
        MSTATUS_SIE_MASK  |
        MSTATUS_UPIE_MASK |
        MSTATUS_SPIE_MASK |
        MSTATUS_SPP_MASK  |
        MSTATUS_FS_MASK   |
        MSTATUS_SUM_MASK  |
        MSTATUS_MXR_MASK  |
        MSTATUS_UXL_MASK  |
        MSTATUS_SD_MASK)  ///< Read mask for sstatus
};

/// \brief Page-table entry shifts
enum PTE_shifts {
    PTE_XWR_R_SHIFT = 0,
    PTE_XWR_W_SHIFT = 1,
    PTE_XWR_C_SHIFT = 2,
    PTE_V_SHIFT     = 0,
    PTE_R_SHIFT     = 1,
    PTE_W_SHIFT     = 2,
    PTE_X_SHIFT     = 3,
    PTE_U_SHIFT     = 4,
    PTE_G_SHIFT     = 5,
    PTE_A_SHIFT     = 6,
    PTE_D_SHIFT     = 7
};

/// \brief Page-table entry masks
enum PTE_masks: uint64_t {
    PTE_V_MASK = UINT64_C(1) << PTE_V_SHIFT, ///< Valid
    PTE_R_MASK = UINT64_C(1) << PTE_R_SHIFT, ///< Readable
    PTE_W_MASK = UINT64_C(1) << PTE_W_SHIFT, ///< Writable
    PTE_X_MASK = UINT64_C(1) << PTE_X_SHIFT, ///< Executable
    PTE_U_MASK = UINT64_C(1) << PTE_U_SHIFT, ///< Accessible to user mode
    PTE_G_MASK = UINT64_C(1) << PTE_G_SHIFT, ///< Global mapping
    PTE_A_MASK = UINT64_C(1) << PTE_A_SHIFT, ///< Accessed
    PTE_D_MASK = UINT64_C(1) << PTE_D_SHIFT  ///< Dirty
};

/// \brief Paging shifts
enum PAGE_shifts {
    PAGE_NUMBER_SHIFT = 12,
};

/// \brief Paging masks
enum PAGE_masks: uint64_t {
    PAGE_OFFSET_MASK = (UINT64_C(1) << PAGE_NUMBER_SHIFT)-1
};

/// \brief mcounteren shifts
enum MCOUNTEREN_shifts {
    MCOUNTEREN_CY_SHIFT = 0,
    MCOUNTEREN_TM_SHIFT = 1,
    MCOUNTEREN_IR_SHIFT = 2
};

/// \brief mcounteren masks
enum MCOUNTEREN_masks: uint64_t {
    MCOUNTEREN_CY_MASK = UINT64_C(1) << MCOUNTEREN_CY_SHIFT, ///< Enable rdcycle
    MCOUNTEREN_TM_MASK = UINT64_C(1) << MCOUNTEREN_TM_SHIFT, ///< Enable rdtime
    MCOUNTEREN_IR_MASK = UINT64_C(1) << MCOUNTEREN_IR_SHIFT, ///< Enable rdinstret
};

/// \brief counteren write masks
enum COUNTEREN_rw_masks: uint64_t {
    MCOUNTEREN_RW_MASK = MCOUNTEREN_CY_MASK | MCOUNTEREN_TM_MASK | MCOUNTEREN_IR_MASK,
    SCOUNTEREN_RW_MASK = MCOUNTEREN_RW_MASK
};

/// \brief Cartesi-specific iflags shifts
enum IFLAGS_shifts {
    IFLAGS_H_SHIFT   = 0,
    IFLAGS_Y_SHIFT   = 1,
    IFLAGS_I_SHIFT   = 2,
    IFLAGS_PRV_SHIFT = 3
};

enum IFLAGS_masks: uint64_t {
    IFLAGS_H_MASK   = UINT64_C(1) << IFLAGS_H_SHIFT,
    IFLAGS_Y_MASK   = UINT64_C(1) << IFLAGS_Y_SHIFT,
    IFLAGS_I_MASK   = UINT64_C(1) << IFLAGS_I_SHIFT,
    IFLAGS_PRV_MASK = UINT64_C(3) << IFLAGS_PRV_SHIFT
};

/// \brief Initial values for Cartesi machines
enum CARTESI_init: uint64_t {
    PC_INIT         = UINT64_C(0x1000), ///< Initial value for pc
    MVENDORID_INIT  = UINT64_C(0x6361727465736920), ///< Initial value for mvendorid
    MARCHID_INIT    = UINT64_C(6), ///< Initial value for marchid
    MIMPID_INIT     = UINT64_C(1), ///< Initial value for mimpid
    MCYCLE_INIT     = UINT64_C(0), ///< Initial value for mcycle
    MINSTRET_INIT   = UINT64_C(0), ///< Initial value for minstret
    MSTATUS_INIT    = (MISA_MXL_VALUE << MSTATUS_UXL_SHIFT) |
        (MISA_MXL_VALUE << MSTATUS_SXL_SHIFT), ///< Initial value for mstatus
    MTVEC_INIT      = UINT64_C(0), ///< Initial value for mtvec
    MSCRATCH_INIT   = UINT64_C(0), ///< Initial value for mscratch
    MEPC_INIT       = UINT64_C(0), ///< Initial value for mepc
    MCAUSE_INIT     = UINT64_C(0), ///< Initial value for mcause
    MTVAL_INIT      = UINT64_C(0), ///< Initial value for mtval
    MISA_INIT       = (MISA_MXL_VALUE << MISA_MXL_SHIFT) |
        MISA_EXT_S_MASK | MISA_EXT_U_MASK | MISA_EXT_I_MASK |
        MISA_EXT_M_MASK | MISA_EXT_A_MASK,  ///< Initial value for misa
    MIE_INIT        = UINT64_C(0), ///< Initial value for mie
    MIP_INIT        = UINT64_C(0), ///< Initial value for mip
    MEDELEG_INIT    = UINT64_C(0), ///< Initial value for medeleg
    MIDELEG_INIT    = UINT64_C(0), ///< Initial value for mideleg
    MCOUNTEREN_INIT = UINT64_C(0), ///< Initial value for mcounteren
    STVEC_INIT      = UINT64_C(0), ///< Initial value for stvec
    SSCRATCH_INIT   = UINT64_C(0), ///< Initial value for sscratch
    SEPC_INIT       = UINT64_C(0), ///< Initial value for sepc
    SCAUSE_INIT     = UINT64_C(0), ///< Initial value for scause
    STVAL_INIT      = UINT64_C(0), ///< Initial value for stval
    SATP_INIT       = UINT64_C(0), ///< Initial value for satp
    SCOUNTEREN_INIT = UINT64_C(0), ///< Initial value for scounteren
    ILRSC_INIT      = UINT64_C(-1), ///< Initial value for ilrsc
    IFLAGS_INIT     = static_cast<uint64_t>(PRV_M) << IFLAGS_PRV_SHIFT, ///< Initial value for iflags
    MTIMECMP_INIT   = UINT64_C(0),  ///< Initial value for mtimecmp
    FROMHOST_INIT   = UINT64_C(0),  ///< Initial value for fromhost
    TOHOST_INIT     = UINT64_C(0),  ///< Initial value for tohost
};

/// \brief Mapping between CSR names and addresses
enum class CSR_address: uint32_t {
    ustatus = 0x000,
    uie = 0x004,
    utvec = 0x005,

    uscratch = 0x040,
    uepc = 0x041,
    ucause = 0x042,
    utval = 0x043,
    uip = 0x044,

    ucycle = 0xc00,
    utime = 0xc01,
    uinstret =  0xc02,
    ucycleh = 0xc80,
    utimeh = 0xc81,
    uinstreth = 0xc82,

    sstatus = 0x100,
    sedeleg = 0x102,
    sideleg = 0x103,
    sie = 0x104,
    stvec = 0x105,
    scounteren = 0x106,

    sscratch = 0x140,
    sepc = 0x141,
    scause = 0x142,
    stval = 0x143,
    sip = 0x144,

    satp = 0x180,

    mvendorid = 0xf11,
    marchid = 0xf12,
    mimpid = 0xf13,
    mhartid = 0xf14,

    mstatus = 0x300,
    misa = 0x301,
    medeleg = 0x302,
    mideleg = 0x303,
    mie = 0x304,
    mtvec = 0x305,
    mcounteren = 0x306,

    mscratch = 0x340,
    mepc = 0x341,
    mcause = 0x342,
    mtval = 0x343,
    mip = 0x344,

    mcycle = 0xb00,
    minstret = 0xb02,
    mcycleh = 0xb80,
    minstreth = 0xb82,

    tselect = 0x7a0,
    tdata1 = 0x7a1,
    tdata2 = 0x7a2,
    tdata3 = 0x7a3,
};

/// \brief The result of insn & 0b111000001111111 can be used to identify
/// most instructions directly
enum class insn_funct3_00000_opcode: uint32_t {
    LB              = 0b000000000000011,
    LH              = 0b001000000000011,
    LW              = 0b010000000000011,
    LD              = 0b011000000000011,
    LBU             = 0b100000000000011,
    LHU             = 0b101000000000011,
    LWU             = 0b110000000000011,
    SB              = 0b000000000100011,
    SH              = 0b001000000100011,
    SW              = 0b010000000100011,
    SD              = 0b011000000100011,
    FENCE           = 0b000000000001111,
    FENCE_I         = 0b001000000001111,
    ADDI            = 0b000000000010011,
    SLLI            = 0b001000000010011,
    SLTI            = 0b010000000010011,
    SLTIU           = 0b011000000010011,
    XORI            = 0b100000000010011,
    ORI             = 0b110000000010011,
    ANDI            = 0b111000000010011,
    ADDIW           = 0b000000000011011,
    SLLIW           = 0b001000000011011,
    SLLW            = 0b001000000111011,
    DIVW            = 0b100000000111011,
    REMW            = 0b110000000111011,
    REMUW           = 0b111000000111011,
    BEQ             = 0b000000001100011,
    BNE             = 0b001000001100011,
    BLT             = 0b100000001100011,
    BGE             = 0b101000001100011,
    BLTU            = 0b110000001100011,
    BGEU            = 0b111000001100011,
    JALR            = 0b000000001100111,
    CSRRW           = 0b001000001110011,
    CSRRS           = 0b010000001110011,
    CSRRC           = 0b011000001110011,
    CSRRWI          = 0b101000001110011,
    CSRRSI          = 0b110000001110011,
    CSRRCI          = 0b111000001110011,
    AUIPC_000       = 0b000000000010111,
    AUIPC_001       = 0b001000000010111,
    AUIPC_010       = 0b010000000010111,
    AUIPC_011       = 0b011000000010111,
    AUIPC_100       = 0b100000000010111,
    AUIPC_101       = 0b101000000010111,
    AUIPC_110       = 0b110000000010111,
    AUIPC_111       = 0b111000000010111,
    LUI_000         = 0b000000000110111,
    LUI_001         = 0b001000000110111,
    LUI_010         = 0b010000000110111,
    LUI_011         = 0b011000000110111,
    LUI_100         = 0b100000000110111,
    LUI_101         = 0b101000000110111,
    LUI_110         = 0b110000000110111,
    LUI_111         = 0b111000000110111,
    JAL_000         = 0b000000001101111,
    JAL_001         = 0b001000001101111,
    JAL_010         = 0b010000001101111,
    JAL_011         = 0b011000001101111,
    JAL_100         = 0b100000001101111,
    JAL_101         = 0b101000001101111,
    JAL_110         = 0b110000001101111,
    JAL_111         = 0b111000001101111,
    // some instructions need additional inspection of funct7 (or part thereof)
    SRLI_SRAI       = 0b101000000010011,
    SRLIW_SRAIW     = 0b101000000011011,
    AMO_W           = 0b010000000101111,
    AMO_D           = 0b011000000101111,
    ADD_MUL_SUB     = 0b000000000110011,
    SLL_MULH        = 0b001000000110011,
    SLT_MULHSU      = 0b010000000110011,
    SLTU_MULHU      = 0b011000000110011,
    XOR_DIV         = 0b100000000110011,
    SRL_DIVU_SRA    = 0b101000000110011,
    OR_REM          = 0b110000000110011,
    AND_REMU        = 0b111000000110011,
    ADDW_MULW_SUBW  = 0b000000000111011,
    SRLW_DIVUW_SRAW = 0b101000000111011,
    privileged      = 0b000000001110011,
};

/// \brief The result of insn >> 26 (6 most significant bits of funct7) can be
/// used to identify the SRI instructions
enum insn_SRLI_SRAI_funct7_sr1: uint32_t {
    SRLI = 0b000000,
    SRAI = 0b010000
};

/// \brief funct7 constants for SRW instructions
enum insn_SRLIW_SRAIW_funct7: uint32_t {
    SRLIW = 0b0000000,
    SRAIW = 0b0100000
};

/// \brief The result of insn >> 27 (5 most significant bits of funct7) can be
/// used to identify the atomic operation
enum insn_AMO_funct7_sr2: uint32_t {
    AMOADD  = 0b00000,
    AMOSWAP = 0b00001,
    LR      = 0b00010,
    SC      = 0b00011,
    AMOXOR  = 0b00100,
    AMOOR   = 0b01000,
    AMOAND  = 0b01100,
    AMOMIN  = 0b10000,
    AMOMAX  = 0b10100,
    AMOMINU = 0b11000,
    AMOMAXU = 0b11100
};

/// \brief funct7 constants for ADD, MUL, SUB instructions
enum insn_ADD_MUL_SUB_funct7: uint32_t {
    ADD = 0b0000000,
    MUL = 0b0000001,
    SUB = 0b0100000
};

/// \brief funct7 constants for SLL, MULH instructions
enum insn_SLL_MULH_funct7: uint32_t {
    SLL  = 0b0000000,
    MULH = 0b0000001
};

/// \brief funct7 constants for SLT, MULHSU instructions
enum insn_SLT_MULHSU_funct7: uint32_t {
    SLT    = 0b0000000,
    MULHSU = 0b0000001
};

/// \brief funct7 constants for SLTU, MULHU instructions
enum insn_SLTU_MULHU_funct7: uint32_t {
    SLTU  = 0b0000000,
    MULHU = 0b0000001
};

/// \brief funct7 constants for XOR, DIV instructions
enum insn_XOR_DIV_funct7: uint32_t {
    XOR        = 0b0000000,
    DIV        = 0b0000001,
};

/// \brief funct7 constants for SRL, DIVU, SRA instructions
enum insn_SRL_DIVU_SRA_funct7: uint32_t {
    SRL  = 0b0000000,
    DIVU = 0b0000001,
    SRA  = 0b0100000,
};

/// \brief funct7 constants for OR, REM instructions
enum insn_OR_REM_funct7: uint32_t {
    OR  = 0b0000000,
    REM = 0b0000001
};

/// \brief funct7 constants for AND, REMU instructions
enum insn_AND_REMU_funct7: uint32_t {
    AND  = 0b0000000,
    REMU = 0b0000001
};

/// \brief funct7 constants for ADDW, MULW, SUBW instructions
enum insn_ADDW_MULW_SUBW_funct7: uint32_t {
    ADDW = 0b0000000,
    MULW = 0b0000001,
    SUBW = 0b0100000
};

/// \brief funct7 constants for SRLW, DIVUW, SRAW instructions
enum insn_SRLW_DIVUW_SRAW_funct7: uint32_t {
    SRLW  = 0b0000000,
    DIVUW = 0b0000001,
    SRAW  = 0b0100000
};

/// \brief Privileged instructions, except for SFENCE.VMA, have no parameters
enum class insn_privileged: uint32_t {
    ECALL  = 0b00000000000000000000000001110011,
    EBREAK = 0b00000000000100000000000001110011,
    URET   = 0b00000000001000000000000001110011,
    SRET   = 0b00010000001000000000000001110011,
    MRET   = 0b00110000001000000000000001110011,
    WFI    = 0b00010000010100000000000001110011
};

} // namespace cartesi

#endif
