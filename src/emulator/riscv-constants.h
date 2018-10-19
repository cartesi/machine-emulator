#ifndef RISCV_CONSTANTS_H
#define RISCV_CONSTANTS_H

/// \file
/// \brief RISC-V constants

/// \name mcause for exceptions
/// \{
#define CAUSE_MISALIGNED_FETCH              0x0
#define CAUSE_FETCH_FAULT                   0x1
#define CAUSE_ILLEGAL_INSTRUCTION           0x2
#define CAUSE_BREAKPOINT                    0x3
#define CAUSE_LOAD_ADDRESS_MISALIGNED       0x4
#define CAUSE_LOAD_FAULT                    0x5
#define CAUSE_STORE_AMO_ADDRESS_MISALIGNED  0x6
#define CAUSE_STORE_AMO_FAULT               0x7
#define CAUSE_ECALL_BASE                    0x8
#define CAUSE_FETCH_PAGE_FAULT              0xc
#define CAUSE_LOAD_PAGE_FAULT               0xd
#define CAUSE_STORE_AMO_PAGE_FAULT          0xf
#define CAUSE_INTERRUPT                     ((uint64_t)1 << 63)
/// \}


/// \name Privilege levels
/// \{
#define PRV_U               0  ///< User
#define PRV_S               1  ///< Supervisor
#define PRV_H               2  ///< Reserved
#define PRV_M               3  ///< Machine
/// \}

/// \name misa extensions
/// \{
#define MISAEXT_S            (1 << ('S' - 'A'))
#define MISAEXT_U            (1 << ('U' - 'A'))
#define MISAEXT_I            (1 << ('I' - 'A'))
#define MISAEXT_M            (1 << ('M' - 'A'))
#define MISAEXT_A            (1 << ('A' - 'A'))
#define MISAEXT_F            (1 << ('F' - 'A'))
#define MISAEXT_D            (1 << ('D' - 'A'))
#define MISAEXT_C            (1 << ('C' - 'A'))
/// \}

/// \name mstatus shifts
/// \{
#define MSTATUS_UIE_SHIFT   0
#define MSTATUS_SIE_SHIFT   1
#define MSTATUS_HIE_SHIFT   2
#define MSTATUS_MIE_SHIFT   3
#define MSTATUS_UPIE_SHIFT  4
#define MSTATUS_SPIE_SHIFT  5
#define MSTATUS_MPIE_SHIFT  7
#define MSTATUS_SPP_SHIFT   8
#define MSTATUS_MPP_SHIFT   11
#define MSTATUS_FS_SHIFT    13
#define MSTATUS_SD_SHIFT    31
#define MSTATUS_UXL_SHIFT   32
#define MSTATUS_SXL_SHIFT   34
/// \}

/// \name mstatus flags
/// \{
#define MSTATUS_UIE         (1 << 0)
#define MSTATUS_SIE         (1 << 1)
#define MSTATUS_HIE         (1 << 2)
#define MSTATUS_MIE         (1 << 3)
#define MSTATUS_UPIE        (1 << 4)
#define MSTATUS_SPIE        (1 << MSTATUS_SPIE_SHIFT)
#define MSTATUS_HPIE        (1 << 6)
#define MSTATUS_MPIE        (1 << MSTATUS_MPIE_SHIFT)
#define MSTATUS_SPP         (1 << MSTATUS_SPP_SHIFT)
#define MSTATUS_HPP         (3 << 9)
#define MSTATUS_MPP         (3 << MSTATUS_MPP_SHIFT)
#define MSTATUS_FS          (3 << MSTATUS_FS_SHIFT)
#define MSTATUS_XS          (3 << 15)
#define MSTATUS_MPRV        (1 << 17)
#define MSTATUS_SUM         (1 << 18)
#define MSTATUS_MXR         (1 << 19)
#define MSTATUS_TVM         (1 << 20)
#define MSTATUS_TW          (1 << 21)
#define MSTATUS_TSR         (1 << 22)
#define MSTATUS_SD          ((uint64_t)1 << MSTATUS_SD_SHIFT)
#define MSTATUS_UXL         ((uint64_t)3 << MSTATUS_UXL_SHIFT)
#define MSTATUS_SXL         ((uint64_t)3 << MSTATUS_SXL_SHIFT)
/// \}

/// \name Paging constants
/// \{
#define PG_SHIFT            12
#define PG_MASK             ((1 << PG_SHIFT) - 1)

#define PTE_V_MASK (1 << 0)
#define PTE_U_MASK (1 << 4)
#define PTE_A_MASK (1 << 6)
#define PTE_D_MASK (1 << 7)
#define PTE_XWR_READ_SHIFT  0
#define PTE_XWR_WRITE_SHIFT 1
#define PTE_XWR_CODE_SHIFT  2
/// \}

/// \name mstatus read/write masks
/// \{

/// \brief Write mask for sstatus
#define SSTATUS_WRITE_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_SPP  | \
    MSTATUS_FS   | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  \
)

/// \brief Read mask for sstatus
#define SSTATUS_READ_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_SPP  | \
    MSTATUS_FS   | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  | \
    MSTATUS_UXL  | \
    MSTATUS_SD  \
)

/// \brief Write mask for mstatus
#define MSTATUS_WRITE_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_MIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_MPIE | \
    MSTATUS_SPP  | \
    MSTATUS_MPP  | \
    MSTATUS_FS   | \
    MSTATUS_MPRV | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  | \
    MSTATUS_TVM  | \
    MSTATUS_TW   | \
    MSTATUS_TSR  \
)

/// \brief Read mask for mstatus
#define MSTATUS_READ_MASK ( \
    MSTATUS_UIE  | \
    MSTATUS_SIE  | \
    MSTATUS_MIE  | \
    MSTATUS_UPIE | \
    MSTATUS_SPIE | \
    MSTATUS_MPIE | \
    MSTATUS_SPP  | \
    MSTATUS_MPP  | \
    MSTATUS_FS   | \
    MSTATUS_MPRV | \
    MSTATUS_SUM  | \
    MSTATUS_MXR  | \
    MSTATUS_TVM  | \
    MSTATUS_TW   | \
    MSTATUS_TSR  | \
    MSTATUS_UXL  | \
    MSTATUS_SXL  | \
    MSTATUS_SD  \
)
/// \}

/// \brief mcycle and minstret masks in counteren
#define COUNTEREN_MASK ((1 << 0) | (1 << 2))

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

/// \brief Names for instruction opcode field.
enum class insn_opcode {
    LUI   = 0b0110111,
    AUIPC = 0b0010111,
    JAL   = 0b1101111,
    JALR  = 0b1100111,

    branch_group = 0b1100011,
    load_group = 0b0000011,
    store_group = 0b0100011,
    arithmetic_immediate_group = 0b0010011,
    arithmetic_group = 0b0110011,
    fence_group = 0b0001111,
    csr_env_trap_int_mm_group = 0b1110011,
    arithmetic_immediate_32_group = 0b0011011,
    arithmetic_32_group = 0b0111011,
    atomic_group = 0b0101111,
};

/// \brief Names for branch instructions funct3 field.
enum class insn_branch_funct3 {
    BEQ  = 0b000,
    BNE  = 0b001,
    BLT  = 0b100,
    BGE  = 0b101,
    BLTU = 0b110,
    BGEU = 0b111
};

/// \brief Names for load instructions funct3 field.
enum class insn_load_funct3 {
    LB  = 0b000,
    LH  = 0b001,
    LW  = 0b010,
    LD  = 0b011,
    LBU = 0b100,
    LHU = 0b101,
    LWU = 0b110
};

/// \brief Names for store instructions funct3 field.
enum class insn_store_funct3 {
    SB = 0b000,
    SH = 0b001,
    SW = 0b010,
    SD = 0b011
};

/// \brief Names for arithmetic-immediate instructions funct3 field.
enum class insn_arithmetic_immediate_funct3 {
    ADDI  = 0b000,
    SLTI  = 0b010,
    SLTIU = 0b011,
    XORI  = 0b100,
    ORI   = 0b110,
    ANDI  = 0b111,
    SLLI  = 0b001,

    shift_right_immediate_group = 0b101,
};

/// \brief Names for shift-right immediate instructions funct6 field.
enum class insn_shift_right_immediate_funct6 {
    SRLI = 0b000000,
    SRAI = 0b010000
};

/// \brief Names for arithmetic instructions concatenated funct3 and funct7 fields.
enum class insn_arithmetic_funct3_funct7 {
    ADD    = 0b0000000000,
    SUB    = 0b0000100000,
    SLL    = 0b0010000000,
    SLT    = 0b0100000000,
    SLTU   = 0b0110000000,
    XOR    = 0b1000000000,
    SRL    = 0b1010000000,
    SRA    = 0b1010100000,
    OR     = 0b1100000000,
    AND    = 0b1110000000,
    MUL    = 0b0000000001,
    MULH   = 0b0010000001,
    MULHSU = 0b0100000001,
    MULHU  = 0b0110000001,
    DIV    = 0b1000000001,
    DIVU   = 0b1010000001,
    REM    = 0b1100000001,
    REMU   = 0b1110000001,
};

/// \brief Names for env, trap, and int instructions.
enum class insn_env_trap_int_group_insn {
    ECALL  = 0b00000000000000000000000001110011,
    EBREAK = 0b00000000000100000000000001110011,
    URET   = 0b00000000001000000000000001110011,
    SRET   = 0b00010000001000000000000001110011,
    MRET   = 0b00110000001000000000000001110011,
    WFI    = 0b00010000010100000000000001110011
};

/// \brief Names for csr, env, trap, int, mm instructions funct3 field.
enum class insn_csr_env_trap_int_mm_funct3 {
    CSRRW  = 0b001,
    CSRRS  = 0b010,
    CSRRC  = 0b011,
    CSRRWI = 0b101,
    CSRRSI = 0b110,
    CSRRCI = 0b111,

    env_trap_int_mm_group  = 0b000,
};

/// \brief Names for 32-bit arithmetic immediate instructions funct3 field.
enum class insn_arithmetic_immediate_32_funct3 {
    ADDIW = 0b000,
    SLLIW = 0b001,

    shift_right_immediate_32_group = 0b101,
};

/// \brief Names for 32-bit shift-right immediate instructions funct7 field.
enum class insn_shift_right_immediate_32_funct7 {
    SRLIW = 0b0000000,
    SRAIW = 0b0100000
};

/// \brief Names for 32-bit arithmetic instructions concatenated funct3 and funct7 fields.
enum class insn_arithmetic_32_funct3_funct7 {
    ADDW  = 0b0000000000,
    SUBW  = 0b0000100000,
    SLLW  = 0b0010000000,
    SRLW  = 0b1010000000,
    SRAW  = 0b1010100000,
    MULW  = 0b0000000001,
    DIVW  = 0b1000000001,
    DIVUW = 0b1010000001,
    REMW  = 0b1100000001,
    REMUW = 0b1110000001
};

/// \brief Names for atomic instructions concatenated funct3 and funct5 fields.
enum class insn_atomic_funct3_funct5 {
    LR_W      = 0b01000010,
    SC_W      = 0b01000011,
    AMOSWAP_W = 0b01000001,
    AMOADD_W  = 0b01000000,
    AMOXOR_W  = 0b01000100,
    AMOAND_W  = 0b01001100,
    AMOOR_W   = 0b01001000,
    AMOMIN_W  = 0b01010000,
    AMOMAX_W  = 0b01010100,
    AMOMINU_W = 0b01011000,
    AMOMAXU_W = 0b01011100,
    LR_D      = 0b01100010,
    SC_D      = 0b01100011,
    AMOSWAP_D = 0b01100001,
    AMOADD_D  = 0b01100000,
    AMOXOR_D  = 0b01100100,
    AMOAND_D  = 0b01101100,
    AMOOR_D   = 0b01101000,
    AMOMIN_D  = 0b01110000,
    AMOMAX_D  = 0b01110100,
    AMOMINU_D = 0b01111000,
    AMOMAXU_D = 0b01111100
};

#endif
