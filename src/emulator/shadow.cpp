#include "shadow.h"
#include "machine.h"
#include "pma.h"

/// \name Processor shadow offsets
/// \{
#define SHADOW_X0           0x000
#define SHADOW_X1           0x008
#define SHADOW_X2           0x010
#define SHADOW_X3           0x018
#define SHADOW_X4           0x020
#define SHADOW_X5           0x028
#define SHADOW_X6           0x030
#define SHADOW_X7           0x038
#define SHADOW_X8           0x040
#define SHADOW_X9           0x048
#define SHADOW_X10          0x050
#define SHADOW_X11          0x058
#define SHADOW_X12          0x060
#define SHADOW_X13          0x068
#define SHADOW_X14          0x070
#define SHADOW_X15          0x078
#define SHADOW_X16          0x080
#define SHADOW_X17          0x088
#define SHADOW_X18          0x090
#define SHADOW_X19          0x098
#define SHADOW_X20          0x0a0
#define SHADOW_X21          0x0a8
#define SHADOW_X22          0x0b0
#define SHADOW_X23          0x0b8
#define SHADOW_X24          0x0c0
#define SHADOW_X25          0x0c8
#define SHADOW_X26          0x0d0
#define SHADOW_X27          0x0d8
#define SHADOW_X28          0x0e0
#define SHADOW_X29          0x0e8
#define SHADOW_X30          0x0f0
#define SHADOW_X31          0x0f8
#define SHADOW_PC           0x100
#define SHADOW_MVENDORID    0x108
#define SHADOW_MARCHID      0x110
#define SHADOW_MIMPID       0x118
#define SHADOW_MCYCLE       0x120
#define SHADOW_MINSTRET     0x128
#define SHADOW_MSTATUS      0x130
#define SHADOW_MTVEC        0x138
#define SHADOW_MSCRATCH     0x140
#define SHADOW_MEPC         0x148
#define SHADOW_MCAUSE       0x150
#define SHADOW_MTVAL        0x158
#define SHADOW_MISA         0x160
#define SHADOW_MIE          0x168
#define SHADOW_MIP          0x170
#define SHADOW_MEDELEG      0x178
#define SHADOW_MIDELEG      0x180
#define SHADOW_MCOUNTEREN   0x188
#define SHADOW_STVEC        0x190
#define SHADOW_SSCRATCH     0x198
#define SHADOW_SEPC         0x1A0
#define SHADOW_SCAUSE       0x1A8
#define SHADOW_STVAL        0x1B0
#define SHADOW_SATP         0x1B8
#define SHADOW_SCOUNTEREN   0x1C0
#define SHADOW_ILRSC        0x1C8
#define SHADOW_IFLAGS       0x1D0
/// \}


/// \name Base of board shadow
#define SHADOW_PMA_BASE     0x800

/// \brief Shadow device peek callback. See ::pma_peek.
static bool shadow_peek(const pma_entry *pma, uint64_t page_address, const uint8_t **page_data, uint8_t *scratch) {
    const machine_state *s = reinterpret_cast<const machine_state *>(pma_get_context(pma));
    // There is only one page: 0
    if (page_address != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);
    // Copy general-purpose registers
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X0) = machine_read_register(s, 0);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X1) = machine_read_register(s, 1);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X2) = machine_read_register(s, 2);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X3) = machine_read_register(s, 3);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X4) = machine_read_register(s, 4);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X5) = machine_read_register(s, 5);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X6) = machine_read_register(s, 6);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X7) = machine_read_register(s, 7);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X8) = machine_read_register(s, 8);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X9) = machine_read_register(s, 9);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X10) = machine_read_register(s, 10);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X11) = machine_read_register(s, 11);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X12) = machine_read_register(s, 12);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X13) = machine_read_register(s, 13);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X14) = machine_read_register(s, 14);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X15) = machine_read_register(s, 15);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X16) = machine_read_register(s, 16);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X17) = machine_read_register(s, 17);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X18) = machine_read_register(s, 18);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X19) = machine_read_register(s, 19);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X20) = machine_read_register(s, 20);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X21) = machine_read_register(s, 21);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X22) = machine_read_register(s, 22);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X23) = machine_read_register(s, 23);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X24) = machine_read_register(s, 24);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X25) = machine_read_register(s, 25);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X26) = machine_read_register(s, 26);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X27) = machine_read_register(s, 27);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X28) = machine_read_register(s, 28);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X29) = machine_read_register(s, 29);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X30) = machine_read_register(s, 30);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_X31) = machine_read_register(s, 31);
    // Copy named registers
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_PC) = machine_read_pc(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MVENDORID) = machine_read_mvendorid(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MARCHID) = machine_read_marchid(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MIMPID) = machine_read_mimpid(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MCYCLE) = machine_read_mcycle(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MINSTRET) = machine_read_minstret(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MSTATUS) = machine_read_mstatus(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MTVEC) = machine_read_mtvec(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MSCRATCH) = machine_read_mscratch(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MEPC) = machine_read_mepc(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MCAUSE) = machine_read_mcause(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MTVAL) = machine_read_mtval(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MISA) = machine_read_misa(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MIE) = machine_read_mie(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MIP) = machine_read_mip(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MEDELEG) = machine_read_medeleg(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MIDELEG) = machine_read_mideleg(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_MCOUNTEREN) = machine_read_mcounteren(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_STVEC) = machine_read_stvec(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_SSCRATCH) = machine_read_sscratch(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_SEPC) = machine_read_sepc(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_SCAUSE) = machine_read_scause(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_STVAL) = machine_read_stval(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_SATP) = machine_read_satp(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_SCOUNTEREN) = machine_read_scounteren(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_ILRSC) = machine_read_ilrsc(s);
    *reinterpret_cast<uint64_t *>(scratch + SHADOW_IFLAGS) = machine_read_iflags(s);
    // Copy PMAs
    uint64_t *shadow_pma = reinterpret_cast<uint64_t *>(scratch + SHADOW_PMA_BASE);
    for (int i = 0; i < machine_get_pma_count(s); i++) {
        auto pma_i = machine_get_pma(s, i);
        shadow_pma[2*i] = pma_get_encoded_start(pma_i);
        shadow_pma[2*i+1] = pma_get_encoded_length(pma_i);
    }
    *page_data = scratch;
    return true;
}

static const pma_driver shadow_driver = {
    "SHADOW",
    pma_read_error,
    pma_write_error,
    shadow_peek
};

bool shadow_register_mmio(machine_state *s, uint64_t start, uint64_t length) {
    return machine_register_mmio(s, start, length, s, &shadow_driver);
}
