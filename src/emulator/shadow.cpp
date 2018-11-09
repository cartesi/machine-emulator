#include "shadow.h"
#include "machine.h"
#include "pma.h"

#define BOARD_SHADOW_BASE     0x800

/// \brief Shadow device peek callback. See ::pma_peek.
static bool shadow_peek(const pma_entry *pma, uint64_t page_index, const uint8_t **page_data, uint8_t *scratch) {
    const machine_state *s = reinterpret_cast<const machine_state *>(pma_get_context(pma));
    // There is only one page: 0
    if (page_index != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);
    // Copy general-purpose registers
    for (int i = 0; i <= 32; i++) {
        reinterpret_cast<uint64_t *>(scratch)[i] = machine_read_register(s, i);
    }
    // Copy named registers
    *reinterpret_cast<uint64_t *>(scratch + 0x100) = machine_read_pc(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x108) = machine_read_mvendorid(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x110) = machine_read_marchid(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x118) = machine_read_mimpid(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x120) = machine_read_mcycle(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x128) = machine_read_minstret(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x130) = machine_read_mstatus(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x138) = machine_read_mtvec(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x140) = machine_read_mscratch(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x148) = machine_read_mepc(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x150) = machine_read_mcause(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x158) = machine_read_mtval(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x160) = machine_read_misa(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x168) = machine_read_mie(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x170) = machine_read_mip(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x178) = machine_read_medeleg(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x180) = machine_read_mideleg(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x188) = machine_read_mcounteren(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x190) = machine_read_stvec(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x198) = machine_read_sscratch(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1a0) = machine_read_sepc(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1a8) = machine_read_scause(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1b0) = machine_read_stval(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1b8) = machine_read_satp(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1c0) = machine_read_scounteren(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1c8) = machine_read_ilrsc(s);
    *reinterpret_cast<uint64_t *>(scratch + 0x1d0) = machine_read_iflags(s);
    // Copy PMAs
    uint64_t *shadow_pma = reinterpret_cast<uint64_t *>(scratch + BOARD_SHADOW_BASE);
    int i = 0;
    const pma_entry *pma_i = nullptr;
    while (1) {
        pma_i = machine_get_pma(s, i);
        if (!pma_i) break;
        shadow_pma[2*i] = pma_get_encoded_start(pma_i);
        shadow_pma[2*i+1] = pma_get_encoded_length(pma_i);
        i++;
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
