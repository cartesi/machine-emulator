#include "shadow.h"
#include "machine.h"
#include "machine-state.h"
#include "pma.h"

#define BOARD_SHADOW_BASE     0x800

/// \brief Shadow device peek callback. See ::pma_device_peek.
static device_peek_status shadow_peek(const machine_state *s, void *context, uint64_t page_index, uint8_t *page_data) {
    (void) context;
    // There is only one page: 0
    if (page_index != 0)
        return device_peek_status::invalid_page;
    // Clear page
    memset(page_data, 0, PMA_PAGE_SIZE);
    // Copy general-purpose registers
    memcpy(page_data, s->x, sizeof(s->x));
    // Copy named registers
    *reinterpret_cast<uint64_t *>(page_data + 0x100) = machine_read_pc(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x108) = machine_read_mvendorid(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x110) = machine_read_marchid(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x118) = machine_read_mimpid(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x120) = machine_read_mcycle(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x128) = machine_read_minstret(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x130) = machine_read_mstatus(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x138) = machine_read_mtvec(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x140) = machine_read_mscratch(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x148) = machine_read_mepc(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x150) = machine_read_mcause(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x158) = machine_read_mtval(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x160) = machine_read_misa(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x168) = machine_read_mie(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x170) = machine_read_mip(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x178) = machine_read_medeleg(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x180) = machine_read_mideleg(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x188) = machine_read_mcounteren(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x190) = machine_read_stvec(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x198) = machine_read_sscratch(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1a0) = machine_read_sepc(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1a8) = machine_read_scause(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1b0) = machine_read_stval(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1b8) = machine_read_satp(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1c0) = machine_read_scounteren(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1c8) = machine_read_ilrsc(s);
    *reinterpret_cast<uint64_t *>(page_data + 0x1d0) = machine_read_iflags(s);
    // Copy PMAs
    uint64_t *shadow_pma = reinterpret_cast<uint64_t *>(page_data
        + BOARD_SHADOW_BASE);
    for (int i = 0; i < s->pma_count; ++i) {
        auto pma = &s->physical_memory[i];
        shadow_pma[2*i] = pma_get_istart(pma);
        shadow_pma[2*i+1] = pma_get_ilength(pma);
    }
    return device_peek_status::success;
}

const pma_device_driver shadow_driver = {
    "SHADOW",
    pma_device_read_error,
    pma_device_write_error,
    shadow_peek
};
