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
    memcpy(page_data, s->reg, sizeof(s->reg));
    // Copy named registers
    *reinterpret_cast<uint64_t *>(page_data + 0x100) = s->pc;
    *reinterpret_cast<uint64_t *>(page_data + 0x108) = s->mvendorid;
    *reinterpret_cast<uint64_t *>(page_data + 0x110) = s->marchid;
    *reinterpret_cast<uint64_t *>(page_data + 0x118) = s->mimpid;
    *reinterpret_cast<uint64_t *>(page_data + 0x120) = s->mcycle;
    *reinterpret_cast<uint64_t *>(page_data + 0x128) = s->minstret;
    *reinterpret_cast<uint64_t *>(page_data + 0x130) = s->mstatus;
    *reinterpret_cast<uint64_t *>(page_data + 0x138) = s->mtvec;
    *reinterpret_cast<uint64_t *>(page_data + 0x140) = s->mscratch;
    *reinterpret_cast<uint64_t *>(page_data + 0x148) = s->mepc;
    *reinterpret_cast<uint64_t *>(page_data + 0x150) = s->mcause;
    *reinterpret_cast<uint64_t *>(page_data + 0x158) = s->mtval;
    *reinterpret_cast<uint64_t *>(page_data + 0x160) = s->misa;
    *reinterpret_cast<uint64_t *>(page_data + 0x168) = s->mie;
    *reinterpret_cast<uint64_t *>(page_data + 0x170) = s->mip;
    *reinterpret_cast<uint64_t *>(page_data + 0x178) = s->medeleg;
    *reinterpret_cast<uint64_t *>(page_data + 0x180) = s->mideleg;
    *reinterpret_cast<uint64_t *>(page_data + 0x188) = s->mcounteren;
    *reinterpret_cast<uint64_t *>(page_data + 0x190) = s->stvec;
    *reinterpret_cast<uint64_t *>(page_data + 0x198) = s->sscratch;
    *reinterpret_cast<uint64_t *>(page_data + 0x1a0) = s->sepc;
    *reinterpret_cast<uint64_t *>(page_data + 0x1a8) = s->scause;
    *reinterpret_cast<uint64_t *>(page_data + 0x1b0) = s->stval;
    *reinterpret_cast<uint64_t *>(page_data + 0x1b8) = s->satp;
    *reinterpret_cast<uint64_t *>(page_data + 0x1c0) = s->scounteren;
    *reinterpret_cast<uint64_t *>(page_data + 0x1c8) = s->ilrsc;
    *reinterpret_cast<uint64_t *>(page_data + 0x1d0) = processor_read_iflags(s);
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
