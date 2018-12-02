#include <cassert>

#include "shadow.h"
#include "machine.h"

namespace cartesi {

static void write_shadow(uint8_t *base, uint64_t offset, uint64_t value) {
    assert((offset & (sizeof(uint64_t)-1)) == 0);
    *reinterpret_cast<uint64_t *>(base + offset) = value;
}

uint64_t shadow_get_csr_rel_addr(shadow_csr reg) {
    return static_cast<uint64_t>(reg);
}

uint64_t shadow_get_register_rel_addr(int reg) {
    assert(reg >= 0 && reg < 32);
    return reg*sizeof(uint64_t);
}

/// \name Base of board shadow, where PMAs start
#define SHADOW_PMA_BASE     UINT64_C(0x800)

uint64_t shadow_get_pma_rel_addr(int p) {
    assert(p >= 0 && p < 32);
    return SHADOW_PMA_BASE + 2*p*sizeof(uint64_t);
}

/// \brief Shadow device peek callback. See ::pma_peek.
static bool shadow_peek(const pma_entry &pma, uint64_t page_offset, const uint8_t **page_data, uint8_t *shadow) {
    const machine *m = reinterpret_cast<const machine *>(
        pma.get_device().get_context());
    // There is only one page: 0
    if (page_offset != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(shadow, 0, PMA_PAGE_SIZE);
    // Copy general-purpose registers
    for (int i = 0; i < 32; ++i) {
        write_shadow(shadow, shadow_get_register_rel_addr(i), m->read_x(i));
    }
    // Copy named registers
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::pc),
        m->read_pc());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mvendorid),
        m->read_mvendorid());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::marchid),
        m->read_marchid());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mimpid),
        m->read_mimpid());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mcycle),
        m->read_mcycle());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::minstret),
        m->read_minstret());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mstatus),
        m->read_mstatus());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mtvec),
        m->read_mtvec());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mscratch),
        m->read_mscratch());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mepc),
        m->read_mepc());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mcause),
        m->read_mcause());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mtval),
        m->read_mtval());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::misa),
        m->read_misa());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mie),
        m->read_mie());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mip),
        m->read_mip());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::medeleg),
        m->read_medeleg());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mideleg),
        m->read_mideleg());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::mcounteren),
        m->read_mcounteren());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::stvec),
        m->read_stvec());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::sscratch),
        m->read_sscratch());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::sepc),
        m->read_sepc());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::scause),
        m->read_scause());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::stval),
        m->read_stval());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::satp),
        m->read_satp());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::scounteren),
        m->read_scounteren());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::ilrsc),
        m->read_ilrsc());
    write_shadow(shadow, shadow_get_csr_rel_addr(shadow_csr::iflags),
        m->read_iflags());
    // Copy PMAs
    int i = 0;
    for (const auto &pma: m->get_pmas()) {
        auto rel_addr = shadow_get_pma_rel_addr(i);
        write_shadow(shadow, rel_addr, pma.get_istart());
        write_shadow(shadow, rel_addr + sizeof(uint64_t), pma.get_ilength());
        ++i;
    }
    *page_data = shadow;
    return true;
}

static const pma_driver shadow_driver = {
    "SHADOW",
    pma_read_error,
    pma_write_error
};

void shadow_register_mmio(machine &m, uint64_t start, uint64_t length) {
    m.register_shadow(start, length, shadow_peek, &m, &shadow_driver);
}

} // namespace cartesi
