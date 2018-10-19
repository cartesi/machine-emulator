#include "shadow.h"
#include "machine.h"
#include "machine-state.h"
#include "pma.h"

#define PROCESSOR_SHADOW_BASE 0x000
#define PROCESSOR_SHADOW_SIZE 0x800
#define BOARD_SHADOW_BASE     0x800
#define BOARD_SHADOW_SIZE     0x800

/// \brief Address of registers in processor's shadow
enum class processor_shadow: int {
    pc = 0x100,
    mvendorid = 0x108,
    marchid = 0x110,
    mimpid = 0x118,
    mcycle = 0x120,
    minstret = 0x128,
    mstatus = 0x130,
    mtvec = 0x138,
    mscratch = 0x140,
    mepc = 0x148,
    mcause = 0x150,
    mtval = 0x158,
    misa = 0x160,
    mie = 0x168,
    mip = 0x170,
    medeleg = 0x178,
    mideleg = 0x180,
    mcounteren = 0x188,
    stvec = 0x190,
    sscratch = 0x198,
    sepc = 0x1a0,
    scause = 0x1a8,
    stval = 0x1b0,
    satp = 0x1b8,
    scounteren = 0x1c0,
    ilrsc = 0x1c8,
    iflags = 0x1d0,
};

/// \brief Shadow device peek callback. See ::pma_device_peek.
static bool shadow_peek(const machine_state *s, void *context, uint64_t offset, uint64_t *val, int size_log2) {
    (void) context;

    if (size_log2 != 3 || offset & 7) return false;

    // Deal with general-purpose register file
    int r = offset >> 3;
    if (r >= 0 && r < 32) {
        *val = s->reg[r];
        return true;
    }

    // Deal with other named registers
    if (offset < PROCESSOR_SHADOW_SIZE) {
        switch (static_cast<processor_shadow>(offset)) {
            case processor_shadow::pc:
                *val = s->pc;
                return true;
            case processor_shadow::mvendorid:
                *val = s->mvendorid;
                return true;
            case processor_shadow::marchid:
                *val = s->marchid;
                return true;
            case processor_shadow::mimpid:
                *val = s->mimpid;
                return true;
            case processor_shadow::mcycle:
                *val = s->mcycle;
                return true;
            case processor_shadow::minstret:
                *val = s->minstret;
                return true;
            case processor_shadow::mstatus:
                *val = s->mstatus;
                return true;
            case processor_shadow::mtvec:
                *val = s->mtvec;
                return true;
            case processor_shadow::mscratch:
                *val = s->mscratch;
                return true;
            case processor_shadow::mepc:
                *val = s->mepc;
                return true;
            case processor_shadow::mcause:
                *val = s->mcause;
                return true;
            case processor_shadow::mtval:
                *val = s->mtval;
                return true;
            case processor_shadow::misa:
                *val = s->misa;
                return true;
            case processor_shadow::mie:
                *val = s->mie;
                return true;
            case processor_shadow::mip:
                *val = s->mip;
                return true;
            case processor_shadow::medeleg:
                *val = s->medeleg;
                return true;
            case processor_shadow::mideleg:
                *val = s->mideleg;
                return true;
            case processor_shadow::mcounteren:
                *val = s->mcounteren;
                return true;
            case processor_shadow::stvec:
                *val = s->stvec;
                return true;
            case processor_shadow::sscratch:
                *val = s->sscratch;
                return true;
            case processor_shadow::sepc:
                *val = s->sepc;
                return true;
            case processor_shadow::scause:
                *val = s->scause;
                return true;
            case processor_shadow::stval:
                *val = s->stval;
                return true;
            case processor_shadow::satp:
                *val = s->satp;
                return true;
            case processor_shadow::scounteren:
                *val = s->scounteren;
                return true;
            case processor_shadow::ilrsc:
                *val = s->ilrsc;
                return true;
            case processor_shadow::iflags:
                *val = processor_read_iflags(s);
                return true;
            default:
                return false;
        }
    }

    // Deal with PMAs
    offset -= BOARD_SHADOW_BASE;
    int i = offset >> 4;
    if (i < 0 || i >= PMA_SIZE) return false;
    auto pma = s->physical_memory + i;
    bool ilength = offset & 1;
    if (ilength) *val = pma_get_ilength(pma);
    else *val = pma_get_istart(pma);
    return true;
}

/// \brief Shadow device update_merkle_tree callback. See ::pma_device_update_merkle_tree.
static bool shadow_update_merkle_tree(const machine_state *s, void *context, uint64_t start, uint64_t length, CryptoPP::Keccak_256 &kc, merkle_tree *t) {
    (void) length;
    assert(length == merkle_tree::get_page_size());
    auto page = reinterpret_cast<uint8_t *>(calloc(1, merkle_tree::get_page_size()));
    if (!page) return false;
    // There is 1 page to be updated
    for (int offset = 0; offset < merkle_tree::get_page_size(); offset += sizeof(uint64_t)) {
        shadow_peek(s, context, offset, reinterpret_cast<uint64_t *>(page + offset), 3);
    }
    bool err = t->is_error(t->update_page(kc, start, page));
    free(page);
    return !err;
}

const pma_device_driver shadow_driver = {
    pma_device_read_error,
    pma_device_write_error,
    shadow_peek,
    shadow_update_merkle_tree
};
