#ifndef SHADOW_H
#define SHADOW_H

#include <cstdint>

/// \file
/// \brief Shadow device.

// Forward declarations
struct machine_state;

/// \brief Mapping between CSRs and their relative addresses in shadow memory
enum class shadow_csr {
    pc         = 0x100,
    mvendorid  = 0x108,
    marchid    = 0x110,
    mimpid     = 0x118,
    mcycle     = 0x120,
    minstret   = 0x128,
    mstatus    = 0x130,
    mtvec      = 0x138,
    mscratch   = 0x140,
    mepc       = 0x148,
    mcause     = 0x150,
    mtval      = 0x158,
    misa       = 0x160,
    mie        = 0x168,
    mip        = 0x170,
    medeleg    = 0x178,
    mideleg    = 0x180,
    mcounteren = 0x188,
    stvec      = 0x190,
    sscratch   = 0x198,
    sepc       = 0x1a0,
    scause     = 0x1a8,
    stval      = 0x1b0,
    satp       = 0x1b8,
    scounteren = 0x1c0,
    ilrsc      = 0x1c8,
    iflags     = 0x1d0
};

/// \brief Obtains the relative address of a CSR in shadow memory.
/// \param reg CSR name.
/// \returns The address.
uint64_t shadow_get_csr_rel_addr(shadow_csr reg);

/// \brief Obtains the relative address of a general purpose register
/// in shadow memory.
/// \param reg Register index in 0...31, for x0...x31, respectively.
/// \returns The address.
uint64_t shadow_get_register_rel_addr(int reg);

/// \brief Obtains the relative address of a PMA entry in shadow memory.
/// \param p Index of desired shadow PMA entry, in 0..31.
/// \returns The address.
uint64_t shadow_get_pma_rel_addr(int p);

/// \brief Registers a shadow device with the machine
/// \param s Machine state.
/// \param start Start address for memory range.
/// \param length Length of memory range.
void shadow_register_mmio(machine_state *s, uint64_t start, uint64_t length);

#endif
