#ifndef CLINT_H
#define CLINT_H

#include <cstdint>

/// \file
/// \brief Clock interruptor device.

struct machine_state;

/// \brief Mapping between CSRs and their relative addresses in CLINT memory
enum class clint_csr {
    msip0 =    UINT64_C(0),      // Machine software interrupt for hart 0
    mtimecmp = UINT64_C(0x4000),
    mtime =    UINT64_C(0xbff8)
};

/// \brief Obtains the relative address of a CSR in HTIF memory.
/// \param reg CSR name.
/// \returns The address.
uint64_t clint_get_csr_rel_addr(clint_csr reg);

/// \brief Registers a CLINT device with the machine
/// \param s Machine state.
/// \param start Start address for memory range.
/// \param length Length of memory range.
void clint_register_mmio(machine_state *s, uint64_t start, uint64_t length);

#endif
