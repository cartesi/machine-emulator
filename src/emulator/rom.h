#ifndef ROM_H
#define ROM_H

/// \file
/// \brief Bootstrap and device tree in ROM

#include <cstdint>

namespace cartesi {

// Forward declarations
struct machine_config;

/// \brief Initializes ROM with bootstrap and device tree
/// \param c Machine configuration.
/// \param misa Machine CSR misa.
/// \param max_xlen Maximum XLEN for machine.
/// \param rom_start Pointer to start of ROM contiguous range in host memory
/// \param length Maximum amount of ROM to use from start.
void rom_init(const machine_config &c, uint64_t misa, int max_xlen,
    uint8_t *rom_start, uint64_t length);

} // namesmpace cartesi

#endif
