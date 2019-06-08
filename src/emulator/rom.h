#ifndef ROM_H
#define ROM_H

/// \file
/// \brief Bootstrap and device tree in ROM

#include <cstdint>

namespace cartesi {

// Forward declarations
struct machine_config;

/// \brief Initializes PMA extension metadata on ROM
/// \param c Machine configuration.
/// \param rom_start Pointer to start of ROM contiguous range in host memory
/// \param length Maximum amount of ROM to use from start.
void rom_init(const machine_config &c, uint8_t *rom_start, uint64_t length);

} // namesmpace cartesi

#endif
