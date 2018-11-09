#ifndef SHADOW_H
#define SHADOW_H

#include <cstdint>

/// \file
/// \brief Shadow device.

struct machine_state;

/// \brief Registers a shadow device with the machine
/// \param s Machine state.
/// \param start Start of memory range mapped to shadow device
/// \param length Length of memory range mapped to shadow device
/// \returns True if succeeded, false otherwise
bool shadow_register_mmio(machine_state *s, uint64_t start, uint64_t length);

#endif
