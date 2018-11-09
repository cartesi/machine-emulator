#ifndef CLINT_H
#define CLINT_H

#include <cstdint>

/// \file
/// \brief Clock interruptor device.

struct machine_state;

/// \brief Registers a CLINT device with the machine
/// \param s Machine state.
/// \param start Start of memory range mapped to CLINT device
/// \param length Length of memory range mapped to CLINT device
/// \returns True if succeeded, false otherwise
bool clint_register_mmio(machine_state *s, uint64_t start, uint64_t length);

#endif
