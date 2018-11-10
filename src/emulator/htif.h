#ifndef HTIF_H
#define HTIF_H

#include <cstdint>

/// \file
/// \brief Host-Target interface device.

// Forward declarations
struct machine_state;
struct htif_state;

/// \brief Creates and returns a new HTIF device
/// \param s The machine state.
/// \param interactive This is an interactive session with terminal support.
/// \returns Newly created state, or nullptr if out-of-memory.
htif_state *htif_init(machine_state *s, bool interactive);

/// \brief Interact with the hosts's terminal.
/// \param htif Pointer to HTIF state
void htif_interact(htif_state *htif);

/// \brief Registers an HTIF device with the machine
/// \param htif Pointer to HTIF state
/// \param start Start of memory range mapped to HTIF device
/// \param length Length of memory range mapped to HTIF device
/// \returns True if succeeded, false otherwise
bool htif_register_mmio(htif_state *htif, uint64_t start, uint64_t length);

/// \brief Destroys an HTIF device
/// \param htif Pointer to HTIF state
void htif_end(htif_state *htif);

#endif
