#ifndef HTIF_H
#define HTIF_H

#include <cstdint>

/// \file
/// \brief Host-Target interface device.

struct htif_state;

/// \brief Creates and returns a new HTIF device
/// \param s The machine state.
/// \param interactive This is an interactive session with terminal support.
/// \returns Newly created state, or nullptr if out-of-memory.
htif_state *htif_init(machine_state *s, bool interactive);

/// \brief Interact with the hosts's terminal.
/// \param htif Pointer to HTIF state
void htif_interact(htif_state *htif);

/// \brief Destroys an HTIF device
/// \param htif Pointer to HTIF state
void htif_end(htif_state *htif);

struct pma_device_driver;
extern pma_device_driver htif_driver;

#endif
