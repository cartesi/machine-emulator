#ifndef HTIF_H
#define HTIF_H

#include <cstdint>

/// \file
/// \brief Host-Target interface device.

#include "i-device-state-access.h"
#include "machine.h"

/// \brief Opaque HTIF device state.
typedef struct htif_state htif_state;

/// \brief HTIF device read callback. See ::pma_device_read.
bool htif_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *pval, int size_log2);

/// \brief HTIF device write callback. See ::pma_device_write.
bool htif_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2);

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

#endif
