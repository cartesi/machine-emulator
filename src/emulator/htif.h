#ifndef HTIF_H
#define HTIF_H

#include <cstdint>

/// \file
/// \brief Host-Target interface device.

// Forward declarations
struct machine_state;
struct htif_state;

/// \brief Mapping between CSRs and their relative addresses in HTIF memory
enum class htif_csr {
    tohost   = UINT64_C(0x0),
    fromhost = UINT64_C(0x8)
};

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

/// \brief Obtains the relative address of a CSR in HTIF memory.
/// \param reg CSR name.
/// \returns The address.
uint64_t htif_get_csr_rel_addr(htif_csr reg);

/// \brief Registers an HTIF device with the machine
/// \param htif Pointer to HTIF state
/// \param start Start address for memory range.
/// \param length Length of memory range.
/// \returns True if succeeded, false otherwise
bool htif_register_mmio(htif_state *htif, uint64_t start, uint64_t length);

#endif
