#include "pma.h"

/// \brief Default device write callback issues error on write.
bool pma_write_error(const pma_entry &, i_virtual_state_access *, uint64_t, uint64_t, int) {
    return false;
}

/// \brief Default device read callback issues error on reads.
bool pma_read_error(const pma_entry &, i_virtual_state_access *, uint64_t, uint64_t *, int) {
    return false;
}

/// \brief Default device peek callback issues error on peeks.
bool pma_peek_error(const pma_entry &, uint64_t, const uint8_t **, uint8_t *) {
    return false;
}
