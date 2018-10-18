#include "pma.h"

/// \brief Default device write callback issues error on write.
bool pma_device_write_error(i_device_state_access *, void *, uint64_t, uint64_t, int) {
    return false;
}

/// \brief Default device read callback issues error on reads.
bool pma_device_read_error(i_device_state_access *, void *, uint64_t, uint64_t *, int) {
    return false;
}

/// \brief Default device peek callback issues error on peeks.
bool pma_device_peek_error(const machine_state *, void *, uint64_t, uint64_t *, int) {
    return false;
}

/// \brief Default device update_merkle_tree callback issues error on updates.
bool pma_device_update_merkle_tree_error(const machine_state *, void *, uint64_t, uint64_t,
    CryptoPP::Keccak_256 &, merkle_tree *) {
    return false;
}
