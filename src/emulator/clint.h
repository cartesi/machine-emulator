#ifndef CLINT_H
#define CLINT_H

/// \file
/// \brief Clock interruptor device.

#include <cstdint>

#include "i-device-state-access.h"
#include "machine.h"

/// \brief CLINT device read callback. See ::pma_device_read.
bool clint_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *val, int size_log2);

/// \brief CLINT device read callback. See ::pma_device_write.
bool clint_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2);

/// \brief CLINT device peek callback. See ::pma_device_peek.
bool clint_peek(const machine_state *s, void *context, uint64_t offset, uint64_t *val, int size_log2);

/// \brief CLINT device update_merkle_tree callback. See ::pma_device_update_merkle_tree.
bool clint_update_merkle_tree(const machine_state *s, void *context, uint64_t start, uint64_t length,
    CryptoPP::Keccak_256 &kc, merkle_tree *t);

#endif
