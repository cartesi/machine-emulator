#ifndef CLINT_H
#define CLINT_H

/// \file
/// \brief Clock interruptor device.

#include <cstdint>

#include "i-device-state-access.h"

/// \brief CLINT device read callback. See ::pma_device_read.
bool clint_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *val, int size_log2);

/// \brief CLINT device read callback. See ::pma_device_write.
bool clint_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2);

#endif
