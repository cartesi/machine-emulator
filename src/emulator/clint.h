#ifndef CLINT_H
#define CLINT_H

#include <cstdint>

#include "i-device-state-access.h"

bool clint_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *val, int size_log2);
bool clint_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2);

#endif
