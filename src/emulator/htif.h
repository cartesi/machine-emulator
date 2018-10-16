#ifndef HTIF_H
#define HTIF_H

#include <cstdint>

#include "i-device-state-access.h"
#include "machine.h"

typedef struct htif_state htif_state;

bool htif_read(i_device_state_access *a, void *context, uint64_t offset, uint64_t *pval, int size_log2);
bool htif_write(i_device_state_access *a, void *context, uint64_t offset, uint64_t val, int size_log2);

htif_state *htif_init(machine_state *s, bool interactive);
void htif_end(htif_state *htif);
void htif_interact(htif_state *htif);

#endif
