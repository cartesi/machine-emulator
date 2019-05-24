#ifndef PMA_EXT_H
#define PMA_EXT_H

#include <cstdint>

#include "pma-defines.h"

#define PMA_EXT_VERSION 		1
#define PMA_EXT_BOOTARGS_SIZE		2048

struct pma {
    uint64_t istart;
    uint64_t ilength;
};

struct pma_ext_hdr {
    uint64_t version;
    char bootargs[PMA_EXT_BOOTARGS_SIZE];
};

#endif /* PMA_EXT_H */
