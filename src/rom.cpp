#include <stdexcept>
#include <cinttypes>

/// \file
/// \brief Bootstrap and device tree in ROM

#include "pma-ext.h"
#include "machine-config.h"

namespace cartesi {

void rom_init(const machine_config &c, unsigned char *rom_start, uint64_t length) {
    if (length < PMA_EXT_LENGTH_DEF)
        throw std::runtime_error{"Not enough space on ROM for PMA extension data"};

    struct pma_ext_hdr *hdr = (struct pma_ext_hdr *)(rom_start + length - PMA_EXT_LENGTH_DEF);
    hdr->version = PMA_EXT_VERSION;

    if (!c.rom.bootargs.empty()) {
        strncpy(hdr->bootargs, c.rom.bootargs.c_str(), PMA_EXT_BOOTARGS_SIZE);
        hdr->bootargs[PMA_EXT_BOOTARGS_SIZE - 1] = '\0';
    } else {
        memset(hdr->bootargs, 0, PMA_EXT_BOOTARGS_SIZE);
    }
}

} // namespace cartesi
