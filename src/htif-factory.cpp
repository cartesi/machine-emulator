// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include "htif-factory.h"
#include "device-driver.h"
#include "machine.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \brief HTIF device peek callback. See ::pma_peek.
static bool htif_peek(const pma_entry &pma, const machine &m, uint64_t page_offset, const unsigned char **page_data,
    unsigned char *scratch) {
    // Check for alignment and range
    if (page_offset % PMA_PAGE_SIZE != 0 || page_offset >= pma.get_length()) {
        *page_data = nullptr;
        return false;
    }
    // Page 0 is the only non-pristine page
    if (page_offset != 0) {
        *page_data = nullptr;
        return true;
    }
    // Clear entire page.
    memset(scratch, 0, PMA_PAGE_SIZE);
    // Copy tohost and fromhost to their places within page.
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::tohost), m.read_htif_tohost());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::fromhost), m.read_htif_fromhost());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::ihalt), m.read_htif_ihalt());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::iconsole), m.read_htif_iconsole());
    aliased_aligned_write<uint64_t>(scratch + htif::get_csr_rel_addr(htif::csr::iyield), m.read_htif_iyield());
    *page_data = scratch;
    return true;
}

pma_entry make_htif_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                // R
        true,                // W
        false,               // X
        false,               // IR
        false,               // IW
        PMA_ISTART_DID::HTIF // DID
    };
    return make_device_pma_entry(start, length, htif_peek, &htif_driver).set_flags(f);
}

pma_entry make_htif_pma_entry(htif &h, uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                // R
        true,                // W
        false,               // X
        false,               // IR
        false,               // IW
        PMA_ISTART_DID::HTIF // DID
    };
    return make_device_pma_entry(start, length, htif_peek, &htif_driver, &h).set_flags(f);
}

} // namespace cartesi
