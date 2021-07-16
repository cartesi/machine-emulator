// Copyright 2020 Cartesi Pte. Ltd.
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

#include <cinttypes>
#include <cstring>

#include "machine.h"
#include "machine-config.h"
#include "dhd.h"
#include "i-device-state-access.h"
#include "strict-aliasing.h"

namespace cartesi {

static constexpr auto dhd_tstart_rel_addr = static_cast<uint64_t>(dhd_csr::tstart);
static constexpr auto dhd_tlength_rel_addr = static_cast<uint64_t>(dhd_csr::tlength);
static constexpr auto dhd_dlength_rel_addr = static_cast<uint64_t>(dhd_csr::dlength);
static constexpr auto dhd_hlength_rel_addr = static_cast<uint64_t>(dhd_csr::hlength);
static constexpr auto dhd_h0_rel_addr = static_cast<uint64_t>(dhd_csr::h0);

uint64_t dhd_get_csr_rel_addr(dhd_csr reg) {
    return static_cast<uint64_t>(reg);
}

uint64_t dhd_get_h_rel_addr(int i) {
    return static_cast<uint64_t>(dhd_csr::h0) + i*sizeof(uint64_t);
}

/// \brief DHD read callback. See ::pma_read.
static bool dhd_read(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t *val, int log2_size) {
    (void) pma;

    if (log2_size != 3) {
        return false;
    }

    switch (offset) {
        case dhd_tstart_rel_addr:
            *val = a->read_dhd_tstart();
            return true;
        case dhd_tlength_rel_addr:
            *val = a->read_dhd_tlength();
            return true;
        case dhd_dlength_rel_addr:
            *val = a->read_dhd_dlength();
            return true;
        case dhd_hlength_rel_addr:
            *val = a->read_dhd_hlength();
            return true;
        default:
            if (offset >= dhd_h0_rel_addr &&
                offset < dhd_h0_rel_addr+DHD_H_REG_COUNT*sizeof(uint64_t)
                && (offset & (sizeof(uint64_t)-1)) == 0) {
                auto i = (offset - dhd_h0_rel_addr)/sizeof(uint64_t);
                *val = a->read_dhd_h(i);
                return true;
            }
            // other reads are exceptions
            return false;
    }
}

// The return value is undefined if v == 0
// This works on gcc and clang and uses the lzcnt instruction
static inline uint64_t ilog2(uint64_t v) {
    return 63 - __builtin_clzl(v);
}

static bool dhd_write_hlength(const pma_entry &pma, i_device_state_access *a,
    uint64_t hlength) {
    (void) pma;

    std::array<uint8_t, DHD_H_REG_COUNT*sizeof(uint64_t)> hash;
    // write requested hlength value
    a->write_dhd_hlength(hlength);
    // get h registers into char buffer to build hash
    for (int i = 0; i < DHD_H_REG_COUNT; i++) {
        aliased_aligned_write<uint64_t>(hash.data()+i*sizeof(uint64_t), a->read_dhd_h(i));
    }
    // get target physical memory range for output data
    uint64_t tstart = a->read_dhd_tstart();
    uint64_t tlength = a->read_dhd_tlength();
    assert((tlength & (tlength-1)) == 0); // length must be power of 2
    if ((tlength & (tlength-1)) != 0) {
        throw std::runtime_error{"dhd tlength must be power of 2"};
    }
    // get requested maximum data length
    uint64_t req_dlength = a->read_dhd_dlength();
    // of course, must fit in target range
    req_dlength = std::min(req_dlength, tlength);
    // obtain data from dhd source
    auto dlength = req_dlength;
    auto data = a->dehash(hash.data(), hlength, dlength);
    assert((dlength == DHD_NOT_FOUND && data.empty()) ||
        (data.size() == dlength && dlength <= req_dlength));
    if (!(dlength == DHD_NOT_FOUND && data.empty()) &&
        !(data.size() == dlength && dlength <= req_dlength)) {
        throw std::runtime_error{"dhd source is buggy"};
    }
    a->write_dhd_dlength(dlength);
    // DHD_NOT_FOUND (-1) in dlength means no data was found with given hash
    if (dlength != DHD_NOT_FOUND) {
        // round dlength to the next power of 2 no less than 2^3
        uint64_t nlength = std::max(dlength, UINT64_C(8));
        uint64_t nlog2 = ilog2(nlength);
        if ((nlength & (nlength-1)) != 0) { // Not power of 2?
            ++nlog2;
            nlength = UINT64_C(1) << nlog2;
        }
        // pad data with zeros to that power of 2
        data.resize(nlength, 0);
        // write to target range
        a->write_memory(tstart, data.data(), nlog2);
    }
    return true;
}

/// \brief DHD device read callback. See ::pma_write.
static bool dhd_write(const pma_entry &pma, i_device_state_access *a, uint64_t offset, uint64_t val, int log2_size) {

    if (log2_size != 3) {
        return false;
    }

    switch (offset) {
        case dhd_dlength_rel_addr:
            a->write_dhd_dlength(val);
            return true;
        case dhd_hlength_rel_addr:
            return dhd_write_hlength(pma, a, val);
        default:
            if (offset >= dhd_h0_rel_addr &&
                offset < dhd_h0_rel_addr+DHD_H_REG_COUNT*sizeof(uint64_t)
                && (offset & (sizeof(uint64_t)-1)) == 0) {
                auto i = (offset - dhd_h0_rel_addr)/sizeof(uint64_t);
                a->write_dhd_h(i, val);
                return true;
            }
            // other writes are exceptions
            return false;
    }
}

/// \brief DHD device peek callback. See ::pma_peek.
static bool dhd_peek(const pma_entry &pma, const machine &m,
    uint64_t page_offset, const unsigned char **page_data,
    unsigned char *scratch) {
    (void) pma;
    // There is only one page: 0
    if (page_offset != 0) {
        *page_data = nullptr;
        return false;
    }
    // Clear page
    memset(scratch, 0, PMA_PAGE_SIZE);
    // Copy all registers
    aliased_aligned_write<uint64_t>(scratch +
        dhd_get_csr_rel_addr(dhd_csr::tstart),
        m.read_dhd_tstart());
    aliased_aligned_write<uint64_t>(scratch +
        dhd_get_csr_rel_addr(dhd_csr::tlength),
        m.read_dhd_tlength());
    aliased_aligned_write<uint64_t>(scratch +
        dhd_get_csr_rel_addr(dhd_csr::dlength),
        m.read_dhd_dlength());
    aliased_aligned_write<uint64_t>(scratch +
        dhd_get_csr_rel_addr(dhd_csr::hlength),
        m.read_dhd_hlength());
    for (int i = 0; i < DHD_H_REG_COUNT; i++) {
        aliased_aligned_write<uint64_t>(scratch +
            dhd_get_h_rel_addr(i),
            m.read_dhd_h(i));
    }
    *page_data = scratch;
    return true;
}

static const pma_driver dhd_driver = {
    "DHD",
    dhd_read,
    dhd_write
};

pma_entry make_dhd_pma_entry(uint64_t start, uint64_t length) {
    pma_entry::flags f{
        true,                   // R
        true,                   // W
        false,                  // X
        false,                  // IR
        false,                  // IW
        PMA_ISTART_DID::DHD     // DID
    };
    return make_device_pma_entry(start, length, dhd_peek, &dhd_driver).
        set_flags(f);
}

} // namespace cartesi
