// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <stdexcept>

#include "assert-printf.hpp"
#include "mock-address-range.hpp"
#include "uarch-address-range.hpp"

using namespace cartesi;

namespace {

uint64_t cases = 0;
uint64_t accepted = 0;
uint64_t containment_checks = 0;
uint64_t random_state = UINT64_C(0x6217acd3347871);

uint64_t random_word() {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

void require(bool condition) {
    if (!condition) {
        throw std::logic_error("compact PMA differs from mock factory");
    }
}

void compare(uint64_t istart, uint64_t length) {
    const auto abrt = [](const char *message) { throw std::runtime_error(message); };
    mock_address_range reference;
    uarch_address_range compact;
    bool reference_accepted = false;
    bool compact_accepted = false;
    try {
        reference = make_mock_address_range(istart, length, abrt);
        reference_accepted = true;
    } catch (const std::runtime_error &) {
    }
    try {
        compact.initialize(istart, length, abrt);
        compact_accepted = true;
    } catch (const std::runtime_error &) {
    }
    require(reference_accepted == compact_accepted);
    require(compact.is_initialized() == compact_accepted);
    ++cases;
    if (!reference_accepted) {
        return;
    }
    ++accepted;
    const auto &ar = get_mock_address_range(reference, abrt);
    require(ar.get_start() == compact.get_start());
    require(ar.get_length() == compact.get_length());
    require(ar.get_driver_id() == compact.get_driver_id());
    require(ar.is_empty() == compact.is_empty());
    require(ar.is_memory() == compact.is_memory());
    require(ar.is_device() == compact.is_device());
    require(ar.is_readable() == compact.is_readable());
    require(ar.is_writeable() == compact.is_writeable());
    require(ar.is_executable() == compact.is_executable());
    for (uint64_t size :
        {UINT64_C(0), UINT64_C(1), UINT64_C(2), UINT64_C(4), UINT64_C(8), UINT64_C(4096), UINT64_C(4097), UINT64_MAX}) {
        for (uint64_t address : {UINT64_C(0), ar.get_start() - 1, ar.get_start(), ar.get_end() - 1, ar.get_end(),
                 UINT64_MAX, random_word()}) {
            require(ar.contains_absolute(address, size) == compact.contains_absolute(address, size));
            ++containment_checks;
        }
    }
    // A cache hit must ignore even malformed newly read metadata.
    compact.initialize(UINT64_MAX, UINT64_MAX, abrt);
    require(compact.get_start() == ar.get_start() && compact.get_length() == length);
    require(compact.get_driver_id() == ar.get_driver_id());
    if (ar.is_memory() || ar.is_empty()) {
        uint64_t value = 0;
        require(!compact.read_device(nullptr, 0, 3, &value));
        require(compact.write_device(nullptr, 0, 3, 0) == execute_status::failure);
    }
}

} // namespace

int main() {
    // Every flag combination, including unknown DIDs and M+IO, at range boundaries.
    for (uint64_t flags = 0; flags < 4096; ++flags) {
        for (uint64_t start : {UINT64_C(0), UINT64_C(0x80000000), UINT64_C(0xfffffffffffff000)}) {
            for (uint64_t length : {UINT64_C(0), UINT64_C(1), UINT64_C(4096), UINT64_C(8192), UINT64_MAX}) {
                compare(start | flags, length);
            }
        }
    }
    const auto abrt = [](const char *message) { throw std::runtime_error(message); };
    clint_address_range clint(abrt);
    htif_address_range htif(abrt);
    plic_address_range plic(abrt);
    for (const address_range *ar : {static_cast<address_range *>(&clint), static_cast<address_range *>(&htif),
             static_cast<address_range *>(&plic)}) {
        compare(ar->get_istart(), ar->get_length());
        for (unsigned bit = 0; bit < 64; ++bit) {
            compare(ar->get_istart() ^ (UINT64_C(1) << bit), ar->get_length());
            compare(ar->get_istart(), ar->get_length() ^ (UINT64_C(1) << bit));
        }
    }
    for (unsigned i = 0; i < 50000; ++i) {
        const uint64_t istart = random_word();
        uint64_t length = random_word();
        if (i % 2 != 0) {
            length &= PMA_ISTART_START_MASK;
        }
        compare(istart, length);
    }
    std::printf("%llu PMA descriptors matched (%llu accepted); %llu containment checks passed\n",
        static_cast<unsigned long long>(cases), static_cast<unsigned long long>(accepted),
        static_cast<unsigned long long>(containment_checks));
}
