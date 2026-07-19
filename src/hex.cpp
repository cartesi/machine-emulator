// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.

#include "hex.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace cartesi::detail {

static constexpr char hex_digits[] = "0123456789abcdef";

void hexencode(uint8_t c, char *output) {
    output[0] = hex_digits[c >> 4];
    output[1] = hex_digits[c & 0x0f];
}

static uint8_t hexnibble(uint8_t c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    throw std::domain_error{"invalid hex character code " + std::to_string(c)};
}

uint8_t hexdecode(uint8_t hi, uint8_t lo) {
    return static_cast<uint8_t>((hexnibble(hi) << 4) | hexnibble(lo));
}

} // namespace cartesi::detail
