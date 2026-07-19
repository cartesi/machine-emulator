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

#ifndef HEX_HPP
#define HEX_HPP

#include <cstddef>
#include <cstdint>
#include <ranges>
#include <stdexcept>
#include <string>

#include "concepts.hpp"

namespace cartesi {

namespace detail {

void hexencode(uint8_t c, char *output);
uint8_t hexdecode(uint8_t hi, uint8_t lo);

} // namespace detail

/// \brief Encodes binary data into lowercase, 0x-prefixed hexadecimal
/// \param data Input data range
/// \returns String with encoded data
template <ContiguousRangeOfByteLike R>
std::string encode_hex(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    const auto size = static_cast<size_t>(std::ranges::distance(data));
    std::string output(2 + (2 * size), '\0');
    output[0] = '0';
    output[1] = 'x';
    size_t offset = 2;
    for (auto b : data) {
        detail::hexencode(static_cast<uint8_t>(b), output.data() + offset);
        offset += 2;
    }
    return output;
}

/// \brief Decodes binary data from 0x-prefixed hexadecimal
/// \param data Input data range
/// \returns String with decoded data
template <ContiguousRangeOfByteLike R>
std::string decode_hex(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    const auto size = static_cast<size_t>(std::ranges::distance(data));
    auto it = std::ranges::begin(data);
    if (size < 2 || static_cast<uint8_t>(*it++) != '0') {
        throw std::domain_error{"hex string must start with 0x"};
    }
    const auto prefix = static_cast<uint8_t>(*it++);
    if (prefix != 'x' && prefix != 'X') {
        throw std::domain_error{"hex string must start with 0x"};
    }
    if (size % 2 != 0) {
        throw std::domain_error{"hex string length must be even"};
    }
    std::string output((size - 2) / 2, '\0');
    for (auto &b : output) {
        const auto hi = static_cast<uint8_t>(*it++);
        const auto lo = static_cast<uint8_t>(*it++);
        b = static_cast<char>(detail::hexdecode(hi, lo));
    }
    return output;
}

} // namespace cartesi

#endif
