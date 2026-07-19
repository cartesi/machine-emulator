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
#include <limits>
#include <ranges>
#include <span>
#include <stdexcept>
#include <string>

#include "concepts.hpp"

namespace cartesi {

/// \brief Encodes bytes into lowercase hexadecimal digits without a prefix
/// \param input Input bytes
/// \param output Output buffer, which must be exactly twice the input size
void encode_hex_digits(std::span<const std::byte> input, std::span<char> output);

/// \brief Decodes hexadecimal digits without a prefix into bytes
/// \param input Input digits, whose size must be even
/// \param output Output buffer, which must be exactly half the input size
void decode_hex_digits(std::span<const std::byte> input, std::span<std::byte> output);

/// \brief Encodes binary data into lowercase, 0x-prefixed hexadecimal
/// \param data Input data range
/// \returns String with encoded data
template <ContiguousRangeOfByteLike R>
std::string encode_hex(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    const auto size = static_cast<size_t>(std::ranges::distance(data));
    if (size > (std::numeric_limits<size_t>::max() - 2) / 2) {
        throw std::length_error{"hex input is too large"};
    }
    const auto input = std::span{std::ranges::data(data), size};
    const auto input_bytes = std::as_bytes(input);
    const auto output_size = 2 + (2 * size);
    std::string output;
    output.resize_and_overwrite(output_size, [&](char *buffer, size_t) {
        buffer[0] = '0';
        buffer[1] = 'x';
        encode_hex_digits(input_bytes, {buffer + 2, output_size - 2});
        return output_size;
    });
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
    const auto input = std::span{std::ranges::data(data), size};
    const auto input_bytes = std::as_bytes(input).subspan(2);
    const auto output_size = (size - 2) / 2;
    std::string output;
    output.resize_and_overwrite(output_size, [&](char *buffer, size_t) {
        auto output_bytes = std::as_writable_bytes(std::span{buffer, output_size});
        decode_hex_digits(input_bytes, output_bytes);
        return output_size;
    });
    return output;
}

} // namespace cartesi

#endif
