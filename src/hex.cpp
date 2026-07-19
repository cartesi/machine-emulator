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

#include <array>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>

namespace cartesi {

static constexpr char hex_digits[] = "0123456789abcdef";

static constexpr auto make_hex_values() {
    std::array<uint8_t, 256> values{};
    values.fill(255);
    for (uint8_t i = 0; i < 10; ++i) {
        values[static_cast<size_t>('0') + i] = i;
    }
    for (uint8_t i = 0; i < 6; ++i) {
        values[static_cast<size_t>('a') + i] = i + 10;
        values[static_cast<size_t>('A') + i] = i + 10;
    }
    return values;
}

static constexpr auto hex_values = make_hex_values();

void encode_hex_digits(std::span<const std::byte> input, std::span<char> output) {
    if (input.size() > std::numeric_limits<size_t>::max() / 2 || output.size() != 2 * input.size()) {
        throw std::invalid_argument{"hex output size must be twice input size"};
    }
    for (const auto input_byte : input) {
        const auto byte = std::to_integer<uint8_t>(input_byte);
        output[0] = hex_digits[byte >> 4];
        output[1] = hex_digits[byte & 0x0f];
        output = output.subspan(2);
    }
}

void decode_hex_digits(std::span<const std::byte> input, std::span<std::byte> output) {
    if (input.size() % 2 != 0) {
        throw std::invalid_argument{"hex input size must be even"};
    }
    if (output.size() != input.size() / 2) {
        throw std::invalid_argument{"hex output size must be half input size"};
    }
    for (auto &byte : output) {
        const auto hi_char = std::to_integer<uint8_t>(input[0]);
        const auto lo_char = std::to_integer<uint8_t>(input[1]);
        const auto hi = hex_values[hi_char];
        const auto lo = hex_values[lo_char];
        if (hi > 15) {
            throw std::domain_error{"invalid hex character code " + std::to_string(hi_char)};
        }
        if (lo > 15) {
            throw std::domain_error{"invalid hex character code " + std::to_string(lo_char)};
        }
        byte = static_cast<std::byte>((hi << 4) | lo);
        input = input.subspan(2);
    }
}

} // namespace cartesi
