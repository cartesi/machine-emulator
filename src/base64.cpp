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

#include "base64.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>

namespace cartesi {

static constexpr char base64_digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static constexpr auto make_base64_values() {
    std::array<uint8_t, 256> values{};
    values.fill(255);
    for (uint8_t i = 0; i < 26; ++i) {
        values[static_cast<size_t>('A') + i] = i;
        values[static_cast<size_t>('a') + i] = i + 26;
    }
    for (uint8_t i = 0; i < 10; ++i) {
        values[static_cast<size_t>('0') + i] = i + 52;
    }
    values[static_cast<size_t>('+')] = 62;
    values[static_cast<size_t>('/')] = 63;
    return values;
}

static constexpr auto base64_values = make_base64_values();

static constexpr bool is_base64_whitespace(uint8_t character) {
    return character == ' ' || character == '\t' || character == '\n' || character == '\v' || character == '\f' ||
        character == '\r';
}

static uint8_t decode_base64_digit(uint8_t character) {
    if (character == '=') {
        return 64;
    }
    const auto value = base64_values[character];
    if (value > 63) {
        throw std::domain_error{"invalid base64 character code " + std::to_string(character)};
    }
    return value;
}

static size_t decode_base64_quartet(const std::array<uint8_t, 4> &quartet, std::span<std::byte> output) {
    if (quartet[0] == 64 || quartet[1] == 64) {
        throw std::domain_error{"invalid base64 padding"};
    }

    size_t decoded_size = 3;
    if (quartet[2] == 64) {
        if (quartet[3] != 64) {
            throw std::domain_error{"invalid base64 padding"};
        }
        if ((quartet[1] & 0x0f) != 0) {
            throw std::domain_error{"non-zero base64 padding bits"};
        }
        decoded_size = 1;
    } else if (quartet[3] == 64) {
        if ((quartet[2] & 0x03) != 0) {
            throw std::domain_error{"non-zero base64 padding bits"};
        }
        decoded_size = 2;
    }
    if (output.size() < decoded_size) {
        throw std::invalid_argument{"invalid base64 output size"};
    }

    output[0] = static_cast<std::byte>((quartet[0] << 2) | (quartet[1] >> 4));
    if (decoded_size > 1) {
        output[1] = static_cast<std::byte>(((quartet[1] & 0x0f) << 4) | (quartet[2] >> 2));
    }
    if (decoded_size > 2) {
        output[2] = static_cast<std::byte>(((quartet[2] & 0x03) << 6) | quartet[3]);
    }
    return decoded_size;
}

size_t encoded_base64_size(size_t input_size) {
    const size_t groups = input_size / 3;
    const size_t tail_size = input_size % 3 == 0 ? 0 : 4;
    if (groups > (std::numeric_limits<size_t>::max() - tail_size) / 4) {
        throw std::length_error{"base64 input is too large"};
    }
    return (4 * groups) + tail_size;
}

void encode_base64_digits(std::span<const std::byte> input, std::span<char> output) {
    if (output.size() != encoded_base64_size(input.size())) {
        throw std::invalid_argument{"invalid base64 output size"};
    }

    while (input.size() >= 3) {
        const auto first = std::to_integer<uint8_t>(input[0]);
        const auto second = std::to_integer<uint8_t>(input[1]);
        const auto third = std::to_integer<uint8_t>(input[2]);
        output[0] = base64_digits[first >> 2];
        output[1] = base64_digits[((first & 0x03) << 4) | (second >> 4)];
        output[2] = base64_digits[((second & 0x0f) << 2) | (third >> 6)];
        output[3] = base64_digits[third & 0x3f];
        input = input.subspan(3);
        output = output.subspan(4);
    }

    if (input.size() == 1) {
        const auto first = std::to_integer<uint8_t>(input[0]);
        output[0] = base64_digits[first >> 2];
        output[1] = base64_digits[(first & 0x03) << 4];
        output[2] = '=';
        output[3] = '=';
    } else if (input.size() == 2) {
        const auto first = std::to_integer<uint8_t>(input[0]);
        const auto second = std::to_integer<uint8_t>(input[1]);
        output[0] = base64_digits[first >> 2];
        output[1] = base64_digits[((first & 0x03) << 4) | (second >> 4)];
        output[2] = base64_digits[(second & 0x0f) << 2];
        output[3] = '=';
    }
}

size_t decode_base64_digits(std::span<const std::byte> input, std::span<std::byte> output) {
    std::array<uint8_t, 4> quartet{};
    size_t quartet_size = 0;
    size_t output_size = 0;
    bool padded = false;
    for (const auto input_byte : input) {
        const auto character = std::to_integer<uint8_t>(input_byte);
        if (is_base64_whitespace(character)) {
            continue;
        }
        if (padded) {
            throw std::domain_error{"base64 padding must appear only at the end"};
        }
        quartet[quartet_size++] = decode_base64_digit(character);
        if (quartet_size != quartet.size()) {
            continue;
        }

        const auto decoded_size = decode_base64_quartet(quartet, output);
        output_size += decoded_size;
        output = output.subspan(decoded_size);
        padded = decoded_size != 3;
        quartet_size = 0;
    }
    if (quartet_size != 0) {
        throw std::domain_error{"base64 string length must be a multiple of 4"};
    }
    return output_size;
}

} // namespace cartesi
