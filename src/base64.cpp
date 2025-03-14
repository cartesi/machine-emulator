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

#include "base64.h"

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>

namespace cartesi::detail {

// Base64 globals
static constexpr uint8_t b64base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static constexpr uint8_t b64unbase[] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 62, 255, 255, 255, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 255, 255, 255, 0, 255, 255, 255,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 255, 255, 255, 255,
    255, 255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255};

// Accumulates bytes in input buffer until 3 bytes are available.
// Translate the 3 bytes into Base64 form and append to buffer.
// Returns new number of bytes in buffer.
size_t b64encode(uint8_t c, uint8_t *input, size_t size, std::ostringstream &sout) {
    input[size++] = c;
    if (size == 3) {
        uint8_t code[4];
        uint64_t value = 0;
        value += input[0];
        value <<= 8;
        value += input[1];
        value <<= 8;
        value += input[2];
        code[3] = b64base[value & 0x3f];
        value >>= 6;
        code[2] = b64base[value & 0x3f];
        value >>= 6;
        code[1] = b64base[value & 0x3f];
        value >>= 6;
        code[0] = b64base[value];
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        sout << std::string_view(reinterpret_cast<char *>(code), 4);
        size = 0;
    }
    return size;
}

// Encodes the Base64 last 1 or 2 bytes and adds padding '='
// Result, if any, is appended to buffer.
// Returns 0.
size_t b64pad(const uint8_t *input, size_t size, std::ostringstream &sout) {
    uint64_t value = 0;
    uint8_t code[4] = {'=', '=', '=', '='};
    switch (size) {
        case 1:
            value = input[0] << 4;
            code[1] = b64base[value & 0x3f];
            value >>= 6;
            code[0] = b64base[value];
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            sout << std::string_view(reinterpret_cast<char *>(code), 4);
            break;
        case 2:
            value = input[0];
            value <<= 8;
            value |= input[1];
            value <<= 2;
            code[2] = b64base[value & 0x3f];
            value >>= 6;
            code[1] = b64base[value & 0x3f];
            value >>= 6;
            code[0] = b64base[value];
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            sout << std::string_view(reinterpret_cast<char *>(code), 4);
            break;
        default:
            break;
    }
    return 0;
}

// Accumulates bytes in input buffer until 4 bytes are available.
// Translate the 4 bytes from Base64 form and append to buffer.
// Returns new number of bytes in buffer.
size_t b64decode(uint8_t c, uint8_t *input, size_t size, std::ostringstream &sout) {
    if (b64unbase[c] > 64) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r') { // ignore whitespace characters
            return size;
        } // throw an error for invalid characters
        throw std::domain_error(std::string("invalid base64 character code ") + std::to_string(c));
    }
    input[size++] = c;
    // decode atom
    if (size == 4) {
        uint8_t decoded[3];
        int valid = 0;
        int value = 0;
        value = b64unbase[input[0]];
        value <<= 6;
        value |= b64unbase[input[1]];
        value <<= 6;
        value |= b64unbase[input[2]];
        value <<= 6;
        value |= b64unbase[input[3]];
        decoded[2] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
        decoded[1] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
        decoded[0] = static_cast<uint8_t>(value);
        // take care of padding
        if (input[2] == '=') {
            valid = 1;
        } else if (input[3] == '=') {
            valid = 2;
        } else {
            valid = 3;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        sout << std::string_view(reinterpret_cast<char *>(decoded), valid);
        return 0;
        // need more data
    }
    return size;
}

} // namespace cartesi::detail
