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

#ifndef BASE64_HPP
#define BASE64_HPP

#include <cstddef>
#include <ranges>
#include <span>
#include <string>

#include "concepts.hpp"

namespace cartesi {

/// \brief Returns the encoded size for a binary input
/// \param input_size Input size in bytes
/// \returns Base64 output size
size_t encoded_base64_size(size_t input_size);

/// \brief Encodes binary input into Base64
/// \param input Input bytes
/// \param output Output buffer with encoded_base64_size(input.size()) bytes
void encode_base64_digits(std::span<const std::byte> input, std::span<char> output);

/// \brief Decodes canonical Base64, ignoring ASCII whitespace
/// \param input Base64 input
/// \param output Output buffer large enough for the decoded bytes
/// \returns Number of decoded bytes written
size_t decode_base64_digits(std::span<const std::byte> input, std::span<std::byte> output);

/// \brief Encodes binary data into base64
/// \param data Input data range
/// \returns String with encoded data
template <ContiguousRangeOfByteLike R>
std::string encode_base64(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    const auto size = static_cast<size_t>(std::ranges::distance(data));
    const auto input = std::span{std::ranges::data(data), size};
    const auto input_bytes = std::as_bytes(input);
    const auto output_size = encoded_base64_size(size);
    std::string output;
    output.resize_and_overwrite(output_size, [&](char *buffer, size_t) {
        encode_base64_digits(input_bytes, {buffer, output_size});
        return output_size;
    });
    return output;
}

/// \brief Decodes binary data from base64
/// \param data Input data range
/// \returns String with decoded data
template <ContiguousRangeOfByteLike R>
std::string decode_base64(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    const auto size = static_cast<size_t>(std::ranges::distance(data));
    const auto input = std::span{std::ranges::data(data), size};
    const auto input_bytes = std::as_bytes(input);
    std::string output;
    output.resize_and_overwrite(3 * (size / 4), [&](char *buffer, size_t buffer_size) {
        const auto output_bytes = std::as_writable_bytes(std::span{buffer, buffer_size});
        return decode_base64_digits(input_bytes, output_bytes);
    });
    return output;
}

} // namespace cartesi

#endif
