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

#ifndef BASE64_H
#define BASE64_H

#include <cstdint>
#include <sstream>
#include <string>

#include "concepts.h"

namespace cartesi {

namespace detail {

size_t b64encode(uint8_t c, uint8_t *input, size_t size, std::ostringstream &sout);
size_t b64pad(const uint8_t *input, size_t size, std::ostringstream &sout);
size_t b64decode(uint8_t c, uint8_t *input, size_t size, std::ostringstream &sout);

} // namespace detail

/// \brief Encodes binary data into base64
/// \param data Input data range
/// \returns String with encoded data
template <ContiguousRangeOfByteLike R>
std::string encode_base64(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    //??D we could make this faster by avoiding ostringstream altogether...
    std::ostringstream sout;
    uint8_t ctx[4]{};
    size_t ctxlen = 0;
    for (auto b : data) {
        ctxlen = detail::b64encode(static_cast<uint8_t>(b), ctx, ctxlen, sout);
    }
    detail::b64pad(ctx, ctxlen, sout);
    return sout.str();
}

/// \brief Decodes binary data from base64
/// \param data Input data range
/// \returns String with decoded data
template <ContiguousRangeOfByteLike R>
std::string decode_base64(R &&data) { // NOLINT(cppcoreguidelines-missing-std-forward)
    std::ostringstream sout;
    uint8_t ctx[4]{};
    size_t ctxlen = 0;
    for (auto b : data) {
        ctxlen = detail::b64decode(static_cast<uint8_t>(b), ctx, ctxlen, sout);
    }
    return sout.str();
}

} // namespace cartesi

#endif
