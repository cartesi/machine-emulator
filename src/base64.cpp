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

#include <sstream>

#ifndef BUFFERSIZE
// To fulfill libb64's assumption that the macro BUFFERSIZE is always defined. It is not.
// bug https://sourceforge.net/p/libb64/bugs/3/
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define BUFFERSIZE 1024
#endif

#include <b64/decode.h>

#include <b64/encode.h>

#include "base64.h"

namespace cartesi {

std::string encode_base64(const std::string &input) {
    std::istringstream sin(input);
    std::ostringstream sout;
    base64::encoder E; // NOLINT(clang-analyzer-optin.cplusplus.UninitializedObject)
    E.encode(sin, sout);
    return sout.str();
}

std::string decode_base64(const std::string &input) {
    std::istringstream sin(input);
    std::ostringstream sout;
    base64::decoder E; // NOLINT(clang-analyzer-optin.cplusplus.UninitializedObject)
    E.decode(sin, sout);
    return sout.str();
}

} // namespace cartesi
