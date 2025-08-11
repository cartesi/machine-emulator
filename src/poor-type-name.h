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

#ifndef POOR_TYPE_NAME_H
#define POOR_TYPE_NAME_H

#include <cstdint>

namespace cartesi {

//?DD Poor man's rtti that works in microarchitecture
template <typename T>
struct poor_type_name {
    static constexpr const char *value = "unknown";
};

template <typename T>
constexpr const char *poor_type_name_v = poor_type_name<T>::value;

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define POOR_TYPE_NAME(type)                                                                                           \
    template <>                                                                                                        \
    struct poor_type_name<type> {                                                                                      \
        static constexpr const char *value = #type;                                                                    \
    }

POOR_TYPE_NAME(uint8_t);
POOR_TYPE_NAME(int8_t);
POOR_TYPE_NAME(uint16_t);
POOR_TYPE_NAME(int16_t);
POOR_TYPE_NAME(uint32_t);
POOR_TYPE_NAME(int32_t);
POOR_TYPE_NAME(uint64_t);
POOR_TYPE_NAME(int64_t);
// NOLINTEND(cppcoreguidelines-macro-usage)

} // namespace cartesi

#endif
