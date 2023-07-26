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

#ifndef I_HASHER_H
#define I_HASHER_H

/// \file
/// \brief Hasher interface

#include <array>
#include <cstddef>
#include <cstdint>

#include "meta.h"

namespace cartesi {

/// \brief Hasher interface.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \tparam HASH_SIZE Size of hash.
template <typename DERIVED, typename HASH_SIZE>
class i_hasher { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    constexpr static size_t hash_size = HASH_SIZE::value;

    using hash_type = std::array<unsigned char, hash_size>;

    void begin(void) {
        return derived().do_begin();
    }

    void add_data(const unsigned char *data, size_t length) {
        return derived().do_add_data(data, length);
    }

    void end(hash_type &hash) {
        return derived().do_end(hash);
    }
};

template <typename DERIVED>
using is_an_i_hasher =
    std::integral_constant<bool, is_template_base_of<i_hasher, typename remove_cvref<DERIVED>::type>::value>;

/// \brief Computes the hash of concatenated hashes
/// \tparam H Hasher class
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \param result Receives the hash of the concatenation
template <typename H>
inline static void get_concat_hash(H &h, const typename H::hash_type &left, const typename H::hash_type &right,
    typename H::hash_type &result) {
    static_assert(is_an_i_hasher<H>::value, "not an i_hasher");
    h.begin();
    h.add_data(left.data(), static_cast<int>(left.size()));
    h.add_data(right.data(), static_cast<int>(right.size()));
    h.end(result);
}

/// \brief Computes the hash of concatenated hashes
/// \tparam H Hasher class
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \return The hash of the concatenation
template <typename H>
inline static typename H::hash_type get_concat_hash(H &h, const typename H::hash_type &left,
    const typename H::hash_type &right) {
    static_assert(is_an_i_hasher<H>::value, "not an i_hasher");
    h.begin();
    h.add_data(left.data(), left.size());
    h.add_data(right.data(), right.size());
    typename H::hash_type result;
    h.end(result);
    return result;
}

} // namespace cartesi

#endif
