// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef I_HASHER_H
#define I_HASHER_H

/// \file
/// \brief Hasher interface

#include <cstdint>
#include <array>

namespace cartesi {

/// \brief Hasher interface.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \tparam HASH_SIZE Size of hash.
template <typename DERIVED, int HASH_SIZE> class i_hasher { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived(void) {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived(void) const {
        return *static_cast<const DERIVED *>(this);
    }

public:

    constexpr static size_t hash_size = HASH_SIZE;

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

} // namespace cartesi

#endif
