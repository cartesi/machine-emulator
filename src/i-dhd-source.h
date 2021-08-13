// Copyright 2020 Cartesi Pte. Ltd.
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

#ifndef I_DHD_SOURCE_H
#define I_DHD_SOURCE_H

#include <cstdint>
#include <memory>

#include "dhd.h"

/// \file
/// \brief Dehash source interface.

namespace cartesi {

/// \brief Dehash source interface
class i_dhd_source {
public:
    /// \brief Default constructor
    i_dhd_source() = default;

    /// \brief Virtual destructor
    virtual ~i_dhd_source() = default;

    i_dhd_source(const i_dhd_source &other) = delete;
    i_dhd_source(i_dhd_source &&other) noexcept = delete;
    i_dhd_source &operator=(const i_dhd_source &other) = delete;
    i_dhd_source &operator=(i_dhd_source &&other) noexcept = delete;

    /// \brief Obtains the block of data that has a given hash
    /// \param hash Pointer to buffer containing hash
    /// \param hlength Length  of hash in bytes
    /// \param dlength Maximum length of desired block of data with that hash.
    /// On return, contains the actual length of the block found. Or
    /// DHD_NOT_FOUND if no matching block was found.
    /// \returns The block of data with the given hash, or an empty block
    /// if not found
    dhd_data dehash(const unsigned char *hash, uint64_t hlength, uint64_t &dlength) {
        return do_dehash(hash, hlength, dlength);
    }

protected:
    virtual dhd_data do_dehash(const unsigned char *hash, uint64_t hlength, uint64_t &dlength) = 0;
};

using i_dhd_source_ptr = std::shared_ptr<i_dhd_source>;

} // namespace cartesi

#endif
