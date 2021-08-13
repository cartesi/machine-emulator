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

#ifndef DHD_SOURCE_H
#define DHD_SOURCE_H

#include <memory>

#include "i-dhd-source.h"

/// \file
/// \brief DHD source implementation.

namespace cartesi {

/// \brief Returns a dehash device source from an address
/// \param address The address of the source
/// \returns Requested source, or nullptr if failed
i_dhd_source_ptr make_dhd_source(const std::string &address);

} // namespace cartesi

#endif
