// Copyright 2022 Cartesi Pte. Ltd.
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

#ifndef SHADOW_TLB_FACTORY_H
#define SHADOW_TLB_FACTORY_H

/// \file
/// \brief TLB device factory.

#include "pma.h"
#include "shadow-tlb.h"

namespace cartesi {

/// \brief Creates a PMA entry for the TLB device
/// \param start Start address for memory range.
/// \param length Length of memory range.
/// \returns Corresponding PMA entry
pma_entry make_shadow_tlb_pma_entry(uint64_t start, uint64_t length);

} // namespace cartesi

#endif
