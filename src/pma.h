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

#ifndef PMA_H
#define PMA_H

#include <cstdint>

#include "pma-constants.h"

namespace cartesi {

/// \file
/// \brief Physical memory attributes.

static constexpr const char *pma_get_DID_name(PMA_ISTART_DID did) {
    switch (did) {
        case PMA_ISTART_DID::memory:
            return "DID.memory";
        case PMA_ISTART_DID::shadow_state:
            return "DID.shadow_state";
        case PMA_ISTART_DID::shadow_pmas:
            return "DID.shadow_pmas";
        case PMA_ISTART_DID::shadow_TLB:
            return "DID.shadow_TLB";
        case PMA_ISTART_DID::flash_drive:
            return "DID.flash_drive";
        case PMA_ISTART_DID::CLINT:
            return "DID.CLINT";
        case PMA_ISTART_DID::PLIC:
            return "DID.PLIC";
        case PMA_ISTART_DID::HTIF:
            return "DID.HTIF";
        case PMA_ISTART_DID::VIRTIO:
            return "DID.VIRTIO";
        case PMA_ISTART_DID::cmio_rx_buffer:
            return "DID.cmio_rx_buffer";
        case PMA_ISTART_DID::cmio_tx_buffer:
            return "DID.cmio_tx_buffer";
        case PMA_ISTART_DID::shadow_uarch_state:
            return "DID.shadow_uarch";
        default:
            return "DID.unknown";
    }
}

///< Unpacked attribute flags
struct pma_flags {
    bool M;             ///< is memory
    bool IO;            ///< is device
    bool E;             ///< is empty
    bool R;             ///< is readable
    bool W;             ///< is writeable
    bool X;             ///< is executable
    bool IR;            ///< is read-idempotent
    bool IW;            ///< is write-idempotent
    PMA_ISTART_DID DID; ///< driver id

    // Defaulted comparison operator
    bool operator==(const pma_flags &) const = default;
};

static constexpr pma_flags unpack_pma_istart(uint64_t istart, uint64_t &start) {
    start = istart & PMA_ISTART_START_MASK;
    return pma_flags{.M = ((istart & PMA_ISTART_M_MASK) >> PMA_ISTART_M_SHIFT) != 0,
        .IO = ((istart & PMA_ISTART_IO_MASK) >> PMA_ISTART_IO_SHIFT) != 0,
        .E = ((istart & PMA_ISTART_E_MASK) >> PMA_ISTART_E_SHIFT) != 0,
        .R = ((istart & PMA_ISTART_R_MASK) >> PMA_ISTART_R_SHIFT) != 0,
        .W = ((istart & PMA_ISTART_W_MASK) >> PMA_ISTART_W_SHIFT) != 0,
        .X = ((istart & PMA_ISTART_X_MASK) >> PMA_ISTART_X_SHIFT) != 0,
        .IR = ((istart & PMA_ISTART_IR_MASK) >> PMA_ISTART_IR_SHIFT) != 0,
        .IW = ((istart & PMA_ISTART_IW_MASK) >> PMA_ISTART_IW_SHIFT) != 0,
        .DID = static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT)};
}

static constexpr uint64_t pack_pma_istart(const pma_flags &flags, uint64_t start) {
    uint64_t istart = start;
    istart |= (static_cast<uint64_t>(flags.M) << PMA_ISTART_M_SHIFT);
    istart |= (static_cast<uint64_t>(flags.IO) << PMA_ISTART_IO_SHIFT);
    istart |= (static_cast<uint64_t>(flags.E) << PMA_ISTART_E_SHIFT);
    istart |= (static_cast<uint64_t>(flags.R) << PMA_ISTART_R_SHIFT);
    istart |= (static_cast<uint64_t>(flags.W) << PMA_ISTART_W_SHIFT);
    istart |= (static_cast<uint64_t>(flags.X) << PMA_ISTART_X_SHIFT);
    istart |= (static_cast<uint64_t>(flags.IR) << PMA_ISTART_IR_SHIFT);
    istart |= (static_cast<uint64_t>(flags.IW) << PMA_ISTART_IW_SHIFT);
    istart |= (static_cast<uint64_t>(flags.DID) << PMA_ISTART_DID_SHIFT);
    return istart;
}

} // namespace cartesi

#endif
