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

#ifndef PMAS_H
#define PMAS_H

#include <array>
#include <cstddef>
#include <cstdint>

#include "address-range-constants.h"
#include "compiler-defines.h"
#include "pmas-constants.h"

namespace cartesi {

/// \file
/// \brief Physical memory attributes.

static constexpr const char *pmas_get_DID_name(PMA_ISTART_DID did) {
    switch (did) {
        case PMA_ISTART_DID::empty:
            return "DID.empty";
        case PMA_ISTART_DID::memory:
            return "DID.memory";
        case PMA_ISTART_DID::shadow_state:
            return "DID.shadow_state";
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
    }
    return "DID.unknown";
}

static constexpr bool pmas_is_protected(PMA_ISTART_DID DID) {
    switch (DID) {
        case PMA_ISTART_DID::memory:
        case PMA_ISTART_DID::flash_drive:
        case PMA_ISTART_DID::cmio_rx_buffer:
        case PMA_ISTART_DID::cmio_tx_buffer:
            return false;
        default:
            return true;
    }
}

///< Unpacked attribute flags
struct pmas_flags {
    bool M;             ///< is memory
    bool IO;            ///< is device
    bool R;             ///< is readable
    bool W;             ///< is writeable
    bool X;             ///< is executable
    bool IR;            ///< is read-idempotent
    bool IW;            ///< is write-idempotent
    PMA_ISTART_DID DID; ///< driver id

    // Defaulted comparison operator
    bool operator==(const pmas_flags &) const = default;
};

static constexpr pmas_flags pmas_unpack_istart(uint64_t istart, uint64_t &start) {
    start = istart & PMA_ISTART_START_MASK;
    return pmas_flags{.M = ((istart & PMA_ISTART_M_MASK) >> PMA_ISTART_M_SHIFT) != 0,
        .IO = ((istart & PMA_ISTART_IO_MASK) >> PMA_ISTART_IO_SHIFT) != 0,
        .R = ((istart & PMA_ISTART_R_MASK) >> PMA_ISTART_R_SHIFT) != 0,
        .W = ((istart & PMA_ISTART_W_MASK) >> PMA_ISTART_W_SHIFT) != 0,
        .X = ((istart & PMA_ISTART_X_MASK) >> PMA_ISTART_X_SHIFT) != 0,
        .IR = ((istart & PMA_ISTART_IR_MASK) >> PMA_ISTART_IR_SHIFT) != 0,
        .IW = ((istart & PMA_ISTART_IW_MASK) >> PMA_ISTART_IW_SHIFT) != 0,
        .DID = static_cast<PMA_ISTART_DID>((istart & PMA_ISTART_DID_MASK) >> PMA_ISTART_DID_SHIFT)};
}

static constexpr uint64_t pmas_pack_istart(const pmas_flags &flags, uint64_t start) {
    uint64_t istart = start;
    istart |= (static_cast<uint64_t>(flags.M) << PMA_ISTART_M_SHIFT);
    istart |= (static_cast<uint64_t>(flags.IO) << PMA_ISTART_IO_SHIFT);
    istart |= (static_cast<uint64_t>(flags.R) << PMA_ISTART_R_SHIFT);
    istart |= (static_cast<uint64_t>(flags.W) << PMA_ISTART_W_SHIFT);
    istart |= (static_cast<uint64_t>(flags.X) << PMA_ISTART_X_SHIFT);
    istart |= (static_cast<uint64_t>(flags.IR) << PMA_ISTART_IR_SHIFT);
    istart |= (static_cast<uint64_t>(flags.IW) << PMA_ISTART_IW_SHIFT);
    istart |= (static_cast<uint64_t>(flags.DID) << PMA_ISTART_DID_SHIFT);
    return istart;
}

/// \brief Shadow memory layout
struct PACKED pmas_entry {
    uint64_t istart;
    uint64_t ilength;
};

using pmas_state = std::array<pmas_entry, PMA_MAX>;

/// \brief List of field types
enum class pmas_what : uint64_t {
    istart = offsetof(pmas_entry, istart),
    ilength = offsetof(pmas_entry, ilength),
    unknown_ = UINT64_C(1) << 63, // Outside of RISC-V address space
};

/// \brief Obtains the absolute address of a PMA entry.
/// \param p Index of desired PMA entry
/// \returns The address.
static constexpr uint64_t pmas_get_abs_addr(uint64_t p) {
    return AR_PMAS_START + (p * sizeof(pmas_entry));
}

/// \brief Obtains the absolute address of a PMA entry.
/// \param p Index of desired PMA entry
/// \param what Desired field
/// \returns The address.
static constexpr uint64_t pmas_get_abs_addr(uint64_t p, pmas_what what) {
    return pmas_get_abs_addr(p) + static_cast<uint64_t>(what);
}

static constexpr pmas_what pmas_get_what(uint64_t paddr) {
    if (paddr < AR_PMAS_START || paddr - AR_PMAS_START >= sizeof(pmas_state) || (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return pmas_what::unknown_;
    }
    //??D First condition ensures offset = (paddr-AR_PMAS_START) >= 0
    //??D Second ensures offset < sizeof(pmas_state)
    //??D Third ensures offset is aligned to sizeof(uint64_t)
    //??D pmas_entry only contains uint64_t fields
    //??D pmas_state_what contains one entry with the offset of each field in pmas_entry
    //??D I don't see how the cast can produce something outside the enum...
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    return pmas_what{(paddr - AR_PMAS_START) % sizeof(pmas_entry)};
}

static constexpr const char *pmas_get_what_name(pmas_what what) {
    const auto paddr = static_cast<uint64_t>(what);
    if (paddr >= sizeof(pmas_entry) || (paddr & (sizeof(uint64_t) - 1)) != 0) {
        return "pma.unknown_";
    }
    switch (what) {
        case pmas_what::istart:
            return "pma.istart";
        case pmas_what::ilength:
            return "pma.ilength";
        case pmas_what::unknown_:
            return "pma.unknown_";
    }
    return "pmas.unknown_";
}

} // namespace cartesi

#endif
