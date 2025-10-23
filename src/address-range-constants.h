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

#ifndef ADDRESS_RANGE_CONSTANTS_H
#define ADDRESS_RANGE_CONSTANTS_H

#include <cstdint>

#include "address-range-defines.h"

namespace cartesi {

/// \brief Fixed address ranges.
enum AR_ranges : uint64_t {
    AR_SHADOW_STATE_START = EXPAND_UINT64_C(AR_SHADOW_STATE_START_DEF),           ///< Start of shadow state range
    AR_SHADOW_STATE_LENGTH = EXPAND_UINT64_C(AR_SHADOW_STATE_LENGTH_DEF),         ///< Length of shadow state range
    AR_SHADOW_REGISTERS_START = EXPAND_UINT64_C(AR_SHADOW_REGISTERS_START_DEF),   ///< Start of shadow registers range
    AR_SHADOW_REGISTERS_LENGTH = EXPAND_UINT64_C(AR_SHADOW_REGISTERS_LENGTH_DEF), ///< Length of shadow registers range
    AR_SHADOW_REVERT_ROOT_HASH_START =
        EXPAND_UINT64_C(AR_SHADOW_REVERT_ROOT_HASH_START_DEF),        ///< Start of revert root hash range
    AR_SHADOW_TLB_START = EXPAND_UINT64_C(AR_SHADOW_TLB_START_DEF),   ///< Start of shadow TLB range
    AR_SHADOW_TLB_LENGTH = EXPAND_UINT64_C(AR_SHADOW_TLB_LENGTH_DEF), ///< Length of shadow TLB range
    AR_PMAS_START = EXPAND_UINT64_C(AR_PMAS_START_DEF),               ///< Start of PMAS list range
    AR_PMAS_LENGTH = EXPAND_UINT64_C(AR_PMAS_LENGTH_DEF),             ///< Length of PMAS list range
    AR_DTB_START = EXPAND_UINT64_C(AR_DTB_START_DEF),                 ///< Start of DTB range
    AR_DTB_LENGTH = EXPAND_UINT64_C(AR_DTB_LENGTH_DEF),               ///< Length of DTB range
    AR_SHADOW_UARCH_STATE_START =
        EXPAND_UINT64_C(AR_SHADOW_UARCH_STATE_START_DEF), ///< Start of uarch shadow state range
    AR_SHADOW_UARCH_STATE_LENGTH =
        EXPAND_UINT64_C(AR_SHADOW_UARCH_STATE_LENGTH_DEF),                  ///< Length of uarch shadow state range
    AR_CLINT_START = EXPAND_UINT64_C(AR_CLINT_START_DEF),                   ///< Start of CLINT range
    AR_CLINT_LENGTH = EXPAND_UINT64_C(AR_CLINT_LENGTH_DEF),                 ///< Length of CLINT range
    AR_PLIC_START = EXPAND_UINT64_C(AR_PLIC_START_DEF),                     ///< Start of PLIC range
    AR_PLIC_LENGTH = EXPAND_UINT64_C(AR_PLIC_LENGTH_DEF),                   ///< Length of PLIC range
    AR_HTIF_START = EXPAND_UINT64_C(AR_HTIF_START_DEF),                     ///< Start of HTIF range
    AR_HTIF_LENGTH = EXPAND_UINT64_C(AR_HTIF_LENGTH_DEF),                   ///< Length of HTIF range
    AR_UARCH_RAM_START = EXPAND_UINT64_C(AR_UARCH_RAM_START_DEF),           ///< Start of uarch RAM range
    AR_UARCH_RAM_LENGTH = EXPAND_UINT64_C(AR_UARCH_RAM_LENGTH_DEF),         ///< Length of uarch RAM range
    AR_CMIO_RX_BUFFER_START = EXPAND_UINT64_C(AR_CMIO_RX_BUFFER_START_DEF), ///< Start of CMIO RX buffer range
    AR_CMIO_RX_BUFFER_LOG2_SIZE = EXPAND_UINT64_C(AR_CMIO_RX_BUFFER_LOG2_SIZE_DEF), ///< Log2 of CMIO RX buffer range
    AR_CMIO_RX_BUFFER_LENGTH = (UINT64_C(1) << AR_CMIO_RX_BUFFER_LOG2_SIZE_DEF),    ///< Length of CMIO RX buffer range
    AR_CMIO_TX_BUFFER_START = EXPAND_UINT64_C(AR_CMIO_TX_BUFFER_START_DEF),         ///< Start of CMIO TX buffer range
    AR_CMIO_TX_BUFFER_LOG2_SIZE = EXPAND_UINT64_C(AR_CMIO_TX_BUFFER_LOG2_SIZE_DEF), ///< Log2 of CMIO TX buffer range
    AR_CMIO_TX_BUFFER_LENGTH = (UINT64_C(1) << AR_CMIO_TX_BUFFER_LOG2_SIZE_DEF),    ///< Length of CMIO TX buffer range
    AR_DRIVE_START = EXPAND_UINT64_C(AR_DRIVE_START_DEF),   ///< Start address for flash drive ranges
    AR_DRIVE_OFFSET = EXPAND_UINT64_C(AR_DRIVE_OFFSET_DEF), ///< Offset for extra flash drive ranges

    AR_FIRST_VIRTIO_START = EXPAND_UINT64_C(AR_FIRST_VIRTIO_START_DEF), ///< Start of first VIRTIO range
    AR_VIRTIO_LENGTH = EXPAND_UINT64_C(AR_VIRTIO_LENGTH_DEF),           ///< Length of each VIRTIO range
    AR_LAST_VIRTIO_END = EXPAND_UINT64_C(AR_LAST_VIRTIO_END_DEF),       ///< End of last VIRTIO range

    AR_RAM_START = EXPAND_UINT64_C(AR_RAM_START_DEF), ///< Start of RAM range
};

static_assert(AR_SHADOW_STATE_LENGTH >= AR_SHADOW_REGISTERS_LENGTH + AR_SHADOW_TLB_LENGTH);
static_assert(AR_SHADOW_TLB_START == AR_SHADOW_REGISTERS_START + AR_SHADOW_REGISTERS_LENGTH);
static_assert(AR_SHADOW_STATE_START == AR_SHADOW_REGISTERS_START);

/// \brief PMA constants.
enum AR_constants : uint64_t {
    AR_LOG2_PAGE_SIZE = EXPAND_UINT64_C(AR_LOG2_PAGE_SIZE_DEF), ///< Log<sub>2</sub> of physical memory page size.
    AR_PAGE_SIZE = (UINT64_C(1) << AR_LOG2_PAGE_SIZE_DEF),      ///< Physical memory page size.
};

/// \brief PMA masks.
enum AR_masks : uint64_t {
    AR_ADDRESSABLE_MASK = ((UINT64_C(1) << 56) - 1) ///< Mask for addressable ranges.
};

} // namespace cartesi

#endif
