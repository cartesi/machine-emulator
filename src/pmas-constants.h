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

#ifndef PMAS_CONSTANTS_H
#define PMAS_CONSTANTS_H

#include <cstdint>

#include "pmas-defines.h"

namespace cartesi {

/// \brief PMA constants.
enum PMA_constants : uint64_t {
    PMA_MAX = EXPAND_UINT64_C(PMA_MAX_DEF) ///< Maximum number of PMAs
};

/// \brief PMA istart shifts
enum PMA_ISTART_shifts {
    PMA_ISTART_M_SHIFT = 0,
    PMA_ISTART_IO_SHIFT = 1,
    PMA_ISTART_E_SHIFT = 2,
    PMA_ISTART_R_SHIFT = 3,
    PMA_ISTART_W_SHIFT = 4,
    PMA_ISTART_X_SHIFT = 5,
    PMA_ISTART_IR_SHIFT = 6,
    PMA_ISTART_IW_SHIFT = 7,
    PMA_ISTART_DID_SHIFT = 8,
    AR_ISTART_START_SHIFT = 12
};

/// \brief PMA istart masks
enum PMA_ISTART_masks : uint64_t {
    PMA_ISTART_M_MASK = UINT64_C(1) << PMA_ISTART_M_SHIFT,       ///< Memory range
    PMA_ISTART_IO_MASK = UINT64_C(1) << PMA_ISTART_IO_SHIFT,     ///< Device range
    PMA_ISTART_E_MASK = UINT64_C(1) << PMA_ISTART_E_SHIFT,       ///< Empty range
    PMA_ISTART_R_MASK = UINT64_C(1) << PMA_ISTART_R_SHIFT,       ///< Readable
    PMA_ISTART_W_MASK = UINT64_C(1) << PMA_ISTART_W_SHIFT,       ///< Writable
    PMA_ISTART_X_MASK = UINT64_C(1) << PMA_ISTART_X_SHIFT,       ///< Executable
    PMA_ISTART_IR_MASK = UINT64_C(1) << PMA_ISTART_IR_SHIFT,     ///< Idempotent reads
    PMA_ISTART_IW_MASK = UINT64_C(1) << PMA_ISTART_IW_SHIFT,     ///< Idempotent writes
    PMA_ISTART_DID_MASK = UINT64_C(15) << PMA_ISTART_DID_SHIFT,  ///< Device id
    AR_ISTART_START_MASK = UINT64_C(-1) << AR_ISTART_START_SHIFT ///< Start of range
};

/// \brief PMA device ids
enum class PMA_ISTART_DID : uint8_t {
    empty = PMA_EMPTY_DID_DEF,                           ///< DID for empty range
    memory = PMA_MEMORY_DID_DEF,                         ///< DID for memory
    shadow_state = PMA_SHADOW_STATE_DID_DEF,             ///< DID for shadow state
    shadow_TLB = PMA_SHADOW_TLB_DID_DEF,                 ///< DID for shadow TLB
    flash_drive = PMA_FLASH_DRIVE_DID_DEF,               ///< DID for flash drives
    CLINT = PMA_CLINT_DID_DEF,                           ///< DID for CLINT device
    PLIC = PMA_PLIC_DID_DEF,                             ///< DID for PLIC device
    HTIF = PMA_HTIF_DID_DEF,                             ///< DID for HTIF device
    VIRTIO = PMA_VIRTIO_DID_DEF,                         ///< DID for VirtIO devices
    cmio_rx_buffer = PMA_CMIO_RX_BUFFER_DID_DEF,         ///< DID for cmio receive buffer
    cmio_tx_buffer = PMA_CMIO_TX_BUFFER_DID_DEF,         ///< DID for cmio transmit buffer
    shadow_uarch_state = PMA_SHADOW_UARCH_STATE_DID_DEF, ///< DID for shadow uarch state
};

} // namespace cartesi

#endif
