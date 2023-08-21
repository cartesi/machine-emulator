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

#ifndef PMA_CONSTANTS_H
#define PMA_CONSTANTS_H

#include <cstdint>

#include <pma-defines.h>

namespace cartesi {

/// \file
/// \brief Physical memory attributes constants.

/// \brief Fixed PMA ranges.
enum PMA_ranges : uint64_t {
    PMA_SHADOW_STATE_START = EXPAND_UINT64_C(PMA_SHADOW_STATE_START_DEF),   ///< Start of processor shadow range
    PMA_SHADOW_STATE_LENGTH = EXPAND_UINT64_C(PMA_SHADOW_STATE_LENGTH_DEF), ///< Length of processor shadow range
    PMA_SHADOW_PMAS_START = EXPAND_UINT64_C(PMA_SHADOW_PMAS_START_DEF),     ///< Start of pma board shadow range
    PMA_SHADOW_PMAS_LENGTH = EXPAND_UINT64_C(PMA_SHADOW_PMAS_LENGTH_DEF),   ///< Length of pma board shadow range
    PMA_DTB_START = EXPAND_UINT64_C(PMA_DTB_START_DEF),                     ///< Start of DTB range
    PMA_DTB_LENGTH = EXPAND_UINT64_C(PMA_DTB_LENGTH_DEF),                   ///< Length of DTB range
    PMA_SHADOW_TLB_START = EXPAND_UINT64_C(PMA_SHADOW_TLB_START_DEF),       ///< Start of TLB shadow range
    PMA_SHADOW_TLB_LENGTH = EXPAND_UINT64_C(PMA_SHADOW_TLB_LENGTH_DEF),     ///< Length of TLB shadow range
    PMA_CLINT_START = EXPAND_UINT64_C(PMA_CLINT_START_DEF),                 ///< Start of CLINT range
    PMA_CLINT_LENGTH = EXPAND_UINT64_C(PMA_CLINT_LENGTH_DEF),               ///< Length of CLINT range
    PMA_HTIF_START = EXPAND_UINT64_C(PMA_HTIF_START_DEF),                   ///< Start of HTIF range
    PMA_HTIF_LENGTH = EXPAND_UINT64_C(PMA_HTIF_LENGTH_DEF),                 ///< Length of HTIF range
    PMA_UARCH_RAM_START = EXPAND_UINT64_C(PMA_UARCH_RAM_START_DEF),         ///< Start of microarchitecture RAM range
    PMA_UARCH_RAM_LENGTH = EXPAND_UINT64_C(PMA_UARCH_RAM_LENGTH_DEF),       ///< Length of microarchitecture RAM range

    //    PMA_FIRST_VIRTIO_START  = EXPAND_UINT64_C(PMA_FIRST_VIRTIO_START_DEF),    ///< Start of first VIRTIO range
    //    PMA_VIRTIO_LENGTH  = EXPAND_UINT64_C(PMA_VIRTIO_LENGTH_DEF),   ///< Length of each VIRTIO range
    //    PMA_LAST_VIRTIO_END  = EXPAND_UINT64_C(PMA_LAST_VIRTIO_END_DEF),   ///< End of last VIRTIO range
    //    PMA_PLIC_START    = EXPAND_UINT64_C(PMA_PLIC_START_DEF),    ///< Start of PLIC range
    //    PMA_PLIC_LENGTH   = EXPAND_UINT64_C(PMA_PLIC_LENGTH_DEF),   ///< Length of PLIC range
    PMA_RAM_START = EXPAND_UINT64_C(PMA_RAM_START_DEF), ///< Start of RAM range
};

/// \brief PMA constants.
enum PMA_constants : uint64_t {
    PMA_PAGE_SIZE_LOG2 = EXPAND_UINT64_C(PMA_PAGE_SIZE_LOG2_DEF), ///< log<sub>2</sub> of physical memory page size.
    PMA_PAGE_SIZE = (UINT64_C(1) << PMA_PAGE_SIZE_LOG2_DEF),      ///< Physical memory page size.
    PMA_WORD_SIZE = EXPAND_UINT64_C(PMA_WORD_SIZE_DEF),           ///< Physical memory word size.
    PMA_MAX = EXPAND_UINT64_C(PMA_MAX_DEF)                        ///< Maximum number of PMAs
};

/// \brief PMA TLB constants.
enum PMA_tlb_constants : uint64_t {
    PMA_TLB_SIZE = EXPAND_UINT64_C(PMA_TLB_SIZE_DEF), ///< Number for entries per TLB type
};

/// \brief PMA masks.
enum PMA_masks : uint64_t {
    PMA_ADDRESSABLE_MASK = ((UINT64_C(1) << 56) - 1) ///< Mask for addressable PMA ranges.
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
    PMA_ISTART_START_SHIFT = 12,
};

/// \brief PMA istart masks
enum PMA_ISTART_masks : uint64_t {
    PMA_ISTART_M_MASK = UINT64_C(1) << PMA_ISTART_M_SHIFT,         ///< Memory range
    PMA_ISTART_IO_MASK = UINT64_C(1) << PMA_ISTART_IO_SHIFT,       ///< Device range
    PMA_ISTART_E_MASK = UINT64_C(1) << PMA_ISTART_E_SHIFT,         ///< Empty range
    PMA_ISTART_R_MASK = UINT64_C(1) << PMA_ISTART_R_SHIFT,         ///< Readable
    PMA_ISTART_W_MASK = UINT64_C(1) << PMA_ISTART_W_SHIFT,         ///< Writable
    PMA_ISTART_X_MASK = UINT64_C(1) << PMA_ISTART_X_SHIFT,         ///< Executable
    PMA_ISTART_IR_MASK = UINT64_C(1) << PMA_ISTART_IR_SHIFT,       ///< Idempotent reads
    PMA_ISTART_IW_MASK = UINT64_C(1) << PMA_ISTART_IW_SHIFT,       ///< Idempotent writes
    PMA_ISTART_DID_MASK = UINT64_C(15) << PMA_ISTART_DID_SHIFT,    ///< Device id
    PMA_ISTART_START_MASK = UINT64_C(-1) << PMA_ISTART_START_SHIFT ///< Start of range
};

/// \brief PMA device ids
enum class PMA_ISTART_DID {
    memory = PMA_MEMORY_DID_DEF,                               ///< DID for memory
    shadow_state = PMA_SHADOW_STATE_DID_DEF,                   ///< DID for shadow device
    shadow_pmas = PMA_SHADOW_PMAS_DID_DEF,                     ///< DID for shadow pma array device
    shadow_TLB = PMA_SHADOW_TLB_DID_DEF,                       ///< DID for shadow TLB device
    flash_drive = PMA_FLASH_DRIVE_DID_DEF,                     ///< DID for drive device
    CLINT = PMA_CLINT_DID_DEF,                                 ///< DID for CLINT device
    HTIF = PMA_HTIF_DID_DEF,                                   ///< DID for HTIF device
    rollup_rx_buffer = PMA_ROLLUP_RX_BUFFER_DID_DEF,           ///< DID for rollup receive buffer
    rollup_tx_buffer = PMA_ROLLUP_TX_BUFFER_DID_DEF,           ///< DID for rollup transmit buffer
    rollup_input_metadata = PMA_ROLLUP_INPUT_METADATA_DID_DEF, ///< DID for rollup input metadata memory range
    rollup_voucher_hashes = PMA_ROLLUP_VOUCHER_HASHES_DID_DEF, ///< DID for rollup voucher hashes memory range
    rollup_notice_hashes = PMA_ROLLUP_NOTICE_HASHES_DID_DEF,   ///< DID for rollup notice hashes memory range
};

} // namespace cartesi

#endif
