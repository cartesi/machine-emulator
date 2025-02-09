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

#ifndef PMA_DEFINES_H
#define PMA_DEFINES_H
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#define PMA_SHADOW_STATE_START_DEF 0x0            ///< Shadow start address
#define PMA_SHADOW_STATE_LENGTH_DEF 0x1000        ///< Shadow length in bytes
#define PMA_SHADOW_PMAS_START_DEF 0x10000         ///< PMA Array start address
#define PMA_SHADOW_PMAS_LENGTH_DEF 0x1000         ///< PMA Array length in bytes
#define PMA_SHADOW_TLB_START_DEF 0x20000          ///< TLB start address
#define PMA_SHADOW_TLB_LENGTH_DEF 0x6000          ///< TLB length in bytes
#define PMA_SHADOW_UARCH_STATE_START_DEF 0x400000 ///< microarchitecture shadow state start address
#define PMA_SHADOW_UARCH_STATE_LENGTH_DEF 0x1000  ///< microarchitecture shadow state length
#define PMA_UARCH_RAM_START_DEF 0x600000          ///< microarchitecture RAM start address
#define PMA_UARCH_RAM_LENGTH_DEF 0x200000         ///< microarchitecture RAM length
#define PMA_CLINT_START_DEF 0x2000000             ///< CLINT start address
#define PMA_CLINT_LENGTH_DEF 0xC0000              ///< CLINT length in bytes
#define PMA_PLIC_START_DEF 0x40100000             ///< Start of PLIC range
#define PMA_PLIC_LENGTH_DEF 0x00400000            ///< Length of PLIC range
#define PMA_HTIF_START_DEF 0x40008000             ///< HTIF base address (to_host)
#define PMA_HTIF_LENGTH_DEF 0x1000                ///< HTIF length in bytes
#define PMA_FIRST_VIRTIO_START_DEF 0x40010000     ///< Start of first VIRTIO range
#define PMA_VIRTIO_LENGTH_DEF 0x1000              ///< Length of each VIRTIO range
#define PMA_LAST_VIRTIO_END_DEF 0x40020000        ///< End of last VIRTIO range
#define PMA_DTB_START_DEF 0x7ff00000              ///< DTB start address
#define PMA_DTB_LENGTH_DEF 0x100000               ///< DTB length in bytes
#define PMA_CMIO_RX_BUFFER_START_DEF 0x60000000   ///< CMIO RX buffer start address
#define PMA_CMIO_RX_BUFFER_LOG2_SIZE_DEF 21       ///< log<sub>2</sub> of CMIO RX buffer length in bytes
#define PMA_CMIO_TX_BUFFER_START_DEF 0x60800000   ///< CMIO TX buffer start address
#define PMA_CMIO_TX_BUFFER_LOG2_SIZE_DEF 21       ///< log<sub>2</sub> of CMIO TX buffer length in bytes
#define PMA_DRIVE_START_DEF 0x80000000000000      ///< Start PMA address for flash drives
#define PMA_DRIVE_OFFSET_DEF 0x10000000000000     ///< PMA offset for extra flash drives

#define PMA_RAM_START_DEF 0x80000000 ///< RAM start address

#define PMA_PAGE_SIZE_LOG2_DEF 12 ///< log<sub>2</sub> of physical memory page size.
#define PMA_WORD_SIZE_DEF 8       ///< Physical memory word size.
#define PMA_MAX_DEF 32            ///< Maximum number of PMAs
#define PMA_PLIC_MAX_IRQ_DEF 31   ///< Maximum PLIC interrupt

#define PMA_MEMORY_DID_DEF 0              ///< Device ID for memory
#define PMA_SHADOW_STATE_DID_DEF 1        ///< Device ID for shadow state device
#define PMA_SHADOW_PMAS_DID_DEF 2         ///< Device ID for shadow pma array device
#define PMA_FLASH_DRIVE_DID_DEF 3         ///< Device ID for flash drive device
#define PMA_CLINT_DID_DEF 4               ///< Device ID for CLINT device
#define PMA_HTIF_DID_DEF 5                ///< Device ID for HTIF device
#define PMA_SHADOW_TLB_DID_DEF 6          ///< Device ID for shadow TLB device
#define PMA_CMIO_RX_BUFFER_DID_DEF 7      ///< Device ID for cmio RX buffer
#define PMA_CMIO_TX_BUFFER_DID_DEF 8      ///< Device ID for cmio TX buffer
#define PMA_PLIC_DID_DEF 10               ///< Device ID for PLIC device
#define PMA_VIRTIO_DID_DEF 11             ///< Device ID for VirtIO devices
#define PMA_SHADOW_UARCH_STATE_DID_DEF 12 ///< Device ID for uarch shadow state device

// helper for using UINT64_C with defines
#ifndef EXPAND_UINT64_C
#define EXPAND_UINT64_C(a) UINT64_C(a)
#endif
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: PMA_DEFINES_H */
