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

#ifndef AR_DEFINES_H
#define AR_DEFINES_H

// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#define AR_SHADOW_STATE_START_DEF 0x0            ///< Shadow start address
#define AR_SHADOW_STATE_LENGTH_DEF 0x8000        ///< Shadow length in bytes
#define AR_SHADOW_REGISTERS_START_DEF 0x0        ///< Shadow registers start address
#define AR_SHADOW_REGISTERS_LENGTH_DEF 0x1000    ///< Shadow registers length in bytes
#define AR_SHADOW_TLB_START_DEF 0x1000           ///< Shadow TLB start address
#define AR_SHADOW_TLB_LENGTH_DEF 0x6000          ///< Shadow TLB length in bytes
#define AR_PMAS_START_DEF 0x10000                ///< PMA Array start address
#define AR_PMAS_LENGTH_DEF 0x1000                ///< PMA Array length in bytes
#define AR_SHADOW_UARCH_STATE_START_DEF 0x400000 ///< microarchitecture shadow state start address
#define AR_SHADOW_UARCH_STATE_LENGTH_DEF 0x1000  ///< microarchitecture shadow state length
#define AR_UARCH_RAM_START_DEF 0x600000          ///< microarchitecture RAM start address
#define AR_UARCH_RAM_LENGTH_DEF 0x200000         ///< microarchitecture RAM length
#define AR_CLINT_START_DEF 0x2000000             ///< CLINT start address
#define AR_CLINT_LENGTH_DEF 0xC0000              ///< CLINT length in bytes
#define AR_PLIC_START_DEF 0x40100000             ///< Start of PLIC range
#define AR_PLIC_LENGTH_DEF 0x00400000            ///< Length of PLIC range
#define AR_HTIF_START_DEF 0x40008000             ///< HTIF base address (to_host)
#define AR_HTIF_LENGTH_DEF 0x1000                ///< HTIF length in bytes
#define AR_FIRST_VIRTIO_START_DEF 0x40010000     ///< Start of first VIRTIO range
#define AR_VIRTIO_LENGTH_DEF 0x1000              ///< Length of each VIRTIO range
#define AR_LAST_VIRTIO_END_DEF 0x40020000        ///< End of last VIRTIO range
#define AR_DTB_START_DEF 0x7ff00000              ///< DTB start address
#define AR_DTB_LENGTH_DEF 0x100000               ///< DTB length in bytes
#define AR_CMIO_RX_BUFFER_START_DEF 0x60000000   ///< CMIO RX buffer start address
#define AR_CMIO_RX_BUFFER_LOG2_SIZE_DEF 21       ///< log<sub>2</sub> of CMIO RX buffer length in bytes
#define AR_CMIO_TX_BUFFER_START_DEF 0x60800000   ///< CMIO TX buffer start address
#define AR_CMIO_TX_BUFFER_LOG2_SIZE_DEF 21       ///< log<sub>2</sub> of CMIO TX buffer length in bytes
#define AR_DRIVE_START_DEF 0x80000000000000      ///< Start PMA address for flash drives
#define AR_DRIVE_OFFSET_DEF 0x10000000000000     ///< PMA offset for extra flash drives

#define AR_RAM_START_DEF 0x80000000 ///< RAM start address

#define AR_LOG2_PAGE_SIZE_DEF 12 ///< log<sub>2</sub> of physical memory page size.

// helper for using UINT64_C with defines
#ifndef EXPAND_UINT64_C
#define EXPAND_UINT64_C(a) UINT64_C(a)
#endif
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: AR_DEFINES_H */
