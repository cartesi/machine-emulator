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

#define PMA_MAX_DEF 32 ///< Maximum number of PMAs

#define PMA_EMPTY_DID_DEF 0              ///< Device ID for empty range
#define PMA_MEMORY_DID_DEF 1             ///< Device ID for memory
#define PMA_SHADOW_STATE_DID_DEF 2       ///< Device ID for shadow state device
#define PMA_FLASH_DRIVE_DID_DEF 3        ///< Device ID for flash drive device
#define PMA_CLINT_DID_DEF 4              ///< Device ID for CLINT device
#define PMA_HTIF_DID_DEF 5               ///< Device ID for HTIF device
#define PMA_PLIC_DID_DEF 6               ///< Device ID for PLIC device
#define PMA_CMIO_RX_BUFFER_DID_DEF 7     ///< Device ID for cmio RX buffer
#define PMA_CMIO_TX_BUFFER_DID_DEF 8     ///< Device ID for cmio TX buffer
#define PMA_SHADOW_UARCH_STATE_DID_DEF 9 ///< Device ID for uarch shadow state device
#define PMA_VIRTIO_DID_DEF 10            ///< Device ID for VirtIO devices

// helper for using UINT64_C with defines
#ifndef EXPAND_UINT64_C
#define EXPAND_UINT64_C(a) UINT64_C(a)
#endif

// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#endif /* end of include guard: PMA_DEFINES_H */
