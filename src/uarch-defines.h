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

#ifndef UARCH_DEFINES_H
#define UARCH_DEFINES_H

#include "pma-defines.h"

/// \brief Address of uarch halt flag in shadow
#define UARCH_HALT_FLAG_SHADDOW_ADDR_DEF  (PMA_SHADOW_STATE_START_DEF + 0x328)

/// \brief The value that halts the microarchitecture when written to UARCH_HALT_FLAG_SHADDOW_ADDR_DEF
#define UARCH_HALT_FLAG_HALT_VALUE_DEF      1

/// \brief Base of microarchitecture special addresses
#define UARCH_MMIO_START_DEF   0x7ffff000  ///< Start of microarchitecture memory mapped IO addresses

/// \brief Abort execution of microarchitecture by writing to this address
#define UARCH_MMIO_ABORT_ADDR_DEF    (UARCH_MMIO_START_DEF + 0)  // NOLINT(cppcoreguidelines-macro-usage)

/// \brief The value that aborts execution of the micro machine when written to UARCH_MMIO_ABORT_ADDR_DEF
#define UARCH_MMIO_ABORT_VALUE_DEF      1

/// \brief Prints a character to to console when written to UARCH_MMIO_HALT_ADDR_DEF
#define UARCH_MMIO_PUTCHAR_ADDR_DEF  (UARCH_MMIO_START_DEF + 8)   // NOLINT(cppcoreguidelines-macro-usage)


#endif /* end of include guard: UARCH_DEFINES_H */
