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

#ifndef HTIF_DEFINES_H
#define HTIF_DEFINES_H
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#define HTIF_DEV_SHIFT_DEF 56
#define HTIF_CMD_SHIFT_DEF 48
#define HTIF_REASON_SHIFT_DEF 32
#define HTIF_DATA_SHIFT_DEF 0

#define HTIF_DEV_MASK_DEF 0xFF00000000000000
#define HTIF_CMD_MASK_DEF 0x00FF000000000000
#define HTIF_REASON_MASK_DEF 0x0000FFFF00000000
#define HTIF_DATA_MASK_DEF 0x00000000FFFFFFFF

#define HTIF_DEV_HALT_DEF 0
#define HTIF_DEV_CONSOLE_DEF 1
#define HTIF_DEV_YIELD_DEF 2

#define HTIF_HALT_CMD_HALT_DEF 0
#define HTIF_CONSOLE_CMD_GETCHAR_DEF 0
#define HTIF_CONSOLE_CMD_PUTCHAR_DEF 1
#define HTIF_YIELD_CMD_AUTOMATIC_DEF 0
#define HTIF_YIELD_CMD_MANUAL_DEF 1

/* request */
#define HTIF_YIELD_AUTOMATIC_REASON_PROGRESS_DEF 1
#define HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT_DEF 2
#define HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT_DEF 4

#define HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED_DEF 1
#define HTIF_YIELD_MANUAL_REASON_RX_REJECTED_DEF 2
#define HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION_DEF 4

/* reply */
#define HTIF_YIELD_REASON_ADVANCE_STATE_DEF 0
#define HTIF_YIELD_REASON_INSPECT_STATE_DEF 1

// helper for using UINT64_C with defines
#ifndef EXPAND_UINT64_C
#define EXPAND_UINT64_C(a) UINT64_C(a)
#endif

// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

#endif /* end of include guard: HTIF_DEFINES_H */
