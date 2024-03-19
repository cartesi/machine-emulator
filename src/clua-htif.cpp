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

#include "clua-htif.h"
#include "htif.h"

#include <array>

namespace cartesi {

int clua_htif_export(lua_State *L, int ctxidx) {
    (void) ctxidx;
    struct named_constant {
        uint64_t value;
        const char *name;
    };
    const std::array constants{
        named_constant{HTIF_DEV_HALT, "HTIF_DEV_HALT"},
        named_constant{HTIF_DEV_CONSOLE, "HTIF_DEV_CONSOLE"},
        named_constant{HTIF_DEV_YIELD, "HTIF_DEV_YIELD"},
        named_constant{HTIF_HALT_CMD_HALT, "HTIF_HALT_CMD_HALT"},
        named_constant{HTIF_YIELD_CMD_AUTOMATIC, "HTIF_YIELD_CMD_AUTOMATIC"},
        named_constant{HTIF_YIELD_CMD_MANUAL, "HTIF_YIELD_CMD_MANUAL"},
        named_constant{HTIF_YIELD_AUTOMATIC_REASON_PROGRESS, "HTIF_YIELD_AUTOMATIC_REASON_PROGRESS"},
        named_constant{HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, "HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT"},
        named_constant{HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT, "HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT"},
        named_constant{HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED"},
        named_constant{HTIF_YIELD_MANUAL_REASON_RX_REJECTED, "HTIF_YIELD_MANUAL_REASON_RX_REJECTED"},
        named_constant{HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION, "HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION"},
        named_constant{HTIF_YIELD_REASON_ADVANCE_STATE, "HTIF_YIELD_REASON_ADVANCE_STATE"},
        named_constant{HTIF_YIELD_REASON_INSPECT_STATE, "HTIF_YIELD_REASON_INSPECT_STATE"},
        named_constant{HTIF_CONSOLE_CMD_GETCHAR, "HTIF_CONSOLE_CMD_GETCHAR"},
        named_constant{HTIF_CONSOLE_CMD_PUTCHAR, "HTIF_CONSOLE_CMD_PUTCHAR"},
    };
    for (const auto &c : constants) {
        lua_pushinteger(L, static_cast<lua_Integer>(c.value));
        lua_setfield(L, -2, c.name);
    }
    return 0;
}

} // namespace cartesi
