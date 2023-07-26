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

#include "clua-i-virtual-machine.h"
#include "clua-jsonrpc-machine.h"
#include "clua.h"
#include "machine-c-defines.h"

/// \file
/// \brief Scripting interface for the Cartesi JSONRPC API SDK.

extern "C" {

/// \brief Entrypoint to the Cartesi JSONRPC Lua library.
/// \param L Lua state.
CM_API int luaopen_cartesi_jsonrpc(lua_State *L) {
    using namespace cartesi;

    // Initialize and export jsonrpc machine bind
    clua_init(L);    // cluactx
    lua_newtable(L); // cluactx jsonrpc
    // Initialize and export machine bind
    clua_i_virtual_machine_export(L, -2); // cluactx jsonrpc
    // Initialize and export jsonrpc machine bind
    clua_jsonrpc_machine_export(L, -2); // cluactx jsonrpc

    return 1;
}
}
