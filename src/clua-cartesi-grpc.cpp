// Copyright 2020 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#include "clua-grpc-machine.h"
#include "clua-i-virtual-machine.h"
#include "clua.h"
#include "machine-c-defines.h"

/// \file
/// \brief Scripting interface for the Cartesi GRPC API SDK.

extern "C" {

/// \brief Entrypoint to the Cartesi GRPC Lua library.
/// \param L Lua state.
CM_API int luaopen_cartesi_grpc(lua_State *L) {
    using namespace cartesi;

    // Initialize and export grpc machine bind
    clua_init(L);    // cluactx
    lua_newtable(L); // cluactx grpc
    // Initialize and export machine bind
    clua_i_virtual_machine_export(L, -2); // cluactx grpc
    // Initialize and export grpc machine bind
    clua_grpc_machine_export(L, -2); // cluactx grpc

    return 1;
}
}
