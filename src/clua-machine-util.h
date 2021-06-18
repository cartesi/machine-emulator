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

#ifndef CLUA_MACHINE_UTIL_H
#define CLUA_MACHINE_UTIL_H

#include "machine-merkle-tree.h"
#include "access-log.h"
#include "machine.h"
#include "semantic-version.h"

/// \file
/// \brief Cartesi machine Lua interface helper functions

namespace cartesi {

/// \brief Pushes a proof to the Lua stack
/// \param L Lua state.
/// \param proof Proof to be pushed.
void clua_push_proof(lua_State *L, const machine_merkle_tree::proof_type &proof);

/// \brief Pushes a semantic_version to the Lua stack
/// \param L Lua state.
/// \param v Semantic_version to be pushed.
void clua_push_semantic_version(lua_State *L, const semantic_version &v);

/// \brief Pushes a hash to the Lua stack
/// \param L Lua state.
/// \param hash Hash to be pushed.
void clua_push_hash(lua_State *L, const machine_merkle_tree::hash_type hash);

/// \brief Pushes a machine_config to the Lua stack
/// \param L Lua state.
/// \param r Machine_config to be pushed.
void clua_push_machine_config(lua_State *L, const machine_config &c);

/// \brief Pushes a machine_runtime_config to the Lua stack
/// \param L Lua state.
/// \param r Machine_runtime_config to be pushed.
void clua_push_machine_runtime_config(lua_State *L,
    const machine_runtime_config &r);

/// \brief Returns a CSR selector from Lua.
/// \param L Lua state.
/// \param idx Index in stack
/// \returns CSR selector. Throws error if unknown.
machine::csr clua_check_csr(lua_State *L, int idx);

/// \brief Pushes an access log to the Lua stack
/// \param L Lua state.
/// \param log Access log to be pushed.
void clua_push_access_log(lua_State *L, const access_log &log);

/// \brief Loads an access_log::type from Lua
/// \param L Lua state.
/// \param tabidx Access_log::type stack index.
/// \param log_type Access_log::type to be pushed.
access_log::type clua_check_log_type(lua_State *L, int tabidx);

/// \brief Return a hash from Lua
/// \param L Lua state.
/// \param idx Index in stack.
/// \returns Hash.
machine_merkle_tree::hash_type clua_check_hash(lua_State *L, int idx);

/// \brief Loads a proof from Lua.
/// \param L Lua state.
/// \param tabidx Proof stack index.
/// \returns The proof.
machine_merkle_tree::proof_type clua_check_proof(lua_State *L, int tabidx);

/// \brief Loads an access_log from Lua.
/// \param L Lua state.
/// \param tabidx Access_log stack index.
/// \returns The access_log.
access_log clua_check_access_log(lua_State *L, int tabidx);

/// \brief Loads a machine_config object from a Lua table
/// \param L Lua state.
/// \param tabidx Index of table in Lua stack
machine_config clua_check_machine_config(lua_State *L, int tabidx);

/// \brief Loads a machine_runtime_config object from a Lua table
/// \param L Lua state.
/// \param tabidx Index of table in Lua stack
machine_runtime_config clua_check_machine_runtime_config(lua_State *L,
    int tabidx);

/// \brief Loads an optional machine_runtime_config object from a Lua
/// \param L Lua state.
/// \param tabidx Index of table in Lua stack
machine_runtime_config clua_opt_machine_runtime_config(lua_State *L,
    int tabidx, const machine_runtime_config &r);

/// \brief Loads flash drive config from a Lua table.
/// \param L Lua state.
/// \param tabidx Flash_config stack index.
/// \returns The flash_config.
flash_drive_config clua_check_flash_drive_config(lua_State *L, int tabidx);

} // namespace cartesi

#endif
