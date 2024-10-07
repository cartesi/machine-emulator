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

#include "clua-machine-util.h"
#include "clua.h"
#include "json-util.h"
#include "machine-c-api.h"
#include "riscv-constants.h"

namespace cartesi {

/// \brief This is the machine.get_default_machine_config()
/// method implementation.
static int machine_class_index_get_default_config(lua_State *L) {
    const char *config = cm_get_default_config();
    if (!config) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_json_table(L, config);
    return 1;
}

/// \brief This is the machine.get_reg_address() method implementation.
static int machine_class_index_get_reg_address(lua_State *L) {
    lua_pushinteger(L, static_cast<lua_Integer>(cm_get_reg_address(clua_check_cm_proc_reg(L, 1))));
    return 1;
}

/// \brief This is the machine.verify_step_uarch() method implementation.
static int machine_class_index_verify_step_uarch(lua_State *L) {
    lua_settop(L, 4);
    const char *log = clua_check_schemed_json_string(L, 2, "AccessLog");
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    if (cm_verify_step_uarch(&root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine.verify_reset_uarch() method implementation.
static int machine_class_index_verify_reset_uarch(lua_State *L) {
    lua_settop(L, 4);
    const char *log = clua_check_schemed_json_string(L, 2, "AccessLog");
    cm_hash root_hash{};
    clua_check_cm_hash(L, 1, &root_hash);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 3, &target_hash);
    if (cm_verify_reset_uarch(&root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine.verify_send_cmio_response() method implementation.
static int machine_class_index_verify_send_cmio_response(lua_State *L) {
    lua_settop(L, 6);
    const uint16_t reason = static_cast<uint16_t>(luaL_checkinteger(L, 1));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 2, &length));
    const char *log = clua_check_schemed_json_string(L, 4, "AccessLog");
    cm_hash root_hash{};
    clua_check_cm_hash(L, 3, &root_hash);
    cm_hash target_hash{};
    clua_check_cm_hash(L, 5, &target_hash);
    if (cm_verify_send_cmio_response(reason, data, length, &root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief Contents of the machine class metatable __index table.
static const auto machine_class_index = cartesi::clua_make_luaL_Reg_array({
    {"get_default_config", machine_class_index_get_default_config},
    {"get_reg_address", machine_class_index_get_reg_address},
    {"verify_step_uarch", machine_class_index_verify_step_uarch},
    {"verify_reset_uarch", machine_class_index_verify_reset_uarch},
    {"verify_send_cmio_response", machine_class_index_verify_send_cmio_response},
});

/// \brief This is the cartesi.machine() constructor implementation.
/// \param L Lua state.
static int machine_ctor(lua_State *L) {
    lua_settop(L, 3);
    auto &managed_machine = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr));
    const char *runtime_config = !lua_isnil(L, 3) ? clua_check_json_string(L, 3) : nullptr;
    if (!lua_isstring(L, 2)) {
        const char *config = clua_check_json_string(L, 2);
        if (cm_create(config, runtime_config, &managed_machine.get()) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        const char *dir = luaL_checkstring(L, 2);
        if (cm_load(dir, runtime_config, &managed_machine.get()) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }
    return 1;
}

/// \brief Tag to identify the machine class-like constructor
struct machine_class {};

int clua_machine_init(lua_State *L, int ctxidx) {
    clua_createnewtype<clua_managed_cm_ptr<unsigned char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<std::string>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<nlohmann::json>>(L, ctxidx);
    if (!clua_typeexists<machine_class>(L, ctxidx)) {
        clua_createtype<machine_class>(L, "cartesi machine class", ctxidx);
        clua_setmethods<machine_class>(L, machine_class_index.data(), 0, ctxidx);
        static const auto machine_class_meta = cartesi::clua_make_luaL_Reg_array({
            {"__call", machine_ctor},
        });
        clua_setmetamethods<machine_class>(L, machine_class_meta.data(), 0, ctxidx);
    }
    return 1;
}

int clua_machine_export(lua_State *L, int ctxidx) {
    const int ctxabsidx = lua_absindex(L, ctxidx);
    // cartesi
    clua_machine_init(L, ctxabsidx);                    // cartesi
    lua_newtable(L);                                    // cartesi machine_class
    clua_setmetatable<machine_class>(L, -1, ctxabsidx); // cartesi machine_class
    lua_setfield(L, -2, "machine");                     // cartesi
    return 0;
}

} // namespace cartesi
