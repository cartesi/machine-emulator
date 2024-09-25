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

#include <cstring>
#include <unordered_map>

#include "base64.h"
#include "clua.h"
#include "os-features.h"
#include "riscv-constants.h"

namespace cartesi {

template <>
void clua_delete<unsigned char>(unsigned char *ptr) { // NOLINT(readability-non-const-parameter)
    delete[] ptr;
}

template <>
void clua_delete<cm_machine>(cm_machine *ptr) {
    cm_delete(ptr);
}

template <>
void clua_delete<std::string>(std::string *ptr) {
    delete ptr;
}

template <>
void clua_delete<nlohmann::json>(nlohmann::json *ptr) {
    delete ptr;
}

cm_csr clua_check_cm_proc_csr(lua_State *L, int idx) try {
    /// \brief Mapping between CSR names and C API constants
    const static std::unordered_map<std::string, cm_csr> g_cm_proc_csr_name = {
        // clang-format off
        {"x0", CM_CSR_X0},
        {"x1", CM_CSR_X1},
        {"x2", CM_CSR_X2},
        {"x3", CM_CSR_X3},
        {"x4", CM_CSR_X4},
        {"x5", CM_CSR_X5},
        {"x6", CM_CSR_X6},
        {"x7", CM_CSR_X7},
        {"x8", CM_CSR_X8},
        {"x9", CM_CSR_X9},
        {"x10", CM_CSR_X10},
        {"x11", CM_CSR_X11},
        {"x12", CM_CSR_X12},
        {"x13", CM_CSR_X13},
        {"x14", CM_CSR_X14},
        {"x15", CM_CSR_X15},
        {"x16", CM_CSR_X16},
        {"x17", CM_CSR_X17},
        {"x18", CM_CSR_X18},
        {"x19", CM_CSR_X19},
        {"x20", CM_CSR_X20},
        {"x21", CM_CSR_X21},
        {"x22", CM_CSR_X22},
        {"x23", CM_CSR_X23},
        {"x24", CM_CSR_X24},
        {"x25", CM_CSR_X25},
        {"x26", CM_CSR_X26},
        {"x27", CM_CSR_X27},
        {"x28", CM_CSR_X28},
        {"x29", CM_CSR_X29},
        {"x30", CM_CSR_X30},
        {"x31", CM_CSR_X31},
        {"f0", CM_CSR_F0},
        {"f1", CM_CSR_F1},
        {"f2", CM_CSR_F2},
        {"f3", CM_CSR_F3},
        {"f4", CM_CSR_F4},
        {"f5", CM_CSR_F5},
        {"f6", CM_CSR_F6},
        {"f7", CM_CSR_F7},
        {"f8", CM_CSR_F8},
        {"f9", CM_CSR_F9},
        {"f10", CM_CSR_F10},
        {"f11", CM_CSR_F11},
        {"f12", CM_CSR_F12},
        {"f13", CM_CSR_F13},
        {"f14", CM_CSR_F14},
        {"f15", CM_CSR_F15},
        {"f16", CM_CSR_F16},
        {"f17", CM_CSR_F17},
        {"f18", CM_CSR_F18},
        {"f19", CM_CSR_F19},
        {"f20", CM_CSR_F20},
        {"f21", CM_CSR_F21},
        {"f22", CM_CSR_F22},
        {"f23", CM_CSR_F23},
        {"f24", CM_CSR_F24},
        {"f25", CM_CSR_F25},
        {"f26", CM_CSR_F26},
        {"f27", CM_CSR_F27},
        {"f28", CM_CSR_F28},
        {"f29", CM_CSR_F29},
        {"f30", CM_CSR_F30},
        {"f31", CM_CSR_F31},
        {"pc", CM_CSR_PC},
        {"fcsr", CM_CSR_FCSR},
        {"mvendorid", CM_CSR_MVENDORID},
        {"marchid", CM_CSR_MARCHID},
        {"mimpid", CM_CSR_MIMPID},
        {"mcycle", CM_CSR_MCYCLE},
        {"icycleinstret", CM_CSR_ICYCLEINSTRET},
        {"mstatus", CM_CSR_MSTATUS},
        {"mtvec", CM_CSR_MTVEC},
        {"mscratch", CM_CSR_MSCRATCH},
        {"mepc", CM_CSR_MEPC},
        {"mcause", CM_CSR_MCAUSE},
        {"mtval", CM_CSR_MTVAL},
        {"misa", CM_CSR_MISA},
        {"mie", CM_CSR_MIE},
        {"mip", CM_CSR_MIP},
        {"medeleg", CM_CSR_MEDELEG},
        {"mideleg", CM_CSR_MIDELEG},
        {"mcounteren", CM_CSR_MCOUNTEREN},
        {"menvcfg", CM_CSR_MENVCFG},
        {"stvec", CM_CSR_STVEC},
        {"sscratch", CM_CSR_SSCRATCH},
        {"sepc", CM_CSR_SEPC},
        {"scause", CM_CSR_SCAUSE},
        {"stval", CM_CSR_STVAL},
        {"satp", CM_CSR_SATP},
        {"scounteren", CM_CSR_SCOUNTEREN},
        {"senvcfg", CM_CSR_SENVCFG},
        {"ilrsc", CM_CSR_ILRSC},
        {"iflags", CM_CSR_IFLAGS},
        {"iflags_prv", CM_CSR_IFLAGS_PRV},
        {"iflags_x", CM_CSR_IFLAGS_X},
        {"iflags_y", CM_CSR_IFLAGS_Y},
        {"iflags_h", CM_CSR_IFLAGS_H},
        {"iunrep", CM_CSR_IUNREP},
        {"clint_mtimecmp", CM_CSR_CLINT_MTIMECMP},
        {"plic_girqpend", CM_CSR_PLIC_GIRQPEND},
        {"plic_girqsrvd", CM_CSR_PLIC_GIRQSRVD},
        {"htif_tohost", CM_CSR_HTIF_TOHOST},
        {"htif_tohost_dev", CM_CSR_HTIF_TOHOST_DEV},
        {"htif_tohost_cmd", CM_CSR_HTIF_TOHOST_CMD},
        {"htif_tohost_reason", CM_CSR_HTIF_TOHOST_REASON},
        {"htif_tohost_data", CM_CSR_HTIF_TOHOST_DATA},
        {"htif_fromhost", CM_CSR_HTIF_FROMHOST},
        {"htif_fromhost_dev", CM_CSR_HTIF_FROMHOST_DEV},
        {"htif_fromhost_cmd", CM_CSR_HTIF_FROMHOST_CMD},
        {"htif_fromhost_reason", CM_CSR_HTIF_FROMHOST_REASON},
        {"htif_fromhost_data", CM_CSR_HTIF_FROMHOST_DATA},
        {"htif_ihalt", CM_CSR_HTIF_IHALT},
        {"htif_iconsole", CM_CSR_HTIF_ICONSOLE},
        {"htif_iyield", CM_CSR_HTIF_IYIELD},
        {"uarch_x0", CM_CSR_UARCH_X0},
        {"uarch_x1", CM_CSR_UARCH_X1},
        {"uarch_x2", CM_CSR_UARCH_X2},
        {"uarch_x3", CM_CSR_UARCH_X3},
        {"uarch_x4", CM_CSR_UARCH_X4},
        {"uarch_x5", CM_CSR_UARCH_X5},
        {"uarch_x6", CM_CSR_UARCH_X6},
        {"uarch_x7", CM_CSR_UARCH_X7},
        {"uarch_x8", CM_CSR_UARCH_X8},
        {"uarch_x9", CM_CSR_UARCH_X9},
        {"uarch_x10", CM_CSR_UARCH_X10},
        {"uarch_x11", CM_CSR_UARCH_X11},
        {"uarch_x12", CM_CSR_UARCH_X12},
        {"uarch_x13", CM_CSR_UARCH_X13},
        {"uarch_x14", CM_CSR_UARCH_X14},
        {"uarch_x15", CM_CSR_UARCH_X15},
        {"uarch_x16", CM_CSR_UARCH_X16},
        {"uarch_x17", CM_CSR_UARCH_X17},
        {"uarch_x18", CM_CSR_UARCH_X18},
        {"uarch_x19", CM_CSR_UARCH_X19},
        {"uarch_x20", CM_CSR_UARCH_X20},
        {"uarch_x21", CM_CSR_UARCH_X21},
        {"uarch_x22", CM_CSR_UARCH_X22},
        {"uarch_x23", CM_CSR_UARCH_X23},
        {"uarch_x24", CM_CSR_UARCH_X24},
        {"uarch_x25", CM_CSR_UARCH_X25},
        {"uarch_x26", CM_CSR_UARCH_X26},
        {"uarch_x27", CM_CSR_UARCH_X27},
        {"uarch_x28", CM_CSR_UARCH_X28},
        {"uarch_x29", CM_CSR_UARCH_X29},
        {"uarch_x30", CM_CSR_UARCH_X30},
        {"uarch_x31", CM_CSR_UARCH_X31},
        {"uarch_pc", CM_CSR_UARCH_PC},
        {"uarch_cycle", CM_CSR_UARCH_CYCLE},
        {"uarch_halt_flag", CM_CSR_UARCH_HALT_FLAG},
        // clang-format on
    };
    const char *name = luaL_checkstring(L, idx);
    auto got = g_cm_proc_csr_name.find(name);
    if (got == g_cm_proc_csr_name.end()) {
        luaL_argerror(L, idx, "unknown csr");
    }
    return got->second;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return CM_CSR_UNKNOWN; // will not be reached
} catch (...) {
    luaL_error(L, "unknown error with csr type conversion");
    return CM_CSR_UNKNOWN; // will not be reached
}

void clua_check_cm_hash(lua_State *L, int idx, cm_hash *c_hash) {
    if (lua_isstring(L, idx)) {
        size_t len = 0;
        const char *data = lua_tolstring(L, idx, &len);
        if (len != sizeof(cm_hash)) {
            luaL_error(L, "hash length must be 32 bytes");
        }
        memcpy(c_hash, data, sizeof(cm_hash));
    } else {
        luaL_error(L, "hash length must be 32 bytes");
    }
}

void clua_push_cm_hash(lua_State *L, const cm_hash *hash) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(hash), CM_HASH_SIZE);
}

static int64_t clua_get_array_table_len(lua_State *L, int tabidx) {
    if (!lua_istable(L, tabidx)) {
        return -1;
    }
    int64_t len = 0;
    lua_pushvalue(L, tabidx);        // push table
    lua_pushnil(L);                  // push key
    while (lua_next(L, -2)) {        // replace key, push value
        if (!lua_isinteger(L, -2)) { // non integer key, not an array
            lua_pop(L, 3);
            return -1;
        }
        const int64_t i = lua_tointeger(L, -2);
        if (i <= 0) { // invalid index, not an array
            lua_pop(L, 3);
            return -1;
        }
        len = std::max(i, len);
        lua_pop(L, 1); // pop value
    }
    lua_pop(L, 1); // pop key
    return len;
}

static nlohmann::json &clua_push_json_value_ref(lua_State *L, int ctxidx, int idx, bool base64encode = false) {
    nlohmann::json &j = *clua_push_new_managed_toclose_ptr(L, nlohmann::json(), ctxidx);
    idx -= idx < 0 ? 1 : 0; // adjust offset after pushing j reference
    switch (lua_type(L, idx)) {
        case LUA_TTABLE: {
            const int64_t len = clua_get_array_table_len(L, idx);
            if (len >= 0) { // array
                j = nlohmann::json::array();
                for (int64_t i = 1; i <= len; ++i) {
                    lua_geti(L, idx, i);
                    j.push_back(clua_push_json_value_ref(L, ctxidx, -1, base64encode));
                    lua_pop(L, 2); // pop value, child j reference
                }
            } else { // object
                j = nlohmann::json::object();
                lua_pushvalue(L, idx);    // push table
                lua_pushnil(L);           // push key
                while (lua_next(L, -2)) { // update key, push value
                    if (!lua_isstring(L, -2)) {
                        luaL_error(L, "table maps cannot contain keys of type %s", lua_typename(L, lua_type(L, -2)));
                    }
                    size_t len = 0;
                    const char *ptr = lua_tolstring(L, -2, &len);
                    const std::string_view key(ptr, len);
                    const bool base64encode_child = base64encode || key == "read_hash" || key == "read" ||
                        key == "sibling_hashes" || key == "written_hash" || key == "written" || key == "target_hash" ||
                        key == "root_hash";
                    j[key] = clua_push_json_value_ref(L, ctxidx, -1, base64encode_child);
                    lua_pop(L, 2); // pop value, child j reference
                }
                lua_pop(L, 1); // pop table
            }
            break;
        }
        case LUA_TNUMBER: {
            if (lua_isinteger(L, idx)) {
                j = lua_tointeger(L, idx);
            } else { // floating point
                j = lua_tonumber(L, idx);
            }
            break;
        }
        case LUA_TSTRING: {
            size_t len = 0;
            const char *ptr = lua_tolstring(L, idx, &len);
            const std::string_view data(ptr, len);
            if (base64encode) {
                j = encode_base64(data);
            } else {
                j = data;
            }
            break;
        }
        case LUA_TBOOLEAN:
            j = static_cast<bool>(lua_toboolean(L, idx));
            break;
        case LUA_TNIL:
            j = nullptr;
            break;
        default:
            luaL_error(L, "lua value of type %s cannot be serialized to JSON", lua_typename(L, lua_type(L, idx)));
            break;
    }
    return j;
}

const char *clua_check_json_string(lua_State *L, int idx, int indent, int ctxidx) {
    assert(idx > 0);
    try {
        const nlohmann::json &j = clua_push_json_value_ref(L, ctxidx, idx);
        std::string &s = *clua_push_new_managed_toclose_ptr(L, j.dump(indent), ctxidx);
        lua_pushlstring(L, s.data(), s.size());
        lua_replace(L, idx);             // replace the Lua value with its JSON string representation
        lua_pop(L, 2);                   // pop s, j references
        return luaL_checkstring(L, idx); // return the string
    } catch (std::exception &e) {
        luaL_error(L, "failed to parse JSON from a table: %s", e.what());
        return nullptr;
    }
}

static void clua_push_json_value(lua_State *L, int ctxidx, const nlohmann::json &j, bool base64decode = false) {
    switch (j.type()) {
        case nlohmann::json::value_t::array: {
            lua_createtable(L, static_cast<int>(j.size()), 0);
            int64_t i = 1;
            for (auto it = j.begin(); it != j.end(); ++it, ++i) {
                clua_push_json_value(L, ctxidx, *it, base64decode);
                lua_rawseti(L, -2, i);
            }
            break;
        }
        case nlohmann::json::value_t::object: {
            lua_createtable(L, 0, static_cast<int>(j.size()));
            for (const auto &el : j.items()) {
                const std::string &key = el.key();
                const bool base64decode_child = base64decode || key == "read_hash" || key == "read" ||
                    key == "sibling_hashes" || key == "written_hash" || key == "written" || key == "target_hash" ||
                    key == "root_hash";
                clua_push_json_value(L, ctxidx, el.value(), base64decode_child);
                lua_setfield(L, -2, key.c_str());
            }
            break;
        }
        case nlohmann::json::value_t::string: {
            const std::string_view &data = j.template get<std::string_view>();
            if (base64decode) {
                lua_pushnil(L); // reserve a slot in the stack (needed because of lua_toclose semantics)
                std::string &binary_data = *clua_push_new_managed_toclose_ptr(L, decode_base64(data), ctxidx);
                lua_pushlstring(L, binary_data.data(), binary_data.length());
                lua_replace(L, -3); // move into the placeholder slot
                lua_pop(L, 1);      // pop binary_data reference
            } else {
                lua_pushlstring(L, data.data(), data.length());
            }
            break;
        }
        case nlohmann::json::value_t::number_integer:
            lua_pushinteger(L, j.template get<int64_t>());
            break;
        case nlohmann::json::value_t::number_unsigned:
            lua_pushinteger(L, static_cast<int64_t>(j.template get<uint64_t>()));
            break;
        case nlohmann::json::value_t::number_float:
            lua_pushnumber(L, j.template get<double>());
            break;
        case nlohmann::json::value_t::boolean:
            lua_pushboolean(L, j.template get<bool>());
            break;
        case nlohmann::json::value_t::null:
            lua_pushnil(L);
            break;
        default:
            luaL_error(L, "JSON value of type %s cannot be to Lua", j.type_name());
            break;
    }
}

void clua_push_json_table(lua_State *L, const char *s, int ctxidx) {
    try {
        lua_pushnil(L); // reserve a slot in the stack (needed because of lua_toclose semantics)
        const nlohmann::json &j = *clua_push_new_managed_toclose_ptr(L, nlohmann::json::parse(s), ctxidx);
        clua_push_json_value(L, ctxidx, j);
        lua_replace(L, -3); // move into the placeholder slot
        lua_pop(L, 1);      // pop j reference
    } catch (std::exception &e) {
        luaL_error(L, "failed to parse JSON from a string: %s", e.what());
    }
}

} // namespace cartesi
