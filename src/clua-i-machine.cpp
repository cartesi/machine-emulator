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

#include "clua-i-machine.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <json.hpp>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

#include "base64.hpp"
#include "clua.hpp"
#include "cm.h"
#include "hash-tree-constants.hpp"

namespace cartesi {

void clua_delete(unsigned char *ptr) { // NOLINT(readability-non-const-parameter)
    delete[] ptr;
}

void clua_delete(cm_machine *ptr) {
    cm_delete(ptr); // this call should never fail
}

void clua_delete(std::string *ptr) {
    delete ptr;
}

void clua_delete(nlohmann::json *ptr) {
    delete ptr;
}

cm_reg clua_check_cm_proc_reg(lua_State *L, int idx) try {
    /// \brief Mapping between register names and C API constants
    const static std::unordered_map<std::string, cm_reg> g_cm_proc_reg_name = {
        // clang-format off
        {"x0", CM_REG_X0},
        {"x1", CM_REG_X1},
        {"x2", CM_REG_X2},
        {"x3", CM_REG_X3},
        {"x4", CM_REG_X4},
        {"x5", CM_REG_X5},
        {"x6", CM_REG_X6},
        {"x7", CM_REG_X7},
        {"x8", CM_REG_X8},
        {"x9", CM_REG_X9},
        {"x10", CM_REG_X10},
        {"x11", CM_REG_X11},
        {"x12", CM_REG_X12},
        {"x13", CM_REG_X13},
        {"x14", CM_REG_X14},
        {"x15", CM_REG_X15},
        {"x16", CM_REG_X16},
        {"x17", CM_REG_X17},
        {"x18", CM_REG_X18},
        {"x19", CM_REG_X19},
        {"x20", CM_REG_X20},
        {"x21", CM_REG_X21},
        {"x22", CM_REG_X22},
        {"x23", CM_REG_X23},
        {"x24", CM_REG_X24},
        {"x25", CM_REG_X25},
        {"x26", CM_REG_X26},
        {"x27", CM_REG_X27},
        {"x28", CM_REG_X28},
        {"x29", CM_REG_X29},
        {"x30", CM_REG_X30},
        {"x31", CM_REG_X31},
        {"f0", CM_REG_F0},
        {"f1", CM_REG_F1},
        {"f2", CM_REG_F2},
        {"f3", CM_REG_F3},
        {"f4", CM_REG_F4},
        {"f5", CM_REG_F5},
        {"f6", CM_REG_F6},
        {"f7", CM_REG_F7},
        {"f8", CM_REG_F8},
        {"f9", CM_REG_F9},
        {"f10", CM_REG_F10},
        {"f11", CM_REG_F11},
        {"f12", CM_REG_F12},
        {"f13", CM_REG_F13},
        {"f14", CM_REG_F14},
        {"f15", CM_REG_F15},
        {"f16", CM_REG_F16},
        {"f17", CM_REG_F17},
        {"f18", CM_REG_F18},
        {"f19", CM_REG_F19},
        {"f20", CM_REG_F20},
        {"f21", CM_REG_F21},
        {"f22", CM_REG_F22},
        {"f23", CM_REG_F23},
        {"f24", CM_REG_F24},
        {"f25", CM_REG_F25},
        {"f26", CM_REG_F26},
        {"f27", CM_REG_F27},
        {"f28", CM_REG_F28},
        {"f29", CM_REG_F29},
        {"f30", CM_REG_F30},
        {"f31", CM_REG_F31},
        {"pc", CM_REG_PC},
        {"fcsr", CM_REG_FCSR},
        {"mvendorid", CM_REG_MVENDORID},
        {"marchid", CM_REG_MARCHID},
        {"mimpid", CM_REG_MIMPID},
        {"mcycle", CM_REG_MCYCLE},
        {"icycleinstret", CM_REG_ICYCLEINSTRET},
        {"mstatus", CM_REG_MSTATUS},
        {"mtvec", CM_REG_MTVEC},
        {"mscratch", CM_REG_MSCRATCH},
        {"mepc", CM_REG_MEPC},
        {"mcause", CM_REG_MCAUSE},
        {"mtval", CM_REG_MTVAL},
        {"misa", CM_REG_MISA},
        {"mie", CM_REG_MIE},
        {"mip", CM_REG_MIP},
        {"medeleg", CM_REG_MEDELEG},
        {"mideleg", CM_REG_MIDELEG},
        {"mcounteren", CM_REG_MCOUNTEREN},
        {"menvcfg", CM_REG_MENVCFG},
        {"stvec", CM_REG_STVEC},
        {"sscratch", CM_REG_SSCRATCH},
        {"sepc", CM_REG_SEPC},
        {"scause", CM_REG_SCAUSE},
        {"stval", CM_REG_STVAL},
        {"satp", CM_REG_SATP},
        {"scounteren", CM_REG_SCOUNTEREN},
        {"senvcfg", CM_REG_SENVCFG},
        {"ilrsc", CM_REG_ILRSC},
        {"iprv", CM_REG_IPRV},
        {"iflags_X", CM_REG_IFLAGS_X},
        {"iflags_Y", CM_REG_IFLAGS_Y},
        {"iflags_H", CM_REG_IFLAGS_H},
        {"iunrep", CM_REG_IUNREP},
        {"clint_mtimecmp", CM_REG_CLINT_MTIMECMP},
        {"plic_girqpend", CM_REG_PLIC_GIRQPEND},
        {"plic_girqsrvd", CM_REG_PLIC_GIRQSRVD},
        {"htif_tohost", CM_REG_HTIF_TOHOST},
        {"htif_tohost_dev", CM_REG_HTIF_TOHOST_DEV},
        {"htif_tohost_cmd", CM_REG_HTIF_TOHOST_CMD},
        {"htif_tohost_reason", CM_REG_HTIF_TOHOST_REASON},
        {"htif_tohost_data", CM_REG_HTIF_TOHOST_DATA},
        {"htif_fromhost", CM_REG_HTIF_FROMHOST},
        {"htif_fromhost_dev", CM_REG_HTIF_FROMHOST_DEV},
        {"htif_fromhost_cmd", CM_REG_HTIF_FROMHOST_CMD},
        {"htif_fromhost_reason", CM_REG_HTIF_FROMHOST_REASON},
        {"htif_fromhost_data", CM_REG_HTIF_FROMHOST_DATA},
        {"htif_ihalt", CM_REG_HTIF_IHALT},
        {"htif_iconsole", CM_REG_HTIF_ICONSOLE},
        {"htif_iyield", CM_REG_HTIF_IYIELD},
        {"uarch_x0", CM_REG_UARCH_X0},
        {"uarch_x1", CM_REG_UARCH_X1},
        {"uarch_x2", CM_REG_UARCH_X2},
        {"uarch_x3", CM_REG_UARCH_X3},
        {"uarch_x4", CM_REG_UARCH_X4},
        {"uarch_x5", CM_REG_UARCH_X5},
        {"uarch_x6", CM_REG_UARCH_X6},
        {"uarch_x7", CM_REG_UARCH_X7},
        {"uarch_x8", CM_REG_UARCH_X8},
        {"uarch_x9", CM_REG_UARCH_X9},
        {"uarch_x10", CM_REG_UARCH_X10},
        {"uarch_x11", CM_REG_UARCH_X11},
        {"uarch_x12", CM_REG_UARCH_X12},
        {"uarch_x13", CM_REG_UARCH_X13},
        {"uarch_x14", CM_REG_UARCH_X14},
        {"uarch_x15", CM_REG_UARCH_X15},
        {"uarch_x16", CM_REG_UARCH_X16},
        {"uarch_x17", CM_REG_UARCH_X17},
        {"uarch_x18", CM_REG_UARCH_X18},
        {"uarch_x19", CM_REG_UARCH_X19},
        {"uarch_x20", CM_REG_UARCH_X20},
        {"uarch_x21", CM_REG_UARCH_X21},
        {"uarch_x22", CM_REG_UARCH_X22},
        {"uarch_x23", CM_REG_UARCH_X23},
        {"uarch_x24", CM_REG_UARCH_X24},
        {"uarch_x25", CM_REG_UARCH_X25},
        {"uarch_x26", CM_REG_UARCH_X26},
        {"uarch_x27", CM_REG_UARCH_X27},
        {"uarch_x28", CM_REG_UARCH_X28},
        {"uarch_x29", CM_REG_UARCH_X29},
        {"uarch_x30", CM_REG_UARCH_X30},
        {"uarch_x31", CM_REG_UARCH_X31},
        {"uarch_pc", CM_REG_UARCH_PC},
        {"uarch_cycle", CM_REG_UARCH_CYCLE},
        {"uarch_halt_flag", CM_REG_UARCH_HALT_FLAG},
        {"unknown_", CM_REG_UNKNOWN_},
        {"first_", CM_REG_FIRST_},
        {"last_", CM_REG_LAST_},
        // clang-format on
    };
    const char *name = luaL_checkstring(L, idx);
    auto got = g_cm_proc_reg_name.find(name);
    if (got == g_cm_proc_reg_name.end()) {
        luaL_argerror(L, idx, "unknown register");
    }
    return got->second;
} catch (const std::exception &e) {
    luaL_error(L, "%s", e.what());
    return CM_REG_UNKNOWN_; // will not be reached
} catch (...) {
    luaL_error(L, "unknown error with register type conversion");
    return CM_REG_UNKNOWN_; // will not be reached
}

void clua_check_cm_hash(lua_State *L, int idx, cm_hash *c_hash) {
    if (lua_isstring(L, idx) != 0) {
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
    if (lua_istable(L, tabidx) == 0) {
        return -1;
    }
    int64_t len = 0;
    lua_pushvalue(L, tabidx);            // push table
    lua_pushnil(L);                      // push key
    while (lua_next(L, -2) != 0) {       // replace key, push value
        if (lua_isinteger(L, -2) == 0) { // non integer key, not an array
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

static const nlohmann::json &clua_get_machine_schema_dict(lua_State *L);

/// \brief Resolves a named type against the user dictionary first, then the machine dictionary.
/// \details nullptr yields an empty (passthrough) schema; an unknown name is an error.
/// \brief Resolves a type name to its schema definition, following alias chains.
/// \details A name is looked up in the user dictionary first, then the machine dictionary. It maps
/// either to an object schema, which is returned, or to a string. A string naming a different type
/// is an alias and is followed. A string naming itself is a leaf primitive (Base64, ArrayIndex,
/// Schema) and is returned as is. Following aliases is what lets a user type be a bare top-level
/// alias to a compound machine type (e.g. "AccessLog"), not just to a leaf. An unknown name or a
/// cyclic chain is an error.
static const nlohmann::json &clua_resolve_type_schema(lua_State *L, std::string_view type_name,
    const nlohmann::json &user_schema_dict) {
    static const nlohmann::json empty_schema;
    // The chain cannot be longer than the number of distinct names, so bound the walk generously
    // to turn a cyclic user dictionary into an error rather than an infinite loop.
    for (int hops = 0; hops < 1024; ++hops) {
        // "Default" and the empty name carry no schema, so the value passes through untranslated,
        // as a plain table. This holds for a top-level name and for a field type alike.
        if (type_name.empty() || type_name == "Default") {
            return empty_schema;
        }
        const nlohmann::json *value = nullptr;
        if (user_schema_dict.contains(type_name)) {
            value = &user_schema_dict.at(type_name);
        } else {
            const auto &machine_schema_dict = clua_get_machine_schema_dict(L);
            if (!machine_schema_dict.contains(type_name)) {
                throw std::runtime_error{"type \"" + std::string{type_name} + "\" is not defined in schema dictionary"};
            }
            value = &machine_schema_dict.at(type_name);
        }
        if (!value->is_string()) {
            return *value; // object schema
        }
        const auto next = value->template get<std::string_view>();
        if (next == type_name) {
            return *value; // self-referential leaf primitive
        }
        type_name = next; // follow the alias
    }
    throw std::runtime_error{"type \"" + std::string{type_name} + "\" has a cyclic schema definition"};
}

static const nlohmann::json &clua_get_type_schema(lua_State *L, const char *type_name,
    const nlohmann::json &user_schema_dict = nlohmann::json()) {
    static const nlohmann::json empty_schema;
    if (type_name == nullptr) {
        return empty_schema;
    }
    return clua_resolve_type_schema(L, type_name, user_schema_dict);
}

/// \brief Resolves the schema of a field within a parent definition.
/// \details A field absent in the parent yields an empty (passthrough) schema. The field's type name
/// is resolved through the same alias chain as a top-level name.
static const nlohmann::json &clua_get_field_schema(lua_State *L, const std::string_view field_name,
    const nlohmann::json &schema, const nlohmann::json &user_schema_dict) {
    static const nlohmann::json empty_schema;
    if (!schema.contains(field_name)) {
        return empty_schema;
    }
    return clua_resolve_type_schema(L, schema.at(field_name).template get<std::string_view>(), user_schema_dict);
}

static nlohmann::json &clua_push_managed_toclose_json_ref(lua_State *L, int idx, const nlohmann::json &schema,
    const nlohmann::json &user_schema_dict, int ctxidx) {
    nlohmann::json &j = *clua_push_new_managed_toclose_ptr(L, nlohmann::json(), ctxidx);
    idx -= idx < 0 ? 1 : 0; // adjust offset after pushing j reference
    switch (lua_type(L, idx)) {
        case LUA_TTABLE: {
            const int64_t len = clua_get_array_table_len(L, idx);
            if (len >= 0) { // array
                j = nlohmann::json::array();
                const auto &field_schema = clua_get_field_schema(L, "items", schema, user_schema_dict);
                for (int64_t i = 1; i <= len; ++i) {
                    lua_geti(L, idx, i);
                    j.push_back(clua_push_managed_toclose_json_ref(L, -1, field_schema, user_schema_dict, ctxidx));
                    lua_pop(L, 2); // pop value, child j reference
                }
            } else { // object
                j = nlohmann::json::object();
                lua_pushvalue(L, idx);         // push table
                lua_pushnil(L);                // push key
                while (lua_next(L, -2) != 0) { // update key, push value
                    if (lua_isstring(L, -2) == 0) {
                        luaL_error(L, "table maps cannot contain keys of type %s", lua_typename(L, lua_type(L, -2)));
                    }
                    const char *field_name = lua_tostring(L, -2);
                    const auto &field_schema = clua_get_field_schema(L, field_name, schema, user_schema_dict);
                    j[field_name] = clua_push_managed_toclose_json_ref(L, -1, field_schema, user_schema_dict, ctxidx);
                    lua_pop(L, 2); // pop value, child j reference
                }
                lua_pop(L, 1); // pop table
            }
            break;
        }
        case LUA_TNUMBER: {
            if (lua_isinteger(L, idx) != 0) {
                int64_t v = lua_tointeger(L, idx);
                if (schema.is_string() && schema.template get<std::string_view>() == "ArrayIndex") {
                    v -= 1;
                }
                j = v;
            } else { // floating point
                j = lua_tonumber(L, idx);
            }
            break;
        }
        case LUA_TSTRING: {
            size_t len = 0;
            const char *ptr = lua_tolstring(L, idx, &len);
            const std::string_view data(ptr, len);
            if (schema.is_string() && schema.template get<std::string_view>() == "Base64") {
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

static void clua_push_json_value(lua_State *L, const nlohmann::json &j, const nlohmann::json &schema,
    const nlohmann::json &user_schema_dict, int ctxidx) {
    switch (j.type()) {
        case nlohmann::json::value_t::array: {
            const auto &field_schema = clua_get_field_schema(L, "items", schema, user_schema_dict);
            lua_createtable(L, static_cast<int>(j.size()), 0);
            int64_t i = 1;
            for (auto it = j.begin(); it != j.end(); ++it, ++i) {
                clua_push_json_value(L, *it, field_schema, user_schema_dict, ctxidx);
                lua_rawseti(L, -2, i);
            }
            break;
        }
        case nlohmann::json::value_t::object: {
            lua_createtable(L, 0, static_cast<int>(j.size()));
            for (const auto &el : j.items()) {
                const auto &field_name = el.key();
                const auto &field_schema = clua_get_field_schema(L, field_name, schema, user_schema_dict);
                clua_push_json_value(L, el.value(), field_schema, user_schema_dict, ctxidx);
                lua_setfield(L, -2, field_name.c_str());
            }
            break;
        }
        case nlohmann::json::value_t::string: {
            const std::string_view &data = j.template get<std::string_view>();
            if (schema.is_string() && schema.template get<std::string_view>() == "Base64") {
                lua_pushnil(L); // reserve a slot in the stack (needed because of lua_toclose semantics)
                std::string &binary_data = *clua_push_new_managed_toclose_ptr(L, decode_base64(data), ctxidx);
                lua_pushlstring(L, binary_data.data(), binary_data.length());
                lua_replace(L, -3); // move into the placeholder slot
                lua_pop(L, 1);      // pop binary_data reference
            } else if (schema.is_object() && schema.contains(data)) {
                static const nlohmann::json empty_schema;
                clua_push_json_value(L, schema.at(data), empty_schema, user_schema_dict, ctxidx);
            } else {
                lua_pushlstring(L, data.data(), data.length());
            }
            break;
        }
        case nlohmann::json::value_t::number_integer: {
            int64_t v = j.template get<int64_t>();
            if (schema.is_string() && schema.template get<std::string_view>() == "ArrayIndex") {
                v += 1;
            }
            lua_pushinteger(L, v);
            break;
        }
        case nlohmann::json::value_t::number_unsigned: {
            auto v = static_cast<int64_t>(j.template get<uint64_t>());
            if (schema.is_string() && schema.template get<std::string_view>() == "ArrayIndex") {
                v += 1;
            }
            lua_pushinteger(L, v);
            break;
        }
        case nlohmann::json::value_t::number_float:
            lua_pushnumber(L, j.template get<double>());
            break;
        case nlohmann::json::value_t::boolean:
            lua_pushboolean(L, static_cast<int>(j.template get<bool>()));
            break;
        case nlohmann::json::value_t::null:
            lua_pushnil(L);
            break;
        default:
            luaL_error(L, "JSON value of type %s cannot be to Lua", j.type_name());
            break;
    }
}

static const nlohmann::json &clua_get_machine_schema_dict(lua_State *L) try {
    // In order to convert Lua tables <-> JSON objects we have to define a schema
    // to transform some special fields, we only care about:
    // - Binary strings (translate Base64 strings in JSON to binary strings in Lua
    //   or convert to integers of an enumeration)
    // - Array indexes (translate 0 based index in JSON to 1 based index in Lua)
    static const nlohmann::json machine_schema_dict = {
        {"Base64", "Base64"},
        {"Schema", "Schema"},
        {"InterpreterBreakReason",
            {{"failed", CM_BREAK_REASON_FAILED}, {"halted", CM_BREAK_REASON_HALTED},
                {"yielded_manually", CM_BREAK_REASON_YIELDED_MANUALLY},
                {"yielded_automatically", CM_BREAK_REASON_YIELDED_AUTOMATICALLY},
                {"yielded_softly", CM_BREAK_REASON_YIELDED_SOFTLY},
                {"reached_target_mcycle", CM_BREAK_REASON_REACHED_TARGET_MCYCLE},
                {"console_output", CM_BREAK_REASON_CONSOLE_OUTPUT}, {"console_input", CM_BREAK_REASON_CONSOLE_INPUT}}},
        {"ArrayIndex", "ArrayIndex"},
        {"Base64Array",
            {
                {"items", "Base64"},
            }},
        {"ArrayArrayIndex",
            {
                {"items", "ArrayIndex"},
            }},
        {"Proof",
            {
                {"target_hash", "Base64"},
                {"root_hash", "Base64"},
                {"sibling_hashes", "Base64Array"},
            }},
        {"Access",
            {
                {"read", "Base64"},
                {"read_hash", "Base64"},
                {"written", "Base64"},
                {"written_hash", "Base64"},
                {"sibling_hashes", "Base64Array"},
            }},
        {"AccessArray",
            {
                {"items", "Access"},
            }},
        {"Bracket",
            {
                {"where", "ArrayIndex"},
            }},
        {"BracketArray",
            {
                {"items", "Bracket"},
            }},
        {"AccessLog",
            {
                {"accesses", "AccessArray"},
                {"brackets", "BracketArray"},
            }},
        {"McycleRootHashes",
            {
                {"hashes", "Base64Array"},
                {"break_reason", "InterpreterBreakReason"},
                {"back_tree", "BackMerkleTree"},
            }},
        {"UarchCycleRootHashes",
            {{"hashes", "Base64Array"}, {"reset_indices", "ArrayArrayIndex"},
                {"break_reason", "InterpreterBreakReason"}}},
        {"BackMerkleTree",
            {
                {"context", "Base64Array"},
            }},
    };
    return machine_schema_dict;
} catch (const std::exception &e) {
    luaL_error(L, "failed to create machine schema dictionary: %s", e.what());
    static const nlohmann::json dummy;
    return dummy;
}

const nlohmann::json &clua_tojsonschemadict(lua_State *L, int idx, int ctxidx) {
    if (lua_isnoneornil(L, idx)) {
        static const nlohmann::json empty_object = nlohmann::json::object();
        return empty_object;
    }
    // A schema dictionary is plain JSON with only string/int leaves and no translated fields,
    // so the "Schema" primitive makes converting one a pure passthrough. The returned reference stays
    // valid while, and only while, the slot it pushes onto the stack remains there.
    const auto &schema = clua_get_type_schema(L, "Schema");
    return clua_push_managed_toclose_json_ref(L, idx, schema, nlohmann::json(), ctxidx);
}

const char *clua_tojson(lua_State *L, int idx, int indent, const char *schema_name,
    const nlohmann::json &user_schema_dict, int ctxidx) {
    idx = lua_absindex(L, idx);
    try {
        const nlohmann::json &schema = clua_get_type_schema(L, schema_name, user_schema_dict);
        const nlohmann::json &j = clua_push_managed_toclose_json_ref(L, idx, schema, user_schema_dict, ctxidx);
        std::string &s = *clua_push_new_managed_toclose_ptr(L, j.dump(indent), ctxidx);
        lua_pushlstring(L, s.data(), s.size());
        lua_replace(L, idx);             // replace the Lua value with its JSON string representation
        lua_pop(L, 2);                   // pop s, j references
        return luaL_checkstring(L, idx); // return the string
    } catch (const std::exception &e) {
        luaL_error(L, "failed to convert a Lua value to JSON: %s", e.what());
        return nullptr;
    }
}

void clua_fromjson(lua_State *L, const char *s, const char *schema_name, const nlohmann::json &user_schema_dict,
    int ctxidx) {
    try {
        const nlohmann::json &schema = clua_get_type_schema(L, schema_name, user_schema_dict);
        lua_pushnil(L); // reserve a slot in the stack (needed because of lua_toclose semantics)
        const nlohmann::json &j = *clua_push_new_managed_toclose_ptr(L, nlohmann::json::parse(s), ctxidx);
        clua_push_json_value(L, j, schema, user_schema_dict, ctxidx);
        lua_replace(L, -3); // move into the placeholder slot
        lua_pop(L, 1);      // pop j reference
    } catch (const std::exception &e) {
        luaL_error(L, "failed to parse JSON from a string: %s", e.what());
    }
}

/// \brief This is the machine:get_proof() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_proof(lua_State *L) {
    lua_settop(L, 4);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const int log2_target_size = static_cast<int>(luaL_checkinteger(L, 3));
    const int log2_root_size = static_cast<int>(luaL_optinteger(L, 4, cartesi::HASH_TREE_LOG2_ROOT_SIZE));
    const char *proof = nullptr;
    if (cm_get_proof(m.get(), address, log2_target_size, log2_root_size, &proof) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, proof, "Proof");
    return 1;
}

/// \brief This is the machine:get_hash_tree_stats() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_hash_tree_stats(lua_State *L) {
    lua_settop(L, 2);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const bool clear = lua_toboolean(L, 2) != 0;
    const char *stats = nullptr;
    if (cm_get_hash_tree_stats(m.get(), clear, &stats) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, stats);
    return 1;
}

static int machine_obj_index_get_initial_config(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *config = nullptr;
    if (cm_get_initial_config(m.get(), &config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, config);
    return 1;
}

/// \brief This is the machine:get_runtime_config() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_runtime_config(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *runtime_config = nullptr;
    if (cm_get_runtime_config(m.get(), &runtime_config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, runtime_config);
    return 1;
}

/// \brief This is the machine:set_runtime_config() method implementation.
/// \param L Lua state.
static int machine_obj_index_set_runtime_config(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *runtime_config = clua_tojson(L, 2);
    if (cm_set_runtime_config(m.get(), runtime_config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:get_root_hash() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_root_hash(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash root_hash{};
    if (cm_get_root_hash(m.get(), &root_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_cm_hash(L, &root_hash);
    return 1;
}

/// \brief This is the machine:read_revert_root_hash() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_revert_root_hash(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash revert_root_hash{};
    if (cm_read_revert_root_hash(m.get(), &revert_root_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_cm_hash(L, &revert_root_hash);
    return 1;
}

/// \brief This is the machine:write_revert_root_hash() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_revert_root_hash(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash revert_root_hash{};
    clua_check_cm_hash(L, 2, &revert_root_hash);
    if (cm_write_revert_root_hash(m.get(), &revert_root_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:get_node_hash() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_node_hash(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const int log2_size = static_cast<int>(luaL_checkinteger(L, 3));
    cm_hash node_hash{};
    if (cm_get_node_hash(m.get(), address, log2_size, &node_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_push_cm_hash(L, &node_hash);
    return 1;
}

/// \brief This is the machine:read_reg() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_reg(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t val{};
    if (cm_read_reg(m.get(), clua_check_cm_proc_reg(L, 2), &val) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(val));
    return 1;
}

/// \brief This is the machine:read_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_memory(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const uint64_t length = luaL_checkinteger(L, 3);
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (const std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    if (cm_read_memory(m.get(), address, managed_data.get(), length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), length);
    managed_data.reset();
    return 1;
}

/// \brief This is the machine:read_virtual_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_virtual_memory(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t address = luaL_checkinteger(L, 2);
    const uint64_t length = luaL_checkinteger(L, 3);
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (const std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    if (cm_read_virtual_memory(m.get(), address, managed_data.get(), length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), length);
    managed_data.reset();
    return 1;
}

/// \brief This is the machine:read_word() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_word(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t word_value{0};
    if (cm_read_word(m.get(), luaL_checkinteger(L, 2), &word_value) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(word_value));
    return 1;
}

/// \brief This is the machine:run() method implementation.
/// \param L Lua state.
static int machine_obj_index_run(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t mcycle_end = luaL_optinteger(L, 2, UINT64_MAX);
    cm_break_reason break_reason = CM_BREAK_REASON_FAILED;
    if (cm_run(m.get(), mcycle_end, &break_reason) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(break_reason));
    return 1;
}

static int machine_obj_index_log_step(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_break_reason break_reason = CM_BREAK_REASON_FAILED;
    if (cm_log_step(m.get(), luaL_checkinteger(L, 2), luaL_checkstring(L, 3), &break_reason) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(break_reason));
    return 1;
}

/// \brief This is the machine:reset_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_reset_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_reset_uarch(m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:get_address_ranges() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_address_ranges(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *ranges = nullptr;
    if (cm_get_address_ranges(m.get(), &ranges) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, ranges);
    return 1;
}

/// \brief This is the machine:reset_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_log_reset_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const int log_type = static_cast<int>(luaL_optinteger(L, 2, 0));
    const char *log = nullptr;
    if (cm_log_reset_uarch(m.get(), log_type, &log) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, log, "AccessLog");
    return 1;
}

/// \brief This is the machine:run_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_run_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t cycle_end = luaL_optinteger(L, 2, UINT64_MAX);
    cm_uarch_break_reason status = CM_UARCH_BREAK_REASON_FAILED;
    if (cm_run_uarch(m.get(), cycle_end, &status) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(status));
    return 1;
}

/// \brief This is the machine:log_step_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_log_step_uarch(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const int log_type = static_cast<int>(luaL_optinteger(L, 2, 0));
    const char *log = nullptr;
    if (cm_log_step_uarch(m.get(), log_type, &log) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, log, "AccessLog");
    return 1;
}

/// \brief This is the machine:store() method implementation.
/// \param L Lua state.
static int machine_obj_index_store(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *dir = luaL_checkstring(L, 2);
    const auto sharing = static_cast<cm_sharing_mode>(luaL_optinteger(L, 3, CM_SHARING_ALL));
    if (cm_store(m.get(), dir, sharing) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:clone_stored() method implementation.
/// \param L Lua state.
static int machine_obj_index_clone_stored(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *from_dir = luaL_checkstring(L, 2);
    const char *to_dir = luaL_checkstring(L, 3);
    if (cm_clone_stored(m.get(), from_dir, to_dir) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:remove_stored() method implementation.
/// \param L Lua state.
static int machine_obj_index_remove_stored(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *dir = luaL_checkstring(L, 2);
    if (cm_remove_stored(m.get(), dir) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:verify_hash_tree() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_hash_tree(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool result{};
    if (cm_verify_hash_tree(m.get(), &result) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, static_cast<int>(result));
    return 1;
}

/// \brief This is the machine:write_reg() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_reg(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_write_reg(m.get(), clua_check_cm_proc_reg(L, 2), luaL_checkinteger(L, 3)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:write_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_memory(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    size_t length{0};
    const uint64_t address = luaL_checkinteger(L, 2);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    if (cm_write_memory(m.get(), address, data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:write_virtual_memory() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_virtual_memory(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    size_t length{0};
    const uint64_t address = luaL_checkinteger(L, 2);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 3, &length));
    if (cm_write_virtual_memory(m.get(), address, data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:write_word() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_word(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    if (cm_write_word(m.get(), luaL_checkinteger(L, 2), luaL_checkinteger(L, 3)) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:translate_virtual_address() method implementation.
/// \param L Lua state.
static int machine_obj_index_translate_virtual_address(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t paddr_value{0};
    if (cm_translate_virtual_address(m.get(), luaL_checkinteger(L, 2), &paddr_value) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(paddr_value));
    return 1;
}

/// \brief This is the machine:read_console_output() method implementation.
/// \param L Lua state.
static int machine_obj_index_read_console_output(lua_State *L) {
    lua_settop(L, 2);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t max_length = luaL_optinteger(L, 2, 0);
    const bool retrieve_available_size = lua_isinteger(L, 2) != 0 && max_length == 0;
    const bool retrieve_full_buffer = lua_isnil(L, 2);

    // Retrieve the available length if needed
    if (retrieve_available_size || retrieve_full_buffer) {
        if (cm_read_console_output(m.get(), nullptr, 0, &max_length) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }

    // If only the available length is requested, return it
    if (retrieve_available_size) {
        lua_pushinteger(L, static_cast<lua_Integer>(max_length));
        return 1;
    }

    // Read the console output data
    if (max_length > 0) {
        unsigned char *buffer{};
        try {
            buffer = new unsigned char[max_length];
        } catch (const std::bad_alloc &e) {
            luaL_error(L, "failed to allocate memory for buffer");
        }

        auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(buffer));
        uint64_t read_len{0};

        if (cm_read_console_output(m.get(), managed_data.get(), max_length, &read_len) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), read_len);
        managed_data.reset();
    } else {
        lua_pushlstring(L, "", 0);
    }

    return 1;
}

/// \brief This is the machine:write_console_input() method implementation.
/// \param L Lua state.
static int machine_obj_index_write_console_input(lua_State *L) {
    lua_settop(L, 2);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const bool retrieve_available_space = lua_isnil(L, 2);

    uint64_t written_len{0};
    if (retrieve_available_space) {
        if (cm_write_console_input(m.get(), nullptr, 0, &written_len) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        size_t length{0};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 2, &length));
        if (length > 0) {
            if (cm_write_console_input(m.get(), data, length, &written_len) != 0) {
                return luaL_error(L, "%s", cm_get_last_error_message());
            }
        }
    }
    lua_pushinteger(L, static_cast<lua_Integer>(written_len));
    return 1;
}

/// \brief Replaces a memory range.
/// \param L Lua state.
static int machine_obj_index_replace_memory_range(lua_State *L) {
    lua_settop(L, 2);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *range_config = clua_tojson(L, 2);
    if (cm_replace_memory_range(m.get(), range_config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:destroy() method implementation for local machines.
/// \param L Lua state.
static int machine_obj_index_destroy(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_destroy(m.get());
    return 0;
}

/// \brief This is the machine:receive_cmio_request() method implementation.
/// \param L Lua state.
static int machine_obj_index_receive_cmio_request(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t length{};
    if (cm_receive_cmio_request(m.get(), nullptr, nullptr, nullptr, &length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    unsigned char *data{};
    try {
        data = new unsigned char[length];
    } catch (const std::bad_alloc &e) {
        luaL_error(L, "failed to allocate memory for buffer");
    }
    auto &managed_data = clua_push_to(L, clua_managed_cm_ptr<unsigned char>(data));
    uint8_t cmd{};
    uint16_t reason{};
    if (cm_receive_cmio_request(m.get(), &cmd, &reason, data, &length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, cmd);
    lua_pushinteger(L, reason);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(managed_data.get()), length);
    managed_data.reset();
    return 3;
}

/// \brief This is the machine:send_cmio_response() method implementation.
/// \param L Lua state.
static int machine_obj_index_send_cmio_response(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash revert_root_hash{};
    clua_check_cm_hash(L, 2, &revert_root_hash);
    const auto reason = static_cast<uint16_t>(luaL_checkinteger(L, 3));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 4, &length));
    if (cm_send_cmio_response(m.get(), &revert_root_hash, reason, data, length) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:log_send_cmio_response() method implementation.
/// \param L Lua state.
static int machine_obj_index_log_send_cmio_response(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash revert_root_hash{};
    clua_check_cm_hash(L, 2, &revert_root_hash);
    const auto reason = static_cast<uint16_t>(luaL_checkinteger(L, 3));
    const int log_type = static_cast<int>(luaL_optinteger(L, 5, 0));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 4, &length));
    const char *log = nullptr;
    if (cm_log_send_cmio_response(m.get(), &revert_root_hash, reason, data, length, log_type, &log) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, log, "AccessLog");
    return 1;
}

/// \brief This is the machine:is_empty() method implementation.
/// \param L Lua state.
static int machine_obj_index_is_empty(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    bool yes = false;
    if (cm_is_empty(m.get(), &yes) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushboolean(L, static_cast<int>(yes));
    return 1;
}

/// \brief This is the machine:create() method implementation.
/// \param L Lua state.
static int machine_obj_index_create(lua_State *L) {
    lua_settop(L, 4);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *runtime_config = !lua_isnil(L, 3) ? clua_tojson(L, 3) : nullptr;
    const char *dir = luaL_optstring(L, 4, nullptr);
    // Create or load a machine depending on the type of the first argument
    const char *config = clua_tojson(L, 2);
    if (cm_create(m.get(), config, runtime_config, dir) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_settop(L, 1);
    return 1;
}

/// \brief This is the machine:collect_mcycle_root_hashes() method implementation.
/// \param L Lua state.
static int machine_obj_index_collect_mcycle_root_hashes(lua_State *L) {
    lua_settop(L, 6);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t mcycle_end = luaL_checkinteger(L, 2);
    const uint64_t mcycle_period = luaL_checkinteger(L, 3);
    const uint64_t mcycle_phase = luaL_optinteger(L, 4, 0);
    const auto log2_bundle_uarch_cycle_count = static_cast<int32_t>(luaL_optinteger(L, 5, 0));
    const char *previous_back_tree = !lua_isnil(L, 6) ? clua_tojson(L, 6, -1, "BackMerkleTree") : nullptr;
    const char *result = nullptr;
    if (cm_collect_mcycle_root_hashes(m.get(), mcycle_end, mcycle_period, mcycle_phase, log2_bundle_uarch_cycle_count,
            previous_back_tree, &result) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, result, "McycleRootHashes");
    return 1;
}

/// \brief This is the machine:collect_uarch_cycle_root_hashes() method implementation.
/// \param L Lua state.
static int machine_obj_index_collect_uarch_cycle_root_hashes(lua_State *L) {
    lua_settop(L, 3);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const uint64_t mcycle_end = luaL_checkinteger(L, 2);
    const auto log2_bundle_uarch_cycle_count = static_cast<int32_t>(luaL_optinteger(L, 3, 0));
    const char *result = nullptr;
    if (cm_collect_uarch_cycle_root_hashes(m.get(), mcycle_end, log2_bundle_uarch_cycle_count, &result) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, result, "UarchCycleRootHashes");
    return 1;
}

/// \brief This is the machine:load() method implementation.
/// \param L Lua state.
static int machine_obj_index_load(lua_State *L) {
    lua_settop(L, 4);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *runtime_config = !lua_isnil(L, 3) ? clua_tojson(L, 3) : nullptr;
    const char *dir = luaL_checkstring(L, 2);
    const auto sharing = static_cast<cm_sharing_mode>(luaL_optinteger(L, 4, CM_SHARING_NONE));
    if (cm_load(m.get(), dir, runtime_config, sharing) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_settop(L, 1);
    return 1;
}

/// \brief This is the machine:get_default_machine_config() method implementation
/// \param L Lua state.
static int machine_obj_index_get_default_config(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *config = nullptr;
    if (cm_get_default_config(m.get(), &config) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    clua_fromjson(L, config);
    return 1;
}

/// \brief This is the machine:get_address_name() method implementation
/// \param L Lua state.
static int machine_obj_index_get_address_name(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    const char *name = nullptr;
    if (cm_get_address_name(m.get(), luaL_checkinteger(L, 2), &name) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushstring(L, name);
    return 1;
}

/// \brief This is the machine:get_reg_address() method implementation.
/// \param L Lua state.
static int machine_obj_index_get_reg_address(lua_State *L) {
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    uint64_t reg_address{};
    const cm_reg reg = clua_check_cm_proc_reg(L, 2);
    if (cm_get_reg_address(m.get(), reg, &reg_address) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(reg_address));
    return 1;
}

/// \brief This is the machine.verify_step() method implementation.
static int machine_obj_index_verify_step(lua_State *L) {
    lua_settop(L, 5);
    cm_hash root_hash_before{};
    clua_check_cm_hash(L, 2, &root_hash_before);
    cm_hash root_hash_after{};
    clua_check_cm_hash(L, 5, &root_hash_after);
    cm_break_reason break_reason{};
    if (cm_verify_step(&root_hash_before, luaL_checkstring(L, 3), luaL_checkinteger(L, 4), &root_hash_after,
            &break_reason) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    lua_pushinteger(L, static_cast<lua_Integer>(break_reason));
    return 1;
}

/// \brief This is the machine:verify_step_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_step_uarch(lua_State *L) {
    lua_settop(L, 4);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 2, &root_hash);
    const char *log = clua_tojson(L, 3, -1, "AccessLog");
    cm_hash target_hash{};
    clua_check_cm_hash(L, 4, &target_hash);
    if (cm_verify_step_uarch(m.get(), &root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:verify_reset_uarch() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_reset_uarch(lua_State *L) {
    lua_settop(L, 4);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash root_hash{};
    clua_check_cm_hash(L, 2, &root_hash);
    const char *log = clua_tojson(L, 3, -1, "AccessLog");
    cm_hash target_hash{};
    clua_check_cm_hash(L, 4, &target_hash);
    if (cm_verify_reset_uarch(m.get(), &root_hash, log, &target_hash) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:verify_send_cmio_response() method implementation.
/// \param L Lua state.
static int machine_obj_index_verify_send_cmio_response(lua_State *L) {
    lua_settop(L, 7);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    cm_hash revert_root_hash{};
    clua_check_cm_hash(L, 2, &revert_root_hash);
    const auto reason = static_cast<uint16_t>(luaL_checkinteger(L, 3));
    size_t length{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *data = reinterpret_cast<const unsigned char *>(luaL_checklstring(L, 4, &length));
    cm_hash root_hash{};
    clua_check_cm_hash(L, 5, &root_hash);
    const char *log = clua_tojson(L, 6, -1, "AccessLog");
    cm_hash target_hash{};
    clua_check_cm_hash(L, 7, &target_hash);
    if (cm_verify_send_cmio_response(m.get(), &revert_root_hash, reason, data, length, &root_hash, log, &target_hash) !=
        0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    return 0;
}

/// \brief This is the machine:swap() method implementation.
/// \param L Lua state.
static int machine_obj_index_swap(lua_State *L) {
    auto &m1 = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1);
    auto &m2 = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 2);
    std::swap(m1.get(), m2.get());
    return 0;
}

/// \brief Contents of the machine object metatable __index table.
static const auto machine_obj_index = cartesi::clua_make_luaL_Reg_array({
    {"create", machine_obj_index_create},
    {"collect_mcycle_root_hashes", machine_obj_index_collect_mcycle_root_hashes},
    {"collect_uarch_cycle_root_hashes", machine_obj_index_collect_uarch_cycle_root_hashes},
    {"destroy", machine_obj_index_destroy},
    {"get_default_config", machine_obj_index_get_default_config},
    {"get_initial_config", machine_obj_index_get_initial_config},
    {"get_address_name", machine_obj_index_get_address_name},
    {"get_address_ranges", machine_obj_index_get_address_ranges},
    {"get_proof", machine_obj_index_get_proof},
    {"get_hash_tree_stats", machine_obj_index_get_hash_tree_stats},
    {"get_reg_address", machine_obj_index_get_reg_address},
    {"get_root_hash", machine_obj_index_get_root_hash},
    {"read_revert_root_hash", machine_obj_index_read_revert_root_hash},
    {"write_revert_root_hash", machine_obj_index_write_revert_root_hash},
    {"get_node_hash", machine_obj_index_get_node_hash},
    {"get_runtime_config", machine_obj_index_get_runtime_config},
    {"is_empty", machine_obj_index_is_empty},
    {"load", machine_obj_index_load},
    {"log_reset_uarch", machine_obj_index_log_reset_uarch},
    {"log_send_cmio_response", machine_obj_index_log_send_cmio_response},
    {"log_step", machine_obj_index_log_step},
    {"log_step_uarch", machine_obj_index_log_step_uarch},
    {"read_console_output", machine_obj_index_read_console_output},
    {"read_memory", machine_obj_index_read_memory},
    {"read_reg", machine_obj_index_read_reg},
    {"read_virtual_memory", machine_obj_index_read_virtual_memory},
    {"read_word", machine_obj_index_read_word},
    {"receive_cmio_request", machine_obj_index_receive_cmio_request},
    {"replace_memory_range", machine_obj_index_replace_memory_range},
    {"reset_uarch", machine_obj_index_reset_uarch},
    {"run", machine_obj_index_run},
    {"run_uarch", machine_obj_index_run_uarch},
    {"send_cmio_response", machine_obj_index_send_cmio_response},
    {"set_runtime_config", machine_obj_index_set_runtime_config},
    {"store", machine_obj_index_store},
    {"clone_stored", machine_obj_index_clone_stored},
    {"remove_stored", machine_obj_index_remove_stored},
    {"swap", machine_obj_index_swap},
    {"translate_virtual_address", machine_obj_index_translate_virtual_address},
    {"verify_hash_tree", machine_obj_index_verify_hash_tree},
    {"verify_reset_uarch", machine_obj_index_verify_reset_uarch},
    {"verify_send_cmio_response", machine_obj_index_verify_send_cmio_response},
    {"verify_step", machine_obj_index_verify_step},
    {"verify_step_uarch", machine_obj_index_verify_step_uarch},
    {"write_console_input", machine_obj_index_write_console_input},
    {"write_memory", machine_obj_index_write_memory},
    {"write_reg", machine_obj_index_write_reg},
    {"write_virtual_memory", machine_obj_index_write_virtual_memory},
    {"write_word", machine_obj_index_write_word},
});

/// \brief This is the class() constructor implementation.
/// \param L Lua state.
static int machine_meta_call(lua_State *L) {
    // This receives the source machine that is being "called" as the first argument,
    // either a config or a directory as second argument, and an optional runtime config as third argument.
    lua_settop(L, 4);
    auto &m = clua_check<clua_managed_cm_ptr<cm_machine>>(L, 1); // source machine
    // We could be creating a local machine or a remote machine.
    // When we call cm_clone_empty(m.get(), ...), it creates a new empty object from the same underlying type as
    // m.get().
    auto &new_m = clua_push_to(L, clua_managed_cm_ptr<cm_machine>(nullptr));
    if (cm_clone_empty(m.get(), &new_m.get()) != 0) {
        return luaL_error(L, "%s", cm_get_last_error_message());
    }
    const char *runtime_config = !lua_isnil(L, 3) ? clua_tojson(L, 3) : nullptr;
    // Create or load a machine depending on the type of the first argument
    if (lua_isstring(L, 2) == 0) {
        const char *config = clua_tojson(L, 2);
        const char *dir = luaL_optstring(L, 4, nullptr);
        if (cm_create(new_m.get(), config, runtime_config, dir) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    } else {
        const char *dir = luaL_checkstring(L, 2);
        const auto sharing = static_cast<cm_sharing_mode>(luaL_optinteger(L, 4, CM_SHARING_NONE));
        if (cm_load(new_m.get(), dir, runtime_config, sharing) != 0) {
            return luaL_error(L, "%s", cm_get_last_error_message());
        }
    }
    return 1;
}

/// \brief Contents of the machine class metatable __index table.
static const auto machine_meta = cartesi::clua_make_luaL_Reg_array({
    {"__call", machine_meta_call},
});

int clua_i_machine_init(lua_State *L, int ctxidx) {
    clua_createnewtype<clua_managed_cm_ptr<unsigned char>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<std::string>>(L, ctxidx);
    clua_createnewtype<clua_managed_cm_ptr<nlohmann::json>>(L, ctxidx);
    if (!clua_typeexists<clua_managed_cm_ptr<cm_machine>>(L, ctxidx)) {
        clua_createtype<clua_managed_cm_ptr<cm_machine>>(L, "cartesi machine object", ctxidx);
        clua_setmethods<clua_managed_cm_ptr<cm_machine>>(L, machine_obj_index.data(), 0, ctxidx);
        clua_setmetamethods<clua_managed_cm_ptr<cm_machine>>(L, machine_meta.data(), 0, ctxidx);
    }
    return 0;
}

int clua_i_machine_export(lua_State *L, int ctxidx) {
    clua_i_machine_init(L, ctxidx);
    return 0;
}

} // namespace cartesi
