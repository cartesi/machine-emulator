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

#ifndef CLUA_I_MACHINE_H
#define CLUA_I_MACHINE_H

#include <memory>
#include <string>
#include <utility>

#include "clua.h"
#include "i-machine.h"
#include "json-util.h"
#include "machine-c-api.h"

/// \file
/// \brief Cartesi machine Lua interface

namespace cartesi {

/// \brief Initialize Cartesi machine Lua interface
/// \param L Lua state
/// \param ctxidx Index of Clua context
int clua_i_machine_init(lua_State *L, int ctxidx);

/// \brief Exports symbols to table on top of Lua stack
/// \param L Lua state
/// \param ctxidx Index of Clua context
int clua_i_machine_export(lua_State *L, int ctxidx);

/// \brief Create overloaded deleters for C API objects
template <typename T>
void clua_delete(T *ptr);

/// \brief Deleter for C data buffer
template <>
void clua_delete<unsigned char>(unsigned char *ptr);

/// \brief Deleter for machine
template <>
void clua_delete<cm_machine>(cm_machine *ptr);

/// \brief Deleter for string
template <>
void clua_delete<std::string>(std::string *ptr);

/// \brief Deleter for JSON
template <>
void clua_delete<nlohmann::json>(nlohmann::json *ptr);

// clua_managed_cm_ptr is a smart pointer,
// however we don't use all its functionally, therefore we exclude it from code coverage.
// LCOV_EXCL_START
template <typename T>
class clua_managed_cm_ptr final {
public:
    clua_managed_cm_ptr() : m_ptr{nullptr} {}

    explicit clua_managed_cm_ptr(T *ptr) : m_ptr{ptr} {}

    clua_managed_cm_ptr(clua_managed_cm_ptr &&other) noexcept : m_ptr{other.m_ptr} {
        other.m_ptr = nullptr;
    }

    clua_managed_cm_ptr &operator=(clua_managed_cm_ptr &&other) noexcept {
        reset();
        std::swap(m_ptr, other.m_ptr);
        return *this;
    };

    ~clua_managed_cm_ptr() {
        reset();
    }

    clua_managed_cm_ptr(const clua_managed_cm_ptr &other) = delete;
    void operator=(const clua_managed_cm_ptr &other) = delete;

    T *operator->() const noexcept {
        return m_ptr;
    }

    T &operator*() const {
        return *m_ptr;
    }

    void reset(T *ptr = nullptr) {
        clua_delete(m_ptr); // use overloaded deleter
        m_ptr = ptr;
    }

    T *release() noexcept {
        auto *tmp_ptr = m_ptr;
        m_ptr = nullptr;
        return tmp_ptr;
    }

    T *&get() noexcept { // return reference to internal ptr
        return m_ptr;
    }

    T *get() const noexcept {
        return m_ptr;
    }

private:
    T *m_ptr;
};
// LCOV_EXCL_STOP

/// \brief Allocates a new type, pushes its reference into the Lua stack and returns its pointer.
/// \param L Lua state
/// \param value Initial value
/// \param ctxidx Index (or pseudo-index) of clua context
/// \returns The value pointer, valid until its reference is removed from the Lua stack.
/// \details The value is marked to-be-closed when popped from the Lua stack.
/// This follow lua_toclose semantics (check Lua 5.4 manual),
/// therefore the stack index can only be removed via lua_pop (e.g. don't use lua_remove).
template <typename T>
T *clua_push_new_managed_toclose_ptr(lua_State *L, T &&value, int ctxidx = lua_upvalueindex(1)) {
    auto &managed_value = clua_push_to(L, clua_managed_cm_ptr<T>(new T(std::forward<T>(value))), ctxidx);
    // ??(edubart): Unfortunately Lua 5.4.4 (default on Ubuntu 22.04) has a bug that causes a crash
    // when using lua_settop with lua_toclose, it was fixed only in Lua 5.4.5 in
    // https://github.com/lua/lua/commit/196bb94d66e727e0aec053a0276c3ad701500762 .
    // Without lua_toclose call, reference will be only collected by the GC (non deterministic).
#if LUA_VERSION_RELEASE_NUM > 50404
    lua_toclose(L, -1);
#endif
    return managed_value.get();
}

/// \brief Returns a register selector from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns C API register selector. Lua argument error if unknown
cm_reg clua_check_cm_proc_reg(lua_State *L, int idx);

/// \brief Pushes a C api hash object to the Lua stack
/// \param L Lua state
/// \param hash Hash to be pushed
void clua_push_cm_hash(lua_State *L, const cm_hash *hash);

/// \brief Return C hash from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \param c_hash Receives hash
void clua_check_cm_hash(lua_State *L, int idx, cm_hash *c_hash);

/// \brief Replaces a Lua table with its JSON string representation and returns the string
/// \param L Lua state
/// \param idx Lua table stack index which will be converted to a Lua string
/// \param indent JSON indentation when converting it to a string
/// \param ctxidx Index (or pseudo-index) of clua context
/// \param schema Schema for the table
/// \param schema_dict Dictionary containing schema for all types
/// \returns It traverses the Lua value while converting to a JSON object
/// \details In case the Lua valua is already a string, it just returns it
const char *clua_check_json_string(lua_State *L, int idx, int indent = -1, int ctxidx = lua_upvalueindex(1),
    const nlohmann::json &schema = nlohmann::json(), const nlohmann::json &schema_dict = nlohmann::json());

/// \brief Parses a JSON from a string and pushes it as a Lua table
/// \param L Lua state
/// \param s JSON string
/// \param ctxidx Index (or pseudo-index) of clua context
/// \param schema Schema for the table
/// \param schema_dict Dictionary containing schema for all types
/// \returns It traverses the JSON object while converting to a Lua object
void clua_push_json_table(lua_State *L, const char *s, int ctxidx = lua_upvalueindex(1),
    const nlohmann::json &schema = nlohmann::json(), const nlohmann::json &schema_dict = nlohmann::json());

/// \brief Replaces a Lua table with its JSON string representation and returns the string (schemed version)
/// \param L Lua state
/// \param idx Lua table stack index which will be converted to a Lua string
/// \param schema_name Schema name to be used while converting the table
/// \param ctxidx Index (or pseudo-index) of clua context
const char *clua_check_schemed_json_string(lua_State *L, int idx, const std::string &schema_name,
    int ctxidx = lua_upvalueindex(1));

/// \brief Parses a JSON from a string and pushes it as a Lua table (schemed version)
/// \param L Lua state
/// \param s JSON string
/// \param idx Lua table stack index which will be converted to a Lua string
/// \param schema_name Schema name to be used while converting the table
/// \param ctxidx Index (or pseudo-index) of clua context
void clua_push_schemed_json_table(lua_State *L, const char *s, const std::string &schema_name,
    int ctxidx = lua_upvalueindex(1));

} // namespace cartesi

#endif
