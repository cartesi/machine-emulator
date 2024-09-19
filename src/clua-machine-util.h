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

#ifndef CLUA_MACHINE_UTIL_H
#define CLUA_MACHINE_UTIL_H

#include <string>
#include <utility>

extern "C" {
#include <lua.h>
}

#include "json-util.h"
#include "machine-c-api.h"

/// \file
/// \brief Cartesi machine Lua interface helper functions

namespace cartesi {

/// \brief Create overloaded deleters for C API objects
template <typename T>
void clua_delete(T *ptr);

/// \brief Deleter for C string
template <>
void clua_delete<char>(char *ptr);

/// \brief Deleter for C data buffer
template <>
void clua_delete<unsigned char>(unsigned char *ptr);

/// \brief Deleter for C api machine
template <>
void clua_delete<cm_machine>(cm_machine *ptr);

// clua_managed_cm_ptr is a smart pointer,
// however we don't use all its functionally, therefore we exclude it from code coverage.
// LCOV_EXCL_START
template <typename T>
class clua_managed_cm_ptr final {
public:
    clua_managed_cm_ptr() : m_ptr{nullptr} {}

    explicit clua_managed_cm_ptr(T *ptr) : m_ptr{ptr} {}

    explicit clua_managed_cm_ptr(clua_managed_cm_ptr &&other) noexcept : m_ptr{other.m_ptr} {
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

    T *release(void) noexcept {
        auto *tmp_ptr = m_ptr;
        m_ptr = nullptr;
        return tmp_ptr;
    }

    T *&get(void) noexcept { // return reference to internal ptr
        return m_ptr;
    }

    T *get(void) const noexcept {
        return m_ptr;
    }

private:
    T *m_ptr;
};
// LCOV_EXCL_STOP

/// \brief Returns a CSR selector from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns C API CSR selector. Lua argument error if unknown
CM_CSR clua_check_cm_proc_csr(lua_State *L, int idx);

/// \brief Pushes a C api hash object to the Lua stack
/// \param L Lua state
/// \param hash Hash to be pushed
void clua_push_cm_hash(lua_State *L, const cm_hash *hash);

/// \brief Return C hash from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \param c_hash Receives hash
void clua_check_cm_hash(lua_State *L, int idx, cm_hash *c_hash);

/// \brief Replaces a Lua table with its JSON string representation and returns the string.
/// \param L Lua state
/// \param tabidx Lua table stack index which will be converted to a Lua string.
/// \param indent JSON indentation when converting it to a string.
/// \returns It traverses the Lua value while converting to a JSON object.
/// \details In case the Lua valua is already a string, it just returns it.
const char *clua_check_json_string(lua_State *L, int idx, int indent = -1);

/// \brief Parses a JSON from a string and pushes it as a Lua table.
/// \param L Lua state
/// \param s JSON string.
/// \returns It traverses the JSON object while converting to a Lua object.
void clua_push_json_table(lua_State *L, const char *s);

} // namespace cartesi

#endif
