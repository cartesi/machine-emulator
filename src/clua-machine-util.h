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
void cm_delete(T *ptr);

/// \brief Deleter for C string
template <>
void cm_delete<char>(char *ptr);

/// \brief Deleter for C data buffer
template <>
void cm_delete<unsigned char>(unsigned char *ptr);

/// \brief Deleter for C api machine
template <>
void cm_delete<cm_machine>(cm_machine *ptr);

/// \brief Deleter for C api access log
template <>
void cm_delete(cm_access_log *ptr);

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
        cm_delete(m_ptr); // use overloaded deleter
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

/// \brief Pushes a C api hash object to the Lua stack
/// \param L Lua state
/// \param hash Hash to be pushed
void clua_push_cm_hash(lua_State *L, const cm_hash *hash);

/// \brief Returns a CSR selector from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns C API CSR selector. Lua argument error if unknown
CM_CSR clua_check_cm_proc_csr(lua_State *L, int idx);

/// \brief Pushes an C api access log to the Lua stack
/// \param L Lua state
/// \param log Access log to be pushed
void clua_push_cm_access_log(lua_State *L, const cm_access_log *log);

/// \brief Loads an cm_access_log_type from Lua
/// \param L Lua state
/// \param tabidx Access log stack index
/// \param log_type C api access log type to be pushed
cm_access_log_type clua_check_cm_log_type(lua_State *L, int tabidx);

/// \brief Return C hash from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \param c_hash Receives hash
void clua_check_cm_hash(lua_State *L, int idx, cm_hash *c_hash);

/// \brief Loads an cm_access_log from Lua.
/// \param L Lua state
/// \param tabidx Access_log stack index.
/// \param ctxidx Index of clua context
/// \returns The access log. Must be delete by the user with cm_delete_access_log
cm_access_log *clua_check_cm_access_log(lua_State *L, int tabidx, int ctxidx = lua_upvalueindex(1));

/// \brief Loads a JSON object from a Lua value.
/// \param L Lua state
/// \param tabidx Lua value stack index.
/// \param base64encode Whether to encode non key strings values using base64.
/// \returns It traverses the Lua value while converting to a JSON object.
nlohmann::json clua_check_json(lua_State *L, int tabidx, bool base64encode = false);

/// \brief Pushes a JSON object as a Lua value.
/// \param L Lua state
/// \param j JSON object.
/// \param base64decode Whether to decode non key strings values using base64.
/// \returns It traverses the JSON object while converting to a Lua object.
void clua_push_json(lua_State *L, const nlohmann::json &j, bool base64decode = false);

} // namespace cartesi

#endif
