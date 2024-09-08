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

/// \brief Deleter for C api merkle tree proof
template <>
void cm_delete(cm_merkle_tree_proof *p);

/// \brief Deleter for C api semantic version
template <>
void cm_delete(const cm_semantic_version *p);

/// \brief Deleter for C api memory range description array
template <>
void cm_delete(cm_memory_range_descr_array *p);

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

/// \brief Pushes a C api proof to the Lua stack
/// \param L Lua state
/// \param proof Proof to be pushed
void clua_push_cm_proof(lua_State *L, const cm_merkle_tree_proof *proof);

/// \brief Pushes a cm_semantic_version to the Lua stack
/// \param L Lua state
/// \param v C api semantic version to be pushed
void clua_push_cm_semantic_version(lua_State *L, const cm_semantic_version *v);

/// \brief Pushes a C api hash object to the Lua stack
/// \param L Lua state
/// \param hash Hash to be pushed
void clua_push_cm_hash(lua_State *L, const cm_hash *hash);

/// \brief Pushes a C api cm_memory_range_descr_array to the Lua stack
/// \param L Lua state
/// \param mrds Memory range description array to be pushed
void clua_push_cm_memory_range_descr_array(lua_State *L, const cm_memory_range_descr_array *mrds);

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

/// \brief Loads a cm_merkle_tree_proof from Lua
/// \param L Lua state
/// \param tabidx Proof stack index
/// \returns The allocated proof object
cm_merkle_tree_proof *clua_check_cm_merkle_tree_proof(lua_State *L, int tabidx);

/// \brief Loads an cm_access_log from Lua.
/// \param L Lua state
/// \param tabidx Access_log stack index.
/// \param ctxidx Index of clua context
/// \returns The access log. Must be delete by the user with cm_delete_access_log
cm_access_log *clua_check_cm_access_log(lua_State *L, int tabidx, int ctxidx = lua_upvalueindex(1));

nlohmann::json clua_value_to_json(lua_State *L, int tabidx);
void clua_push_json(lua_State *L, const nlohmann::json &j);

} // namespace cartesi

#endif
