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

#include "access-log.h"
#include "clua.h"
#include "grpc-machine-c-api.h"
#include "machine-c-api.h"
#include "machine-merkle-tree.h"
#include "machine.h"
#include "semantic-version.h"

/// \file
/// \brief Cartesi machine Lua interface helper functions

namespace cartesi {

constexpr size_t MAX_ERR_MSG_LEN = 1024;

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define TRY_EXECUTE(func_call)                                                                                         \
    do {                                                                                                               \
        char *err_msg_heap = nullptr;                                                                                  \
        char **err_msg = &err_msg_heap;                                                                                \
        if ((func_call) != 0) {                                                                                        \
            std::array<char, MAX_ERR_MSG_LEN> err_msg_stack{};                                                         \
            strncpy(err_msg_stack.data(), err_msg_heap, MAX_ERR_MSG_LEN - 1);                                          \
            err_msg_stack[MAX_ERR_MSG_LEN - 1] = '\0';                                                                 \
            cm_delete_cstring(err_msg_heap);                                                                           \
            return luaL_error(L, err_msg_stack.data());                                                                \
        }                                                                                                              \
    } while (0)

/// \brief Create overloaded deleters for C API objects
template <typename T>
void cm_delete(T *ptr);

/// \brief Deleter for C string
template <>
void cm_delete<char>(char *ptr);

/// \brief Deleter for C data buffer
template <>
void cm_delete<unsigned char>(unsigned char *ptr);

/// \brief Deleter for C api machine configuration
template <>
void cm_delete<const cm_machine_config>(const cm_machine_config *ptr);
template <>
void cm_delete<cm_machine_config>(cm_machine_config *ptr);

/// \brief Deleter for C api machine
template <>
void cm_delete<cm_machine>(cm_machine *ptr);

/// \brief Deleter for C api runtime machine configuration
template <>
void cm_delete(cm_machine_runtime_config *ptr);

/// \brief Deleter for C api ram config
template <>
void cm_delete(cm_ram_config *p);

/// \brief Deleter for C api dtb config
template <>
void cm_delete(cm_dtb_config *p);

/// \brief Deleter for C api access log
template <>
void cm_delete(cm_access_log *ptr);

/// \brief Deleter for C api merkle tree proof
template <>
void cm_delete(cm_merkle_tree_proof *p);

/// \brief Deleter for C api flash drive config
template <>
void cm_delete(cm_memory_range_config *p);

/// \brief Deleter for C api semantic version
template <>
void cm_delete(const cm_semantic_version *p);

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

/// \brief Pushes a C api cm_machine_config to the Lua stack
/// \param L Lua state
/// \param c Machine configuration to be pushed
void clua_push_cm_machine_config(lua_State *L, const cm_machine_config *c);

#if 0
/// \brief Pushes a cm_machine_runtime_config to the Lua stack
/// \param L Lua state
/// \param r C api machine runtime config to be pushed
void clua_push_cm_machine_runtime_config(lua_State *L, const cm_machine_runtime_config *r);
#endif

/// \brief Returns a CSR selector from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns C API CSR selector. Lua argument error if unknown
CM_PROC_CSR clua_check_cm_proc_csr(lua_State *L, int idx);

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

/// \brief Loads a cm_machine_config object from a Lua table
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \param ctxidx Index of clua context
/// \returns Allocated machine config. It must be deleted with cm_delete_machine_config
cm_machine_config *clua_check_cm_machine_config(lua_State *L, int tabidx, int ctxidx = lua_upvalueindex(1));

/// \brief Loads a cm_machine_runtime_config object from a Lua table
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \param ctxidx Index of clua context
/// \returns Allocated machine runtime config object. It must be deleted with cm_delete_machine_runtime_config
cm_machine_runtime_config *clua_check_cm_machine_runtime_config(lua_State *L, int tabidx,
    int ctxidx = lua_upvalueindex(1));

/// \brief Loads an optional cm_machine_runtime_config object from a Lua
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \param r Default C api machine runtime config value if optional field not present
/// \param ctxidx Index of clua context
/// \returns Allocated machine runtime config object. It must be deleted with cm_delete_machine_runtime_config
cm_machine_runtime_config *clua_opt_cm_machine_runtime_config(lua_State *L, int tabidx,
    const cm_machine_runtime_config *r, int ctxidx = lua_upvalueindex(1));

/// \brief Loads C api memory range config from a Lua table
/// \param L Lua state
/// \param tabidx Memory range config stack index
/// \param what Description of memory range for error messages
/// \param m Pointer to cm_memory_range structure that will receive
/// \returns m
cm_memory_range_config *clua_check_cm_memory_range_config(lua_State *L, int tabidx, const char *what,
    cm_memory_range_config *m);

} // namespace cartesi

#endif
