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

#include "clua.h"
#include "machine-merkle-tree.h"
#include "access-log.h"
#include "machine.h"
#include "semantic-version.h"
#include "machine-c-api.h"

/// \file
/// \brief Cartesi machine Lua interface helper functions

namespace cartesi {

#define CREATE_LUA_TYPE(TYPE, DESCRIPTION, ctxidx) \
        if (!clua_typeexists<TYPE>(L, ctxidx)) { \
            clua_createtype<TYPE>(L, DESCRIPTION, ctxidx); \
        }

#define TRY_EXECUTE(func_call) \
    do {                       \
       auto &managed_err_msg = clua_push_to(L, clua_managed_cm_ptr<char>(nullptr)); \
       char **err_msg = &managed_err_msg.get();\
       if (func_call != 0) {                   \
           return luaL_error(L, *err_msg); \
       }                                       \
       lua_pop(L, 1);                           \
    } while (0)

#define DEMANGLE_TYPEID_NAME(x) abi::__cxa_demangle(typeid((x)).name(), NULL, NULL, NULL)

/// \brief Create overloaded deleters for C API objects
template<typename T>
void cm_delete(T *ptr) {
    fprintf(stderr, "Calling default deleter, maybe specialized deleter "
                    "is missing for type <%s>?\n", DEMANGLE_TYPEID_NAME(*ptr));
}

/// \brief Deleter for C string
template<>
void cm_delete<char>(char *err_msg);

/// \brief Deleter for C api machine configuration
template<>
void cm_delete<const cm_machine_config>(const cm_machine_config *c);
template<>
void cm_delete<cm_machine_config>(cm_machine_config *c);

/// \brief Deleter for C api machine
template<>
void cm_delete<cm_machine>(cm_machine *m);

/// \brief Deleter for C api runtime machine configuration
template<>
void cm_delete(cm_machine_runtime_config *c);

/// \brief Deleter for C api access log
template<>
void cm_delete(cm_access_log *a);

/// \brief Deleter for C api merkle tree proof
template<>
void cm_delete(cm_merkle_tree_proof *p);

template<typename T>
class clua_managed_cm_ptr final {
public:
    explicit clua_managed_cm_ptr(T *ptr): m_ptr{ptr} {
    }

    explicit clua_managed_cm_ptr(clua_managed_cm_ptr &&other) {
        m_ptr = other.m_ptr;
        other.m_ptr = nullptr;
    }

    void operator= (clua_managed_cm_ptr &&other) {
        release();
        std::swap(m_ptr, other.m_ptr);
    };

    explicit clua_managed_cm_ptr(const clua_managed_cm_ptr &other) = delete;
    void operator= (const clua_managed_cm_ptr &other) = delete;

    ~clua_managed_cm_ptr() {
        cm_delete(m_ptr); // use overloaded deleter
        m_ptr = nullptr; // not needed, just in end of the world case
    }

    void operator = (T *ptr) {
        m_ptr = ptr;
    }

    void release(void) {
        cm_delete(m_ptr); // use overloaded deleter
        m_ptr = nullptr;
    }

    T *&get(void) { // return reference to internal ptr
        return m_ptr;
    }

    const T *get(void) const {
        return m_ptr;
    }

private:
    T *m_ptr{};
};

/// \brief Pushes a proof to the Lua stack
/// \param L Lua state
/// \param proof Proof to be pushed
void clua_push_proof(lua_State *L, const machine_merkle_tree::proof_type &proof);

/// \brief Pushes a C api proof to the Lua stack
/// \param L Lua state
/// \param proof Proof to be pushed
void clua_push_cm_proof(lua_State *L, const cm_merkle_tree_proof *proof);

/// \brief Pushes a semantic_version to the Lua stack
/// \param L Lua state
/// \param v Semantic_version to be pushed.
void clua_push_semantic_version(lua_State *L, const semantic_version &v);

/// \brief Pushes a hash to the Lua stack
/// \param L Lua state
/// \param hash Hash to be pushed.
void clua_push_hash(lua_State *L, const machine_merkle_tree::hash_type &hash);

/// \brief Pushes a C api hash object to the Lua stack
/// \param L Lua state
/// \param hash Hash to be pushed.
void clua_push_cm_hash(lua_State *L, const cm_hash *hash);


/// \brief Pushes a machine_config to the Lua stack
/// \param L Lua state
/// \param c Machine_config to be pushed.
void clua_push_machine_config(lua_State *L, const machine_config &c);

/// \brief Pushes a C api cm_machine_config to the Lua stack
/// \param L Lua state
/// \param c Machine configuration to be pushed.
void clua_push_cm_machine_config(lua_State *L, const cm_machine_config *c);

/// \brief Pushes a machine_runtime_config to the Lua stack
/// \param L Lua state
/// \param r Machine_runtime_config to be pushed.
void clua_push_machine_runtime_config(lua_State *L, const machine_runtime_config &r);

/// \brief Pushes a cm_machine_runtime_config to the Lua stack
/// \param L Lua state
/// \param r C api machine runtime config to be pushed.
void clua_push_cm_machine_runtime_config(lua_State *L, const cm_machine_runtime_config *r);

/// \brief Returns a CSR selector from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns CSR selector. Throws error if unknown.
machine::csr clua_check_csr(lua_State *L, int idx);

/// \brief Returns a CSR selector from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns C API CSR selector. Lua argument error if unknown
CM_PROC_CSR clua_check_cm_proc_csr(lua_State *L, int idx);

/// \brief Pushes an access log to the Lua stack
/// \param L Lua state
/// \param log Access log to be pushed
void clua_push_access_log(lua_State *L, const access_log &log);

/// \brief Pushes an C api access log to the Lua stack
/// \param L Lua state
/// \param log Access log to be pushed
void clua_push_cm_access_log(lua_State *L, const cm_access_log *log);

/// \brief Loads an access_log::type from Lua
/// \param L Lua state
/// \param tabidx Access_log::type stack index.
/// \param log_type Access_log::type to be pushed
access_log::type clua_check_log_type(lua_State *L, int tabidx);

/// \brief Loads an cm_access_log_type from Lua
/// \param L Lua state
/// \param tabidx Access log stack index
/// \param log_type C api access log type to be pushed
cm_access_log_type clua_check_cm_log_type(lua_State *L, int tabidx);

/// \brief Return a hash from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \returns Hash
machine_merkle_tree::hash_type clua_check_hash(lua_State *L, int idx);

/// \brief Return C hash from Lua
/// \param L Lua state
/// \param idx Index in stack
/// \param c_hash Receives hash
void clua_check_cm_hash(lua_State *L, int idx, cm_hash *c_hash);

/// \brief Loads a proof from Lua
/// \param L Lua state
/// \param tabidx Proof stack index
/// \returns The proof
machine_merkle_tree::proof_type clua_check_proof(lua_State *L, int tabidx);

/// \brief Loads a cm_merkle_tree_proof from Lua
/// \param L Lua state
/// \param tabidx Proof stack index
/// \returns The allocated proof object
cm_merkle_tree_proof *clua_check_cm_merkle_tree_proof(lua_State *L, int tabidx);

/// \brief Loads an access_log from Lua
/// \param L Lua state
/// \param tabidx Access_log stack index
/// \returns The access_log
access_log clua_check_access_log(lua_State *L, int tabidx);


/// \brief Loads an cm_access_log from Lua.
/// \param L Lua state
/// \param tabidx Access_log stack index.
/// \returns The access log. Must be delete by the user with cm_delete_access_log
cm_access_log* clua_check_cm_access_log(lua_State *L, int tabidx);

/// \brief Loads a machine_config object from a Lua table
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
machine_config clua_check_machine_config(lua_State *L, int tabidx);

/// \brief Loads a cm_machine_config object from a Lua table
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \returns Allocated machine config. It must be deleted with cm_delete_machine_config
cm_machine_config* clua_check_cm_machine_config(lua_State *L, int tabidx);

/// \brief Loads a machine_runtime_config object from a Lua table
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
machine_runtime_config clua_check_machine_runtime_config(lua_State *L,
    int tabidx);

/// \brief Loads a cm_machine_runtime_config object from a Lua table
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \returns Allocated machine runtime config object. It must be deleted with cm_delete_machine_runtime_config
cm_machine_runtime_config* clua_check_cm_machine_runtime_config(lua_State *L,
    int tabidx);

/// \brief Loads an optional machine_runtime_config object from a Lua
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \param r Default value if optional runtime config not present
machine_runtime_config clua_opt_machine_runtime_config(lua_State *L,
    int tabidx, const machine_runtime_config &r);

/// \brief Loads an optional cm_machine_runtime_config object from a Lua
/// \param L Lua state
/// \param tabidx Index of table in Lua stack
/// \param r Default C api machine runtime config value if optional field not present
/// \returns Allocated machine runtime config object. It must be deleted with cm_delete_machine_runtime_config
cm_machine_runtime_config* clua_opt_cm_machine_runtime_config(lua_State *L,
    int tabidx, const cm_machine_runtime_config *r);

/// \brief Loads flash drive config from a Lua table.
/// \param L Lua state
/// \param tabidx Flash_config stack index.
/// \returns The flash_config.
flash_drive_config clua_check_flash_drive_config(lua_State *L, int tabidx);

/// \brief Loads C api flash drive config from a Lua table
/// \param L Lua state
/// \param tabidx Flash config stack index
/// \returns The cm_flash_drive_config
cm_flash_drive_config clua_check_cm_flash_drive_config(lua_State *L, int tabidx);


} // namespace cartesi

#endif
