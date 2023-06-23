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

#include <cstring>
#include <unordered_map>

#include "clua-machine-util.h"
#include "clua.h"

namespace cartesi {

/// \brief Deleter for C string
template <>
void cm_delete<char>(char *ptr) {
    cm_delete_cstring(ptr);
}

/// \brief Deleter for C data buffer
template <>
void cm_delete<unsigned char>(unsigned char *ptr) { // NOLINT(readability-non-const-parameter)
    delete[] ptr;
}

/// \brief Deleter for C api semantic version
template <>
void cm_delete(const cm_semantic_version *p) {
    cm_delete_semantic_version(p);
}

/// \brief Deleter for C api machine configuration
template <>
void cm_delete<const cm_machine_config>(const cm_machine_config *ptr) {
    cm_delete_machine_config(ptr);
}

template <>
void cm_delete<cm_machine_config>(cm_machine_config *ptr) {
    cm_delete_machine_config(ptr);
}

/// \brief Deleter for C api runtime machine configuration
template <>
void cm_delete(cm_machine_runtime_config *ptr) {
    cm_delete_machine_runtime_config(ptr);
}

/// \brief Deleter for C api machine
template <>
void cm_delete(cm_machine *ptr) {
    cm_delete_machine(ptr);
}

/// \brief Deleter for C api access log
template <>
void cm_delete(cm_access_log *ptr) {
    cm_delete_access_log(ptr);
}

/// \brief Deleter for C api merkle tree proof
template <>
void cm_delete(cm_merkle_tree_proof *ptr) {
    cm_delete_merkle_tree_proof(ptr);
}

/// \brief Deleter for C api memory range config
template <>
void cm_delete(cm_memory_range_config *ptr) {
    cm_delete_memory_range_config(ptr);
}

static char *copy_lua_str(lua_State *L, int idx) {
    const char *lua_str = lua_tostring(L, idx);
    auto size = strlen(lua_str) + 1;
    auto *copy = new char[size];
    strncpy(copy, lua_str, size);
    return copy;
}

/// \brief Returns an optional boolean field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \param def Default value for missing field.
/// \returns Field value, or false if missing.
static bool opt_boolean_field(lua_State *L, int tabidx, const char *field, bool def = false) {
    tabidx = lua_absindex(L, tabidx);
    lua_getfield(L, tabidx, field);
    bool val = def;
    if (!lua_isnil(L, -1)) {
        val = lua_toboolean(L, -1);
    }
    lua_pop(L, 1);
    return val;
}

/// \brief Returns an optional integer field indexed by integer in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \param def Default value for missing field.
/// \returns Field value, or default value if missing.
static uint64_t opt_uint_field(lua_State *L, int tabidx, int field, uint64_t def = 0) {
    tabidx = lua_absindex(L, tabidx);
    uint64_t val = def;
    lua_geti(L, tabidx, field);
    if (lua_isinteger(L, -1)) {
        val = lua_tointeger(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid entry %d (expected unsigned integer)", field);
    }
    lua_pop(L, 1);
    return static_cast<uint64_t>(val);
}

/// \brief Returns an optional integer field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \param def Default value for missing field.
/// \returns Field value, or default value if missing.
static uint64_t opt_uint_field(lua_State *L, int tabidx, const char *field, uint64_t def = 0) {
    tabidx = lua_absindex(L, tabidx);
    uint64_t val = def;
    lua_getfield(L, tabidx, field);
    if (lua_isinteger(L, -1)) {
        val = lua_tointeger(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid %s (expected unsigned integer)", field);
    }
    lua_pop(L, 1);
    return static_cast<uint64_t>(val);
}

/// \brief Returns an optional string field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value, or empty string if missing.
static std::string opt_string_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    std::string str;
    lua_getfield(L, tabidx, field);
    if (lua_isstring(L, -1)) {
        str = lua_tostring(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid %s (expected string)", field);
    }
    lua_pop(L, 1);
    return str;
}

/// \brief Returns an allocated optional c string field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value, or nullptr if missing. If field value is returned,
/// it must be deallocated by the caller
static char *opt_copy_string_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    char *str = nullptr;
    lua_getfield(L, tabidx, field);
    if (lua_isstring(L, -1)) {
        str = copy_lua_str(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid %s (expected string)", field);
    }
    lua_pop(L, 1);
    return str;
}

/// \brief Returns an integer field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value. Throws error if field is missing.
static int check_int_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    lua_getfield(L, tabidx, field);
    if (!lua_isinteger(L, -1)) {
        luaL_error(L, "invalid %s (expected integer, got %s)", field, lua_typename(L, lua_type(L, -1)));
    }
    lua_Integer ival = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return static_cast<int>(ival);
}

/// \brief Returns an integer field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value. Throws error if field is missing.
static uint64_t check_uint_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    lua_getfield(L, tabidx, field);
    if (!lua_isinteger(L, -1)) {
        luaL_error(L, "invalid %s (expected unsigned integer, got %s)", field, lua_typename(L, lua_type(L, -1)));
    }
    lua_Integer ival = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return static_cast<uint64_t>(ival);
}

/// \brief Returns a string field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value. Throws error if field is missing.
static std::string check_string_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    std::string str;
    lua_getfield(L, tabidx, field);
    if (lua_isstring(L, -1)) {
        str = lua_tostring(L, -1);
    } else {
        luaL_error(L, "invalid %s (expected string)", field);
    }
    lua_pop(L, 1);
    return str;
}

/// \brief Returns a allocated c string field indexed by string in a table.
/// \param L Lua state
/// \param tabidx Table stack index
/// \param field Field index
/// \returns Field value as c string. Throws error if field is missing. Returned result
/// must be deallocated from the user
static char *check_copy_string_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    char *str = nullptr;
    lua_getfield(L, tabidx, field);
    if (lua_isstring(L, -1)) {
        str = copy_lua_str(L, -1);
    } else {
        luaL_error(L, "invalid %s (expected string)", field);
    }
    lua_pop(L, 1);
    return str;
}

/// \brief Pushes to the stack a table field indexed by string in another table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field is returned in Lua stack.
static void check_table_field(lua_State *L, int tabidx, const char *field) {
    lua_getfield(L, tabidx, field);
    if (!lua_istable(L, -1)) {
        luaL_error(L, "missing %s", field);
    }
}

/// \brief Pushes to stack an optional table field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns True if field is present, false if missing. If field is present,
/// it is pushed to the Lua stack, otherwise stack is left unchanged.
static bool opt_table_field(lua_State *L, int tabidx, const char *field) {
    lua_getfield(L, tabidx, field);
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return false;
    } else if (!lua_istable(L, -1)) {
        luaL_error(L, "missing %s", field);
        return false;
    } else {
        return true;
    }
}

/// \brief Returns an CM_ACCESS_TYPE table field indexed by string in a table
/// \param L Lua state
/// \param tabidx Table stack index
/// \param field Field index
/// \returns Corresponding CM_ACCESS_TYPE
static CM_ACCESS_TYPE check_cm_access_type_field(lua_State *L, int tabidx, const char *field) {
    auto name = check_string_field(L, tabidx, field);
    if (name == "read") {
        return CM_ACCESS_READ;
    } else if (name == "write") {
        return CM_ACCESS_WRITE;
    } else {
        luaL_error(L, "invalid %s (expected access type)", field);
        return CM_ACCESS_READ; // never reached
    }
}

/// \brief Returns an CM_BRACKET_TYPE table field indexed by string in a table.
/// \param L Lua state
/// \param tabidx Table stack index
/// \param field Field index
/// \returns Corresponding CM_BRACKET_TYPE
static CM_BRACKET_TYPE check_cm_bracket_type_field(lua_State *L, int tabidx, const char *field) {
    auto name = check_string_field(L, tabidx, field);
    if (name == "begin") {
        return CM_BRACKET_BEGIN;
    } else if (name == "end") {
        return CM_BRACKET_END;
    } else {
        luaL_error(L, "invalid %s (expected bracket type)", field);
        return CM_BRACKET_BEGIN; // never reached
    }
}

/// \brief Loads a cm_bracket_note from Lua
/// \param L Lua state
/// \param tabidx Bracket_note stack index
/// \returns The bracket note
static cm_bracket_note check_cm_bracket_note(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    cm_bracket_note new_bracket_note{};
    new_bracket_note.type = check_cm_bracket_type_field(L, -1, "type");
    new_bracket_note.where = check_uint_field(L, -1, "where") - 1; // convert from 1- to 0-based index
    new_bracket_note.text = check_copy_string_field(L, -1, "text");
    return new_bracket_note;
}

/// \brief Loads an array of sibling cm_hashes from Lua
/// \param L Lua state.
/// \param idx Proof stack index.
/// \param log2_target_size Size of node from which to obtain siblings
/// \param log2_root_size Root log2 size of tree
/// \param p Receives array of sibling hashes
static void check_sibling_cm_hashes(lua_State *L, int idx, size_t log2_target_size, const size_t log2_root_size,
    cm_hash_array *sibling_hashes) {
    luaL_checktype(L, idx, LUA_TTABLE);
    memset(sibling_hashes, 0, sizeof(cm_hash_array));
    size_t sibling_hashes_count = log2_root_size - log2_target_size;
    if (sibling_hashes_count > 64) {
        luaL_error(L, "too many sibling hashes (expected max %d, got %d)", 64, static_cast<int>(sibling_hashes_count));
    }
    sibling_hashes->count = sibling_hashes_count;
    sibling_hashes->entry = new cm_hash[sibling_hashes_count]{};
    for (; log2_target_size < log2_root_size; ++log2_target_size) {
        lua_rawgeti(L, idx, static_cast<lua_Integer>(log2_root_size - log2_target_size));
        auto index = log2_root_size - 1 - log2_target_size;
        clua_check_cm_hash(L, -1, &sibling_hashes->entry[index]);
        lua_pop(L, 1);
    }
}

cm_merkle_tree_proof *clua_check_cm_merkle_tree_proof(lua_State *L, int tabidx, int ctxidx) {
    tabidx = lua_absindex(L, tabidx);
    luaL_checktype(L, tabidx, LUA_TTABLE);
    auto &managed = clua_push_to(L, clua_managed_cm_ptr<cm_merkle_tree_proof>(new cm_merkle_tree_proof{}), ctxidx);
    cm_merkle_tree_proof *proof = managed.get();
    proof->log2_target_size = check_uint_field(L, tabidx, "log2_target_size");
    proof->log2_root_size = check_uint_field(L, tabidx, "log2_root_size");
    proof->target_address = check_uint_field(L, tabidx, "target_address");
    lua_getfield(L, tabidx, "target_hash");
    clua_check_cm_hash(L, -1, &proof->target_hash);
    lua_pop(L, 1);
    lua_getfield(L, tabidx, "root_hash");
    clua_check_cm_hash(L, -1, &proof->root_hash);
    lua_pop(L, 1);
    lua_getfield(L, tabidx, "sibling_hashes");
    check_sibling_cm_hashes(L, -1, proof->log2_target_size, proof->log2_root_size, &proof->sibling_hashes);
    managed.release();
    lua_pop(L, 2);
    return proof;
}

/// \brief Returns an access data field indexed by string in a table
/// \param L Lua state
/// \param tabidx Table stack index
/// \param field Field index
/// \param log2_size Expected log2 of size of data
/// \param opt Whether filed is optional
/// \param data_size Receives size of the returned data field
/// \returns Allocated field value. Throws error if field is not optional but is missing.
/// If field is optional but missing returns nullptr
static unsigned char *aux_cm_access_data_field(lua_State *L, int tabidx, const char *field, uint64_t log2_size,
    bool opt, size_t *data_size) {
    unsigned char *a = nullptr;
    *data_size = 0;
    tabidx = lua_absindex(L, tabidx);
    lua_getfield(L, tabidx, field);
    if (lua_isstring(L, -1)) {
        size_t len = 0;
        const char *s = lua_tolstring(L, -1, &len);
        uint64_t expected_len = UINT64_C(1) << log2_size;
        if (len != expected_len) {
            luaL_error(L, "invalid %s (expected string with 2^%d bytes)", field, static_cast<int>(log2_size));
        }
        a = new unsigned char[len];
        memcpy(a, s, len);
        *data_size = len;
    } else if (!opt || !lua_isnil(L, -1)) {
        luaL_error(L, "invalid %s (expected string)", field);
    }
    lua_pop(L, 1);
    return a;
}

static unsigned char *check_cm_access_data_field(lua_State *L, int tabidx, const char *field, uint64_t log2_size,
    size_t *data_size) {
    return aux_cm_access_data_field(L, tabidx, field, log2_size, false, data_size);
}

static unsigned char *opt_cm_access_data_field(lua_State *L, int tabidx, const char *field, uint64_t log2_size,
    size_t *data_size) {
    return aux_cm_access_data_field(L, tabidx, field, log2_size, true, data_size);
}

/// \brief Loads an cm_access from Lua
/// \param L Lua state
/// \param tabidx access stack index
/// \param a Pointer to receive access
/// \param ctxidx Index (or pseudo-index) of clua context
static void check_cm_access(lua_State *L, int tabidx, bool proofs, cm_access *a, int ctxidx) {
    ctxidx = lua_absindex(L, ctxidx);
    tabidx = lua_absindex(L, tabidx);
    luaL_checktype(L, tabidx, LUA_TTABLE);
    a->type = check_cm_access_type_field(L, tabidx, "type");
    a->address = check_uint_field(L, tabidx, "address");
    a->log2_size = check_int_field(L, tabidx, "log2_size");
    if (a->log2_size < CM_TREE_LOG2_WORD_SIZE || a->log2_size > CM_TREE_LOG2_ROOT_SIZE) {
        luaL_error(L, "invalid log2_size (expected integer in {%d..%d})", CM_TREE_LOG2_WORD_SIZE,
            CM_TREE_LOG2_ROOT_SIZE);
    }
    if (proofs) {
        lua_getfield(L, tabidx, "proof");
        a->proof = clua_check_cm_merkle_tree_proof(L, -1, ctxidx);
        lua_pop(L, 1);
    }
    a->read_data = check_cm_access_data_field(L, tabidx, "read", a->log2_size, &a->read_data_size);
    a->written_data = opt_cm_access_data_field(L, tabidx, "written", a->log2_size, &a->written_data_size);
}

cm_access_log *clua_check_cm_access_log(lua_State *L, int tabidx, int ctxidx) {
    tabidx = lua_absindex(L, tabidx);
    ctxidx = lua_absindex(L, ctxidx);
    luaL_checktype(L, tabidx, LUA_TTABLE);
    auto &managed = clua_push_to(L, clua_managed_cm_ptr<cm_access_log>(new cm_access_log{}), ctxidx);
    cm_access_log *log = managed.get();
    check_table_field(L, tabidx, "log_type");
    log->log_type.proofs = opt_boolean_field(L, -1, "proofs");
    log->log_type.annotations = opt_boolean_field(L, -1, "annotations");
    lua_pop(L, 1);
    check_table_field(L, tabidx, "accesses");
    log->accesses.count = luaL_len(L, -1);
    log->accesses.entry = new cm_access[log->accesses.count]{};
    for (size_t i = 1; i <= log->accesses.count; i++) {
        lua_geti(L, -1, static_cast<lua_Integer>(i));
        if (!lua_istable(L, -1)) {
            luaL_error(L, "access [%d] not a table", i);
        }
        check_cm_access(L, -1, log->log_type.proofs, &log->accesses.entry[i - 1], ctxidx);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    if (log->log_type.annotations) {
        check_table_field(L, tabidx, "notes");
        log->notes.count = luaL_len(L, -1);
        log->notes.entry = new const char *[log->notes.count] {};
        for (size_t i = 1; i <= log->notes.count; i++) {
            lua_geti(L, -1, static_cast<lua_Integer>(i));
            if (!lua_isstring(L, -1)) {
                luaL_error(L, "note [%d] not a string", i);
            }
            log->notes.entry[i - 1] = copy_lua_str(L, -1);
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        check_table_field(L, tabidx, "brackets");
        log->brackets.count = luaL_len(L, -1);
        log->brackets.entry = new cm_bracket_note[log->brackets.count]{};
        for (size_t i = 1; i <= log->brackets.count; i++) {
            lua_geti(L, -1, static_cast<lua_Integer>(i));
            if (!lua_istable(L, -1)) {
                luaL_error(L, "bracket [%d] not a table", i);
            }
            log->brackets.entry[i - 1] = check_cm_bracket_note(L, -1);
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    managed.release();
    lua_pop(L, 1); // cleanup managed log from stack
    return log;
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

CM_PROC_CSR clua_check_cm_proc_csr(lua_State *L, int idx) try {
    /// \brief Mapping between CSR names and C API constants
    const static std::unordered_map<std::string, CM_PROC_CSR> g_cm_proc_csr_name = {
        // clang-format off
        {"pc", CM_PROC_PC},
        {"fcsr", CM_PROC_FCSR},
        {"mvendorid", CM_PROC_MVENDORID},
        {"marchid", CM_PROC_MARCHID},
        {"mimpid", CM_PROC_MIMPID},
        {"mcycle", CM_PROC_MCYCLE},
        {"icycleinstret", CM_PROC_ICYCLEINSTRET},
        {"mstatus", CM_PROC_MSTATUS},
        {"mtvec", CM_PROC_MTVEC},
        {"mscratch", CM_PROC_MSCRATCH},
        {"mepc", CM_PROC_MEPC},
        {"mcause", CM_PROC_MCAUSE},
        {"mtval", CM_PROC_MTVAL},
        {"misa", CM_PROC_MISA},
        {"mie", CM_PROC_MIE},
        {"mip", CM_PROC_MIP},
        {"medeleg", CM_PROC_MEDELEG},
        {"mideleg", CM_PROC_MIDELEG},
        {"mcounteren", CM_PROC_MCOUNTEREN},
        {"menvcfg", CM_PROC_MENVCFG},
        {"stvec", CM_PROC_STVEC},
        {"sscratch", CM_PROC_SSCRATCH},
        {"sepc", CM_PROC_SEPC},
        {"scause", CM_PROC_SCAUSE},
        {"stval", CM_PROC_STVAL},
        {"satp", CM_PROC_SATP},
        {"scounteren", CM_PROC_SCOUNTEREN},
        {"senvcfg", CM_PROC_SENVCFG},
        {"ilrsc", CM_PROC_ILRSC},
        {"iflags", CM_PROC_IFLAGS},
        {"clint_mtimecmp", CM_PROC_CLINT_MTIMECMP},
        {"htif_tohost", CM_PROC_HTIF_TOHOST},
        {"htif_fromhost", CM_PROC_HTIF_FROMHOST},
        {"htif_ihalt", CM_PROC_HTIF_IHALT},
        {"htif_iconsole", CM_PROC_HTIF_ICONSOLE},
        {"htif_iyield", CM_PROC_HTIF_IYIELD},
        {"uarch_pc", CM_PROC_UARCH_PC},
        {"uarch_cycle", CM_PROC_UARCH_CYCLE},
        {"uarch_halt_flag", CM_PROC_UARCH_HALT_FLAG},
        {"uarch_ram_length", CM_PROC_UARCH_RAM_LENGTH}
        // clang-format on
    };
    const char *name = luaL_checkstring(L, idx);
    auto got = g_cm_proc_csr_name.find(name);
    if (got == g_cm_proc_csr_name.end()) {
        luaL_argerror(L, idx, "unknown csr");
    }
    return got->second;
} catch (const std::exception &e) {
    luaL_error(L, e.what());
    return CM_PROC_UNKNOWN; // will not be reached
} catch (...) {
    luaL_error(L, "unknown error with csr type conversion");
    return CM_PROC_UNKNOWN; // will not be reached
}

/// \brief Pushes C array of data to the Lua stack
/// \param L Lua state.
/// \param data Pointer to C array of data
/// \param data_size Size of array of data
static void push_raw_data(lua_State *L, const uint8_t *data, size_t data_size) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(data), data_size);
}

/// \brief Pushes a cm_access_log_type to the Lua stack
/// \param L Lua state.
/// \param log_type Pointer to cm_access_log_type to be pushed.
static void push_cm_access_log_type(lua_State *L, const cm_access_log_type *log_type) {
    lua_newtable(L);
    clua_setbooleanfield(L, log_type->annotations, "annotations", -1);
    clua_setbooleanfield(L, log_type->proofs, "proofs", -1);
}

/// \brief Converts an CM_ACCESS_TYPE to a string.
/// \param type Access type.
/// \returns String with access type name.
static const char *cm_access_type_name(CM_ACCESS_TYPE type) {
    switch (type) {
        case CM_ACCESS_READ:
            return "read";
        case CM_ACCESS_WRITE:
            return "write";
    }
    return nullptr;
}

/// \brief Converts a CM_BRACKET_TYPE to a string
/// \param type Bracket type.
/// \returns String with bracket type name.
static const char *cm_bracket_type_name(CM_BRACKET_TYPE type) {
    switch (type) {
        case CM_BRACKET_BEGIN:
            return "begin";
        case CM_BRACKET_END:
            return "end";
    }
    return nullptr;
}

void clua_push_cm_access_log(lua_State *L, const cm_access_log *log) {
    lua_newtable(L); // log
    lua_newtable(L); // log type
    push_cm_access_log_type(L, &log->log_type);
    lua_setfield(L, -2, "log_type"); // log

    // Add all accesses
    lua_newtable(L); // log accesses
    for (size_t i = 0; i < log->accesses.count; ++i) {
        const cm_access *a = &log->accesses.entry[i];
        lua_newtable(L); // log accesses wordaccess
        clua_setstringfield(L, cm_access_type_name(a->type), "type", -1);
        clua_setintegerfield(L, a->address, "address", -1);
        clua_setintegerfield(L, a->log2_size, "log2_size", -1);
        push_raw_data(L, a->read_data, a->read_data_size);
        lua_setfield(L, -2, "read");
        if (a->type == CM_ACCESS_WRITE) {
            push_raw_data(L, a->written_data, a->written_data_size);
            lua_setfield(L, -2, "written");
        }
        if (log->log_type.proofs && a->proof != nullptr) {
            clua_push_cm_proof(L, a->proof);
            lua_setfield(L, -2, "proof");
        }
        lua_rawseti(L, -2, static_cast<lua_Integer>(i) + 1);
    }
    lua_setfield(L, -2, "accesses"); // log
    // Add all brackets
    if (log->log_type.annotations) {
        lua_newtable(L); // log brackets
        for (size_t i = 0; i < log->brackets.count; ++i) {
            const cm_bracket_note *b = &log->brackets.entry[i];
            lua_newtable(L); // log brackets bracket
            clua_setstringfield(L, cm_bracket_type_name(b->type), "type", -1);
            clua_setintegerfield(L, b->where + 1, "where", -1); // convert from 0- to 1-based index
            clua_setstringfield(L, b->text, "text", -1);
            lua_rawseti(L, -2, static_cast<lua_Integer>(i) + 1);
        }
        lua_setfield(L, -2, "brackets"); // log

        lua_newtable(L); // log notes
        for (size_t i = 0; i < log->notes.count; ++i) {
            const char *note = log->notes.entry[i];
            lua_pushstring(L, note);
            lua_rawseti(L, -2, static_cast<lua_Integer>(i) + 1);
        }
        lua_setfield(L, -2, "notes"); // log
    }
}

void clua_push_cm_hash(lua_State *L, const cm_hash *hash) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    lua_pushlstring(L, reinterpret_cast<const char *>(hash), CM_MACHINE_HASH_BYTE_SIZE);
}

void clua_push_cm_semantic_version(lua_State *L, const cm_semantic_version *v) {
    lua_newtable(L);                                           // version
    clua_setintegerfield(L, v->major, "major", -1);            // version
    clua_setintegerfield(L, v->minor, "minor", -1);            // version
    clua_setintegerfield(L, v->patch, "patch", -1);            // version
    clua_setstringfield(L, v->pre_release, "pre_release", -1); // version
    clua_setstringfield(L, v->build, "build", -1);             // version
}

void clua_push_cm_proof(lua_State *L, const cm_merkle_tree_proof *proof) {
    lua_newtable(L); // proof
    lua_newtable(L); // proof siblings
    for (size_t log2_size = proof->log2_target_size; log2_size < proof->log2_root_size; ++log2_size) {
        clua_push_cm_hash(L, &proof->sibling_hashes.entry[proof->log2_root_size - 1 - log2_size]);
        lua_rawseti(L, -2, static_cast<lua_Integer>(proof->log2_root_size - log2_size));
    }
    lua_setfield(L, -2, "sibling_hashes");                                    // proof
    clua_setintegerfield(L, proof->target_address, "target_address", -1);     // proof
    clua_setintegerfield(L, proof->log2_target_size, "log2_target_size", -1); // proof
    clua_setintegerfield(L, proof->log2_root_size, "log2_root_size", -1);     // proof
    clua_push_cm_hash(L, &proof->root_hash);
    lua_setfield(L, -2, "root_hash"); // proof
    clua_push_cm_hash(L, &proof->target_hash);
    lua_setfield(L, -2, "target_hash"); // proof
}

cm_access_log_type clua_check_cm_log_type(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    return cm_access_log_type{opt_boolean_field(L, tabidx, "proofs"), opt_boolean_field(L, tabidx, "annotations")};
}

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define PUSH_PROCESSOR_CONFIG_CSR(regname)                                                                             \
    do {                                                                                                               \
        clua_setintegerfield(L, p.regname, #regname, -1);                                                              \
    } while (0)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define PUSH_CM_PROCESSOR_CONFIG_CSR(regname)                                                                          \
    do {                                                                                                               \
        clua_setintegerfield(L, p->regname, #regname, -1);                                                             \
    } while (0)

/// \brief Pushes a cm_processor_config to the Lua stack
/// \param L Lua state.
/// \param p Processor_config to be pushed.
static void push_cm_processor_config(lua_State *L, const cm_processor_config *p) {
    lua_newtable(L); // p
    lua_newtable(L); // p x
    for (int i = 1; i <= (X_REG_COUNT - 1); i++) {
        lua_pushinteger(L, static_cast<lua_Integer>(p->x[i]));
        lua_rawseti(L, -2, i);
    }
    lua_setfield(L, -2, "x");
    lua_newtable(L); // p f
    for (int i = 0; i <= (F_REG_COUNT - 1); i++) {
        lua_pushinteger(L, static_cast<lua_Integer>(p->f[i]));
        lua_rawseti(L, -2, i);
    }
    lua_setfield(L, -2, "f");
    PUSH_CM_PROCESSOR_CONFIG_CSR(pc);
    PUSH_CM_PROCESSOR_CONFIG_CSR(fcsr);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mvendorid);
    PUSH_CM_PROCESSOR_CONFIG_CSR(marchid);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mimpid);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mcycle);
    PUSH_CM_PROCESSOR_CONFIG_CSR(icycleinstret);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mstatus);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mtvec);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mscratch);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mepc);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mcause);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mtval);
    PUSH_CM_PROCESSOR_CONFIG_CSR(misa);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mie);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mip);
    PUSH_CM_PROCESSOR_CONFIG_CSR(medeleg);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mideleg);
    PUSH_CM_PROCESSOR_CONFIG_CSR(mcounteren);
    PUSH_CM_PROCESSOR_CONFIG_CSR(menvcfg);
    PUSH_CM_PROCESSOR_CONFIG_CSR(stvec);
    PUSH_CM_PROCESSOR_CONFIG_CSR(sscratch);
    PUSH_CM_PROCESSOR_CONFIG_CSR(sepc);
    PUSH_CM_PROCESSOR_CONFIG_CSR(scause);
    PUSH_CM_PROCESSOR_CONFIG_CSR(stval);
    PUSH_CM_PROCESSOR_CONFIG_CSR(satp);
    PUSH_CM_PROCESSOR_CONFIG_CSR(scounteren);
    PUSH_CM_PROCESSOR_CONFIG_CSR(senvcfg);
    PUSH_CM_PROCESSOR_CONFIG_CSR(ilrsc);
    PUSH_CM_PROCESSOR_CONFIG_CSR(iflags);
}

/// \brief Pushes a cm_ram_config to the Lua stack
/// \param L Lua state.
/// \param r Ram configuration to be pushed.
static void push_cm_ram_config(lua_State *L, const cm_ram_config *r) {
    lua_newtable(L);
    clua_setintegerfield(L, r->length, "length", -1);
    if (r->image_filename != nullptr) {
        clua_setstringfield(L, r->image_filename, "image_filename", -1);
    }
}

/// \brief Pushes a cm_rom_config to the Lua stack
/// \param L Lua state.
/// \param r Ram configuration to be pushed.
static void push_cm_rom_config(lua_State *L, const cm_rom_config *r) {
    lua_newtable(L);
    if (r->bootargs != nullptr) {
        clua_setstringfield(L, r->bootargs, "bootargs", -1);
    }
    if (r->image_filename) {
        clua_setstringfield(L, r->image_filename, "image_filename", -1);
    }
}

/// \brief Pushes an cm_tlb_config to the Lua stack
/// \param L Lua state.
/// \param c Tlb configuration to be pushed.
static void push_cm_tlb_config(lua_State *L, const cm_tlb_config *t) {
    lua_newtable(L);
    if (t->image_filename != nullptr) {
        clua_setstringfield(L, t->image_filename, "image_filename", -1);
    }
}

/// \brief Pushes an cm_htif_config to the Lua stack
/// \param L Lua state.
/// \param h Htif configuration to be pushed.
static void push_cm_htif_config(lua_State *L, const cm_htif_config *h) {
    lua_newtable(L);
    clua_setbooleanfield(L, h->console_getchar, "console_getchar", -1);
    clua_setbooleanfield(L, h->yield_manual, "yield_manual", -1);
    clua_setbooleanfield(L, h->yield_automatic, "yield_automatic", -1);
    clua_setintegerfield(L, h->fromhost, "fromhost", -1);
    clua_setintegerfield(L, h->tohost, "tohost", -1);
}

/// \brief Pushes an cm_clint_config to the Lua stack
/// \param L Lua state.
/// \param c Clint configuration to be pushed.
static void push_cm_clint_config(lua_State *L, const cm_clint_config *c) {
    lua_newtable(L);
    clua_setintegerfield(L, c->mtimecmp, "mtimecmp", -1);
}

/// \brief Pushes cm_memory_range_config to the Lua stack
/// \param L Lua state.
/// \param m Memory range config to be pushed.
static void push_cm_memory_range_config(lua_State *L, const cm_memory_range_config *m) {
    lua_newtable(L);
    clua_setintegerfield(L, m->start, "start", -1);
    clua_setintegerfield(L, m->length, "length", -1);
    if (m->image_filename != nullptr) {
        clua_setstringfield(L, m->image_filename, "image_filename", -1);
    }
    clua_setbooleanfield(L, m->shared, "shared", -1);
}

/// \brief Pushes cm_rollup_config to the Lua stack
/// \param L Lua state.
/// \param r Rollup config to be pushed.
static void push_cm_rollup_config(lua_State *L, const cm_rollup_config *r) {
    lua_newtable(L);                                    // rollup
    push_cm_memory_range_config(L, &r->rx_buffer);      // rollup rx_buffer
    lua_setfield(L, -2, "rx_buffer");                   // rollup
    push_cm_memory_range_config(L, &r->tx_buffer);      // rollup tx_buffer
    lua_setfield(L, -2, "tx_buffer");                   // rollup
    push_cm_memory_range_config(L, &r->input_metadata); // rollup input_metadata
    lua_setfield(L, -2, "input_metadata");              // rollup
    push_cm_memory_range_config(L, &r->voucher_hashes); // rollup voucher_hashes
    lua_setfield(L, -2, "voucher_hashes");              // rollup
    push_cm_memory_range_config(L, &r->notice_hashes);  // rollup notice_hashes
    lua_setfield(L, -2, "notice_hashes");               // rollup
}

/// \brief Pushes cm_flash_drive_configs to the Lua stack
/// \param L Lua state.
/// \param flash_drives Flash drive configuration array to be pushed.
static void push_cm_flash_drive_configs(lua_State *L, const cm_memory_range_config_array *flash_drives) {
    lua_newtable(L);
    for (size_t j = 0; j < flash_drives->count; ++j) {
        push_cm_memory_range_config(L, &flash_drives->entry[j]);
        lua_rawseti(L, -2, static_cast<lua_Integer>(j) + 1);
    }
}

/// \brief Pushes a cm_uarch_ram_config to the Lua stack
/// \param L Lua state.
/// \param r microarchitecture RAM configuration to be pushed.
static void push_cm_uarch_ram_config(lua_State *L, const cm_uarch_ram_config *r) {
    lua_newtable(L);
    clua_setintegerfield(L, r->length, "length", -1);
    if (r->image_filename != nullptr) {
        clua_setstringfield(L, r->image_filename, "image_filename", -1);
    }
}

/// \brief Pushes an cm_uarch_processor_config to the Lua stack
/// \param L Lua state.
/// \param c microarchitecture processor configuration to be pushed.
static void push_cm_uarch_processor_config(lua_State *L, const cm_uarch_processor_config *u) {
    lua_newtable(L);
    clua_setintegerfield(L, u->pc, "pc", -1);
    clua_setintegerfield(L, u->cycle, "cycle", -1);
    lua_newtable(L);
    for (int i = 1; i <= (UARCH_X_REG_COUNT - 1); i++) {
        lua_pushinteger(L, static_cast<lua_Integer>(u->x[i]));
        lua_rawseti(L, -2, i);
    }
    lua_setfield(L, -2, "x");
}

/// \brief Pushes an cm_uarch_config to the Lua stack
/// \param L Lua state.
/// \param c microarchitecture configuration to be pushed.
static void push_cm_uarch_config(lua_State *L, const cm_uarch_config *u) {
    lua_newtable(L);
    push_cm_uarch_ram_config(L, &u->ram);             // config ram
    lua_setfield(L, -2, "ram");                       // config
    push_cm_uarch_processor_config(L, &u->processor); // config processor
    lua_setfield(L, -2, "processor");                 // config
}

void clua_push_cm_machine_config(lua_State *L, const cm_machine_config *c) {
    lua_newtable(L);                                 // config
    push_cm_processor_config(L, &c->processor);      // config processor
    lua_setfield(L, -2, "processor");                // config
    push_cm_tlb_config(L, &c->tlb);                  // config tlb
    lua_setfield(L, -2, "tlb");                      // config
    push_cm_htif_config(L, &c->htif);                // config htif
    lua_setfield(L, -2, "htif");                     // config
    push_cm_clint_config(L, &c->clint);              // config clint
    lua_setfield(L, -2, "clint");                    // config
    push_cm_flash_drive_configs(L, &c->flash_drive); // config flash_drive
    lua_setfield(L, -2, "flash_drive");              // config
    push_cm_ram_config(L, &c->ram);                  // config ram
    lua_setfield(L, -2, "ram");                      // config
    push_cm_rom_config(L, &c->rom);                  // config rom
    lua_setfield(L, -2, "rom");                      // config
    push_cm_uarch_config(L, &c->uarch);              // uarch
    lua_setfield(L, -2, "uarch");                    // config
    if (c->rollup.has_value) {
        push_cm_rollup_config(L, &c->rollup); // config rollup
        lua_setfield(L, -2, "rollup");        // config
    }
}

#if 0
/// \brief Pushes an cm_concurrency_runtime_config to the Lua stack
/// \param L Lua state.
/// \param c C api concurrency runtime config to be pushed.
static void push_cm_concurrency_runtime_config(lua_State *L, const cm_concurrency_runtime_config *c) {
    lua_newtable(L);
    clua_setintegerfield(L, c->update_merkle_tree, "update_merkle_tree", -1);
}

void clua_push_cm_machine_runtime_config(lua_State *L, const cm_machine_runtime_config *r) {
    lua_newtable(L);                                        // config
    push_cm_concurrency_runtime_config(L, &r->concurrency); // config concurrency
    lua_setfield(L, -2, "concurrency");                     // config
}
#endif

/// \brief Loads RAM config from Lua to cm_machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param r C api RAM config structure to receive results.
static void check_cm_ram_config(lua_State *L, int tabidx, cm_ram_config *r) {
    check_table_field(L, tabidx, "ram");
    r->length = check_uint_field(L, -1, "length");
    r->image_filename = opt_copy_string_field(L, -1, "image_filename");
    lua_pop(L, 1);
}

/// \brief Loads ROM config from Lua to cm_rom_config
/// \param L Lua state
/// \param tabidx Config stack index
/// \param r C api ROM config structure to receive results
static void check_cm_rom_config(lua_State *L, int tabidx, cm_rom_config *r) {
    if (!opt_table_field(L, tabidx, "rom")) {
        return;
    }
    r->image_filename = opt_copy_string_field(L, -1, "image_filename");
    r->bootargs = opt_copy_string_field(L, -1, "bootargs");
    lua_pop(L, 1);
}

cm_memory_range_config *clua_check_cm_memory_range_config(lua_State *L, int tabidx, const char *what,
    cm_memory_range_config *m) {
    if (!lua_istable(L, tabidx)) {
        luaL_error(L, "%s memory range not a table", what);
    }
    m->shared = opt_boolean_field(L, tabidx, "shared");
    m->start = check_uint_field(L, tabidx, "start");
    m->length = check_uint_field(L, tabidx, "length");
    m->image_filename = opt_copy_string_field(L, tabidx, "image_filename");
    return m;
}

/// \brief Loads rollup config from Lua to cm_rollup_config
/// \param L Lua state
/// \param tabidx Config stack index
/// \param r C api rollup config structure to receive results
static void check_cm_rollup_config(lua_State *L, int tabidx, cm_rollup_config *r) {
    if (!opt_table_field(L, tabidx, "rollup")) {
        r->has_value = false;
        return;
    }
    r->has_value = true;
    lua_getfield(L, -1, "rx_buffer");
    clua_check_cm_memory_range_config(L, -1, "rollup rx buffer", &r->rx_buffer);
    lua_pop(L, 1);
    lua_getfield(L, -1, "tx_buffer");
    clua_check_cm_memory_range_config(L, -1, "rollup rx buffer", &r->tx_buffer);
    lua_pop(L, 1);
    lua_getfield(L, -1, "input_metadata");
    clua_check_cm_memory_range_config(L, -1, "rollup input metadata", &r->input_metadata);
    lua_pop(L, 1);
    lua_getfield(L, -1, "voucher_hashes");
    clua_check_cm_memory_range_config(L, -1, "rollup voucher hashes", &r->voucher_hashes);
    lua_pop(L, 1);
    lua_getfield(L, -1, "notice_hashes");
    clua_check_cm_memory_range_config(L, -1, "rollup notice hashes", &r->notice_hashes);
    lua_pop(L, 2);
}

/// \brief Loads a C api flash drive configs from a Lua machine config
/// \param L Lua state
/// \param tabidx Machine config stack index
/// \param fs Receives allocated array of flash drive configs
static void check_cm_flash_drive_configs(lua_State *L, int tabidx, cm_memory_range_config_array *fs) {
    memset(fs, 0, sizeof(cm_memory_range_config_array));
    if (!opt_table_field(L, tabidx, "flash_drive")) {
        return;
    }
    auto flash_drive_table_idx = lua_gettop(L);
    size_t count = luaL_len(L, flash_drive_table_idx);
    if (count > CM_FLASH_DRIVE_CONFIGS_MAX_SIZE) {
        luaL_error(L, "too many flash drives (expected max %d, got %d)", CM_FLASH_DRIVE_CONFIGS_MAX_SIZE,
            static_cast<int>(fs->count));
    }
    fs->count = count;
    fs->entry = new cm_memory_range_config[count]{};
    for (unsigned i = 1; i <= fs->count; ++i) {
        lua_geti(L, flash_drive_table_idx, i);
        clua_check_cm_memory_range_config(L, -1, "flash drive", &fs->entry[i - 1]);
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

/// \brief Loads processor config from a Lua to C api machine config
/// \param L Lua state
/// \param tabidx Config stack index
/// \param p Pointer to C api processor config structure to receive results
/// \param def Default configuration
static void check_cm_processor_config(lua_State *L, int tabidx, cm_processor_config *p,
    const cm_processor_config *def) {
    if (!opt_table_field(L, tabidx, "processor")) {
        *p = *def;
        return;
    }
    // x
    lua_getfield(L, -1, "x");
    if (lua_istable(L, -1)) {
        for (int i = 1; i < X_REG_COUNT; i++) {
            p->x[i] = opt_uint_field(L, -1, i, def->x[i]);
        }
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid processor.x (expected table)");
    }
    lua_pop(L, 1);
    // f
    lua_getfield(L, -1, "f");
    if (lua_istable(L, -1)) {
        for (int i = 0; i < F_REG_COUNT; i++) {
            p->f[i] = opt_uint_field(L, -1, i, def->f[i]);
        }
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid processor.f (expected table)");
    }
    lua_pop(L, 1);
    // CSRs
    p->pc = opt_uint_field(L, -1, "pc", def->pc);
    p->fcsr = opt_uint_field(L, -1, "fcsr", def->fcsr);
    p->mvendorid = opt_uint_field(L, -1, "mvendorid", def->mvendorid);
    p->marchid = opt_uint_field(L, -1, "marchid", def->marchid);
    p->mimpid = opt_uint_field(L, -1, "mimpid", def->mimpid);
    p->mcycle = opt_uint_field(L, -1, "mcycle", def->mcycle);
    p->icycleinstret = opt_uint_field(L, -1, "icycleinstret", def->icycleinstret);
    p->mstatus = opt_uint_field(L, -1, "mstatus", def->mstatus);
    p->mtvec = opt_uint_field(L, -1, "mtvec", def->mtvec);
    p->mscratch = opt_uint_field(L, -1, "mscratch", def->mscratch);
    p->mepc = opt_uint_field(L, -1, "mepc", def->mepc);
    p->mcause = opt_uint_field(L, -1, "mcause", def->mcause);
    p->mtval = opt_uint_field(L, -1, "mtval", def->mtval);
    p->misa = opt_uint_field(L, -1, "misa", def->misa);
    p->mie = opt_uint_field(L, -1, "mie", def->mie);
    p->mip = opt_uint_field(L, -1, "mip", def->mip);
    p->medeleg = opt_uint_field(L, -1, "medeleg", def->medeleg);
    p->mideleg = opt_uint_field(L, -1, "mideleg", def->mideleg);
    p->mcounteren = opt_uint_field(L, -1, "mcounteren", def->mcounteren);
    p->menvcfg = opt_uint_field(L, -1, "menvcfg", def->menvcfg);
    p->stvec = opt_uint_field(L, -1, "stvec", def->stvec);
    p->sscratch = opt_uint_field(L, -1, "sscratch", def->sscratch);
    p->sepc = opt_uint_field(L, -1, "sepc", def->sepc);
    p->scause = opt_uint_field(L, -1, "scause", def->scause);
    p->stval = opt_uint_field(L, -1, "stval", def->stval);
    p->satp = opt_uint_field(L, -1, "satp", def->satp);
    p->scounteren = opt_uint_field(L, -1, "scounteren", def->scounteren);
    p->senvcfg = opt_uint_field(L, -1, "senvcfg", def->senvcfg);
    p->ilrsc = opt_uint_field(L, -1, "ilrsc", def->ilrsc);
    p->iflags = opt_uint_field(L, -1, "iflags", def->iflags);
    lua_pop(L, 1);
}

/// \brief Loads tlb config from a Lua to C api machine config
/// \param L Lua state
/// \param tabidx Config stack index
/// \param p Pointer to C api processor config structure to receive results
/// \param def Default configuration
static void check_cm_tlb_config(lua_State *L, int tabidx, cm_tlb_config *t) {
    if (!opt_table_field(L, tabidx, "tlb")) {
        return;
    }
    t->image_filename = opt_copy_string_field(L, -1, "image_filename");
    lua_pop(L, 1);
}

/// \brief Loads C api HTIF config from Lua.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param h C api HTIF config structure to receive results
static void check_cm_htif_config(lua_State *L, int tabidx, cm_htif_config *h) {
    if (!opt_table_field(L, tabidx, "htif")) {
        return;
    }
    h->tohost = opt_uint_field(L, -1, "tohost", h->tohost);
    h->fromhost = opt_uint_field(L, -1, "fromhost", h->fromhost);
    h->console_getchar = opt_boolean_field(L, -1, "console_getchar");
    h->yield_manual = opt_boolean_field(L, -1, "yield_manual");
    h->yield_automatic = opt_boolean_field(L, -1, "yield_automatic");
    lua_pop(L, 1);
}

/// \brief Loads C api CLINT config from Lua
/// \param L Lua state
/// \param tabidx Config stack index
/// \param c CLINT config structure to receive results
static void check_cm_clint_config(lua_State *L, int tabidx, cm_clint_config *c) {
    if (!opt_table_field(L, tabidx, "clint")) {
        return;
    }
    c->mtimecmp = opt_uint_field(L, -1, "mtimecmp", c->mtimecmp);
    lua_pop(L, 1);
}

cm_processor_config get_default_processor_config(lua_State *L) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to adjust config
    const auto *config = cm_new_default_machine_config();
    if (!config) {
        luaL_error(L, "unable to obtain default config (out of memory?)"); // LCOV_EXCL_LINE
        // Just to make clang-tidy happy. It doesn't know luaL_error is [[noreturn]]
        return cm_processor_config{}; // LCOV_EXCL_LINE
    }
    cm_processor_config processor = config->processor;
    cm_delete_machine_config(config);
    return processor;
}

cm_uarch_processor_config get_default_uarch_processor_config(lua_State *L) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): remove const to adjust config
    const auto *config = cm_new_default_machine_config();
    if (!config) {
        luaL_error(L, "unable to obtain default config (out of memory?)"); // LCOV_EXCL_LINE
        // Just to make clang-tidy happy. It doesn't know luaL_error is [[noreturn]]
        return cm_uarch_processor_config{}; // LCOV_EXCL_LINE
    }
    cm_uarch_processor_config uarch_processor_config = config->uarch.processor;
    cm_delete_machine_config(config);
    return uarch_processor_config;
}

/// \brief Loads microarchitecture RAM config from Lua to cm_uarch_ram_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param r C api microarchitecture RAM config structure to receive results.
static void check_cm_uarch_ram_config(lua_State *L, int tabidx, cm_uarch_ram_config *r) {
    check_table_field(L, tabidx, "ram");
    r->length = check_uint_field(L, -1, "length");
    r->image_filename = opt_copy_string_field(L, -1, "image_filename");
    lua_pop(L, 1);
}

/// \brief Loads C api microarchitecture processor config from Lua to cm_uarch_processor_config
/// \param L Lua state
/// \param tabidx Config stack index
/// \param u C api microarchitecture processor config structure to receive results
static void check_cm_uarch_processor_config(lua_State *L, int tabidx, cm_uarch_processor_config *p,
    const cm_uarch_processor_config *def) {
    if (!opt_table_field(L, tabidx, "processor")) {
        *p = *def;
        return;
    }
    p->pc = opt_uint_field(L, -1, "pc", def->pc);
    p->cycle = opt_uint_field(L, -1, "cycle", def->cycle);
    lua_getfield(L, -1, "x");
    if (lua_istable(L, -1)) {
        for (int i = 1; i <= (UARCH_X_REG_COUNT - 1); i++) {
            p->x[i] = opt_uint_field(L, -1, i, def->x[i]);
        }
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid uarch.processor.x (expected table)");
    }
    lua_pop(L, 1); // x
    lua_pop(L, 1); // processor
}

/// \brief Loads C api microarchitecture config from Lua to cm_uarch_config
/// \param L Lua state
/// \param tabidx Config stack index
/// \param u C api microarchitecture config structure to receive results
static void check_cm_uarch_config(lua_State *L, int tabidx, cm_uarch_config *u) {
    u->processor = get_default_uarch_processor_config(L);
    if (!opt_table_field(L, tabidx, "uarch")) {
        return;
    }
    check_cm_uarch_ram_config(L, -1, &u->ram);
    check_cm_uarch_processor_config(L, -1, &u->processor, &u->processor);
    lua_pop(L, 1); // uarch
}

cm_machine_config *clua_check_cm_machine_config(lua_State *L, int tabidx, int ctxidx) {
    auto &managed = clua_push_to(L, clua_managed_cm_ptr<cm_machine_config>(new cm_machine_config{}), ctxidx);
    cm_machine_config *config = managed.get();
    config->processor = get_default_processor_config(L);
    check_cm_processor_config(L, tabidx, &config->processor, &config->processor);
    check_cm_ram_config(L, tabidx, &config->ram);
    check_cm_rom_config(L, tabidx, &config->rom);
    check_cm_tlb_config(L, tabidx, &config->tlb);
    check_cm_htif_config(L, tabidx, &config->htif);
    check_cm_clint_config(L, tabidx, &config->clint);
    check_cm_uarch_config(L, tabidx, &config->uarch);
    check_cm_rollup_config(L, tabidx, &config->rollup);
    check_cm_flash_drive_configs(L, tabidx, &config->flash_drive);
    managed.release();
    lua_pop(L, 1); //??DD I don't think lua_pop can throw, but we should check
    return config;
}

/// \brief Loads C api concurrency runtime config from Lua
/// \param L Lua state
/// \param tabidx Runtime config stack index
/// \param c C api concurrency runtime config structure to receive results
static void check_cm_concurrency_runtime_config(lua_State *L, int tabidx, cm_concurrency_runtime_config *c) {
    if (!opt_table_field(L, tabidx, "concurrency")) {
        return;
    }
    c->update_merkle_tree = opt_uint_field(L, -1, "update_merkle_tree");
    lua_pop(L, 1);
}

/// \brief Loads C api htif runtime config from Lua
/// \param L Lua state
/// \param tabidx Runtime config stack index
/// \param c C api htif runtime config structure to receive results
static void check_cm_htif_runtime_config(lua_State *L, int tabidx, cm_htif_runtime_config *c) {
    if (!opt_table_field(L, tabidx, "htif")) {
        return;
    }
    c->no_console_putchar = opt_boolean_field(L, -1, "no_console_putchar");
    lua_pop(L, 1);
}

cm_machine_runtime_config *clua_check_cm_machine_runtime_config(lua_State *L, int tabidx, int ctxidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    auto &managed =
        clua_push_to(L, clua_managed_cm_ptr<cm_machine_runtime_config>(new cm_machine_runtime_config{}), ctxidx);
    cm_machine_runtime_config *config = managed.get();
    check_cm_concurrency_runtime_config(L, tabidx, &config->concurrency);
    check_cm_htif_runtime_config(L, tabidx, &config->htif);
    config->skip_root_hash_check = opt_boolean_field(L, tabidx, "skip_root_hash_check");
    config->skip_version_check = opt_boolean_field(L, tabidx, "skip_version_check");
    managed.release();
    lua_pop(L, 1);
    return config;
}

cm_machine_runtime_config *clua_opt_cm_machine_runtime_config(lua_State *L, int tabidx,
    const cm_machine_runtime_config *r, int ctxidx) {
    if (!lua_isnoneornil(L, tabidx)) {
        return clua_check_cm_machine_runtime_config(L, tabidx, ctxidx);
    } else {
        auto *def = new cm_machine_runtime_config{};
        if (r != nullptr) {
            def->concurrency = r->concurrency;
        }
        return def;
    }
}

} // namespace cartesi
