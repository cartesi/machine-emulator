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
#include "riscv-constants.h"

namespace cartesi {

/// \brief Deleter for C string
template <>
void cm_delete<char>(char *ptr) { // NOLINT(readability-non-const-parameter)
    delete[] ptr;
}

/// \brief Deleter for C data buffer
template <>
void cm_delete<unsigned char>(unsigned char *ptr) { // NOLINT(readability-non-const-parameter)
    delete[] ptr;
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
    const lua_Integer ival = lua_tointeger(L, -1);
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
    const lua_Integer ival = lua_tointeger(L, -1);
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
    if (log2_target_size > log2_root_size) {
        luaL_error(L, "target size cannot be greater than root size");
    }
    const size_t sibling_hashes_count = log2_root_size - log2_target_size;
    if (sibling_hashes_count > 64) {
        luaL_error(L, "too many sibling hashes (expected max %d, got %d)", 64, static_cast<int>(sibling_hashes_count));
    }
    sibling_hashes->count = sibling_hashes_count;
    sibling_hashes->entry = new cm_hash[sibling_hashes_count]{};
    for (size_t log2_size = log2_target_size; log2_size < log2_root_size; ++log2_size) {
        lua_rawgeti(L, idx, static_cast<lua_Integer>(log2_size - log2_target_size) + 1);
        auto index = log2_size - log2_target_size;
        clua_check_cm_hash(L, -1, &sibling_hashes->entry[index]);
        lua_pop(L, 1);
    }
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
        const uint64_t expected_len = UINT64_C(1) << log2_size;
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

static unsigned char *opt_cm_access_data_field(lua_State *L, int tabidx, const char *field, uint64_t log2_size,
    size_t *data_size) {
    return aux_cm_access_data_field(L, tabidx, field, log2_size, true, data_size);
}

/// \brief Loads an cm_access from Lua
/// \param L Lua state
/// \param tabidx access stack index
/// \param proofs Whether to load sibling hashes for constructing proofs
/// \param a Pointer to receive access
/// \param ctxidx Index (or pseudo-index) of clua context
static void check_cm_access(lua_State *L, int tabidx, bool proofs, cm_access *a, int ctxidx) {
    (void) ctxidx;
    luaL_checktype(L, tabidx, LUA_TTABLE);
    a->type = check_cm_access_type_field(L, tabidx, "type");
    a->address = check_uint_field(L, tabidx, "address");
    a->log2_size = check_int_field(L, tabidx, "log2_size");
    const int expected_data_log2_size = std::max<int>(a->log2_size, CM_TREE_LOG2_WORD_SIZE);
    if (opt_table_field(L, tabidx, "sibling_hashes")) {
        a->sibling_hashes = new cm_hash_array{};
        check_sibling_cm_hashes(L, -1, expected_data_log2_size, CM_TREE_LOG2_ROOT_SIZE, a->sibling_hashes);
        lua_pop(L, 1);
    } else if (proofs) {
        luaL_error(L, "missing sibling_hashes");
    }
    lua_getfield(L, tabidx, "read_hash");
    clua_check_cm_hash(L, -1, &a->read_hash);
    lua_pop(L, 1);
    if (a->type == CM_ACCESS_WRITE) {
        lua_getfield(L, tabidx, "written_hash");
        clua_check_cm_hash(L, -1, &a->written_hash);
        lua_pop(L, 1);
    }
    a->read_data = opt_cm_access_data_field(L, tabidx, "read", expected_data_log2_size, &a->read_data_size);
    a->written_data = opt_cm_access_data_field(L, tabidx, "written", expected_data_log2_size, &a->written_data_size);
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
    log->log_type.large_data = opt_boolean_field(L, -1, "large_data");
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

CM_CSR clua_check_cm_proc_csr(lua_State *L, int idx) try {
    /// \brief Mapping between CSR names and C API constants
    const static std::unordered_map<std::string, CM_CSR> g_cm_proc_csr_name = {
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
    luaL_error(L, e.what());
    return CM_CSR_UNKNOWN; // will not be reached
} catch (...) {
    luaL_error(L, "unknown error with csr type conversion");
    return CM_CSR_UNKNOWN; // will not be reached
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
    clua_setbooleanfield(L, log_type->large_data, "large_data", -1);
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
        clua_push_cm_hash(L, &a->read_hash);
        lua_setfield(L, -2, "read_hash"); // read_hash
        if (a->read_data != nullptr) {
            push_raw_data(L, a->read_data, a->read_data_size);
            lua_setfield(L, -2, "read");
        }
        if (a->type == CM_ACCESS_WRITE) {
            clua_push_cm_hash(L, &a->written_hash);
            lua_setfield(L, -2, "written_hash");
            if (a->written_data != nullptr) {
                push_raw_data(L, a->written_data, a->written_data_size);
                lua_setfield(L, -2, "written");
            }
        }
        if (log->log_type.proofs && a->sibling_hashes != nullptr) {
            lua_newtable(L);
            const int proof_log2_size = std::max<int>(a->log2_size, CM_TREE_LOG2_WORD_SIZE);
            for (size_t log2_size = proof_log2_size; log2_size < CM_TREE_LOG2_ROOT_SIZE; log2_size++) {
                clua_push_cm_hash(L, &a->sibling_hashes->entry[log2_size - proof_log2_size]);
                lua_rawseti(L, -2, static_cast<lua_Integer>(log2_size - proof_log2_size) + 1);
            }
            lua_setfield(L, -2, "sibling_hashes");
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

cm_access_log_type clua_check_cm_log_type(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    return cm_access_log_type{
        opt_boolean_field(L, tabidx, "proofs"),
        opt_boolean_field(L, tabidx, "annotations"),
        opt_boolean_field(L, tabidx, "large_data"),
    };
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

nlohmann::json clua_value_to_json(lua_State *L, int idx, bool base64encode) {
    nlohmann::json j;
    const int64_t len = clua_get_array_table_len(L, idx);
    if (len >= 0) { // array
        j = nlohmann::json::array();
        for (int64_t i = 1; i <= len; ++i) {
            lua_geti(L, idx, i);
            j.push_back(clua_value_to_json(L, -1, base64encode));
            lua_pop(L, 1); // pop value
        }
    } else if (lua_istable(L, idx)) { // object
        j = nlohmann::json::object();
        lua_pushvalue(L, idx);    // push table
        lua_pushnil(L);           // push key
        while (lua_next(L, -2)) { // update key, push value
            lua_pushvalue(L, -2); // push key again, because luaL_checkstring may overwrite it
            const char *key = luaL_checkstring(L, -1);
            j[key] = clua_value_to_json(L, -2, base64encode);
            lua_pop(L, 2); // pop key, value
        }
        lua_pop(L, 1); // pop table
    } else if (lua_isinteger(L, idx)) {
        j = lua_tointeger(L, idx);
    } else if (lua_isnumber(L, idx)) {
        j = lua_tonumber(L, idx);
    } else if (lua_isstring(L, idx)) {
        size_t len = 0;
        const char *ptr = lua_tolstring(L, idx, &len);
        const std::string_view data(ptr, len);
        if (base64encode) {
            j = cartesi::encode_base64(data);
        } else {
            j = data;
        }
    } else if (lua_isboolean(L, idx)) {
        j = static_cast<bool>(lua_toboolean(L, idx));
    } else if (lua_isnil(L, idx)) {
        j = nullptr;
    } else {
        luaL_error(L, "lua value of type %s cannot be serialized to JSON", lua_typename(L, lua_type(L, idx)));
    }
    return j;
}

void clua_push_json(lua_State *L, const nlohmann::json &j, bool base64decode) {
    if (j.is_array()) {
        lua_createtable(L, static_cast<int>(j.size()), 0);
        int64_t i = 1;
        for (auto it = j.begin(); it != j.end(); ++it, ++i) {
            clua_push_json(L, *it, base64decode);
            lua_rawseti(L, -2, i);
        }
    } else if (j.is_object()) {
        lua_createtable(L, 0, static_cast<int>(j.size()));
        for (const auto &el : j.items()) {
            clua_push_json(L, el.value(), base64decode);
            lua_setfield(L, -2, el.key().c_str());
        }
    } else if (j.is_string()) {
        const auto data = j.template get<std::string_view>();
        if (base64decode) {
            const auto base64data = cartesi::decode_base64(data);
            lua_pushlstring(L, base64data.data(), base64data.length());
        } else {
            lua_pushlstring(L, data.data(), data.length());
        }
    } else if (j.is_number_unsigned()) {
        lua_pushinteger(L, static_cast<int64_t>(j.template get<uint64_t>()));
    } else if (j.is_number_integer()) {
        lua_pushinteger(L, j.template get<int64_t>());
    } else if (j.is_number_float()) {
        lua_pushnumber(L, j.template get<double>());
    } else if (j.is_boolean()) {
        lua_pushboolean(L, j.template get<bool>());
    } else if (j.is_null()) {
        lua_pushnil(L);
    } else {
        luaL_error(L, "JSON value of type %s cannot be to Lua", j.type_name());
    }
}

} // namespace cartesi
