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

#include <unordered_map>

#include "clua.h"
#include "clua-machine-util.h"

namespace cartesi {

/// \brief Mapping between CSR names and constants
const static std::unordered_map<std::string, machine::csr> g_csr_name = {
    {"pc", machine::csr::pc},
    {"mvendorid", machine::csr::mvendorid},
    {"marchid", machine::csr::marchid},
    {"mimpid", machine::csr::mimpid},
    {"mcycle", machine::csr::mcycle},
    {"minstret", machine::csr::minstret},
    {"mstatus", machine::csr::mstatus},
    {"mtvec", machine::csr::mtvec},
    {"mscratch", machine::csr::mscratch},
    {"mepc", machine::csr::mepc},
    {"mcause", machine::csr::mcause},
    {"mtval", machine::csr::mtval},
    {"misa", machine::csr::misa},
    {"mie", machine::csr::mie},
    {"mip", machine::csr::mip},
    {"medeleg", machine::csr::medeleg},
    {"mideleg", machine::csr::mideleg},
    {"mcounteren", machine::csr::mcounteren},
    {"stvec", machine::csr::stvec},
    {"sscratch", machine::csr::sscratch},
    {"sepc", machine::csr::sepc},
    {"scause", machine::csr::scause},
    {"stval", machine::csr::stval},
    {"satp", machine::csr::satp},
    {"scounteren", machine::csr::scounteren},
    {"ilrsc", machine::csr::ilrsc},
    {"iflags", machine::csr::iflags},
    {"clint_mtimecmp", machine::csr::clint_mtimecmp},
    {"htif_tohost", machine::csr::htif_tohost},
    {"htif_fromhost", machine::csr::htif_fromhost},
    {"htif_ihalt", machine::csr::htif_ihalt},
    {"htif_iconsole", machine::csr::htif_iconsole},
    {"htif_iyield", machine::csr::htif_iyield},
};

/// \brief Returns an optional boolean field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value, or false if missing.
static bool opt_boolean_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    lua_getfield(L, tabidx, field);
    bool val = lua_toboolean(L, -1);
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
    return (uint64_t) val;
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
    return (uint64_t) val;
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

/// \brief Returns an integer field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value. Throws error if field is missing.
static int check_int_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    lua_Integer ival;
    lua_getfield(L, tabidx, field);
    if (!lua_isinteger(L, -1))
        luaL_error(L, "invalid %s (expected integer, got %s)", field,
            lua_typename(L, lua_type(L, -1)));
    ival = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return (int) ival;
}

/// \brief Returns an integer field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Field value. Throws error if field is missing.
static uint64_t check_uint_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    lua_Integer ival;
    lua_getfield(L, tabidx, field);
    if (!lua_isinteger(L, -1))
        luaL_error(L, "invalid %s (expected unsigned integer, got %s)", field,
            lua_typename(L, lua_type(L, -1)));
    ival = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return (uint64_t) ival;
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

/// \brief Returns an access_type table field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Corresponding access_type.
static access_type check_access_type_field(lua_State *L, int tabidx,
    const char *field) {
    auto name = check_string_field(L, tabidx, field);
    if (name.compare("read") == 0) {
        return access_type::read;
    } else if (name.compare("write") == 0) {
        return access_type::write;
    } else {
        luaL_error(L, "invalid %s (expected access type)", field);
        return access_type::read; // never reached
    }
}

/// \brief Returns an bracket_type table field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \returns Corresponding bracket_type.
static bracket_type check_bracket_type_field(lua_State *L, int tabidx,
    const char *field) {
    auto name = check_string_field(L, tabidx, field);
    if (name.compare("begin") == 0) {
        return bracket_type::begin;
    } else if (name.compare("end") == 0) {
        return bracket_type::end;
    } else {
        luaL_error(L, "invalid %s (expected bracket type)", field);
        return bracket_type::begin; // never reached
    }
}

/// \brief Loads a bracket_note from Lua.
/// \param L Lua state.
/// \param tabidx Bracket_note stack index.
/// \returns The bracket_note.
static bracket_note check_bracket_note(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    return {
        check_bracket_type_field(L, -1, "type"),
        check_uint_field(L, -1, "where")-1, // confert from 1- to 0-based index
        check_string_field(L, -1, "text")
    };
}

/// \brief Loads an array of sibling_hashes from Lua.
/// \param L Lua state.
/// \param idx Proof stack index.
/// \param log2_size of node from which to obtain siblings.
/// \returns The sibling_hashes array.
static merkle_tree::siblings_type check_sibling_hashes(lua_State *L, int idx,
    int log2_size) {
    luaL_checktype(L, idx, LUA_TTABLE);
    merkle_tree::siblings_type sibling_hashes;
    if (log2_size < merkle_tree::get_log2_word_size()) {
        luaL_error(L, "invalid log2_size");
    }
    for ( ; log2_size < merkle_tree::get_log2_tree_size(); ++log2_size) {
        lua_rawgeti(L, idx, merkle_tree::get_log2_tree_size()-log2_size);
        merkle_tree::set_sibling_hash(clua_check_hash(L, -1),
            log2_size, sibling_hashes);
        lua_pop(L, 1);
    }
    return sibling_hashes;
}

/// \brief Loads a proof from Lua.
/// \param L Lua state.
/// \param tabidx Proof stack index.
/// \returns The proof.
merkle_tree::proof_type clua_check_proof(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    uint64_t address = check_uint_field(L, tabidx, "address");
    int log2_size = check_int_field(L, tabidx, "log2_size");
    lua_getfield(L, tabidx, "target_hash");
    auto target_hash = clua_check_hash(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tabidx, "root_hash");
    auto root_hash = clua_check_hash(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tabidx, "sibling_hashes");
    auto sibling_hashes = check_sibling_hashes(L, -1, log2_size);
    lua_pop(L, 1);
    return {
        address,
        log2_size,
        target_hash,
        sibling_hashes,
        root_hash
    };
}

/// \brief Loads a word_acces from Lua.
/// \param L Lua state.
/// \param tabidx Word_access stack index.
/// \returns The word_access.
static word_access check_word_access(lua_State *L, int tabidx, bool proofs) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    merkle_tree::proof_type proof;
    if (proofs) {
        lua_getfield(L, tabidx, "proof");
        proof = clua_check_proof(L, -1);
        lua_pop(L, 1);
    }
    return {
        check_access_type_field(L, tabidx, "type"),
        check_uint_field(L, tabidx, "address"),
        check_uint_field(L, tabidx, "read"),
        opt_uint_field(L, tabidx, "written", 0),
        proof
    };
}

access_log clua_check_access_log(lua_State *L, int tabidx) {
    std::vector<word_access> accesses;
    std::vector<bracket_note> brackets;
    std::vector<std::string> notes;
    luaL_checktype(L, tabidx, LUA_TTABLE);
    check_table_field(L, tabidx, "log_type");
    bool proofs = opt_boolean_field(L, -1, "proofs");
    bool annotations = opt_boolean_field(L, -1, "annotations");
    lua_pop(L, 1);
    check_table_field(L, tabidx, "accesses");
    int len = luaL_len(L, -1);
    for (int i = 1; i <= len; i++) {
        lua_geti(L, -1, i);
        if (!lua_istable(L, -1)) {
            luaL_error(L, "access [%d] not a table", i);
        }
        accesses.emplace_back(check_word_access(L, -1, proofs));
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    if (annotations) {
        check_table_field(L, tabidx, "notes");
        len = luaL_len(L, -1);
        for (int i = 1; i <= len; i++) {
            lua_geti(L, -1, i);
            if (!lua_isstring(L, -1)) {
                luaL_error(L, "note [%d] not a string", i);
            }
            notes.emplace_back(lua_tostring(L, -1));
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
        check_table_field(L, tabidx, "brackets");
        len = luaL_len(L, -1);
        for (int i = 1; i <= len; i++) {
            lua_geti(L, -1, i);
            if (!lua_istable(L, -1)) {
                luaL_error(L, "bracket [%d] not a table", i);
            }
            brackets.emplace_back(check_bracket_note(L, -1));
            lua_pop(L, 1);
        }
        lua_pop(L, 1);
    }
    return {
        std::move(accesses),
        std::move(brackets),
        std::move(notes),
        access_log::type{proofs, annotations}
    };
}

/// \brief Return a hash from Lua
/// \param L Lua state.
/// \param idx Index in stack.
/// \returns Hash.
merkle_tree::hash_type clua_check_hash(lua_State *L, int idx) {
    merkle_tree::hash_type hash;
    if (lua_isstring(L, idx)) {
        const char *data = nullptr;
        size_t len = 0;
        data = lua_tolstring(L, idx, &len);
        if (len != hash.max_size()) {
            luaL_error(L, "expected hash");
        }
        memcpy(hash.data(), data, hash.max_size());
    } else {
        luaL_error(L, "expected hash");
    }
    return hash;
}

machine::csr clua_check_csr(lua_State *L, int idx) {
    std::string name = luaL_checkstring(L, idx);
    auto got = g_csr_name.find(name);
    if (got == g_csr_name.end()) {
        luaL_argerror(L, idx, "unknown csr");
    }
    return got->second;
}

/// \brief Pushes an access_log::type to the Lua stack
/// \param L Lua state.
/// \param log_type Access_log::type to be pushed.
static void push_log_type(lua_State *L, bool proofs, bool annotations) {
    lua_newtable(L);
    lua_pushboolean(L, annotations);
    lua_setfield(L, -2, "annotations");
    lua_pushboolean(L, proofs);
    lua_setfield(L, -2, "proofs");
}

/// \brief Converts an access_type to a string.
/// \param type Access type.
/// \returns String with access_type name.
static const char *access_type_name(access_type type) {
    switch (type) {
        case access_type::read:
            return "read";
        case access_type::write:
            return "write";
    }
    return nullptr;
}

/// \brief Converts a note_type to a string
/// \param type Note type.
/// \returns String with note type name.
static const char *bracket_type_name(bracket_type type) {
    switch (type) {
        case bracket_type::begin:
            return "begin";
        case bracket_type::end:
            return "end";
    }
    return nullptr;
}

/// \brief Pushes an access log to the Lua stack
/// \param L Lua state.
/// \param log Access log to be pushed.
void clua_push_access_log(lua_State *L, const access_log &log) {
    lua_newtable(L); // log
    lua_newtable(L); // log type
    auto log_type = log.get_log_type();
    push_log_type(L, log_type.has_proofs(), log_type.has_annotations());
    lua_setfield(L, -2, "log_type"); // log
    // Add all accesses
    lua_newtable(L); // log accesses
    int i = 1; // convert from 0- to 1-based index
    for (const auto &a: log.get_accesses()) {
        lua_newtable(L); // log accesses wordaccess
        lua_pushstring(L, access_type_name(a.type));
        lua_setfield(L, -2, "type");
        lua_pushinteger(L, a.address);
        lua_setfield(L, -2, "address");
        lua_pushinteger(L, a.read);
        lua_setfield(L, -2, "read");
        if (a.type == access_type::write) {
            lua_pushinteger(L, a.written);
            lua_setfield(L, -2, "written");
        }
        if (log_type.has_proofs()) {
            clua_push_proof(L, a.proof);
            lua_setfield(L, -2, "proof");
        }
        lua_rawseti(L, -2, i);
        ++i;
    }
    lua_setfield(L, -2, "accesses"); // log
    // Add all brackets
    if (log_type.has_annotations()) {
        lua_newtable(L); // log brackets
        i = 1; // convert from 0- to 1-based index
        for (const auto &b: log.get_brackets()) {
            lua_newtable(L); // log brackets bracket
            lua_pushstring(L, bracket_type_name(b.type));
            lua_setfield(L, -2, "type");
            lua_pushinteger(L, b.where+1); // convert from 0- to 1-based index
            lua_setfield(L, -2, "where");
            lua_pushlstring(L, b.text.data(), b.text.size());
            lua_setfield(L, -2, "text");
            lua_rawseti(L, -2, i);
            ++i;
        }
        lua_setfield(L, -2, "brackets"); // log

        lua_newtable(L); // log notes
        i = 1; // convert from 0- to 1-based index
        for (const auto &n: log.get_notes()) {
            lua_pushlstring(L, n.data(), n.size());
            lua_rawseti(L, -2, i);
            i++;
        }
        lua_setfield(L, -2, "notes"); // log
    }
}

void clua_push_hash(lua_State *L, const merkle_tree::hash_type hash) {
    lua_pushlstring(L, reinterpret_cast<const char *>(hash.data()),
        hash.size());
}

void clua_push_semantic_version(lua_State *L, const semantic_version &v) {
    lua_newtable(L); // version
    lua_pushinteger(L, v.major); lua_setfield(L, -2, "major"); // version
    lua_pushinteger(L, v.minor); lua_setfield(L, -2, "minor"); // version
    lua_pushinteger(L, v.patch); lua_setfield(L, -2, "patch"); // version
    lua_pushlstring(L, v.pre_release.data(), v.pre_release.size()); lua_setfield(L, -2, "pre_release"); // version
    lua_pushlstring(L, v.build.data(), v.build.size()); lua_setfield(L, -2, "build"); // version
}

void clua_push_proof(lua_State *L, const merkle_tree::proof_type proof) {
    lua_newtable(L); // proof
    lua_newtable(L); // proof siblings
    for (int log2_size = proof.log2_size; log2_size < merkle_tree::get_log2_tree_size(); ++log2_size) {
        const auto &hash = merkle_tree::get_sibling_hash(proof.sibling_hashes, log2_size);
        clua_push_hash(L, hash);
        lua_rawseti(L, -2, merkle_tree::get_log2_tree_size()-log2_size);
    }
    lua_setfield(L, -2, "sibling_hashes"); // proof
    lua_pushinteger(L, proof.address); lua_setfield(L, -2, "address"); // proof
    lua_pushinteger(L, proof.log2_size); lua_setfield(L, -2, "log2_size"); // proof
    clua_push_hash(L, proof.root_hash); lua_setfield(L, -2, "root_hash"); // proof
    clua_push_hash(L, proof.target_hash); lua_setfield(L, -2, "target_hash"); // proof
}

access_log::type clua_check_log_type(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    return access_log::type{
        opt_boolean_field(L, -1, "proofs"),
        opt_boolean_field(L, -1, "annotations")
    };
}

/// \brief Pushes a processor_config to the Lua stack
/// \param L Lua state.
/// \param p Processor_config to be pushed.
static void push_processor_config(lua_State *L, const processor_config &p) {
    lua_newtable(L); // p
    lua_newtable(L); // p x
    for (int i = 1; i <= 31; i++) {
        lua_pushinteger(L, p.x[i]);
        lua_rawseti(L, -2, i);
    }
    lua_setfield(L, -2, "x");
    lua_pushinteger(L, p.pc); lua_setfield(L, -2, "pc");
    lua_pushinteger(L, p.mvendorid); lua_setfield(L, -2, "mvendorid");
    lua_pushinteger(L, p.marchid); lua_setfield(L, -2, "marchid");
    lua_pushinteger(L, p.mimpid); lua_setfield(L, -2, "mimpid");
    lua_pushinteger(L, p.mcycle); lua_setfield(L, -2, "mcycle");
    lua_pushinteger(L, p.minstret); lua_setfield(L, -2, "minstret");
    lua_pushinteger(L, p.mstatus); lua_setfield(L, -2, "mstatus");
    lua_pushinteger(L, p.mtvec); lua_setfield(L, -2, "mtvec");
    lua_pushinteger(L, p.mscratch); lua_setfield(L, -2, "mscratch");
    lua_pushinteger(L, p.mepc); lua_setfield(L, -2, "mepc");
    lua_pushinteger(L, p.mcause); lua_setfield(L, -2, "mcause");
    lua_pushinteger(L, p.mtval); lua_setfield(L, -2, "mtval");
    lua_pushinteger(L, p.misa); lua_setfield(L, -2, "misa");
    lua_pushinteger(L, p.mie); lua_setfield(L, -2, "mie");
    lua_pushinteger(L, p.mip); lua_setfield(L, -2, "mip");
    lua_pushinteger(L, p.medeleg); lua_setfield(L, -2, "medeleg");
    lua_pushinteger(L, p.mideleg); lua_setfield(L, -2, "mideleg");
    lua_pushinteger(L, p.mcounteren); lua_setfield(L, -2, "mcounteren");
    lua_pushinteger(L, p.stvec); lua_setfield(L, -2, "stvec");
    lua_pushinteger(L, p.sscratch); lua_setfield(L, -2, "sscratch");
    lua_pushinteger(L, p.sepc); lua_setfield(L, -2, "sepc");
    lua_pushinteger(L, p.scause); lua_setfield(L, -2, "scause");
    lua_pushinteger(L, p.stval); lua_setfield(L, -2, "stval");
    lua_pushinteger(L, p.satp); lua_setfield(L, -2, "satp");
    lua_pushinteger(L, p.scounteren); lua_setfield(L, -2, "scounteren");
    lua_pushinteger(L, p.ilrsc); lua_setfield(L, -2, "ilrsc");
    lua_pushinteger(L, p.iflags); lua_setfield(L, -2, "iflags");
}

/// \brief Pushes a ram_config to the Lua stack
/// \param L Lua state.
/// \param r Ram_config to be pushed.
static void push_ram_config(lua_State *L, const ram_config &r) {
    lua_newtable(L);
    lua_pushinteger(L, r.length); lua_setfield(L, -2, "length");
    if (!r.image_filename.empty()) {
        lua_pushlstring(L, r.image_filename.data(), r.image_filename.size());
        lua_setfield(L, -2, "image_filename");
    }
}

/// \brief Pushes a rom_config to the Lua stack
/// \param L Lua state.
/// \param r Ram_config to be pushed.
static void push_rom_config(lua_State *L, const rom_config &r) {
    lua_newtable(L);
    if (!r.bootargs.empty()) {
        lua_pushlstring(L, r.bootargs.data(), r.bootargs.size());
        lua_setfield(L, -2, "bootargs");
    }
    if (!r.image_filename.empty()) {
        lua_pushlstring(L, r.image_filename.data(), r.image_filename.size());
        lua_setfield(L, -2, "image_filename");
    }
}

/// \brief Pushes an htif_config to the Lua stack
/// \param L Lua state.
/// \param h Htif_config to be pushed.
static void push_htif_config(lua_State *L, const htif_config &h) {
    lua_newtable(L);
    lua_pushboolean(L, h.console_getchar); lua_setfield(L, -2, "console_getchar");
    lua_pushboolean(L, h.yield_progress); lua_setfield(L, -2, "yield_progress");
    lua_pushboolean(L, h.yield_rollup); lua_setfield(L, -2, "yield_rollup");
    lua_pushinteger(L, h.fromhost); lua_setfield(L, -2, "fromhost");
    lua_pushinteger(L, h.tohost); lua_setfield(L, -2, "tohost");
}

/// \brief Pushes an clint_config to the Lua stack
/// \param L Lua state.
/// \param c Clint_config to be pushed.
static void push_clint_config(lua_State *L, const clint_config &c) {
    lua_newtable(L);
    lua_pushinteger(L, c.mtimecmp); lua_setfield(L, -2, "mtimecmp");
}

/// \brief Pushes flash_drive_configs to the Lua stack
/// \param L Lua state.
/// \param flash_drive Flash_drive_configs to be pushed.
static void push_flash_drive_configs(lua_State *L,
    const flash_drive_configs &flash_drive) {
    lua_newtable(L);
    int i = 1;
    for (const auto &f: flash_drive) {
        lua_newtable(L);
        lua_pushinteger(L, f.start); lua_setfield(L, -2, "start");
        lua_pushinteger(L, f.length); lua_setfield(L, -2, "length");
        if (!f.image_filename.empty()) {
            lua_pushlstring(L, f.image_filename.data(), f.image_filename.size());
            lua_setfield(L, -2, "image_filename");
        }
        lua_pushboolean(L, f.shared); lua_setfield(L, -2, "shared");
        lua_rawseti(L, -2, i);
        i++;
    }
}

void clua_push_machine_config(lua_State *L, const machine_config &c) {
    lua_newtable(L); // config
    push_processor_config(L, c.processor); // config processor
    lua_setfield(L, -2, "processor"); // config
    push_htif_config(L, c.htif); // config htif
    lua_setfield(L, -2, "htif"); // config
    push_clint_config(L, c.clint); // config clint
    lua_setfield(L, -2, "clint"); // config
    push_flash_drive_configs(L, c.flash_drive); // config flash_drive
    lua_setfield(L, -2, "flash_drive"); // config
    push_ram_config(L, c.ram); // config ram
    lua_setfield(L, -2, "ram"); // config
    push_rom_config(L, c.rom); // config rom
    lua_setfield(L, -2, "rom"); // config
}

/// \brief Loads RAM config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param r RAM config structure to receive results.
static void check_ram_config(lua_State *L, int tabidx, ram_config &r) {
    check_table_field(L, tabidx, "ram");
    r.length = check_uint_field(L, -1, "length");
    r.image_filename = opt_string_field(L, -1, "image_filename");
    lua_pop(L, 1);
}

/// \brief Loads ROM config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param r ROM config structure to receive results.
static void check_rom_config(lua_State *L, int tabidx, rom_config &r) {
    if (!opt_table_field(L, tabidx, "rom"))
        return;
    r.image_filename = opt_string_field(L, -1, "image_filename");
    r.bootargs = opt_string_field(L, -1, "bootargs");
    lua_pop(L, 1);
}

flash_drive_config clua_check_flash_drive_config(lua_State *L, int tabidx) {
    if (!lua_istable(L, tabidx)) {
        luaL_error(L, "flash drive not a table");
    }
    flash_drive_config f;
    f.shared = opt_boolean_field(L, tabidx, "shared");
    f.image_filename = opt_string_field(L, tabidx, "image_filename");
    f.start = check_uint_field(L, tabidx, "start");
    f.length = check_uint_field(L, tabidx, "length");
    return f;
}

/// \brief Loads flash drive configs from a Lua machine config.
/// \param L Lua state.
/// \param tabidx Machine config stack index.
/// \param f Flash_configs structure to receive results.
void check_flash_drive_configs(lua_State *L, int tabidx,
    flash_drive_configs &fs) {
    if (!opt_table_field(L, tabidx, "flash_drive"))
        return;
    int len = luaL_len(L, -1);
    if (len > (int) fs.capacity()) {
        luaL_error(L, "too many flash drives");
    }
    for (int i = 1; i <= len; i++) {
        lua_geti(L, -1, i);
        fs.push_back(clua_check_flash_drive_config(L, -1));
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

/// \brief Loads processor config from a Lua to machine config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param p Processor config structure to receive results.
static void check_processor_config(lua_State *L, int tabidx,
    processor_config &p) {
    if (!opt_table_field(L, tabidx, "processor"))
        return;
    lua_getfield(L, -1, "x");
    if (lua_istable(L, -1)) {
        int len = luaL_len(L, -1);
        for (int i = 1; i <= std::min(len, 31); i++) {
            p.x[i] = opt_uint_field(L, -1, i, p.x[i]);
        }
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid processor.x (expected table)");
    }
    lua_pop(L, 1);
    p.pc = opt_uint_field(L, -1, "pc", p.pc);
    p.mvendorid = opt_uint_field(L, -1, "mvendorid", p.mvendorid);
    p.marchid = opt_uint_field(L, -1, "marchid", p.marchid);
    p.mimpid = opt_uint_field(L, -1, "mimpid", p.mimpid);
    p.mcycle = opt_uint_field(L, -1, "mcycle", p.mcycle);
    p.minstret = opt_uint_field(L, -1, "minstret", p.minstret);
    p.mstatus = opt_uint_field(L, -1, "mstatus", p.mstatus);
    p.mtvec = opt_uint_field(L, -1, "mtvec", p.mtvec);
    p.mscratch = opt_uint_field(L, -1, "mscratch", p.mscratch);
    p.mepc = opt_uint_field(L, -1, "mepc", p.mepc);
    p.mcause = opt_uint_field(L, -1, "mcause", p.mcause);
    p.mtval = opt_uint_field(L, -1, "mtval", p.mtval);
    p.misa = opt_uint_field(L, -1, "misa", p.misa);
    p.mie = opt_uint_field(L, -1, "mie", p.mie);
    p.mip = opt_uint_field(L, -1, "mip", p.mip);
    p.medeleg = opt_uint_field(L, -1, "medeleg", p.medeleg);
    p.mideleg = opt_uint_field(L, -1, "mideleg", p.mideleg);
    p.mcounteren = opt_uint_field(L, -1, "mcounteren", p.mcounteren);
    p.stvec = opt_uint_field(L, -1, "stvec", p.stvec);
    p.sscratch = opt_uint_field(L, -1, "sscratch", p.sscratch);
    p.sepc = opt_uint_field(L, -1, "sepc", p.sepc);
    p.scause = opt_uint_field(L, -1, "scause", p.scause);
    p.stval = opt_uint_field(L, -1, "stval", p.stval);
    p.satp = opt_uint_field(L, -1, "satp", p.satp);
    p.scounteren = opt_uint_field(L, -1, "scounteren", p.scounteren);
    p.ilrsc = opt_uint_field(L, -1, "ilrsc", p.ilrsc);
    p.iflags = opt_uint_field(L, -1, "iflags", p.iflags);
    lua_pop(L, 1);
}

/// \brief Loads HTIF config from Lua.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param h HTIF config structure to receive results.
static void check_htif_config(lua_State *L, int tabidx, htif_config &h) {
    if (!opt_table_field(L, tabidx, "htif"))
        return;
    h.tohost = opt_uint_field(L, -1, "tohost", h.tohost);
    h.fromhost = opt_uint_field(L, -1, "fromhost", h.fromhost);
    h.console_getchar = opt_boolean_field(L, -1, "console_getchar");
    h.yield_progress = opt_boolean_field(L, -1, "yield_progress");
    h.yield_rollup = opt_boolean_field(L, -1, "yield_rollup");
    lua_pop(L, 1);
}

/// \brief Loads CLINT config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c CLINT config structure to receive results.
static void check_clint_config(lua_State *L, int tabidx, clint_config &c) {
    if (!opt_table_field(L, tabidx, "clint"))
        return;
    c.mtimecmp = opt_uint_field(L, -1, "mtimecmp", c.mtimecmp);
    lua_pop(L, 1);
}

machine_config clua_check_machine_config(lua_State *L, int tabidx) {
    machine_config c;
    // Check all parameters from Lua initialization table
    // and copy them to the machine_config object
    check_processor_config(L, tabidx, c.processor);
    check_ram_config(L, tabidx, c.ram);
    check_rom_config(L, tabidx, c.rom);
    check_flash_drive_configs(L, tabidx, c.flash_drive);
    check_htif_config(L, tabidx, c.htif);
    check_clint_config(L, tabidx, c.clint);
    return c;
}

} // namespace cartesi
