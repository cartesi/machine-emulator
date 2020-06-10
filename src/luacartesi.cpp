// Copyright 2019 Cartesi Pte. Ltd.
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
#include <cinttypes>
#include <cstdio>
#include <lua.h>
#include <lauxlib.h>
#include <new>
#include <unordered_map>

#include "machine.h"
#include "access-log.h"
#include "keccak-256-hasher.h"
#include "unique-c-ptr.h"

using cartesi::merkle_tree;
using cartesi::access_type;
using cartesi::bracket_type;
using cartesi::bracket_note;
using cartesi::word_access;
using cartesi::access_log;
using cartesi::machine_config;
using cartesi::processor_config;
using cartesi::flash_config;
using cartesi::flash_configs;
using cartesi::rom_config;
using cartesi::ram_config;
using cartesi::htif_config;
using cartesi::clint_config;
using cartesi::machine_config;
using cartesi::machine;
using cartesi::keccak_256_hasher;

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

/// \file
/// \brief Scripting interface for the Cartesi machine in the Lua language.

#ifdef GPERF
#include "gperftools/profiler.h"
#endif

/// \brief Returns a CSR selector from Lua.
/// \param L Lua state.
/// \param idx Index in stack
/// \returns CSR selector. Throws error if unknown.
static machine::csr check_csr(lua_State *L, int idx) {
    std::string name = luaL_checkstring(L, idx);
    auto got = g_csr_name.find(name);
    if (got == g_csr_name.end()) {
        luaL_argerror(L, idx, "unknown csr");
    }
    return got->second;
}

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

/// \brief Pushes a hash to the Lua stack
/// \param L Lua state.
/// \param hash Hash to be pushed.
static void push_hash(lua_State *L, const merkle_tree::hash_type hash) {
    lua_pushlstring(L, reinterpret_cast<const char *>(hash.data()),
        hash.size());
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

/// \brief Pushes a proof to the Lua stack
/// \param L Lua state.
/// \param proof Proof to be pushed.
static void push_proof(lua_State *L, const merkle_tree::proof_type proof) {
    lua_newtable(L); // proof
    lua_newtable(L); // proof siblings
    for (int log2_size = proof.log2_size; log2_size < merkle_tree::get_log2_tree_size(); ++log2_size) {
        const auto &hash = merkle_tree::get_sibling_hash(proof.sibling_hashes, log2_size);
        push_hash(L, hash);
        lua_rawseti(L, -2, merkle_tree::get_log2_tree_size()-log2_size);
    }
    lua_setfield(L, -2, "sibling_hashes"); // proof
    lua_pushinteger(L, proof.address); lua_setfield(L, -2, "address"); // proof
    lua_pushinteger(L, proof.log2_size); lua_setfield(L, -2, "log2_size"); // proof
    push_hash(L, proof.root_hash); lua_setfield(L, -2, "root_hash"); // proof
    push_hash(L, proof.target_hash); lua_setfield(L, -2, "target_hash"); // proof
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

/// \brief Pushes flash_configs to the Lua stack
/// \param L Lua state.
/// \param flash Flash_configs to be pushed.
static void push_flash_configs(lua_State *L, const flash_configs &flash) {
    lua_newtable(L);
    int i = 1;
    for (const auto &f: flash) {
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

/// \brief Pushes a machine_config to the Lua stack
/// \param L Lua state.
/// \param c Machine_config to be pushed.
static void push_machine_config(lua_State *L, const machine_config &c) {
    lua_newtable(L); // config
    push_processor_config(L, c.processor); // config processor
    lua_setfield(L, -2, "processor"); // config
    push_htif_config(L, c.htif); // config htif
    lua_setfield(L, -2, "htif"); // config
    push_clint_config(L, c.clint); // config clint
    lua_setfield(L, -2, "clint"); // config
    push_flash_configs(L, c.flash); // config flash
    lua_setfield(L, -2, "flash"); // config
    push_ram_config(L, c.ram); // config ram
    lua_setfield(L, -2, "ram"); // config
    push_rom_config(L, c.rom); // config rom
    lua_setfield(L, -2, "rom"); // config
}

/// \brief Pushes an access log to the Lua stack
/// \param L Lua state.
/// \param log Access log to be pushed.
static void push_access_log(lua_State *L, const access_log &log) {
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
            push_proof(L, a.proof);
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

/// \brief Loads an access_log::type from Lua
/// \param L Lua state.
/// \param tabidx Access_log::type stack index.
/// \param log_type Access_log::type to be pushed.
static access_log::type check_log_type(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    return access_log::type{
        opt_boolean_field(L, -1, "proofs"),
        opt_boolean_field(L, -1, "annotations")
    };
}

/// \brief Return a hash from Lua
/// \param L Lua state.
/// \param idx Index in stack.
/// \returns Hash.
static merkle_tree::hash_type check_hash(lua_State *L, int idx) {
    merkle_tree::hash_type hash;
    if (lua_isstring(L, idx)) {
        const char *data = nullptr;
        size_t len = 0;
        data = lua_tolstring(L, -1, &len);
        if (len != hash.max_size()) {
            luaL_error(L, "expected hash");
        }
        memcpy(hash.data(), data, hash.max_size());
    } else {
        luaL_error(L, "expected hash");
    }
    return hash;
}

/// \brief Loads an array of sibling_hashes from Lua.
/// \param L Lua state.
/// \param idx Proof stack index.
/// \param log2_size of node from which to obtain siblings.
/// \returns The sibling_hashes array.
merkle_tree::siblings_type check_sibling_hashes(lua_State *L, int idx,
    int log2_size) {
    luaL_checktype(L, idx, LUA_TTABLE);
    merkle_tree::siblings_type sibling_hashes;
    if (log2_size < merkle_tree::get_log2_word_size()) {
        luaL_error(L, "invalid log2_size");
    }
    for ( ; log2_size < merkle_tree::get_log2_tree_size(); ++log2_size) {
        lua_rawgeti(L, idx, merkle_tree::get_log2_tree_size()-log2_size);
        merkle_tree::set_sibling_hash(check_hash(L, -1),
            log2_size, sibling_hashes);
        lua_pop(L, 1);
    }
    return sibling_hashes;
}

/// \brief Loads a proof from Lua.
/// \param L Lua state.
/// \param tabidx Proof stack index.
/// \returns The proof.
merkle_tree::proof_type check_proof(lua_State *L, int tabidx) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    uint64_t address = check_uint_field(L, tabidx, "address");
    int log2_size = check_int_field(L, tabidx, "log2_size");
    lua_getfield(L, tabidx, "target_hash");
    auto target_hash = check_hash(L, -1);
    lua_pop(L, 1);
    lua_getfield(L, tabidx, "root_hash");
    auto root_hash = check_hash(L, -1);
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
word_access check_word_access(lua_State *L, int tabidx, bool proofs) {
    luaL_checktype(L, tabidx, LUA_TTABLE);
    merkle_tree::proof_type proof;
    if (proofs) {
        lua_getfield(L, tabidx, "proof");
        proof = check_proof(L, -1);
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

/// \brief Loads an access_log from Lua.
/// \param L Lua state.
/// \param tabidx Access_log stack index.
/// \returns The access_log.
access_log check_access_log(lua_State *L, int tabidx) {
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

/// \brief Loads flash-drive config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param f Flash_configs structure to receive results.
static void check_flash_config(lua_State *L, int tabidx, flash_configs &f) {
    if (!opt_table_field(L, tabidx, "flash"))
        return;
    int len = luaL_len(L, -1);
    if (len > (int) f.capacity()) {
        luaL_error(L, "too many flash drives");
    }
    for (int i = 1; i <= len; i++) {
        lua_geti(L, -1, i);
        if (!lua_istable(L, -1)) {
            luaL_error(L, "flash[%d] not a table", i);
        }
        flash_config flash;
        flash.shared = opt_boolean_field(L, -1, "shared");
        flash.image_filename = opt_string_field(L, -1, "image_filename");
        flash.start = check_uint_field(L, -1, "start");
        flash.length = check_uint_field(L, -1, "length");
        f.push_back(std::move(flash));
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

/// \brief Loads processor config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param p Processor config structure to receive results.
static void check_processor_config(lua_State *L, int tabidx, processor_config &p) {
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

/// \brief loads a machine_config object from a Lua table
/// \param L Lua state.
/// \param tabidx Index of table in Lua stack
static machine_config check_machine_config(lua_State *L, int tabidx) {
    machine_config c;
    // Check all parameters from Lua initialization table
    // and copy them to the machine_config object
    check_processor_config(L, tabidx, c.processor);
    check_ram_config(L, tabidx, c.ram);
    check_rom_config(L, tabidx, c.rom);
    check_flash_config(L, tabidx, c.flash);
    check_htif_config(L, tabidx, c.htif);
    check_clint_config(L, tabidx, c.clint);
    return c;
}

/// \brief This is the cartesi.keccak() function implementation.
/// \param L Lua state.
static int cartesi_mod_keccak(lua_State *L) {
    keccak_256_hasher h;
    keccak_256_hasher::hash_type hash;
    switch (lua_gettop(L)) {
        case 0:
            luaL_argerror(L, 1, "too few arguments");
            break;
        case 1: {
            uint64_t word = luaL_checkinteger(L, 1);
            h.begin();
            h.add_data(reinterpret_cast<const unsigned char *>(&word),
                sizeof(word));
            h.end(hash);
            push_hash(L, hash);
            break;
        }
        case 2: {
            size_t len1 = 0;
            const char *hash1 = luaL_checklstring(L, 1, &len1);
            if (len1 != keccak_256_hasher::hash_size) {
                luaL_argerror(L, 1, "invalid hash size");
            }
            size_t len2 = 0;
            const char *hash2 = luaL_checklstring(L, 2, &len2);
            if (len2 != keccak_256_hasher::hash_size) {
                luaL_argerror(L, 2, "invalid hash size");
            }
            h.begin();
            h.add_data(reinterpret_cast<const unsigned char *>(hash1), len1);
            h.add_data(reinterpret_cast<const unsigned char *>(hash2), len2);
            h.end(hash);
            push_hash(L, hash);
            break;
        }
        default:
            luaL_argerror(L, 3, "too many arguments");
            break;
    }
    return 1;
}

/// \brief This is the cartesi.machine() function implementation.
/// \param L Lua state.
static int machine_ctor_meta__call(lua_State *L) try {
    // Allocate room for machine object as a Lua userdata
    void *p = lua_newuserdata(L, sizeof(machine));
    // Invoke placement new to construct it in place
    if (lua_type(L, 2) == LUA_TTABLE) {
        new (p) machine{check_machine_config(L, 2)};
    } else {
        new (p) machine{luaL_checkstring(L, 2)};
    }
    // Set metatable so Lua recognizes userdata as a machine object
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_setmetatable(L, -2);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Machine constructor __gc metamethod.
/// \param L Lua state.
static int machine_ctor_meta__gc(lua_State *L) {
    (void) L;
    return 0;
}

/// \brief Machine constructor __tostring metamethod.
/// \param L Lua state.
static int machine_ctor_meta__tostring(lua_State *L) {
    lua_pushstring(L, "class");
    return 1;
}

/// \brief Contents of the machine metatable.
static const luaL_Reg machine_ctor_meta[] = {
    {"__call", machine_ctor_meta__call},
    {"__tostring", machine_ctor_meta__tostring},
    { NULL, NULL }
};

/// \brief Contents of the cartesi module table.
static const luaL_Reg cartesi_mod[] = {
    {"keccak", cartesi_mod_keccak},
    { NULL, NULL }
};

/// \brief Checks if object is a machine.
/// \param L Lua state.
/// \param idx Stack index.
/// \returns 1 if it is a machine, 0 otherwise.
static int is_machine(lua_State *L, int idx) {
    idx = lua_absindex(L, idx);
    if (!lua_getmetatable(L, idx)) lua_pushnil(L);
    int ret = lua_compare(L, -1, lua_upvalueindex(1), LUA_OPEQ);
    lua_pop(L, 1);
    return ret;
}

/// \brief Checks if object is a machine.
/// \param L Lua state.
/// \param idx Stack index.
/// \returns 1 if it is a machine, 0 otherwise.
static machine *check_machine(lua_State *L, int idx) {
    if (!is_machine(L, idx)) {
        luaL_argerror(L, idx, "expected machine");
    }
    return reinterpret_cast<machine *>(lua_touserdata(L, idx));
}

/// \brief This is the machine:destroy() method implementation.
/// \param L Lua state.
static int machine_meta__index_destroy(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushnil(L); // Remove metatable from object
    lua_setmetatable(L, 1);
    m->~machine(); // Explicitly invoke object destructor
    return 0;
}

/// \brief This is the machine:update_merkle_tree() method implementation.
/// \param L Lua state.
static int machine_meta__index_update_merkle_tree(lua_State *L) try {
    lua_pushboolean(L, check_machine(L, 1)->update_merkle_tree());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:serialize() method implementation.
/// \param L Lua state.
static int machine_meta__index_store(lua_State *L) try {
    check_machine(L, 1)->store(luaL_checkstring(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:verify_merkle_tree() method implementation.
/// \param L Lua state.
static int machine_meta__index_verify_merkle_tree(lua_State *L) try {
    lua_pushboolean(L, check_machine(L, 1)->get_merkle_tree().verify_tree());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:get_root_hash() method implementation.
/// \param L Lua state.
static int machine_meta__index_get_root_hash(lua_State *L) try {
    machine *m = check_machine(L, 1);
    merkle_tree::hash_type hash;
    if (m->get_merkle_tree().get_root_hash(hash)) {
        push_hash(L, hash);
        return 1;
    } else {
        lua_pushboolean(L, false);
        return 1;
    }
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:run() method implementation.
/// \param L Lua state.
static int machine_meta__index_run(lua_State *L) try {
    check_machine(L, 1)->run(luaL_checkinteger(L, 2));
    lua_pushboolean(L, true);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_csr() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_csr(lua_State *L) try {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_csr(check_csr(L, 2)));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:write_csr() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_csr(lua_State *L) try {
    machine *m = check_machine(L, 1);
    m->write_csr(check_csr(L, 2), luaL_checkinteger(L, 3));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:dump_pmas() method implementation.
/// \param L Lua state.
static int machine_meta__index_dump_pmas(lua_State *L) try {
    machine *m = check_machine(L, 1);
    m->dump_pmas();
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:dump_regs() method implementation.
/// \param L Lua state.
static int machine_meta__index_dump_regs(lua_State *L) {
    machine *m = check_machine(L, 1);
    fprintf(stderr, "pc = %" PRIx64 "\n", m->read_pc());
    for (int i = 0; i < 32; ++i) {
        fprintf(stderr, "x%d = %" PRIx64 "\n", i, m->read_x(i));
    }
    fprintf(stderr, "minstret = %" PRIx64 "\n", m->read_minstret());
    fprintf(stderr, "mcycle = %" PRIx64 "\n", m->read_mcycle());
    fprintf(stderr, "mvendorid = %" PRIx64 "\n", m->read_mvendorid());
    fprintf(stderr, "marchid = %" PRIx64 "\n", m->read_marchid());
    fprintf(stderr, "mimpid = %" PRIx64 "\n", m->read_mimpid());
    fprintf(stderr, "mstatus = %" PRIx64 "\n", m->read_mstatus());
    fprintf(stderr, "mtvec = %" PRIx64 "\n", m->read_mtvec());
    fprintf(stderr, "mscratch = %" PRIx64 "\n", m->read_mscratch());
    fprintf(stderr, "mepc = %" PRIx64 "\n", m->read_mepc());
    fprintf(stderr, "mcause = %" PRIx64 "\n", m->read_mcause());
    fprintf(stderr, "mtval = %" PRIx64 "\n", m->read_mtval());
    fprintf(stderr, "misa = %" PRIx64 "\n", m->read_misa());
    fprintf(stderr, "mie = %" PRIx64 "\n", m->read_mie());
    fprintf(stderr, "mip = %" PRIx64 "\n", m->read_mip());
    fprintf(stderr, "medeleg = %" PRIx64 "\n", m->read_medeleg());
    fprintf(stderr, "mideleg = %" PRIx64 "\n", m->read_mideleg());
    fprintf(stderr, "mcounteren = %" PRIx64 "\n", m->read_mcounteren());
    fprintf(stderr, "stvec = %" PRIx64 "\n", m->read_stvec());
    fprintf(stderr, "sscratch = %" PRIx64 "\n", m->read_sscratch());
    fprintf(stderr, "sepc = %" PRIx64 "\n", m->read_sepc());
    fprintf(stderr, "scause = %" PRIx64 "\n", m->read_scause());
    fprintf(stderr, "stval = %" PRIx64 "\n", m->read_stval());
    fprintf(stderr, "satp = %" PRIx64 "\n", m->read_satp());
    fprintf(stderr, "scounteren = %" PRIx64 "\n", m->read_scounteren());
    fprintf(stderr, "ilrsc = %" PRIx64 "\n", m->read_ilrsc());
    fprintf(stderr, "iflags = %" PRIx64 "\n", m->read_iflags());
    fprintf(stderr, "clint_mtimecmp = %" PRIx64 "\n", m->read_clint_mtimecmp());
    fprintf(stderr, "htif_tohost = %" PRIx64 "\n", m->read_htif_tohost());
    fprintf(stderr, "htif_fromhost = %" PRIx64 "\n", m->read_htif_fromhost());
    fprintf(stderr, "htif_ihalt = %" PRIx64 "\n", m->read_htif_ihalt());
    fprintf(stderr, "htif_iconsole = %" PRIx64 "\n", m->read_htif_iconsole());
    fprintf(stderr, "htif_iyield = %" PRIx64 "\n", m->read_htif_iyield());
    return 0;
}

/// \brief This is the machine:write_memory() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_memory(lua_State *L) try {
    machine *m = check_machine(L, 1);
    size_t length = 0;
    const unsigned char *data = reinterpret_cast<const unsigned char *>(
        luaL_checklstring(L, 3, &length));
    m->write_memory(luaL_checkinteger(L, 2), data, length);
    lua_pushboolean(L, true);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_memory() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_memory(lua_State *L) try {
    machine *m = check_machine(L, 1);
    size_t length = luaL_checkinteger(L, 3);
    auto data = cartesi::unique_calloc<unsigned char>(1, length);
    m->read_memory(luaL_checkinteger(L, 2), data.get(), length);
    lua_pushlstring(L, reinterpret_cast<const char *>(data.get()), length);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_word() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_word(lua_State *L) try {
    machine *m = check_machine(L, 1);
    uint64_t word_value = 0;
    if (m->read_word(luaL_checkinteger(L, 2), word_value)) {
        lua_pushinteger(L, word_value);
        return 1;
    } else {
        lua_pushboolean(L, false);
        return 1;
    }
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:get_proof() method implementation.
/// \param L Lua state.
static int machine_meta__index_get_proof(lua_State *L) try {
    machine *m = check_machine(L, 1);
    merkle_tree::proof_type proof;
    m->get_proof(luaL_checkinteger(L, 2), luaL_checkinteger(L, 3), proof);
    push_proof(L, proof);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:verify_dirty_page_maps() method implementation.
/// \param L Lua state.
static int machine_meta__index_verify_dirty_page_maps(lua_State *L) try {
    machine *m = check_machine(L, 1);
    lua_pushboolean(L, m->verify_dirty_page_maps());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:step() method implementation.
/// \param L Lua state.
static int machine_meta__index_step(lua_State *L) try {
    machine *m = check_machine(L, 1);
    push_access_log(L, m->step(check_log_type(L, 2)));
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_pc() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_pc(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_pc());
    return 1;
}

/// \brief This is the machine:read_mvendorid() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mvendorid(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mvendorid());
    return 1;
}

/// \brief This is the machine:read_marchid() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_marchid(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_marchid());
    return 1;
}

/// \brief This is the machine:read_mimpid() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mimpid(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mimpid());
    return 1;
}

/// \brief This is the machine:read_mcycle() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mcycle(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mcycle());
    return 1;
}

/// \brief This is the machine:read_minstret() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_minstret(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_minstret());
    return 1;
}

/// \brief This is the machine:read_mstatus() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mstatus(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mstatus());
    return 1;
}

/// \brief This is the machine:read_mtvec() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mtvec(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mtvec());
    return 1;
}

/// \brief This is the machine:read_mscratch() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mscratch(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mscratch());
    return 1;
}

/// \brief This is the machine:read_mepc() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mepc(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mepc());
    return 1;
}

/// \brief This is the machine:read_mcause() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mcause(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mcause());
    return 1;
}

/// \brief This is the machine:read_mtval() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mtval(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mtval());
    return 1;
}

/// \brief This is the machine:read_misa() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_misa(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_misa());
    return 1;
}

/// \brief This is the machine:read_mie() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mie(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mie());
    return 1;
}

/// \brief This is the machine:read_mip() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mip(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mip());
    return 1;
}

/// \brief This is the machine:read_medeleg() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_medeleg(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_medeleg());
    return 1;
}

/// \brief This is the machine:read_mideleg() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mideleg(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mideleg());
    return 1;
}

/// \brief This is the machine:read_mcounteren() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_mcounteren(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mcounteren());
    return 1;
}

/// \brief This is the machine:read_stvec() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_stvec(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_stvec());
    return 1;
}

/// \brief This is the machine:read_sscratch() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_sscratch(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_sscratch());
    return 1;
}

/// \brief This is the machine:read_sepc() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_sepc(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_sepc());
    return 1;
}

/// \brief This is the machine:read_scause() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_scause(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_scause());
    return 1;
}

/// \brief This is the machine:read_stval() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_stval(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_stval());
    return 1;
}

/// \brief This is the machine:read_satp() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_satp(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_satp());
    return 1;
}

/// \brief This is the machine:read_scounteren() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_scounteren(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_scounteren());
    return 1;
}

/// \brief This is the machine:read_ilrsc() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_ilrsc(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_ilrsc());
    return 1;
}

/// \brief This is the machine:read_iflags() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_iflags(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_iflags());
    return 1;
}

/// \brief This is the machine:read_iflags_H() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_iflags_H(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushboolean(L, m->read_iflags_H());
    return 1;
}

/// \brief This is the machine:read_iflags_I() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_iflags_I(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushboolean(L, m->read_iflags_I());
    return 1;
}

/// \brief This is the machine:read_iflags_Y() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_iflags_Y(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushboolean(L, m->read_iflags_Y());
    return 1;
}

/// \brief This is the machine:read_clint_mtimecmp() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_clint_mtimecmp(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_clint_mtimecmp());
    return 1;
}

/// \brief This is the machine:read_htif_tohost() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_htif_tohost(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_htif_tohost());
    return 1;
}

/// \brief This is the machine:read_htif_fromhost() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_htif_fromhost(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_htif_fromhost());
    return 1;
}

/// \brief This is the machine:read_htif_ihalt() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_htif_ihalt(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_htif_ihalt());
    return 1;
}

/// \brief This is the machine:read_htif_iconsole() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_htif_iconsole(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_htif_iconsole());
    return 1;
}

/// \brief This is the machine:read_htif_yield() method implementation.
/// \param L Lua state.
static int machine_meta__index_read_htif_iyield(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_htif_iyield());
    return 1;
}

/// \brief This is the machine:write_pc() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_pc(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_pc(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mcycle() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mcycle(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mcycle(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_minstret() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_minstret(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_minstret(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mstatus() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mstatus(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mstatus(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mtvec() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mtvec(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mtvec(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mscratch() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mscratch(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mscratch(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mepc() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mepc(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mepc(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mcause() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mcause(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mcause(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mtval() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mtval(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mtval(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_misa() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_misa(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_misa(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mie() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mie(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mie(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mip() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mip(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mip(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_medeleg() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_medeleg(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_medeleg(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mideleg() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mideleg(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mideleg(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_mcounteren() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_mcounteren(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_mcounteren(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_stvec() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_stvec(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_stvec(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_sscratch() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_sscratch(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_sscratch(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_sepc() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_sepc(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_sepc(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_scause() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_scause(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_scause(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_stval() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_stval(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_stval(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_satp() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_satp(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_satp(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_scounteren() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_scounteren(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_scounteren(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_ilrsc() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_ilrsc(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_ilrsc(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_iflags() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_iflags(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_iflags(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_clint_mtimecmp() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_clint_mtimecmp(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_clint_mtimecmp(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_htif_tohost() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_htif_tohost(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_htif_tohost(luaL_checkinteger(L, 2));
    return 0;
}

/// \brief This is the machine:write_htif_fromhost() method implementation.
/// \param L Lua state.
static int machine_meta__index_write_htif_fromhost(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->write_htif_fromhost(luaL_checkinteger(L, 2));
    return 0;
}

static int machine_meta__index_get_initial_config(lua_State *L) {
    machine *m = check_machine(L, 1);
    push_machine_config(L, m->get_initial_config());
    return 1;
}

/// \brief Contents of the machine metatable __index table.
static const luaL_Reg machine_meta__index[] = {
    {"destroy", machine_meta__index_destroy},
    {"dump_pmas", machine_meta__index_dump_pmas},
    {"dump_regs", machine_meta__index_dump_regs},
    {"get_proof", machine_meta__index_get_proof},
    {"get_initial_config", machine_meta__index_get_initial_config},
    {"get_root_hash", machine_meta__index_get_root_hash},
    {"read_clint_mtimecmp", machine_meta__index_read_clint_mtimecmp},
    {"read_csr", machine_meta__index_read_csr},
    {"read_htif_fromhost", machine_meta__index_read_htif_fromhost},
    {"read_htif_tohost", machine_meta__index_read_htif_tohost},
    {"read_iflags", machine_meta__index_read_iflags},
    {"read_iflags_H", machine_meta__index_read_iflags_H},
    {"read_iflags_Y", machine_meta__index_read_iflags_Y},
    {"read_iflags_I", machine_meta__index_read_iflags_I},
    {"read_ilrsc", machine_meta__index_read_ilrsc},
    {"read_marchid", machine_meta__index_read_marchid},
    {"read_mcause", machine_meta__index_read_mcause},
    {"read_mcounteren", machine_meta__index_read_mcounteren},
    {"read_mcycle", machine_meta__index_read_mcycle},
    {"read_medeleg", machine_meta__index_read_medeleg},
    {"read_memory", machine_meta__index_read_memory},
    {"read_mepc", machine_meta__index_read_mepc},
    {"read_mideleg", machine_meta__index_read_mideleg},
    {"read_mie", machine_meta__index_read_mie},
    {"read_mimpid", machine_meta__index_read_mimpid},
    {"read_minstret", machine_meta__index_read_minstret},
    {"read_mip", machine_meta__index_read_mip},
    {"read_misa", machine_meta__index_read_misa},
    {"read_mscratch", machine_meta__index_read_mscratch},
    {"read_mstatus", machine_meta__index_read_mstatus},
    {"read_mtval", machine_meta__index_read_mtval},
    {"read_mtvec", machine_meta__index_read_mtvec},
    {"read_mvendorid", machine_meta__index_read_mvendorid},
    {"read_pc", machine_meta__index_read_pc},
    {"read_satp", machine_meta__index_read_satp},
    {"read_scause", machine_meta__index_read_scause},
    {"read_scounteren", machine_meta__index_read_scounteren},
    {"read_sepc", machine_meta__index_read_sepc},
    {"read_sscratch", machine_meta__index_read_sscratch},
    {"read_stval", machine_meta__index_read_stval},
    {"read_stvec", machine_meta__index_read_stvec},
    {"read_word", machine_meta__index_read_word},
    {"run", machine_meta__index_run},
    {"step", machine_meta__index_step},
    {"store", machine_meta__index_store},
    {"update_merkle_tree", machine_meta__index_update_merkle_tree},
    {"verify_dirty_page_maps", machine_meta__index_verify_dirty_page_maps},
    {"verify_merkle_tree", machine_meta__index_verify_merkle_tree},
    {"write_clint_mtimecmp", machine_meta__index_write_clint_mtimecmp},
    {"write_csr", machine_meta__index_write_csr},
    {"write_htif_fromhost", machine_meta__index_write_htif_fromhost},
    {"write_htif_tohost", machine_meta__index_write_htif_tohost},
    {"write_iflags", machine_meta__index_write_iflags},
    {"write_ilrsc", machine_meta__index_write_ilrsc},
    {"write_mcause", machine_meta__index_write_mcause},
    {"write_mcounteren", machine_meta__index_write_mcounteren},
    {"write_mcycle", machine_meta__index_write_mcycle},
    {"write_medeleg", machine_meta__index_write_medeleg},
    {"write_memory", machine_meta__index_write_memory},
    {"write_mepc", machine_meta__index_write_mepc},
    {"write_mideleg", machine_meta__index_write_mideleg},
    {"write_mie", machine_meta__index_write_mie},
    {"write_minstret", machine_meta__index_write_minstret},
    {"write_mip", machine_meta__index_write_mip},
    {"write_misa", machine_meta__index_write_misa},
    {"write_mscratch", machine_meta__index_write_mscratch},
    {"write_mstatus", machine_meta__index_write_mstatus},
    {"write_mtval", machine_meta__index_write_mtval},
    {"write_mtvec", machine_meta__index_write_mtvec},
    {"write_pc", machine_meta__index_write_pc},
    {"write_satp", machine_meta__index_write_satp},
    {"write_scause", machine_meta__index_write_scause},
    {"write_scounteren", machine_meta__index_write_scounteren},
    {"write_sepc", machine_meta__index_write_sepc},
    {"write_sscratch", machine_meta__index_write_sscratch},
    {"write_stval", machine_meta__index_write_stval},
    {"write_stvec", machine_meta__index_write_stvec},
    { NULL, NULL }
};

/// \brief Machine __tostring metamethod.
/// \param L Lua state.
static int machine_meta__tostring(lua_State *L) {
    lua_pushstring(L, "machine");
    return 1;
}

/// \brief Machine __gc metamethod.
/// \param L Lua state.
static int machine_meta__gc(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->~machine(); // Explicitly invoke object destructor
    return 0;
}

/// \brief Contents of the machine metatable.
static const luaL_Reg machine_meta[] = {
    {"__gc", machine_meta__gc},
    {"__tostring", machine_meta__tostring},
    { NULL, NULL }
};

#ifdef GPERF
static int gperf__gc(lua_State *) {
    ProfilerStop();
    return 0;
}

static const luaL_Reg gperf_meta[] = {
    {"__gc", gperf__gc},
    { NULL, NULL }
};
#endif

static int machine_verify_access_log(lua_State *L) try {
    luaL_argcheck(L, lua_gettop(L) >= 2, 2, "expected boolean");
    machine::verify_access_log(check_access_log(L, 1), lua_toboolean(L, 2));
    lua_pushnumber(L, 1);
    return 1;
} catch (std::exception &x) {
    lua_pushnil(L);
    lua_pushstring(L, x.what());
    return 2;
}

/// \brief Sets machine class static entries in table at top of stack
/// \param L Lua state.
static void machine_set_static(lua_State *L) {
    lua_pushinteger(L, machine::MVENDORID);
    lua_setfield(L, -2, "MVENDORID");
    lua_pushinteger(L, machine::MARCHID);
    lua_setfield(L, -2, "MARCHID");
    lua_pushinteger(L, machine::MIMPID);
    lua_setfield(L, -2, "MIMPID");
    lua_pushcfunction(L, machine_verify_access_log);
    lua_setfield(L, -2, "verify_access_log");
    push_machine_config(L, machine_config{});
    lua_setfield(L, -2, "DEFAULT_CONFIG");
}

extern "C"
__attribute__((visibility("default")))
/// \brief Entrypoint to the Cartesi Lua library.
/// \param L Lua state.
int luaopen_cartesi(lua_State *L) {
#ifdef GPERF
    lua_newuserdata(L, 1); /* gperf */
    lua_pushvalue(L, -1); /* gperf gperf */
    lua_newtable(L); /* gperf gperf gperfmeta */
    luaL_setfuncs(L, gperf_meta, 0); /* gperf gperf gperfmeta */
    lua_setmetatable(L, -2); /* gperf gperf */
    lua_settable(L, LUA_REGISTRYINDEX); /**/
    ProfilerStart("cartesi.prof");
#endif
    lua_newtable(L); /* cartesi_mod */
    lua_newtable(L); /* cartesi_mod machine_meta */
    lua_newtable(L); /* cartesi_mod machine_meta metaidx */
    machine_set_static(L);
    lua_pushvalue(L, -2); /* cartesi_mod machine_meta metaidx machine_meta */
    luaL_setfuncs(L, machine_meta__index, 1); /* cartesi_mod machine_meta metaidx */
    lua_setfield(L, -2, "__index"); /* cartesi_mod machine_meta */
    lua_pushvalue(L, -1); /* cartesi_mod machine_meta machine_meta */
    luaL_setfuncs(L, machine_meta, 1); /* cartesi_mod machine_meta */
    lua_newtable(L); /* cartesi_mod machine_meta ctor */
    lua_newtable(L); /* cartesi_mod machine_meta ctor ctor_meta */
    lua_pushvalue(L, -3); /* cartesi_mod machine_meta ctor ctor_meta machine_meta */
    luaL_setfuncs(L, machine_ctor_meta, 1); /* cartesi_mod machine_meta ctor ctor_meta */
    lua_newtable(L); /* cartesi_mod machine_meta ctor ctor_meta ctoridx */
    machine_set_static(L);
    lua_setfield(L, -2, "__index"); /* cartesi_mod machine_meta ctor ctor_meta */
    lua_setmetatable(L, -2); /* cartesi_mod machine_meta ctor */
    lua_setfield(L, -3, "machine"); /* caretsi_mod machine_meta */
    luaL_setfuncs(L, cartesi_mod, 1); /* cartesi_mod */
    return 1;
}
