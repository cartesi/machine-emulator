#include <cstring>
#include <cinttypes>
#include <cstdio>
#include <lua.h>
#include <lauxlib.h>
#include <new>

#include "machine.h"
#include "access-log.h"
#include "keccak-256-hasher.h"

using cartesi::merkle_tree;
using cartesi::access_type;
using cartesi::bracket_type;
using cartesi::access_log;
using cartesi::machine_config;
using cartesi::processor_config;
using cartesi::flash_config;
using cartesi::rom_config;
using cartesi::ram_config;
using cartesi::htif_config;
using cartesi::clint_config;
using cartesi::machine_config;
using cartesi::machine;
using cartesi::keccak_256_hasher;

/// \file
/// \brief Scripting interface for the Cartesi machine in the Lua language.

#ifdef GPERF
#include "gperftools/profiler.h"
#endif

/// \brief Returns an optinoal boolean field indexed by string in a table.
/// \param L Lua state.
/// \param tabidx Table stack index.
/// \param field Field index.
/// \param def Default value for missing field.
/// \returns Field value, or default value if missing.
static bool opt_boolean_field(lua_State *L, int tabidx, const char *field, bool def) {
    tabidx = lua_absindex(L, tabidx);
    int val = def;
    lua_getfield(L, tabidx, field);
    if (lua_isboolean(L, -1)) {
        val = lua_toboolean(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid %s (expected Boolean)", field);
    }
    lua_pop(L, 1);
    return val;
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

/// \brief Pushes to stack a table field indexed by string in a table.
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

/// \brief Pushes a hash to the Lua stack
/// \param L Lua state.
/// \param hash Hash to be pushed.
static void push_hash(lua_State *L, const merkle_tree::hash_type hash) {
    lua_pushlstring(L, reinterpret_cast<const char *>(hash.data()),
        hash.size());
}

/// \brief Pushes a proof to the Lua stack
/// \param L Lua state.
/// \param proof Proof to be pushed.
static void push_proof(lua_State *L, const merkle_tree::proof_type proof) {
    lua_newtable(L); // proof
    lua_newtable(L); // proof siblings
    for (int log2_size = merkle_tree::get_log2_word_size(); log2_size < merkle_tree::get_log2_tree_size(); ++log2_size) {
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

/// \brief Converts an access type to a string.
/// \param type Access type.
/// \returns String with access type name.
static const char *access_name(access_type type) {
    switch (type) {
        case access_type::read:
            return "read";
        case access_type::write:
            return "write";
        default:
            return "invalid";
    }
}

/// \brief Converts a note type to a string
/// \param type Note type.
/// \returns String with note type name.
static const char *bracket_name(bracket_type type) {
    switch (type) {
        case bracket_type::begin:
            return "begin";
        case bracket_type::end:
            return "end";
        case bracket_type::invalid:
        default:
            return "invalid";
    }
}

/// \brief Pushes an access log to the Lua stack
/// \param L Lua state.
/// \param log Access log to be pushed.
static void push_log(lua_State *L, access_log &log) {
    lua_newtable(L); // log
    // Add all accesses
    lua_newtable(L); // log accesses
    int i = 1; // convert from 0- to 1-based index
    for (const auto &a: log.get_accesses()) {
        lua_newtable(L); // log accesses wordaccess
        lua_pushstring(L, access_name(a.type));
        lua_setfield(L, -2, "type");
        lua_pushinteger(L, a.read);
        lua_setfield(L, -2, "read");
        if (a.type == access_type::write) {
            lua_pushinteger(L, a.written);
            lua_setfield(L, -2, "written");
        }
        push_proof(L, a.proof);
        lua_setfield(L, -2, "proof");
        lua_rawseti(L, -2, i);
        ++i;
    }
    lua_setfield(L, -2, "accesses"); // log
    // Add all brackets
    lua_newtable(L); // log brackets
    i = 1; // convert from 0- to 1-based index
    for (const auto &b: log.get_brackets()) {
        lua_newtable(L); // log brackets bracket
        lua_pushstring(L, bracket_name(b.type));
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

/// \brief Checks if the machine field in config matches the machine name.
/// \param L Lua state.
/// \param tabidx Config stack index.
static void check_machine_config(lua_State *L, int tabidx) {
    std::string config_name = check_string_field(L, tabidx, "machine");
    auto cartesi_name = cartesi::get_name();
    if (config_name != cartesi_name) {
        luaL_error(L, "Cartesi machine-config mismatch (%s running in %s)",
            config_name.c_str(), cartesi_name.c_str());
    }
}

/// \brief Loads RAM config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c Machine config structure.
static void load_ram_config(lua_State *L, int tabidx, machine_config &c) {
    check_table_field(L, tabidx, "ram");
    c.ram.length = check_uint_field(L, -1, "length");
    c.ram.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

/// \brief Loads ROM config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c Machine config structure.
static void load_rom_config(lua_State *L, int tabidx, machine_config &c) {
    if (!opt_table_field(L, tabidx, "rom"))
        return;
    c.rom.backing = opt_string_field(L, -1, "backing");
    c.rom.bootargs = opt_string_field(L, -1, "bootargs");
    lua_pop(L, 1);
}

/// \brief Loads flash-drive config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c Machine config structure.
static void load_flash_config(lua_State *L, int tabidx, machine_config &c) {
    if (!opt_table_field(L, tabidx, "flash"))
        return;
    int len = luaL_len(L, -1);
    if (len > (int) c.flash.capacity()) {
        luaL_error(L, "too many flash drives");
    }
    for (int i = 1; i <= len; i++) {
        lua_geti(L, -1, i);
        if (!lua_istable(L, -1)) {
            luaL_error(L, "flash[%d] not a table", i);
        }
        flash_config flash;
        flash.shared = opt_boolean_field(L, -1, "shared", false);
        flash.backing = check_string_field(L, -1, "backing");
        flash.start = check_uint_field(L, -1, "start");
        flash.length = check_uint_field(L, -1, "length");
        c.flash.push_back(std::move(flash));
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

/// \brief Loads processor config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c Machine config structure.
static void load_processor_config(lua_State *L, int tabidx, machine_config &c) {
    if (!opt_table_field(L, tabidx, "processor"))
        return;
    lua_getfield(L, -1, "x");
    auto &p = c.processor;
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
    p.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

/// \brief Loads HTIF config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c Machine config structure.
static void load_htif_config(lua_State *L, int tabidx, machine_config &c) {
    if (!opt_table_field(L, tabidx, "htif"))
        return;
    c.htif.tohost = opt_uint_field(L, -1, "tohost", c.htif.tohost);
    c.htif.fromhost = opt_uint_field(L, -1, "fromhost", c.htif.fromhost);
    c.htif.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

/// \brief Loads CLINT config from Lua to machine_config.
/// \param L Lua state.
/// \param tabidx Config stack index.
/// \param c Machine config structure.
static void load_clint_config(lua_State *L, int tabidx, machine_config &c) {
    if (!opt_table_field(L, tabidx, "clint"))
        return;
    c.clint.mtimecmp = opt_uint_field(L, -1, "mtimecmp", c.clint.mtimecmp);
    c.clint.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

/// \brief This is the cartesi.get_name() function implementation.
/// \param L Lua state.
static int mod_get_name(lua_State *L) {
    auto name = cartesi::get_name();
    lua_pushlstring(L, name.data(), name.size());
    return 1;
}

/// \brief This is the cartesi.keccak() function implementation.
/// \param L Lua state.
static int mod_keccak(lua_State *L) {
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
static int mod_machine(lua_State *L) try {
    int tabidx = 1;
    int meta = lua_upvalueindex(1);
    machine_config c{};
    // Check all parameters from Lua initialization table
    // and copy them to the machine_config object
    check_machine_config(L, tabidx);
    load_processor_config(L, tabidx, c);
    load_ram_config(L, tabidx, c);
    load_rom_config(L, tabidx, c);
    load_flash_config(L, tabidx, c);
    load_htif_config(L, tabidx, c);
    load_clint_config(L, tabidx, c);
    c.interactive = opt_boolean_field(L, tabidx, "interactive", false);
    // Allocate room for machine object as a Lua userdata
    // and invoke placement new to construct it in place
    void *p = lua_newuserdata(L, sizeof(machine));
    new (p) machine{c};
    // Set metatable so Lua recognizes userdata as a machine object
    lua_pushvalue(L, meta);
    lua_setmetatable(L, -2);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Contents of the cartesi module table.
static const luaL_Reg mod[] = {
    {"keccak", mod_keccak},
    {"machine", mod_machine},
    {"get_name", mod_get_name},
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
static int meta__index_destroy(lua_State *L) {
    machine *m = check_machine(L, 1);
    lua_pushnil(L); // Remove metatable from object
    lua_setmetatable(L, 1);
    m->~machine(); // Explicitly invoke object destructor
    return 0;
}

/// \brief This is the machine:update_merkle_tree() method implementation.
/// \param L Lua state.
static int meta__index_update_merkle_tree(lua_State *L) try {
    check_machine(L, 1)->update_merkle_tree();
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:verify_merkle_tree() method implementation.
/// \param L Lua state.
static int meta__index_verify_merkle_tree(lua_State *L) try {
    lua_pushboolean(L, check_machine(L, 1)->get_merkle_tree().verify_tree());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:get_root_hash() method implementation.
/// \param L Lua state.
static int meta__index_get_root_hash(lua_State *L) try {
    machine *m = check_machine(L, 1);
    merkle_tree::hash_type hash;
    if (m->get_merkle_tree().get_root_hash(hash)) {
        push_hash(L, hash);
        return 1;
    } else {
        return 0;
    }
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:run() method implementation.
/// \param L Lua state.
static int meta__index_run(lua_State *L) try {
    check_machine(L, 1)->run(luaL_checkinteger(L, 2));
    return 0;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_mcycle() method implementation.
/// \param L Lua state.
static int meta__index_read_mcycle(lua_State *L) try {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_mcycle());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_tohost() method implementation.
/// \param L Lua state.
static int meta__index_read_tohost(lua_State *L) try {
    machine *m = check_machine(L, 1);
    lua_pushinteger(L, m->read_htif_tohost());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:read_tohost() method implementation.
/// \param L Lua state.
static int meta__index_read_iflags_H(lua_State *L) try {
    machine *m = check_machine(L, 1);
    lua_pushboolean(L, m->read_iflags_H());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:dump() method implementation.
/// \param L Lua state.
static int meta__index_dump(lua_State *L) try {
    machine *m = check_machine(L, 1);
    m->dump();
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:dump_regs() method implementation.
/// \param L Lua state.
static int meta__index_dump_regs(lua_State *L) {
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
    return 0;
}

/// \brief This is the machine:read_word() method implementation.
/// \param L Lua state.
static int meta__index_read_word(lua_State *L) try {
    machine *m = check_machine(L, 1);
    uint64_t word_value = 0;
    if (m->read_word(luaL_checkinteger(L, 2), word_value)) {
        lua_pushinteger(L, word_value);
        return 1;
    } else {
        return 0;
    }
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:get_proof() method implementation.
/// \param L Lua state.
static int meta__index_get_proof(lua_State *L) try {
    machine *m = check_machine(L, 1);
    merkle_tree::proof_type proof;
    if (m->get_proof(luaL_checkinteger(L, 2), luaL_checkinteger(L, 3), proof)) {
        push_proof(L, proof);
        return 1;
    } else {
        return 0;
    }
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:verify_dirty_page_maps() method implementation.
/// \param L Lua state.
static int meta__index_verify_dirty_page_maps(lua_State *L) try {
    machine *m = check_machine(L, 1);
    lua_pushboolean(L, m->verify_dirty_page_maps());
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief This is the machine:step() method implementation.
/// \param L Lua state.
static int meta__index_step(lua_State *L) try {
    machine *m = check_machine(L, 1);
    access_log log;
    m->step(log);
    push_log(L, log);
    return 1;
} catch (std::exception &x) {
    luaL_error(L, x.what());
    return 0;
}

/// \brief Contents of the machine metatable __index table.
static const luaL_Reg meta__index[] = {
    {"run", meta__index_run},
    {"dump", meta__index_dump},
    {"dump_regs", meta__index_dump_regs},
    {"get_proof", meta__index_get_proof},
    {"read_word", meta__index_read_word},
    {"read_mcycle", meta__index_read_mcycle},
    {"read_tohost", meta__index_read_tohost},
    {"read_iflags_H", meta__index_read_iflags_H},
    {"update_merkle_tree", meta__index_update_merkle_tree},
    {"verify_merkle_tree", meta__index_verify_merkle_tree},
    {"get_root_hash", meta__index_get_root_hash},
    {"step", meta__index_step},
    {"destroy", meta__index_destroy},
    {"verify_dirty_page_maps", meta__index_verify_dirty_page_maps},
    { NULL, NULL }
};

/// \brief Machine __tostring metamethod.
/// \param L Lua state.
static int meta__tostring(lua_State *L) {
    lua_pushstring(L, "machine");
    return 1;
}

/// \brief Machine __gc metamethod.
/// \param L Lua state.
static int meta__gc(lua_State *L) {
    machine *m = check_machine(L, 1);
    m->~machine(); // Explicitly invoke object destructor
    return 0;
}

/// \brief Contents of the machine metatable.
static const luaL_Reg meta[] = {
    {"__gc", meta__gc},
    {"__tostring", meta__tostring},
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

/// \brief Entrypoint to the Cartesi Lua library.
/// \param L Lua state.
extern "C"
__attribute__((visibility("default")))
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
    lua_newtable(L); /* mod */
    lua_newtable(L); /* mod meta */
    lua_newtable(L); /* mod meta metaidx */
    lua_pushvalue(L, -2); /* mod meta metaidx meta */
    luaL_setfuncs(L, meta__index, 1); /* mod meta metaidx */
    lua_setfield(L, -2, "__index"); /* mod meta */
    lua_pushvalue(L, -1); /* mod meta meta */
    luaL_setfuncs(L, meta, 1); /* mod meta */
    luaL_setfuncs(L, mod, 1); /* mod */
    return 1;
}
