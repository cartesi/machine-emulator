#include <cstring>
#include <lua.hpp>
#include <iostream>

#include "emulator.h"

/// \file
/// \brief Scripting interface for the emulator in the Lua language.

#ifdef GPERF
#include "gperftools/profiler.h"
#endif

#if 0
static void print(lua_State *L, int idx) {
    idx = lua_absindex(L, idx);
    lua_getglobal(L, "tostring");
    lua_pushvalue(L, idx);
    lua_call(L, 1, 1);
    fprintf(stderr, "%02d: %s\n", idx, lua_tostring(L, -1));
    lua_pop(L, 1);
}
#endif

static int opt_boolean_field(lua_State *L, int tabidx, const char *field, int def) {
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

static uint64_t check_uint_field(lua_State *L, int tabidx, const char *field) {
    tabidx = lua_absindex(L, tabidx);
    lua_Integer ival;
    lua_getfield(L, tabidx, field);
    if (!lua_isinteger(L, -1))
        luaL_error(L, "invalid %s (expected unsigned integer)", field);
    ival = lua_tointeger(L, -1);
    lua_pop(L, 1);
    return (uint64_t) ival;
}

static uint64_t opt_uint_field(lua_State *L, int tabidx, int i, uint64_t def = 0) {
    tabidx = lua_absindex(L, tabidx);
    uint64_t val = def;
    lua_geti(L, tabidx, i);
    if (lua_isinteger(L, -1)) {
        val = lua_tointeger(L, -1);
    } else if (!lua_isnil(L, -1)) {
        luaL_error(L, "invalid entry %d (expected unsigned integer)", i);
    }
    lua_pop(L, 1);
    return (uint64_t) val;
}

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

static void check_table_field(lua_State *L, int tabidx, const char *field) {
    lua_getfield(L, tabidx, field);
    if (!lua_istable(L, -1)) {
        luaL_error(L, "missing %s", field);
    }
}

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

static void check_machine_config(lua_State *L, int tabidx) {
    // Check emulator and machine specification match each other
    std::string machine_name = check_string_field(L, tabidx, "machine");
    auto emulator_name = emulator_get_name();
    if (emulator_name != machine_name) {
        luaL_error(L, "machine-emulator mismatch (%s running in %s)",
            machine_name.c_str(), emulator_name.c_str());
    }
}

static void check_ram_config(lua_State *L, int tabidx, emulator_config *c) {
    check_table_field(L, tabidx, "ram");
    c->ram.length = check_uint_field(L, -1, "length");
    c->ram.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

static void check_rom_config(lua_State *L, int tabidx, emulator_config *c) {
    if (!opt_table_field(L, tabidx, "rom"))
        return;
    c->rom.backing = opt_string_field(L, -1, "backing");
    c->rom.bootargs = opt_string_field(L, -1, "bootargs");
    lua_pop(L, 1);
}

static void check_flash_config(lua_State *L, int tabidx, emulator_config *c) {
    if (!opt_table_field(L, tabidx, "flash"))
        return;
    int len = luaL_len(L, -1);
    c->flash.reserve(len);
    for (int i = 1; i <= len; i++) {
        lua_geti(L, -1, i);
        if (!lua_istable(L, -1)) {
            luaL_error(L, "flash[%d] not a table", i);
        }
        flash_config flash;
        flash.shared = opt_boolean_field(L, -1, "shared", 0);
        flash.backing = check_string_field(L, -1, "backing");
        flash.label = check_string_field(L, -1, "label");
        flash.start = check_uint_field(L, -1, "start");
        flash.length = check_uint_field(L, -1, "length");
        c->flash.push_back(std::move(flash));
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
}

static void check_processor_config(lua_State *L, int tabidx, emulator_config *c) {
    if (!opt_table_field(L, tabidx, "processor"))
        return;
    lua_getfield(L, -1, "x");
    auto &p = c->processor;
    if (lua_istable(L, -1)) {
        int len = luaL_len(L, -1);
        for (int i = 1; i <= std::min(len, 32); i++) {
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

static void check_clint_config(lua_State *L, int tabidx, emulator_config *c) {
    if (!opt_table_field(L, tabidx, "clint"))
        return;
    c->clint.mtimecmp = opt_uint_field(L, -1, "mtimecmp", c->clint.mtimecmp);
    c->clint.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

static void check_htif_config(lua_State *L, int tabidx, emulator_config *c) {
    if (!opt_table_field(L, tabidx, "htif"))
        return;
    c->htif.tohost = opt_uint_field(L, -1, "tohost", c->htif.tohost);
    c->htif.fromhost = opt_uint_field(L, -1, "fromhost", c->htif.fromhost);
    c->htif.backing = opt_string_field(L, -1, "backing");
    lua_pop(L, 1);
}

static int protected_create(lua_State *L) {
    int tabidx = 1;
    emulator_config *c = reinterpret_cast<emulator_config *>(lua_touserdata(L, 2));
    int meta = 3;
    // Check all parameters from Lua initialization table
    // and copy them to the emulator_config object
    check_machine_config(L, tabidx);
    check_processor_config(L, tabidx, c);
    check_ram_config(L, tabidx, c);
    check_rom_config(L, tabidx, c);
    check_flash_config(L, tabidx, c);
    check_htif_config(L, tabidx, c);
    check_clint_config(L, tabidx, c);
    c->interactive = opt_boolean_field(L, tabidx, "interactive", 0);
    // Initialize machine and create corresponding Lua object
    emulator **pemu = reinterpret_cast<emulator **>(
        lua_newuserdata(L, sizeof(emulator *)));
    lua_pushvalue(L, meta);
    lua_setmetatable(L, -2);
    *pemu = emulator_init(c);
    if (!(*pemu)) {
        luaL_error(L, "machine initialization failed");
    }
    return 1;
}

static int emu_lua_machine(lua_State *L) {
    if (!lua_checkstack(L, 4)) {
        luaL_error(L, "stack overflow");
    }
    emulator_config *c = emulator_config_init();
    if (!c) {
        luaL_error(L, "machine config allocation failed");
    }
    lua_pushcfunction(L, protected_create);
    lua_pushvalue(L, 1);
    lua_pushlightuserdata(L, c);
    lua_pushvalue(L, lua_upvalueindex(1));
    if (lua_pcall(L, 3, 1, 0) != 0) {
        emulator_config_end(c);
        lua_error(L);
    }
    emulator_config_end(c);
    return 1;
}

static int is_emulator(lua_State *L, int idx) {
    idx = lua_absindex(L, idx);
    if (!lua_getmetatable(L, idx)) lua_pushnil(L);
    int ret = lua_compare(L, -1, lua_upvalueindex(1), LUA_OPEQ);
    lua_pop(L, 1);
    return ret;
}

static emulator *check_emulator(lua_State *L, int idx) {
    if (!is_emulator(L, idx)) {
        luaL_argerror(L, idx, "expected virtual machine");
    }
    emulator **pv = (emulator **) lua_touserdata(L, idx);
    return *pv;
}

static int emu_lua_destroy(lua_State *L) {
    emulator *e = check_emulator(L, 1);
    emulator_end(e);
    lua_pushnil(L);
    lua_setmetatable(L, -2);
    return 0;
}

static int emu_lua_update_merkle_tree(lua_State *L) {
    emulator *e = check_emulator(L, 1);
    emulator_update_merkle_tree(e);
    return 0;
}

static int emu_lua_get_merkle_tree_root_hash(lua_State *L) {
    emulator *e = check_emulator(L, 1);
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    emulator_get_merkle_tree_root_hash(e, buf, sizeof(buf));
    lua_pushlstring(L, reinterpret_cast<char *>(buf), sizeof(buf));
    return 1;
}

static int emu_lua_run(lua_State *L) {
    emulator *e = check_emulator(L, 1);
    uint64_t cycles_end = luaL_checkinteger(L, 2);
    int halted = emulator_run(e, cycles_end);
    lua_pushinteger(L, emulator_read_mcycle(e));
    if (halted) {
        uint64_t htif_tohost = emulator_read_tohost(e);
        uint64_t payload = (htif_tohost & (~1ULL >> 16));
        lua_pushnil(L);
        lua_pushinteger(L, payload >> 1);
        return 3;
    } else {
        lua_pushinteger(L, 1);
        return 2;
    }
}

static int emu_lua_get_name(lua_State *L) {
    lua_pushstring(L, emulator_get_name().c_str());
    return 1;
}

static int emu_lua__tostring(lua_State *L) {
    lua_pushstring(L, "virtual machine");
    return 1;
}

static int emu_lua__gc(lua_State *L) {
    emulator *e = check_emulator(L, 1);
    if (e) emulator_end(e);
    return 0;
}

static const luaL_Reg emu_lua__index[] = {
    {"run", emu_lua_run},
    {"update_merkle_tree", emu_lua_update_merkle_tree},
    {"get_merkle_tree_root_hash", emu_lua_get_merkle_tree_root_hash},
    {"destroy", emu_lua_destroy},
    { NULL, NULL }
};

static const luaL_Reg emu_lua_meta[] = {
    {"__gc", emu_lua__gc},
    {"__tostring", emu_lua__tostring},
    { NULL, NULL }
};

static const luaL_Reg emu_module[] = {
    {"machine", emu_lua_machine},
    {"get_name", emu_lua_get_name},
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

extern "C"
__attribute__((visibility("default")))
int luaopen_emu(lua_State *L) {
#ifdef GPERF
    lua_newuserdata(L, 1); /* gperf */
    lua_pushvalue(L, -1); /* gperf gperf */
    lua_newtable(L); /* gperf gperf gperfmeta */
    luaL_setfuncs(L, gperf_meta, 0); /* gperf gperf gperfmeta */
    lua_setmetatable(L, -2); /* gperf gperf */
    lua_settable(L, LUA_REGISTRYINDEX); /**/
    ProfilerStart("emu.prof");
#endif
    lua_newtable(L); /* mod */
    lua_newtable(L); /* mod emumeta */
    lua_newtable(L); /* mod emumeta emuidx */
    lua_pushvalue(L, -2); /* mod emumeta emuidx emumeta */
    luaL_setfuncs(L, emu_lua__index, 1); /* mod emumeta emuidx */
    lua_setfield(L, -2, "__index"); /* mod emumeta */
    lua_pushvalue(L, -1); /* mod emumeta emumeta */
    luaL_setfuncs(L, emu_lua_meta, 1); /* mod emumeta */
    luaL_setfuncs(L, emu_module, 1); /* mod */
    return 1;
}
