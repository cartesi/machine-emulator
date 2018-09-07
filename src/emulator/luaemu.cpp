#include <lua.hpp>

#include "emulator.h"

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
    emulator *v = check_emulator(L, 1);
    emulator_end(v);
    lua_pushnil(L);
    lua_setmetatable(L, -2);
    return 0;
}

static int emu_lua_run(lua_State *L) {
    emulator *v = check_emulator(L, 1);
    uint64_t cycles_end = luaL_checkinteger(L, 2);
    int halted = emulator_run(v, cycles_end);
    lua_pushinteger(L, emulator_read_mcycle(v));
    if (halted) {
        uint64_t htif_tohost = emulator_read_tohost(v);
        uint64_t payload = (htif_tohost & (~1ULL >> 16));
        lua_pushnil(L);
        lua_pushinteger(L, payload >> 1);
        return 3;
    } else {
        lua_pushinteger(L, 1);
        return 2;
    }
}

static int emu_lua_create(lua_State *L) {
    emulator_config p_c, *c = &p_c;
    emulator_load_lua_config(L, c, 1);
    emulator *emu = emulator_init(c);
    emulator_free_config(c);
    if (!emu) {
        luaL_error(L, "Failed to initialize machine.");
    }
    emulator **ud = reinterpret_cast<emulator **>(lua_newuserdata(L, sizeof(emu)));
    *ud = emu;
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_setmetatable(L, -2);
    return 1;
}

static int emu_lua__tostring(lua_State *L) {
    lua_pushstring(L, "virtual machine");
    return 1;
}

static int emu_lua__gc(lua_State *L) {
    emulator *v = check_emulator(L, 1);
    emulator_end(v);
    return 0;
}

static const luaL_Reg emu_lua__index[] = {
    {"run", emu_lua_run},
    {"destroy", emu_lua_destroy},
    { NULL, NULL }
};

static const luaL_Reg emu_lua_meta[] = {
    {"__gc", emu_lua__gc},
    {"__tostring", emu_lua__tostring},
    { NULL, NULL }
};

static const luaL_Reg emu_module[] = {
    {"create", emu_lua_create},
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
