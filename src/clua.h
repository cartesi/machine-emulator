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

#ifndef CLUA_H
#define CLUA_H

#include <utility>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <boost/type_index.hpp>

#define CLUA_REGISTRY_KEY "clua_key"

namespace cartesi {

/// \brief Initizizes clua, leaving the context on top of stack
/// \param L Lua state.
int clua_init(lua_State *L);

/// \brief Returns the C++ type name as a string
/// \tparam T C++ type whose name is desired
template <typename T> const char *clua_rawname(void) {
    return boost::typeindex::type_id_with_cvr<T>().raw_name();
}

/// \brief Pushes the metatable of a previously defined type to the top of stack
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_gettypemetatable(lua_State *L, int ctxidx = lua_upvalueindex(1)) {
    ctxidx = lua_absindex(L, ctxidx);
    lua_pushstring(L, clua_rawname<T>());
    lua_rawget(L, ctxidx);
    if (lua_isnil(L, -1))
        luaL_error(L, "unknown type (%s)",
            boost::typeindex::type_id_with_cvr<T>().pretty_name().c_str());
}

/// \brief Checks if a type has been previously defined
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
int clua_typeexists(lua_State *L, int ctxidx = lua_upvalueindex(1)) {
    ctxidx = lua_absindex(L, ctxidx);
    lua_pushstring(L, clua_rawname<T>());
    lua_rawget(L, ctxidx);
    int exists = !lua_isnil(L, -1);
    lua_pop(L, 1);
    return exists;
}

/// \brief Checks if object in stack is of a given type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param idx Object index (or pseudo-index)
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
int clua_is(lua_State *L, int idx, int ctxidx = lua_upvalueindex(1)) {
    idx = lua_absindex(L, idx);
    clua_gettypemetatable<T>(L, ctxidx);
    if (!lua_getmetatable(L, idx)) lua_pushnil(L);
    int ret = lua_compare(L, -1, -2, LUA_OPEQ);
    lua_pop(L, 2);
    return ret;
}

/// \brief Obtain reference to object in stack
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param idx Object index (or pseudo-index)
template <typename T>
T &clua_to(lua_State *L, int idx) {
    return *reinterpret_cast<T *>(lua_touserdata(L, idx));
}

/// \brief Finalize an object of a previously defined type
/// \tparam T Associated C++ type
/// \param L Lua state.
template <typename T>
int clua_gc(lua_State *L) {
    T *ptr = reinterpret_cast<T *>(lua_touserdata(L, 1));
    ptr->~T();
    lua_pushnil(L);
    lua_setmetatable(L, 1);
    return 0;
}

/// \brief Prints an object of a previously defined type
/// \tparam T Associated C++ type
/// \param L Lua state.
template <typename T>
int clua_tostring(lua_State *L) {
    const char *name = "unknown";
    if (luaL_getmetafield(L, 1, "name") == LUA_TSTRING) {
        name = lua_tostring(L, -1);
    }
    if (lua_type(L, 1) == LUA_TUSERDATA) {
        T *ptr = reinterpret_cast<T *>(lua_touserdata(L, 1));
        lua_pushfstring(L, "%s: %p", name, ptr);
    }
    return 1;
}

/// \brief Pushes the type name associated to a type to the top of stack
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_pushname(lua_State *L, int ctxidx = lua_upvalueindex(1)) {
    clua_gettypemetatable<T>(L, ctxidx);
    lua_getfield(L, -1, "name");
    lua_replace(L, -2);
}

/// \brief Asserts if an object in stack matches a given type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param idx Index (or pseudo-index) of object in stack
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_argerror(lua_State *L, int idx, int ctxidx = lua_upvalueindex(1)) {
    idx = lua_absindex(L, idx);
    clua_pushname<T>(L, ctxidx);
    luaL_argerror(L, idx, lua_pushfstring(L, "expected %s",
        lua_tostring(L, -1)));
}

/// \brief Checks if Lua object matches associated type and returns a reference
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param idx Index (or pseudo-index) of object in stack
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
T &clua_check(lua_State *L, int idx, int ctxidx = lua_upvalueindex(1)) {
    if (!clua_is<T>(L, idx, ctxidx))
        clua_argerror<T>(L, idx, ctxidx);
    return clua_to<T>(L, idx);
}

/// \brief Sets the metatable of the object to that of a previously
/// created Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_setmetatable(lua_State *L, int objidx,
    int ctxidx = lua_upvalueindex(1)) {
    objidx = lua_absindex(L, objidx);
    clua_gettypemetatable<T>(L, ctxidx);
    lua_setmetatable(L, objidx);
}

/// \brief Pushes a copy of an object as a Lua object of a previously
/// created Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param value Object to be copied
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
int clua_push(lua_State *L, const T &value, int ctxidx = lua_upvalueindex(1)) {
    T* ptr = reinterpret_cast<T*>(lua_newuserdata(L, sizeof(T)));
    new (ptr) T{value};
    clua_setmetatable<T>(L, -1, ctxidx);
    return 1;
}

/// \brief Moves an object to a Lua object of a previously defined Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param value Object to be moved
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
int clua_push(lua_State *L, T &&value, int ctxidx = lua_upvalueindex(1)) {
    T* ptr = reinterpret_cast<T*>(lua_newuserdata(L, sizeof(T)));
    new (ptr) T{std::move(value)};
    clua_setmetatable<T>(L, -1, ctxidx);
    return 1;
}

/// \brief Sets metamethods of a previously defined Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param methods Registry of metamethods
/// \param nup Number of upvalues (on top of stack)
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_setmetamethods(lua_State *L, const luaL_Reg *methods,
    int nup, int ctxidx) {
    ctxidx = lua_absindex(L, ctxidx); // up1 .. upn
    clua_gettypemetatable<T>(L, ctxidx); // up1 .. upn meta
    lua_insert(L, -nup-1); // meta up1 .. upn
    lua_pushvalue(L, ctxidx); // meta up1 .. upn ctxtab
    luaL_setfuncs(L, methods, nup+1); // meta
    lua_pop(L, 1); //
}

/// \brief Sets methods of a previously defined Lua type (i.e., fills out the
/// __index entry in the associated metatable with the desired methods)
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param methods Registry of methods
/// \param nup Number of upvalues (on top of stack)
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_setmethods(lua_State *L, const luaL_Reg *methods,
    int nup, int ctxidx) {
    ctxidx = lua_absindex(L, ctxidx); // up1 .. upn
    clua_gettypemetatable<T>(L, ctxidx); // up1 .. upn meta
    lua_getfield(L, -1, "__index");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L); // up1 .. upn meta index
        lua_pushvalue(L, -1); // up1 .. upn meta index index
        lua_setfield(L, -3, "__index");
    } // up1 .. upn meta index
    lua_insert(L, -nup-2); // index up1 .. upn meta
    lua_pop(L, 1); // index up1 .. upn
    lua_pushvalue(L, ctxidx); // index up1 .. upn ctxtab
    luaL_setfuncs(L, methods, nup+1); // index
    lua_pop(L, 1); //
}

/// \brief Creates a new Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param name String with name for type
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_createtype(lua_State *L, const char *name, int ctxidx) {
    ctxidx = lua_absindex(L, ctxidx);
    // check if name is already taken
    lua_getfield(L, ctxidx, name);
    if (!lua_isnil(L, -1)) {
        luaL_error(L, "redefinition of %s", name);
    }
    lua_pop(L, 1);
    // create new type
    luaL_Reg default_meta[] = {
        { "__gc", &clua_gc<T> },
        { "__tostring", &clua_tostring<T> },
        { nullptr, nullptr },
    };
    lua_pushstring(L, clua_rawname<T>()); // T_rawname
    lua_newtable(L); // T_rawname T_meta
    lua_pushstring(L, name); // T_rawname T_meta T_name
    lua_setfield(L, -2, "name"); // T_rawname T_meta
    lua_pushvalue(L, ctxidx); // T_rawname T_meta ctxtab
    luaL_setfuncs(L, default_meta, 1); // T_rawname T_meta
    lua_pushliteral(L, "access denied"); // T_rawname T_meta "access denied"
    lua_setfield(L, -2, "__metatable"); // T_rawname T_meta
    lua_rawset(L, ctxidx); //
}

} // namespace cartesi

#endif
