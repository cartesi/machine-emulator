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

#ifndef CLUA_H
#define CLUA_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

extern "C" {
#include <lauxlib.h>
#include <lua.h>
}

#include <boost/type_index.hpp>

namespace cartesi {

#ifdef CLUA_DEBUG_UTILS

/// \brief Prints element at given stack index
/// \param L Lua state.
/// \param idx Stack index.
void clua_print(lua_State *L, int idx);

/// \brief Dumps stack contents
/// \param L Lua state.
void clua_dumpstack(lua_State *L);

#endif

namespace detail {
template <size_t N, std::size_t... I>
constexpr auto clua_make_luaL_Reg_array_impl(luaL_Reg const (&vec)[N], std::index_sequence<I...> /*unused*/) noexcept {
    return std::array<luaL_Reg, N + 1>{{vec[I]..., {nullptr, nullptr}}};
}
} // namespace detail

constexpr const char *clua_registry_key = "clua_key";

/// \brief Initizizes clua, leaving the context on top of stack
/// \param L Lua state.
int clua_init(lua_State *L);

/// \brief Returns the C++ type name as a string
/// \tparam T C++ type whose name is desired
template <typename T>
const char *clua_rawname() {
    return boost::typeindex::type_id_with_cvr<T>().raw_name();
}

/// \brief Returns an array with the Regs and the sentinel in the end
/// \param N number of Regs
/// \param regs C array with Regs
template <size_t N>
constexpr auto clua_make_luaL_Reg_array(luaL_Reg const (&vec)[N]) noexcept {
    return detail::clua_make_luaL_Reg_array_impl(vec, std::make_index_sequence<N>{});
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
    if (lua_isnil(L, -1)) {
        // This should be unreachable, unless there is a code mistake
        // LCOV_EXCL_START
        luaL_error(L, "unknown type (%s)", boost::typeindex::type_id_with_cvr<T>().pretty_name().c_str());
        // LCOV_EXCL_STOP
    }
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
    const int exists = !lua_isnil(L, -1);
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
    if (!lua_getmetatable(L, idx)) {
        lua_pushnil(L);
    }
    const int ret = lua_compare(L, -1, -2, LUA_OPEQ);
    lua_pop(L, 2);
    return ret;
}

/// \brief Obtain reference to object in stack
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param idx Object index (or pseudo-index)
template <typename T>
T &clua_to(lua_State *L, int idx) {
    return *static_cast<T *>(lua_touserdata(L, idx));
}

/// \brief Finalize an object of a previously defined type
/// \tparam T Associated C++ type
/// \param L Lua state.
template <typename T>
int clua_gc(lua_State *L) {
    T *ptr = static_cast<T *>(lua_touserdata(L, 1));
    ptr->~T();
    lua_pushnil(L);
    lua_setmetatable(L, 1);
    return 0;
}

/// \brief Close an object of a previously defined type
/// \tparam T Associated C++ type
/// \param L Lua state.
template <typename T>
int clua_close(lua_State *L) {
    T *ptr = static_cast<T *>(lua_touserdata(L, 1));
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
        T *ptr = static_cast<T *>(lua_touserdata(L, 1));
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
    luaL_argerror(L, idx, lua_pushfstring(L, "expected %s", lua_tostring(L, -1)));
}

/// \brief Checks if Lua object matches associated type and returns a reference
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param idx Index (or pseudo-index) of object in stack
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
T &clua_check(lua_State *L, int idx, int ctxidx = lua_upvalueindex(1)) {
    if (!clua_is<T>(L, idx, ctxidx)) {
        clua_argerror<T>(L, idx, ctxidx);
    }
    return clua_to<T>(L, idx);
}

/// \brief Sets the metatable of the object to that of a previously
/// created Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_setmetatable(lua_State *L, int objidx, int ctxidx = lua_upvalueindex(1)) {
    objidx = lua_absindex(L, objidx);
    clua_gettypemetatable<T>(L, ctxidx);
    lua_setmetatable(L, objidx);
}

/// \brief Creates lua managed C++ object on stack
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param value C++ object for initialization of managed object
/// \param idx Object index (or pseudo-index)
///
template <typename T>
int clua_push(lua_State *L, T &&value, int ctxidx = lua_upvalueindex(1)) {
    T *ptr = static_cast<T *>(lua_newuserdata(L, sizeof(T)));
    new (ptr) T{std::forward<T>(value)};
    clua_setmetatable<T>(L, -1, ctxidx);
    return 1;
}

/// \brief Creates lua managed C++/C object on stack and returns reference to it
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param value C++ object for initialization of managed object
/// \param idx Object index (or pseudo-index)
template <typename T>
T &clua_push_to(lua_State *L, T &&value, int ctxidx = lua_upvalueindex(1)) {
    clua_push(L, std::forward<T>(value), ctxidx);
    return clua_to<T>(L, -1);
}

/// \brief Sets metamethods of a previously defined Lua type
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param methods Registry of metamethods
/// \param nup Number of upvalues (on top of stack)
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_setmetamethods(lua_State *L, const luaL_Reg *methods, int nup, int ctxidx) {
    ctxidx = lua_absindex(L, ctxidx);    // up1 .. upn
    clua_gettypemetatable<T>(L, ctxidx); // up1 .. upn meta
    lua_insert(L, -nup - 1);             // meta up1 .. upn
    lua_pushvalue(L, ctxidx);            // meta up1 .. upn ctxtab
    luaL_setfuncs(L, methods, nup + 1);  // meta
    lua_pop(L, 1);                       //
}

/// \brief Sets methods of a previously defined Lua type (i.e., fills out the
/// __index entry in the associated metatable with the desired methods)
/// \tparam T Associated C++ type
/// \param L Lua state.
/// \param methods Registry of methods
/// \param nup Number of upvalues (on top of stack)
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_setmethods(lua_State *L, const luaL_Reg *methods, int nup, int ctxidx) {
    ctxidx = lua_absindex(L, ctxidx);    // up1 .. upn
    clua_gettypemetatable<T>(L, ctxidx); // up1 .. upn meta
    lua_getfield(L, -1, "__index");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);      // up1 .. upn meta index
        lua_pushvalue(L, -1); // up1 .. upn meta index index
        lua_setfield(L, -3, "__index");
    }
    // up1 .. upn meta index
    lua_insert(L, -nup - 2);            // index up1 .. upn meta
    lua_pop(L, 1);                      // index up1 .. upn
    lua_pushvalue(L, ctxidx);           // index up1 .. upn ctxtab
    luaL_setfuncs(L, methods, nup + 1); // index
    lua_pop(L, 1);                      //
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
        // This should be unreachable, unless there is a code mistake
        luaL_error(L, "redefinition of %s", name); // LCOV_EXCL_LINE
    }
    lua_pop(L, 1);
    // create new type
    auto default_meta = clua_make_luaL_Reg_array({
        {"__gc", &clua_gc<T>},
        {"__close", &clua_close<T>},
        {"__tostring", &clua_tostring<T>},
    });
    lua_pushstring(L, clua_rawname<T>());     // T_rawname
    lua_newtable(L);                          // T_rawname T_meta
    lua_pushstring(L, name);                  // T_rawname T_meta T_name
    lua_setfield(L, -2, "name");              // T_rawname T_meta
    lua_pushvalue(L, ctxidx);                 // T_rawname T_meta ctxtab
    luaL_setfuncs(L, default_meta.data(), 1); // T_rawname T_meta
    lua_rawset(L, ctxidx);                    //
}

/// \brief Creates a new Lua type if it doesn't exists.
/// Use default C++ type name for lua name description
/// \tparam T Associated C++ type
/// \param L Lua state
/// \param ctxidx Index (or pseudo-index) of clua context
template <typename T>
void clua_createnewtype(lua_State *L, int ctxidx) {
    if (!clua_typeexists<T>(L, ctxidx)) {
        clua_createtype<T>(L, boost::typeindex::type_id_with_cvr<T>().pretty_name().c_str(), ctxidx);
    }
}

/// \brief Sets the lua named field to integer value
/// \param L Lua state
/// \param val Integer value
/// \param idx Index (or pseudo-index) of object in stack
/// \param ctxidx Index (or pseudo-index) of clua context
void clua_setintegerfield(lua_State *L, uint64_t val, const char *name, int idx);

/// \brief Sets the lua named field to C string value
/// \param L Lua state
/// \param val String value
/// \param idx Index (or pseudo-index) of object in stack
/// \param ctxidx Index (or pseudo-index) of clua context
void clua_setstringfield(lua_State *L, const char *val, const char *name, int idx);

/// \brief Sets the lua named field to arbitrary string value
/// \param L Lua state
/// \param val String value
/// \param val String length
/// \param idx Index (or pseudo-index) of object in stack
/// \param ctxidx Index (or pseudo-index) of clua context
void clua_setlstringfield(lua_State *L, const char *val, size_t length, const char *name, int idx);

} // namespace cartesi

#endif
