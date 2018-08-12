#include <lua.h>
int luaopen_emu(lua_State *L);

int main(void) {
    luaopen_emu(0);
    return 0;
}
