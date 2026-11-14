# Source after bugs/env.sh (or set HARNESS_SANITIZE=1 before sourcing bugs/env.sh) to run Lua tests and the
# jsonrpc server against the ASan+UBSan build in bugs/harness/work/sanitizer (sanitizer/build.sh).
# lua5.4 itself is not instrumented, so libasan must be preloaded (LD_PRELOAD); the variable LUA_SAN gives a
# ready command line. Any ASan/UBSan report aborts the process (-fno-sanitize-recover=all; abort_on_error),
# which bugs/run.sh maps to status 2 unless the test itself catches it (spawn a child and check its status
# and stderr for "ERROR: AddressSanitizer" / "runtime error:").
_san_src="${HARNESS_WORK:?source bugs/env.sh first}/sanitizer/src"
export SANITIZER_SRC="$_san_src"
export LD_LIBRARY_PATH="$_san_src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$_san_src:$PATH"
export LUA_PATH_5_4="$_san_src/?.lua;$LUA_PATH_5_4"
export LUA_CPATH_5_4="$_san_src/?.so;;"
_libasan="$(realpath "$(gcc -print-file-name=libasan.so)")"
_libstdcpp="$(realpath "$(gcc -print-file-name=libstdc++.so)")"
export SANITIZER_PRELOAD="$_libasan $_libstdcpp"
# detect_leaks=0: lua5.4 exits without closing everything; leaks are not what we look for here.
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=1:detect_stack_use_after_return=1:strict_string_checks=1}"
export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=1}"
export LUA_SAN="env LD_PRELOAD=\"$SANITIZER_PRELOAD\" lua5.4"
# Run lua5.4 with libasan preloaded: san_lua script.lua args...
san_lua() { LD_PRELOAD="$SANITIZER_PRELOAD" lua5.4 "$@"; }
export CARTESI_MACHINE="env LD_PRELOAD=\"$SANITIZER_PRELOAD\" lua5.4 $_san_src/cartesi-machine.lua"
unset _san_src _libasan _libstdcpp
