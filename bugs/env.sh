# Source this file (bash): `. bugs/env.sh`
# Sets up the environment to use the emulator built in-tree from this branch (`make` at the repository root)
# and the audit harness artifacts under bugs/harness/work.
#
# Exported variables:
#   REPO                 repository root
#   HARNESS              bugs/harness
#   HARNESS_WORK         bugs/harness/work (large, rebuilt by bugs/harness/setup.sh)
#   LUA                  the Lua 5.4 interpreter to run tests with (lua5.4)
#   CARTESI_MACHINE      command line of the in-tree cartesi-machine CLI ("lua5.4 <repo>/src/cartesi-machine.lua")
#   CARTESI_IMAGES_PATH  directory with linux.bin and rootfs.ext2 (dependencies.lock images, checksum-verified)
#   LINUX_IMAGE          $CARTESI_IMAGES_PATH/linux.bin
#   ROOTFS_IMAGE         $CARTESI_IMAGES_PATH/rootfs.ext2 (machine-guest-tools rootfs-tools.ext2)
#   ROOTFS_DOCS_IMAGE    doc/recipes/rootfs-docs.ext2 (git lfs) used by doc/recipes
#   HARNESS_CONFIGS      bugs/harness/work/configs (ready machine configurations, see bugs/harness/README.md)
#   BAREMETAL_DIR        bugs/harness/baremetal (bare-metal guest builder)
#   LUA_PATH_5_4, LUA_CPATH_5_4, LD_LIBRARY_PATH, PATH
# Lua modules available: cartesi (src/cartesi.so), cartesi.* (src/cartesi/), tests/lua helpers,
# doc/recipes modules (prt, prtu, vg, ...), bugs/harness/lib/*.lua (harness helpers, e.g. require("harness")).
#
# Set HARNESS_SANITIZE=1 before sourcing to use the ASan+UBSan out-of-tree build instead
# (bugs/harness/sanitizer/env.sh is sourced on top).

_bugs_env_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export REPO="$(cd "$_bugs_env_dir/.." && pwd)"
export HARNESS="$REPO/bugs/harness"
export HARNESS_WORK="$HARNESS/work"
export LUA=lua5.4
export CARTESI_IMAGES_PATH="$HARNESS_WORK/images"
export LINUX_IMAGE="$CARTESI_IMAGES_PATH/linux.bin"
export ROOTFS_IMAGE="$CARTESI_IMAGES_PATH/rootfs.ext2"
export ROOTFS_DOCS_IMAGE="$REPO/doc/recipes/rootfs-docs.ext2"
export HARNESS_CONFIGS="$HARNESS_WORK/configs"
export BAREMETAL_DIR="$HARNESS/baremetal"
export RECIPES_DIR="$REPO/doc/recipes"

export LD_LIBRARY_PATH="$REPO/src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
case ":$PATH:" in
*":$REPO/src:"*) ;;
*) export PATH="$REPO/src:$REPO/tests/misc:$HARNESS_WORK/bin:$HARNESS_WORK/foundry/bin:$PATH" ;;
esac
export LUA_PATH_5_4="$REPO/src/?.lua;$REPO/tests/lua/?.lua;$REPO/doc/recipes/?.lua;$HARNESS/lib/?.lua;;"
export LUA_CPATH_5_4="$REPO/src/?.so;;"
export CARTESI_MACHINE="lua5.4 $REPO/src/cartesi-machine.lua"
export TZ=UTC

if [ "${HARNESS_SANITIZE:-0}" = 1 ]; then
    . "$HARNESS/sanitizer/env.sh"
fi
unset _bugs_env_dir
