# Environment of the PRT recipes on the host (source after bugs/env.sh), as doc/Makefile HOST=yes sets it:
# default images = linux.bin + rootfs-docs.ext2 (the docs image's rootfs.ext2), installed command names in PATH,
# recipes on LUA_PATH, Dave artifacts of the chosen build (PRT_VARIANT=patched by default).
: "${HARNESS_WORK:?source bugs/env.sh first}"
_imgs="$HARNESS_WORK/images-docs"
mkdir -p "$_imgs"
ln -sf "$HARNESS_WORK/images/linux.bin" "$_imgs/linux.bin"
ln -sf "$REPO/doc/recipes/rootfs-docs.ext2" "$_imgs/rootfs.ext2"
export CARTESI_IMAGES_PATH="$_imgs"
export RECIPES_DIR="$REPO/doc/recipes"
export PRT_VARIANT="${PRT_VARIANT:-patched}"
export PRT_DAVE_DIR="$HARNESS_WORK/dave/$PRT_VARIANT"
export PRT_OUTPUT_DIR="${PRT_OUTPUT_DIR:-$HARNESS_WORK/prt-runs}"
export PATH="$HARNESS_WORK/bin:$HARNESS_WORK/foundry/bin:$RECIPES_DIR:$PATH"
export MAKE=make
export TZ=UTC
unset _imgs
