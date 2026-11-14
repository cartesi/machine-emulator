#!/bin/bash
# Runs inside an ephemeral `docker run --rm --network none` of cartesi/machine-emulator:toolchain (the image
# of the Dockerfile's `toolchain` stage). /src: a fresh `git archive` of the audited tree. /alt/<deb>: ONE
# alternate Debian build of a package that the Dockerfile does not pin (may be absent for the control build).
# /out: results. Builds the uarch exactly as the uarch-rebuild harness stage does (same sources, same pinned
# gcc/g++, same flags), after replacing only that one package.
set -euo pipefail
label=$1
if [ -n "${ALT_DEB:-}" ]; then
    dpkg -i --force-downgrade --force-depends --force-breaks "/alt/$ALT_DEB" > "/out/dpkg-$label.log" 2>&1 ||
        { cat "/out/dpkg-$label.log" >&2; exit 3; }
fi
cp -a /src /work
make -s -C /work/src cm-version.h interpret-jump-table.hpp > /dev/null
make -s -j2 -C /work/uarch > "/out/build-$label.log" 2>&1 || { tail -20 "/out/build-$label.log" >&2; exit 3; }
cp /work/uarch/uarch-ram.bin "/out/uarch-ram-$label.bin"
cp /work/uarch/uarch-pristine-hash.c "/out/uarch-pristine-hash-$label.c"
{
    dpkg-query -W gcc-riscv64-unknown-elf g++-14-riscv64-linux-gnu binutils-riscv64-unknown-elf \
        libc6-dev-riscv64-cross linux-libc-dev-riscv64-cross libstdc++-14-dev-riscv64-cross
    echo "ld used by g++: $(readlink -f "$(riscv64-unknown-elf-g++ -print-prog-name=ld)") ->" \
        "$("$(riscv64-unknown-elf-g++ -print-prog-name=ld)" --version | head -1)"
} > "/out/versions-$label.txt"
chown -R "${OUT_UID:-0}:${OUT_GID:-0}" /out
