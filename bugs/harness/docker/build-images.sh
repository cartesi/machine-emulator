#!/bin/bash
# Build the Docker images of this repository's Dockerfile, out of tree:
#   toolchain -> cartesi/machine-emulator:toolchain   (used by `make uarch-with-toolchain`, i.e. by in-tree `make`)
#   emulator  -> cartesi/machine-emulator:devel       (runtime image with the emulator .deb, as `make build-emulator-image`)
#   uarch     -> audit-harness/uarch-rebuild:latest   (stage that only rebuilds the uarch, see uarch-rebuild/)
#
# The Dockerfile used is a generated copy of the repository's Dockerfile (never edited in place) with ONE
# addition: the session's HTTPS-proxy CA (if any) is copied to /usr/local/share/ca-certificates before
# `apt-get install ca-certificates`, so that the https fetches of the toolchain stage (stylua, luarocks)
# work behind the agent proxy. Package lists and versions are untouched.
#
# The build context is a copy of the files tracked by git (working-tree contents), minus bugs/ and minus
# the generated files (uarch-pristine-*.c, cm-version.h, ...), so the images never pick up artifacts of
# the in-tree build. Usage: build-images.sh [toolchain] [emulator] [uarch] [--force]
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"

FORCE=no
TARGETS=()
for a in "$@"; do
    case "$a" in
    --force) FORCE=yes ;;
    *) TARGETS+=("$a") ;;
    esac
done
[ ${#TARGETS[@]} -gt 0 ] || TARGETS=(toolchain emulator)

ensure_docker || DIE_STATUS=2 die "docker daemon not available"

D="$WORK/docker"
mkdir -p "$D"

# Context: tracked files of the working tree, without bugs/ and without generated files.
make_context() {
    local ctx="$D/context"
    rm -rf "$ctx"
    mkdir -p "$ctx"
    (cd "$REPO" && git ls-files -z --cached | grep -zv -E '^(bugs/|doc/)' |
        while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done |
        tar --null -T - -cf -) | tar -xf - -C "$ctx"
    # submodule directories are gitlinks: tar copies them empty, which is what the Dockerfile build expects
    echo "$ctx"
}

# Derived Dockerfile: insert the CA copy at the top of the toolchain stage.
make_dockerfile() {
    local out="$D/Dockerfile"
    awk '
        /^FROM \$RUNTIME_BASE$/ { print "FROM $RUNTIME_BASE AS runtime"; next }
        { print }
        /^FROM \$BUILD_BASE AS toolchain/ {
            print "# [audit harness] trust the session HTTPS proxy CA, if any (empty context otherwise)"
            print "COPY --from=hostca / /usr/local/share/ca-certificates/"
        }
    ' "$REPO/Dockerfile" > "$out"
    cat >> "$out" << 'EOF'

####################################################################################################
# [audit harness] uarch-only rebuild with the pinned toolchain, independent of the in-tree build.
FROM toolchain AS uarch-rebuild
COPY . /usr/src/emulator
RUN make -C /usr/src/emulator/src cm-version.h interpret-jump-table.hpp && \
    make -C /usr/src/emulator/uarch && \
    sha256sum /usr/src/emulator/uarch/uarch-ram.bin /usr/src/emulator/uarch/uarch-pristine-hash.c && \
    cat /usr/src/emulator/uarch/uarch-pristine-hash.c && \
    (riscv64-unknown-elf-gcc --version | head -1; riscv64-linux-gnu-g++-14 --version | head -1; \
     dpkg-query -W gcc-riscv64-unknown-elf g++-14-riscv64-linux-gnu binutils-riscv64-unknown-elf) \
        > /usr/src/emulator/uarch/toolchain-versions.txt
EOF
    # Dockerfile-specific ignore file (BuildKit): never send build outputs.
    {
        cat "$REPO/.dockerignore"
        printf '%s\n' 'uarch/uarch-pristine-ram.c' 'uarch/uarch-pristine-hash.c' 'uarch/uarch-ram.bin' \
            'uarch/*.elf' 'uarch/*.ld' 'uarch/compute-uarch-pristine-hash' 'src/cm-version.h' \
            'src/interpret-jump-table.hpp' 'src/jsonrpc-discover.cpp' 'bugs/'
    } > "$out.dockerignore"
    echo "$out"
}

image_exists() { docker image inspect "$1" > /dev/null 2>&1; }

build() {
    local target=$1 tag=$2
    shift 2
    if [ "$FORCE" = no ] && image_exists "$tag"; then
        log "image $tag exists (use --force to rebuild)"
        return 0
    fi
    local ctx df ca
    ctx=$(make_context)
    df=$(make_dockerfile)
    ca=$(hostca_dir)
    mapfile -t net < <(docker_build_net_args)
    log "docker build --target $target -t $tag"
    docker build "${net[@]}" --progress=plain --build-context "hostca=$ca" \
        --build-arg GIT_COMMIT="$(git -C "$REPO" rev-parse HEAD)" "$@" \
        --target "$target" -t "$tag" -f "$df" "$ctx" > "$D/build-$target.log" 2>&1 || {
        tail -40 "$D/build-$target.log" >&2
        die "docker build of $target failed (log: $D/build-$target.log)"
    }
}

for t in "${TARGETS[@]}"; do
    case "$t" in
    toolchain) build toolchain cartesi/machine-emulator:toolchain ;;
    emulator)
        # same as `make build-emulator-image` (debug=no coverage=no threads=yes sanitize=no), final stage
        build runtime cartesi/machine-emulator:devel
        ;;
    uarch) build uarch-rebuild audit-harness/uarch-rebuild:latest ;;
    *) die "unknown target $t" ;;
    esac
done
