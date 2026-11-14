# Shared helpers for the audit harness scripts. Source it from bash:
#   . "$(dirname "$0")/../lib/common.sh"
# It defines REPO (repository root), HARNESS (bugs/harness), WORK (bugs/harness/work)
# and a few helpers. It does not change the shell options of the caller beyond what it says.

HARNESS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="$(cd "$HARNESS/../.." && pwd)"
WORK="$HARNESS/work"
mkdir -p "$WORK"

# Pinned external components (see AUDIT.md "Components").
MSS_REPO=https://github.com/cartesi/machine-solidity-step.git
MSS_TAG=v0.17.0-test1
MSS_COMMIT=6f91eb9b4fff915a19672f8fe14396b3836859c5
DAVE_REPO=https://github.com/cartesi/dave.git
DAVE_TAG=v3.0.0-alpha.7
DAVE_COMMIT=7eb6c6beb7c0beeb007399d88958d8af42da16e7
FOUNDRY_VERSION=v1.5.1 # same as doc/Dockerfile.prt (ghcr.io/foundry-rs/foundry:v1.5.1)
JUST_VERSION=1.57.0    # same as doc/Dockerfile.prt

log() { printf '[harness] %s\n' "$*" >&2; }
die() {
    printf '[harness] ERROR: %s\n' "$*" >&2
    exit "${DIE_STATUS:-1}"
}

# Start dockerd if the client cannot reach a daemon. Returns non-zero if docker is unusable.
ensure_docker() {
    command -v docker > /dev/null || return 1
    if docker info > /dev/null 2>&1; then return 0; fi
    if command -v dockerd > /dev/null && [ "$(id -u)" = 0 ]; then
        log "starting dockerd (log: /tmp/dockerd.log)"
        (nohup dockerd > /tmp/dockerd.log 2>&1 &)
        for _ in $(seq 1 30); do
            docker info > /dev/null 2>&1 && return 0
            sleep 1
        done
    fi
    return 1
}

# Arguments that let `docker build` RUN steps reach the network through the session's HTTPS proxy,
# if there is one. Plain HTTP (deb.debian.org) works without it.
docker_build_net_args() {
    local args=(--network host)
    if [ -n "${HTTPS_PROXY:-}" ]; then
        args+=(--build-arg "https_proxy=$HTTPS_PROXY" --build-arg "HTTPS_PROXY=$HTTPS_PROXY")
    fi
    printf '%s\n' "${args[@]}"
}

# A directory holding the proxy CA as a .crt (or nothing), for a `--build-context hostca=<dir>`
# that derived Dockerfiles copy into /usr/local/share/ca-certificates before ca-certificates is set up.
hostca_dir() {
    local d="$WORK/hostca"
    mkdir -p "$d"
    rm -f "$d"/*.crt
    if [ -f /root/.ccr/agent-proxy-ca.crt ]; then
        cp /root/.ccr/agent-proxy-ca.crt "$d/agent-proxy-ca.crt"
    fi
    echo "$d"
}

# sha256 check helper: verify_sha256 <file> <hex>
verify_sha256() {
    echo "$2  $1" | sha256sum -c --status - || {
        log "checksum mismatch for $1 (want $2, have $(sha256sum "$1" | cut -c1-64))"
        return 1
    }
}

# Read a variable from dependencies.lock (Make syntax VAR?=value, with $(VAR) references).
lock_var() {
    make -s -f - print-var VAR="$1" << EOF
include $REPO/dependencies.lock
print-var:
	@echo \$(\$(VAR))
EOF
}

# git clone of a tag into a fresh directory, verifying the commit.
# clone_at_tag <url> <tag> <commit> <dir>
clone_at_tag() {
    local url=$1 tag=$2 commit=$3 dir=$4
    if [ -d "$dir/.git" ] && [ "$(git -C "$dir" rev-parse HEAD 2> /dev/null)" = "$commit" ]; then
        return 0
    fi
    rm -rf "$dir"
    git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$tag" "$url" "$dir"
    local have
    have=$(git -C "$dir" rev-parse HEAD)
    [ "$have" = "$commit" ] || die "$url $tag is at $have, expected $commit"
}
