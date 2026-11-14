#!/bin/bash
# Rebuilds guest.bin from guest.c with the harness bare-metal builder (pinned toolchain image, docker).
set -euo pipefail
cd "$(dirname "$0")"
. ../env.sh
"$HARNESS/baremetal/build.sh" -o guest.bin guest.c
