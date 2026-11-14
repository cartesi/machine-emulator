#!/bin/bash
# Rebuilds spin-accept.bin from spin-accept.c with the shared bare-metal builder (pinned toolchain image).
set -euo pipefail
cd "$(dirname "$0")"
. ../env.sh
"$HARNESS/baremetal/build.sh" -o spin-accept.bin spin-accept.c
