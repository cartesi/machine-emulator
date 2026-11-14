#!/bin/bash
# Rebuilds Flood.bin (creation bytecode, hex) from Flood.sol with solc 0.8.30 (the solc of the harness's Dave build).
set -euo pipefail
cd "$(dirname "$0")"
SOLC=${SOLC:-$HOME/.local/share/svm/0.8.30/solc-0.8.30}
"$SOLC" --optimize --bin Flood.sol | awk '/^Binary:/{getline; print}' > Flood.bin
