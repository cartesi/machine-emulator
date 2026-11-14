#!/bin/bash
# Installs a wrapper around the harness anvil that bounds the block states anvil dumps under ~/.foundry/anvil/tmp.
# Without it, a long or busy chain filled the disk (12 GB in 6 minutes during round 1). Idempotent.
# Override the bound with ANVIL_MAX_PERSISTED_STATES; pass --max-persisted-states or --prune-history yourself to opt out.
set -euo pipefail
B="$(cd "$(dirname "$0")" && pwd)/work/foundry/bin"
[ -x "$B/anvil.real" ] || mv "$B/anvil" "$B/anvil.real"
cat > "$B/anvil" <<'W'
#!/bin/bash
real="$(dirname "$(readlink -f "$0")")/anvil.real"
case " $* " in
  *" --max-persisted-states"*|*" --prune-history"*) exec "$real" "$@" ;;
  *) exec "$real" --max-persisted-states "${ANVIL_MAX_PERSISTED_STATES:-16}" "$@" ;;
esac
W
chmod +x "$B/anvil"
