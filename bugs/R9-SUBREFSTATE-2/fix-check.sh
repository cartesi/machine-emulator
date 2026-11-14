#!/bin/bash
# Optional check of the test against a sketch of a fix (not run by bugs/run.sh). It copies
# doc/recipes to a temp directory, patches the copy so that
#   * game-transport.lua: a player that announces after admission closed is added to the audience of
#     every open first-valid request (and is sent it), and to the audience of every later
#     subscription request, i.e. claims stop being bound to the connections that posted them;
#   * prt.lua: the honest handlers answer "nothing" for a claim whose tree they do not hold (a late
#     player now also sees requests about other claims),
# and runs test.sh against the copy. Expected: exit 0 (the restarted player answers for its claim,
# builds its uarch claim, proves the transition and the honest claim wins).
#   . bugs/env.sh; bugs/R9-SUBREFSTATE-2/fix-check.sh
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${REPO:?source bugs/env.sh first}"
COPY=$(mktemp -d "${TMPDIR:-/tmp}/r9-subrefstate-2-fix.XXXXXX")
trap 'rm -rf "$COPY"' EXIT
cp "$REPO"/doc/recipes/*.lua "$COPY/"
python3 - "$COPY" << 'EOF'
import sys, os
d = sys.argv[1]
def patch(name, pairs):
    p = os.path.join(d, name)
    s = open(p).read()
    for old, new in pairs:
        assert old in s, (name, old)
        s = s.replace(old, new)
    open(p, "w").write(s)
patch("game-transport.lua", [
("""    local seen, list = {}, {}
    for _, hash in ipairs(subscriptions) do""",
"""    local seen, list = {}, {}
    for _, connection in ipairs(self.connections) do
        if connection.late and not connection.dead then
            seen[connection] = true
            list[#list + 1] = connection
        end
    end
    for _, hash in ipairs(subscriptions) do"""),
("""    queue_control(self, conns, future.event, arguments, future.id, future)
    return future""",
"""    future.line_arguments = arguments
    queue_control(self, conns, future.event, arguments, future.id, future)
    return future"""),
("""        connection.is_player = true""",
"""        connection.is_player = true
        if self.admission_closed then
            connection.late = true
            for entry in pairs(self.active) do
                if entry.kind == "request_first_valid" and entry.audience and entry.id
                    and not entry.closed and not entry.resolved then
                    entry.audience[connection] = true
                    entry.pending[connection] = true
                    local control = { pending = { [connection] = true }, replies = {}, future = entry }
                    self.controls[#self.controls + 1] = control
                    send_event(self, connection, control,
                        encode_event(self.protocol, entry.event, entry.line_arguments, entry.id, entry.block))
                end
            end
        end"""),
])
pairs = []
for sig in ["function event_handler.win_match_by_timeout(self, computation_hash)\n    local tree = self.trees[computation_hash]\n",
            "function event_handler.reveal_bisection(self, computation_hash, position, height, other_left_node)\n    local tree = self.trees[computation_hash]\n",
            "function event_handler.seal_divergence(self, computation_hash, position, other_left_node)\n    local tree = self.trees[computation_hash]\n"]:
    pairs.append((sig, sig + '    if not tree then return "nothing" end\n'))
patch("prt.lua", pairs)
EOF
export RECIPES_DIR="$COPY" LUA_PATH_5_4="$COPY/?.lua;$LUA_PATH_5_4"
cd "$HERE"
set +e
bash "$HERE/test.sh"
status=$?
echo "fix-check: test.sh against the patched copy exited $status (expected 0)"
exit "$status"
