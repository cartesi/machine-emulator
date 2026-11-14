#!/bin/bash
# Kill (-9) and restart the honest PRT player of doc/recipes from its stored state, and check that it resumes and
# the demo still settles. The player is doc/recipes/crisium.lua under prt-supervise.sh, which relaunches it with
# the same --state directory (players/honest/) after it dies; the orchestrator is doc/recipes/prt-demo.lua.
#
#   run.sh fixed  [story]          the recipe's own restart points: PRT_TEST_RESTART=yes (kills at: after an input,
#                                  after the seal, during a bisection, after a uarch claim, before staging, after a
#                                  removal); needs the story mode (opponents), so `story` is forced
#   run.sh random [smoke|story]    random points: an OUT-OF-TREE COPY of prt-demo.lua (work/player-restart/) with a
#                                  hook that, at the start of each orchestration wait, kills the honest player with
#                                  probability RESTART_PROBABILITY (default 0.15), at most RESTART_COUNT times
#                                  (default 3), seeded by RESTART_SEED (default: time); the hook uses the same
#                                  bookkeeping as the recipe's restart_honest (killed pid, status file removed)
#
# Exit 0 if the demo settles (prt-demo.lua's assertions hold) and, in random mode, at least one kill happened;
# 1 if the demo fails after kills; 2 on harness errors. Logs: work/player-restart/<mode>-<seed>.log and the run
# directory under work/prt-runs.
set -uo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
export PRT_VARIANT=patched
. "$HARNESS/chain/env.sh"
MODE=${1:-random}
DEMO_MODE=${2:-smoke}
P="$WORK/player-restart"
mkdir -p "$P"
[ -d "$PRT_DAVE_DIR/prt/contracts/out" ] || DIE_STATUS=2 die "Dave patched not built (chain/build-dave.sh patched)"
export LUA_PATH_5_4="$RECIPES_DIR/?.lua;$LUA_PATH_5_4"
# doc/recipes/prt-demo.sh starts anvil on 8545 and silently uses whatever already answers there
if [ -z "${PRT_RPC_URL:-}" ] && cast block-number --rpc-url http://127.0.0.1:8545 > /dev/null 2>&1; then
    DIE_STATUS=2 die "something already answers on 127.0.0.1:8545 (stale anvil?); stop it first"
fi
# reflink filesystem for the players' machine clones (see chain/reflink-fs.sh); without it runs need far more disk
[ "$PRT_OUTPUT_DIR" != "$WORK/prt-runs" ] || "$HARNESS/chain/reflink-fs.sh" || log "WARNING: no reflink filesystem at $PRT_OUTPUT_DIR (every machine clone is a full copy)"

# prt-demo.sh leaves its anvil running at exit on the host (it kills the subshell of run_anvil); stop it
stop_recipe_anvil() { pkill -f '^anvil --host 127.0.0.1 --port 8545 --accounts 10 --balance 10000 .* --silent$' 2> /dev/null || true; }
trap stop_recipe_anvil EXIT

case "$MODE" in
fixed)
    log "fixed restart points (PRT_TEST_RESTART=yes, story)"
    LOGF="$P/fixed.log"
    PRT_TEST_RESTART=yes bash "$RECIPES_DIR/prt-demo.sh" story > "$LOGF" 2>&1
    rc=$?
    kills=$(grep -c 'Killed the honest player' "$LOGF")
    ;;
random)
    SEED=${RESTART_SEED:-$(date +%s)}
    export RESTART_SEED=$SEED RESTART_COUNT=${RESTART_COUNT:-3} RESTART_PROBABILITY=${RESTART_PROBABILITY:-0.15}
    C="$P/recipe-copy"
    rm -rf "$C"
    mkdir -p "$C"
    # copy of prt-demo.lua with the hook; every module still comes from doc/recipes (RECIPES_DIR)
    awk '
        /^local function await_players\(\)$/ && !a { print "local harness_random_restart -- [audit harness]"; a = 1 }
        { print }
        /^local function await_players\(\)$/ && !b { print "    if harness_random_restart then harness_random_restart() end -- [audit harness]"; b = 1 }
        /^local function restart_honest\(point\)$/ { in_rh = 1 }
        in_rh && /^end$/ {
            in_rh = 0
            print "-- [audit harness] random restarts of the honest player (see bugs/harness/player-restart/run.sh)"
            print "math.randomseed(tonumber(os.getenv(\"RESTART_SEED\") or \"1\"))"
            print "local harness_kills_left = tonumber(os.getenv(\"RESTART_COUNT\") or \"3\")"
            print "local harness_probability = tonumber(os.getenv(\"RESTART_PROBABILITY\") or \"0.15\")"
            print "harness_random_restart = function()"
            print "    if harness_kills_left <= 0 or math.random() >= harness_probability then return end"
            print "    local honest = players[1]"
            print "    local pid = read_pid(honest)"
            print "    if not pid or pid == killed[honest.label] then return end"
            print "    command.run({ \"kill\", \"-9\", pid })"
            print "    killed[honest.label], pids[honest.label] = pid, nil"
            print "    if fs.exists(get_status_path(honest)) then fs.remove_file(get_status_path(honest)) end"
            print "    harness_kills_left = harness_kills_left - 1"
            print "    io.stderr:write(\"[harness] Killed the honest player at a random point (pid \", pid, \").\\n\")"
            print "end"
        }
    ' "$RECIPES_DIR/prt-demo.lua" > "$C/prt-demo.lua"
    n=$(grep -c '\[audit harness\]' "$C/prt-demo.lua")
    [ "$n" -ge 3 ] || DIE_STATUS=2 die "could not insert the restart hook into the prt-demo.lua copy ($n markers)"
    # copy of prt-demo.sh that runs the patched orchestrator
    sed "s|lua5.4 \"\$RECIPES_DIR/prt-demo.lua\"|lua5.4 \"$C/prt-demo.lua\"|" "$RECIPES_DIR/prt-demo.sh" > "$C/prt-demo.sh"
    grep -q "$C/prt-demo.lua" "$C/prt-demo.sh" || DIE_STATUS=2 die "could not redirect prt-demo.sh"
    LOGF="$P/random-$SEED.log"
    log "random restarts: seed $SEED, count $RESTART_COUNT, probability $RESTART_PROBABILITY, demo $DEMO_MODE"
    bash "$C/prt-demo.sh" "$DEMO_MODE" > "$LOGF" 2>&1
    rc=$?
    kills=$(grep -c 'Killed the honest player' "$LOGF")
    ;;
*) DIE_STATUS=2 die "usage: run.sh fixed|random [smoke|story]" ;;
esac

run_dir=$(grep -o 'PRT chain artifacts: .*' "$LOGF" | head -1 | cut -d' ' -f4)
relaunches=0
[ -n "$run_dir" ] && relaunches=$(grep -c 'relaunching' "$run_dir/players/honest/log.txt" 2> /dev/null)
echo "mode=$MODE demo-exit=$rc kills=$kills supervisor-relaunches=$relaunches run=$run_dir log=$LOGF"
tail -5 "$LOGF"
if [ "$rc" != 0 ]; then
    grep -q 'Killed' "$LOGF" && exit 1
    exit 2
fi
if [ "$kills" -lt 1 ]; then
    echo "no kill happened (raise RESTART_PROBABILITY or change RESTART_SEED)" >&2
    exit 2
fi
exit 0
