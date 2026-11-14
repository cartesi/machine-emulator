#!/bin/bash
# R2-DFINPUTCOUNT-2: the PRT player (doc/recipes/crisium.lua + prt-epoch.lua) fetches epoch 0's InputAdded
# logs only from the DaveConsensus deployment block, but the DaveConsensus constructor seals into epoch 0
# every input the application already had. When those inputs are in earlier blocks, the player raises
# "sealed input count mismatch" and every relaunch fails the same way.
#
# On a private anvil with the pinned Dave contracts (recipe build, work/dave/patched; the DaveConsensus
# constructor is identical in the released build), it deploys, with documented permissionless entry points:
#   - an Application through ApplicationFactory.newApplication whose outputs Merkle root validator is the
#     (precomputed) address of a DaveConsensus the deployer creates later;
#   - two inputs to it through InputBox.addInput, from another account, in blocks before the consensus;
#   - the DaveConsensus (EpochSealed(0, lower 0, upper 2) in its constructor).
# A control application has the same shape, except that its two inputs are mined in the consensus's own
# deployment block. Then it runs the real crisium.lua (sentinel mode: honest claims, no keystore) on each
# application, with epoch 0's checkpoint made from the harness bare-metal rolling template.
#
# Requirement (THREAT_MODEL.md R4): "It assigns inputs to epochs exactly as the referee does, including the
# input limit per epoch (A3)"; section 8 Critical: "A crash ... caused by data from other parties that the
# honest operator must process". Pass (exit 0): crisium's status reports epoch 0 sealed with the 2 inputs
# the consensus assigned to it. Fail (exit 1): crisium dies on its input-assignment check, and again after a
# relaunch. Exit 2: setup failure, including the control not reaching epoch 0 sealed with 2 inputs.
set -uo pipefail
: "${REPO:?run through bugs/run.sh}"
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

setup_error() {
    echo "HARNESS ERROR: $*" >&2
    exit 2
}

DAVE=${DAVE_DIR:-$HARNESS_WORK/dave/patched}
ROLLUPS_OUT=$DAVE/cartesi-rollups/contracts/out
PRT_OUT=$DAVE/prt/contracts/out
TEMPLATE=$HARNESS_CONFIGS/baremetal-template/machine
[ -f "$ROLLUPS_OUT/DaveConsensus.sol/DaveConsensus.json" ] || setup_error "Dave not built at $DAVE (bugs/harness/chain/build-dave.sh)"
[ -d "$TEMPLATE" ] || setup_error "missing $TEMPLATE (bugs/harness/configs/make-configs.sh)"
command -v anvil > /dev/null && command -v cast > /dev/null && command -v jq > /dev/null || setup_error "anvil, cast or jq missing"

# Premise: the pinned DaveConsensus seals epoch 0 in its constructor with every pending input.
CSRC=$DAVE/cartesi-rollups/contracts/src/DaveConsensus.sol
grep -q 'uint256 inputIndexUpperBound = _nextInputIndexUpperBound(0);' "$CSRC" \
    && grep -q 'emit EpochSealed(0, 0, inputIndexUpperBound' "$CSRC" \
    && grep -q 'uint256 immutable _DEPLOYMENT_BLOCK_NUMBER = block.number;' "$CSRC" \
    || setup_error "pinned DaveConsensus no longer seals epoch 0 with the pending inputs in its constructor"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/r2-dfinputcount-2.XXXXXX") || setup_error "mktemp"
ANVIL_PID=
PIDS=()
cleanup() {
    for p in "${PIDS[@]}"; do kill -KILL -- "-$p" 2> /dev/null; done
    [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2> /dev/null && wait "$ANVIL_PID" 2> /dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# A private chain on a free port (never 8545/8546), with recipe parameters and FIFO ordering so that
# transactions mined together keep their send order.
PORT=
for p in $(seq 18640 18720); do
    if ! (exec 3<> "/dev/tcp/127.0.0.1/$p") 2> /dev/null; then PORT=$p && break; fi
done
[ -n "$PORT" ] || setup_error "no free port"
RPC=http://127.0.0.1:$PORT
anvil --host 127.0.0.1 --port "$PORT" --accounts 10 --balance 10000 --hardfork prague --timestamp 1780000000 \
    --prune-history 256 --order fifo > "$TMP/anvil.log" 2>&1 &
ANVIL_PID=$!
for _ in $(seq 1 100); do cast block-number --rpc-url "$RPC" > /dev/null 2>&1 && break; sleep 0.1; done
cast block-number --rpc-url "$RPC" > /dev/null 2>&1 || setup_error "anvil did not start"

DEPLOYER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 # anvil account 0: deploys the application and consensus
SENDER=0x70997970C51812dc3A010C7d01b50e0d17dc79C8   # anvil account 1: an input sender (untrusted)
ZERO=0x0000000000000000000000000000000000000000
TEMPLATE_HASH=$(tr -d ' \n' < "$HARNESS_CONFIGS/baremetal-template/root-hash.txt")

send() { # from, to, sig, args... -> receipt JSON
    local from=$1
    shift
    cast send --unlocked --from "$from" --rpc-url "$RPC" --json "$@"
}
deploy() { # artifact-dir name [constructor-sig args...] -> address
    local dir=$1 name=$2
    shift 2
    local code
    code=$(jq -r .bytecode.object "$dir/$name.sol/$name.json") || return 1
    if [ $# -gt 0 ]; then
        local sig=$1
        shift
        code=$code$(cast abi-encode "f($sig)" "$@" | sed 's/^0x//') || return 1
    fi
    send "$DEPLOYER" --create "$code" | jq -er '.contractAddress' || return 1
}
lower() { tr 'A-F' 'a-f'; }

echo "== deploying the pinned Dave contracts on $RPC ($DAVE)"
IMPL=$(deploy "$PRT_OUT" Tournament) || setup_error "deploy Tournament"
STF=$(deploy "$PRT_OUT" CartesiStateTransition) || setup_error "deploy CartesiStateTransition"
PROVIDER=$(deploy "$PRT_OUT" CanonicalTournamentParametersProvider "uint64,uint64,uint64" 1000 10000 2) || setup_error "deploy provider"
FACTORY=$(deploy "$PRT_OUT" MultiLevelTournamentFactory "address,address,address" "$IMPL" "$PROVIDER" "$STF") || setup_error "deploy factory"
INPUT_BOX=$(deploy "$ROLLUPS_OUT" InputBox) || setup_error "deploy InputBox"
APP_FACTORY=$(deploy "$ROLLUPS_OUT" ApplicationFactory "address" "$ZERO") || setup_error "deploy ApplicationFactory"

NEW_APP_SIG="newApplication(address,address,bytes32,address,(address,uint8,uint8,uint64,address))"
CONSENSUS_SIG="address,address,address,bytes32,uint256,address,address[]"
CONSENSUS_CODE=$(jq -r .bytecode.object "$ROLLUPS_OUT/DaveConsensus.sol/DaveConsensus.json")

# Creates an application whose validator is the address of the deployer's next-but-one contract creation,
# the DaveConsensus created later. Prints the application and the predicted consensus address.
new_application() {
    local nonce consensus app
    nonce=$(cast nonce "$DEPLOYER" --rpc-url "$RPC") || return 1
    consensus=$(cast compute-address "$DEPLOYER" --nonce $((nonce + 1)) | awk '{print $NF}') || return 1
    local args=("$consensus" "$DEPLOYER" "$TEMPLATE_HASH" "$INPUT_BOX" "($DEPLOYER,0,0,0,$ZERO)")
    app=$(cast call --from "$DEPLOYER" --rpc-url "$RPC" "$APP_FACTORY" "$NEW_APP_SIG(address)" "${args[@]}") || return 1
    send "$DEPLOYER" "$APP_FACTORY" "$NEW_APP_SIG" "${args[@]}" | jq -e '.status == "0x1"' > /dev/null || return 1
    echo "$app $consensus"
}
consensus_create_code() { # app
    echo "$CONSENSUS_CODE$(cast abi-encode "f($CONSENSUS_SIG)" "$INPUT_BOX" "$1" "$FACTORY" "$TEMPLATE_HASH" 10 "$DEPLOYER" "[]" | sed 's/^0x//')"
}
block_of() { cast receipt --rpc-url "$RPC" --json "$1" | jq -r '.blockNumber' | xargs printf '%d'; }
add_input_payload() { cast --from-utf8 "$1"; }

# Scenario A (the defect): inputs in blocks before the consensus deployment.
read -r APP_A CONS_A <<< "$(new_application)" || setup_error "newApplication A"
[ -n "${CONS_A:-}" ] || setup_error "newApplication A"
cast rpc --rpc-url "$RPC" anvil_mine 0x2 > /dev/null
TXA0=$(send "$SENDER" "$INPUT_BOX" "addInput(address,bytes)" "$APP_A" "$(add_input_payload input-0)" | jq -r .transactionHash)
TXA1=$(send "$SENDER" "$INPUT_BOX" "addInput(address,bytes)" "$APP_A" "$(add_input_payload input-1)" | jq -r .transactionHash)
cast rpc --rpc-url "$RPC" anvil_mine 0x2 > /dev/null
GOT_A=$(send "$DEPLOYER" --create "$(consensus_create_code "$APP_A")" | jq -r .contractAddress)
[ "$(echo "$GOT_A" | lower)" = "$(echo "$CONS_A" | lower)" ] || setup_error "consensus A at $GOT_A, expected $CONS_A"

# Scenario B (control): the same shape, with both inputs mined in the consensus's deployment block.
read -r APP_B CONS_B <<< "$(new_application)" || setup_error "newApplication B"
[ -n "${CONS_B:-}" ] || setup_error "newApplication B"
cast rpc --rpc-url "$RPC" anvil_mine 0x2 > /dev/null
cast rpc --rpc-url "$RPC" evm_setAutomine false > /dev/null
SN=$(cast nonce "$SENDER" --rpc-url "$RPC")
DN=$(cast nonce "$DEPLOYER" --rpc-url "$RPC")
TXB0=$(cast send --async --nonce "$SN" --unlocked --from "$SENDER" --rpc-url "$RPC" "$INPUT_BOX" "addInput(address,bytes)" "$APP_B" "$(add_input_payload input-0)")
TXB1=$(cast send --async --nonce $((SN + 1)) --unlocked --from "$SENDER" --rpc-url "$RPC" "$INPUT_BOX" "addInput(address,bytes)" "$APP_B" "$(add_input_payload input-1)")
TXBC=$(cast send --async --nonce "$DN" --unlocked --from "$DEPLOYER" --rpc-url "$RPC" --create "$(consensus_create_code "$APP_B")")
[ -n "$TXB0" ] && [ -n "$TXB1" ] && [ -n "$TXBC" ] || setup_error "cannot send scenario B transactions"
cast rpc --rpc-url "$RPC" evm_mine > /dev/null
cast rpc --rpc-url "$RPC" evm_setAutomine true > /dev/null
GOT_B=$(cast receipt --rpc-url "$RPC" --json "$TXBC" | jq -r .contractAddress)
[ "$(echo "$GOT_B" | lower)" = "$(echo "$CONS_B" | lower)" ] || setup_error "consensus B at $GOT_B, expected $CONS_B"
cast rpc --rpc-url "$RPC" anvil_mine 0x2 > /dev/null

# Premises read from the chain: the application names the consensus, the consensus names the
# application, epoch 0 is sealed as [0, 2), and where the inputs and the deployment block are.
EPOCH_SEALED_TOPIC=$(cast keccak "EpochSealed(uint256,uint256,uint256,bytes32,bytes32,address)")
for S in A B; do
    APP_VAR=APP_$S CONS_VAR=CONS_$S
    app=$(echo "${!APP_VAR}" | lower) cons=$(echo "${!CONS_VAR}" | lower)
    v=$(cast call --rpc-url "$RPC" "$app" "getOutputsMerkleRootValidator()(address)" | lower)
    [ "$v" = "$cons" ] || setup_error "application $S validator $v != $cons"
    a=$(cast call --rpc-url "$RPC" "$cons" "getApplicationContract()(address)" | lower)
    [ "$a" = "$app" ] || setup_error "consensus $S serves $a"
    seal=$(cast logs --rpc-url "$RPC" --json --from-block 0 --address "$cons" "$EPOCH_SEALED_TOPIC" | jq -r '.[0].data')
    upper=$(cast abi-decode --input "f(uint256,uint256,bytes32,bytes32,address)" "$seal" | sed -n 2p | awk '{print $1}')
    [ "$upper" = 2 ] || setup_error "consensus $S sealed epoch 0 with upper bound $upper, expected 2"
    dep=$(cast call --rpc-url "$RPC" "$cons" "getDeploymentBlockNumber()(uint256)" | awk '{print $1}')
    eval "DEP_$S=$dep"
done
echo "scenario A: app $APP_A, consensus $CONS_A deployed at block $DEP_A; inputs 0,1 at blocks $(block_of "$TXA0"),$(block_of "$TXA1"); EpochSealed(0, 0, 2)"
echo "scenario B: app $APP_B, consensus $CONS_B deployed at block $DEP_B; inputs 0,1 at blocks $(block_of "$TXB0"),$(block_of "$TXB1"); EpochSealed(0, 0, 2)  [control]"
[ "$(block_of "$TXA1")" -lt "$DEP_A" ] || setup_error "scenario A inputs are not before the consensus deployment"
[ "$(block_of "$TXB0")" = "$DEP_B" ] && [ "$(block_of "$TXB1")" = "$DEP_B" ] || setup_error "scenario B inputs not in the deployment block"

# Runs crisium.lua as a sentinel on an application until its status reports epoch 0 sealed or it exits.
# Prints "sealed <inputs>", "exited <status>" or "timeout"; its log is $TMP/<name>/log.txt.
run_crisium() { # name app
    local name=$1 app=$2 dir=$TMP/$1
    mkdir -p "$dir/state" "$dir/checkpoints"
    local hash
    hash=$(cd "$dir" && lua5.4 "$HERE/make-checkpoint.lua" "$RPC" "$FACTORY" "$DAVE" "$TEMPLATE" "$dir/checkpoints/epoch-0" 2> "$dir/checkpoint.log") \
        || {
            cat "$dir/checkpoint.log" >&2
            return 1
        }
    [ "$hash" = "$(echo "$TEMPLATE_HASH" | lower)" ] || return 1
    rm -f "$dir/status.json"
    (cd "$dir" && exec setsid lua5.4 "$RECIPES_DIR/crisium.lua" --mode=sentinel --rpc="$RPC" --application="$app" \
        --state="$dir/state" --checkpoints="$dir/checkpoints" --dave="$DAVE" --label=sentinel \
        --input-policy=0 --dispute-policy=0 --poll-interval=0.2 --status-file="$dir/status.json" \
        >> "$dir/log.txt" 2>&1) &
    local pid=$!
    PIDS+=("$pid")
    local result=timeout
    for _ in $(seq 1 600); do
        if [ -f "$dir/status.json" ] && jq -e '.epochs["0"].sealed == true' "$dir/status.json" > /dev/null 2>&1; then
            result="sealed $(jq -r '.epochs["0"].inputs' "$dir/status.json")"
            break
        fi
        if ! kill -0 "$pid" 2> /dev/null; then
            wait "$pid"
            result="exited $?"
            break
        fi
        sleep 0.5
    done
    kill -KILL -- "-$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    echo "$result"
}

echo "== control: crisium on application B (inputs in the consensus deployment block)"
R_B=$(run_crisium B "$APP_B") || setup_error "cannot prepare crisium for B"
echo "control result: $R_B"
if [ "$R_B" != "sealed 2" ]; then
    tail -n 20 "$TMP/B/log.txt" >&2
    setup_error "control did not reach epoch 0 sealed with 2 inputs ($R_B)"
fi

echo "== crisium on application A (inputs before the consensus deployment), launch 1 and a relaunch"
VIOLATED=0
for launch in 1 2; do
    R_A=$(run_crisium A "$APP_A") || setup_error "cannot prepare crisium for A"
    err=$(grep -m1 -E '^lua5\.4: ' "$TMP/A/log.txt" | sed "s|$REPO/||")
    echo "launch $launch: $R_A${err:+; error: $err}"
    grep -E 'processed confirmed InputAdded' "$TMP/A/log.txt" | sed 's/^/  log: /'
    case "$R_A" in
    "sealed 2")
        echo "launch $launch: epoch 0 sealed with inputs 0 and 1"
        ;;
    "exited "*)
        if grep -qE 'sealed input count mismatch|input stream has a gap or duplicate' "$TMP/A/log.txt"; then
            VIOLATED=$((VIOLATED + 1))
        else
            tail -n 20 "$TMP/A/log.txt" >&2
            setup_error "crisium on A exited for another reason"
        fi
        ;;
    "sealed "*)
        VIOLATED=$((VIOLATED + 1))
        ;;
    *)
        tail -n 20 "$TMP/A/log.txt" >&2
        setup_error "crisium on A: $R_A"
        ;;
    esac
    mv "$TMP/A/log.txt" "$TMP/A/log-launch-$launch.txt"
done

if [ "$VIOLATED" -gt 0 ]; then
    echo "VIOLATED: R4 'It assigns inputs to epochs exactly as the referee does': the consensus sealed inputs [0, 2)" \
        "into epoch 0, but the player fetched epoch 0's InputAdded logs only from block $DEP_A (consensus deployment)" \
        "and died on every launch ($VIOLATED of 2) instead of delivering them" >&2
    exit 1
fi
echo "OK: R4: the player assigned the inputs the consensus sealed into epoch 0 to epoch 0" >&2
exit 0
