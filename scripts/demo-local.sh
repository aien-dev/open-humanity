#!/usr/bin/env bash
# Volunteer compute v0 on one machine.
#
# For each seed: start oh-coordinator and three oh-volunteer processes on
# loopback for ROUNDS rounds, then run the single-process baseline
# (oh-coordinator --baseline: same corpus, same shards, same total steps, no
# compression, no averaging). Prints final held-out bits per byte for both,
# then the mean and spread over the seeds.
#
# Corpus: the repository LICENSE file (fixed text, so runs repeat).
# Settings can be changed through the environment, for example:
#   ROUNDS=10 STEPS=500 DIM=32 SEEDS="1 2 3" scripts/demo-local.sh
# KEEP is the share of each update a volunteer keeps (oh-volunteer --keep);
# OUTER_LR scales the mean of the accepted updates (oh-coordinator --outer-lr).
# Set VOLUNTEER_VAULT_KEYS to three distinct atlas-vault entry names whose
# 32-byte identity seeds have already been created on the volunteer hosts.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ROUNDS="${ROUNDS:-10}"
STEPS="${STEPS:-500}"
DIM="${DIM:-32}"
SEEDS="${SEEDS:-1 2 3}"
KEEP="${KEEP:-0.2}"
OUTER_LR="${OUTER_LR:-1}"
BASE_PORT="${BASE_PORT:-18100}"
VOLUNTEERS=3
read -r -a VAULT_KEYS <<< "${VOLUNTEER_VAULT_KEYS:-}"
if [ "${#VAULT_KEYS[@]}" -ne "$VOLUNTEERS" ]; then
    echo "Set VOLUNTEER_VAULT_KEYS to $VOLUNTEERS distinct atlas-vault entry names" >&2
    exit 2
fi

# Set LOG_DIR to keep every process log; otherwise logs go to a temporary
# directory that is removed on exit.
if [ -n "${LOG_DIR:-}" ]; then
    mkdir -p "$LOG_DIR"
    WORK="$(cd "$LOG_DIR" && pwd)"
else
    WORK="$(mktemp -d)"
fi
cleanup() {
    local pids
    pids="$(jobs -p)"
    if [ -n "$pids" ]; then kill $pids 2>/dev/null || true; fi
    if [ -z "${LOG_DIR:-}" ]; then rm -rf "$WORK"; fi
}
trap cleanup EXIT

echo "Building release binaries..."
cargo build --release --quiet -p oh-coordinator -p oh-volunteer --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/release"
approved=()
for name in "${VAULT_KEYS[@]}"; do
    line="$("$BIN/oh-volunteer" --print-key --key-from-vault "$name")"
    approved+=(--allow-volunteer "${line#volunteer key }")
done

CORPUS="$ROOT/LICENSE"
echo "Corpus: LICENSE, $(wc -c < "$CORPUS") bytes, sha256 $(sha256sum "$CORPUS" | cut -c1-16)..."
echo "Settings: rounds=$ROUNDS volunteers=$VOLUNTEERS steps=$STEPS dim=$DIM seeds=\"$SEEDS\" keep=$KEEP outer_lr=$OUTER_LR"
echo

# Prints the key from the coordinator's "coordinator key <hex>" line,
# waiting up to 30 seconds for it to appear in log $1 (process $2).
wait_for_key() {
    local tries=0 key=""
    while [ -z "$key" ]; do
        key="$(sed -n 's/^coordinator key \([0-9a-f]\{64\}\)$/\1/p' "$1" 2>/dev/null | head -n 1)"
        if [ -n "$key" ]; then break; fi
        if ! kill -0 "$2" 2>/dev/null || [ "$tries" -ge 300 ]; then
            echo "The coordinator did not start:" >&2
            cat "$1" >&2
            exit 1
        fi
        tries=$((tries + 1))
        sleep 0.1
    done
    echo "$key"
}

common=(--corpus "$CORPUS" --rounds "$ROUNDS" --volunteers-per-round "$VOLUNTEERS"
        --steps "$STEPS" --dim "$DIM")
dist_results=()
base_results=()

for seed in $SEEDS; do
    port=$((BASE_PORT + seed))
    coord_log="$WORK/coordinator-$seed.log"
    "$BIN/oh-coordinator" "${common[@]}" "${approved[@]}" --seed "$seed" --outer-lr "$OUTER_LR" \
        --listen "127.0.0.1:$port" --ledger "$WORK/ledger-$seed.jsonl" > "$coord_log" 2>&1 &
    coord_pid=$!
    # Volunteers pin the key the coordinator prints, so the encrypted link
    # only opens to this coordinator.
    key="$(wait_for_key "$coord_log" "$coord_pid")"

    vol_pids=()
    for i in $(seq 1 "$VOLUNTEERS"); do
        "$BIN/oh-volunteer" --coordinator "127.0.0.1:$port" --rounds "$ROUNDS" \
            --key-from-vault "${VAULT_KEYS[i-1]}" --seed $((seed + i)) \
            --coordinator-key "$key" --keep "$KEEP" \
            > "$WORK/volunteer-$seed-$i.log" 2>&1 &
        vol_pids+=($!)
    done
    for pid in "${vol_pids[@]}"; do wait "$pid"; done
    wait "$coord_pid"

    base_log="$WORK/baseline-$seed.log"
    "$BIN/oh-coordinator" "${common[@]}" --seed "$seed" --baseline > "$base_log" 2>&1

    start=$(grep '^start heldout_bpb=' "$coord_log" | cut -d= -f2)
    dist=$(grep '^final_heldout_bpb=' "$coord_log" | cut -d= -f2)
    base=$(grep '^final_heldout_bpb=' "$base_log" | cut -d= -f2)
    applied=$(grep -c 'applied=yes' "$coord_log" || true)
    accepted=$(cat "$WORK"/volunteer-"$seed"-*.log | grep -c 'accepted' || true)
    dist_results+=("$dist")
    base_results+=("$base")

    echo "Seed $seed: start $start bits/byte; volunteers $dist; baseline $base"
    echo "  rounds applied: $applied of $ROUNDS; updates accepted: $accepted of $((ROUNDS * VOLUNTEERS))"
    echo "  volunteer 1 said: $(tail -n 1 "$WORK/volunteer-$seed-1.log")"
done

# Mean and sample standard deviation of the arguments.
stats() {
    printf '%s\n' "$@" | awk '{ s += $1; q += $1 * $1; n++ }
        END { m = s / n; v = (n > 1) ? (q - n * m * m) / (n - 1) : 0; if (v < 0) v = 0;
              printf "mean %.4f, spread (sample std dev) %.4f, n %d", m, sqrt(v), n }'
}

echo
echo "Final held-out bits per byte (lower is better):"
echo "  $VOLUNTEERS volunteers over loopback: $(stats "${dist_results[@]}")"
echo "  single-process baseline:    $(stats "${base_results[@]}")"
