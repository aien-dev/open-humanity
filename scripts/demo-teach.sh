#!/usr/bin/env bash
# Teaching mode on one machine: the local model writes text, the
# coordinator scores it in Turings.
#
# Starts oh-coordinator with one volunteer slot per round, then one
# `oh-volunteer teach` that asks the local chat server for BATCHES passages.
# Each passage goes through the Personal Data Firewall before it is sent.
# Prints each batch's score and the held-out bits per byte before and after.
#
# Needs a chat server on TEACHER (default 127.0.0.1:18091) that answers
# GET /v1/models. If none answers, the script says so and exits 0.
# This script never starts or stops that server.
#
# Corpus: the repository LICENSE file (fixed text, so runs repeat).
# Settings can be changed through the environment, for example:
#   BATCHES=4 MAX_TOKENS=128 scripts/demo-teach.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TEACHER="${TEACHER:-127.0.0.1:18091}"
BATCHES="${BATCHES:-2}"
MAX_TOKENS="${MAX_TOKENS:-256}"
# Each passage trains for one pass over its bytes, at most STEPS steps.
STEPS="${STEPS:-500}"
DIM="${DIM:-32}"
SEED="${SEED:-1}"
PORT="${PORT:-18120}"

if ! models="$(curl -s -m 10 "http://$TEACHER/v1/models")" || [ -z "$models" ]; then
    echo "No chat server answered at http://$TEACHER/v1/models, so there is no"
    echo "local teacher to ask. Start one (or set TEACHER=host:port) and rerun."
    exit 0
fi

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

CORPUS="$ROOT/LICENSE"
echo "Corpus: LICENSE, $(wc -c < "$CORPUS") bytes, sha256 $(sha256sum "$CORPUS" | cut -c1-16)..."
echo "Teacher: $TEACHER; settings: batches=$BATCHES max_tokens=$MAX_TOKENS steps=$STEPS dim=$DIM seed=$SEED"
echo

coord_log="$WORK/coordinator.log"
"$BIN/oh-coordinator" --corpus "$CORPUS" --rounds "$BATCHES" --volunteers-per-round 1 \
    --steps "$STEPS" --dim "$DIM" --seed "$SEED" --listen "127.0.0.1:$PORT" \
    --ledger "$WORK/ledger.jsonl" > "$coord_log" 2>&1 &
coord_pid=$!

# The volunteer pins the key the coordinator prints, so the encrypted link
# only opens to this coordinator. Wait up to 30 seconds for that line.
key=""
for _ in $(seq 1 300); do
    key="$(sed -n 's/^coordinator key \([0-9a-f]\{64\}\)$/\1/p' "$coord_log" | head -n 1)"
    if [ -n "$key" ] || ! kill -0 "$coord_pid" 2>/dev/null; then break; fi
    sleep 0.1
done
if [ -z "$key" ]; then
    echo "The coordinator did not start:"
    cat "$coord_log"
    exit 1
fi

vol_log="$WORK/volunteer.log"
"$BIN/oh-volunteer" teach --coordinator "127.0.0.1:$PORT" --teacher "$TEACHER" \
    --batches "$BATCHES" --max-tokens "$MAX_TOKENS" --seed "$SEED" \
    --coordinator-key "$key" > "$vol_log" 2>&1 &
vol_pid=$!

vol_status=0
wait "$vol_pid" || vol_status=$?
if [ "$vol_status" -ne 0 ]; then
    echo "The teaching volunteer stopped with an error:"
    cat "$vol_log"
    exit 1
fi
wait "$coord_pid"

echo "Volunteer said:"
sed 's/^/  /' "$vol_log"
echo "Coordinator scored:"
grep -E 'teaching|^round=' "$coord_log" | sed 's/^/  /'
echo
echo "Held-out bits per byte: start $(grep '^start heldout_bpb=' "$coord_log" | cut -d= -f2)," \
     "after teaching $(grep '^final_heldout_bpb=' "$coord_log" | cut -d= -f2)"
