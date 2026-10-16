#!/usr/bin/env bash
# Where does the volunteer run's gap to the single-process baseline come from?
#
# Runs oh-coordinator --baseline and then oh-coordinator --simulate (the
# volunteer protocol in one process, so runs repeat exactly) over SEEDS,
# changing one knob at a time from the v0 settings (keep 0.05, plain mean,
# per-update gate on, fixed shard order, 10 rounds x 500 steps): compression,
# outer learning rate, the per-update score gate, shard order, and rounds
# versus local steps at the same total steps. Prints one table row per
# setting with final held-out bits per byte for each seed, the mean, the
# sample standard deviation, and the mean count of accepted updates.
#
# Corpus: the repository LICENSE file. Total steps stay at
# ROUNDS x 3 volunteers x STEPS unless a row says otherwise.
#   SEEDS="1 2 3" scripts/volunteer-gap.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEEDS="${SEEDS:-1 2 3}"
ROUNDS="${ROUNDS:-10}"
STEPS="${STEPS:-500}"
DIM="${DIM:-32}"
VOLUNTEERS=3

echo "Building release binary..."
cargo build --release --quiet -p oh-coordinator --manifest-path "$ROOT/Cargo.toml"
BIN="$ROOT/target/release/oh-coordinator"
CORPUS="$ROOT/LICENSE"
echo "Corpus: LICENSE, $(wc -c < "$CORPUS") bytes, sha256 $(sha256sum "$CORPUS" | cut -c1-16)..."
echo "Defaults: rounds=$ROUNDS volunteers=$VOLUNTEERS steps=$STEPS dim=$DIM seeds=\"$SEEDS\""
echo

# The v0 volunteer protocol as shipped, spelled out so the rows do not move
# when a binary default changes.
V0=(--simulate --keep-fraction 0.05 --outer-lr 1 --shard-order fixed)

# Mean and sample standard deviation of the arguments.
stats() {
    printf '%s\n' "$@" | awk '{ s += $1; q += $1 * $1; n++ }
        END { m = s / n; v = (n > 1) ? (q - n * m * m) / (n - 1) : 0; if (v < 0) v = 0;
              printf "%.4f | %.4f", m, sqrt(v) }'
}

# row <label> <rounds> <steps> <mode flags...>
# Mode flags are --baseline or --simulate plus its knobs.
row() {
    local label="$1" rounds="$2" steps="$3"
    shift 3
    local finals=() accepted=() out
    for seed in $SEEDS; do
        out="$("$BIN" --corpus "$CORPUS" --rounds "$rounds" --volunteers-per-round "$VOLUNTEERS" \
            --steps "$steps" --dim "$DIM" --seed "$seed" "$@")"
        finals+=("$(grep '^final_heldout_bpb=' <<< "$out" | cut -d= -f2)")
        accepted+=("$(grep '^accepted_updates=' <<< "$out" | cut -d= -f2 | cut -d' ' -f1 || echo "-")")
    done
    local acc="-"
    if [ "${accepted[0]}" != "" ]; then
        acc="$(printf '%s\n' "${accepted[@]}" | awk '{ s += $1; n++ } END { if (n) printf "%.1f", s / n }')"
    fi
    printf '| %s | %s | %s | %s | %s |\n' "$label" "$(IFS=' / '; echo "${finals[*]}")" \
        "$(stats "${finals[@]}")" "$acc" "$*"
}

header() {
    echo
    echo "### $1"
    echo
    echo "| Setting | Seeds $(echo $SEEDS | sed 's/ / \/ /g') | Mean | Spread | Accepted of $((ROUNDS * VOLUNTEERS)) | Flags |"
    echo "|---|---|---|---|---|---|"
}

header "Reference"
row "baseline (one process, exact, sequential)" "$ROUNDS" "$STEPS" --baseline
row "simulate, v0 settings (keep 0.05, mean, gate on)" "$ROUNDS" "$STEPS" "${V0[@]}"

header "(a) Compression, everything else v0"
row "keep 0.05 (v0)" "$ROUNDS" "$STEPS" "${V0[@]}"
row "keep 0.10" "$ROUNDS" "$STEPS" "${V0[@]}" --keep-fraction 0.1
row "keep 0.20" "$ROUNDS" "$STEPS" "${V0[@]}" --keep-fraction 0.2
row "keep 0.50" "$ROUNDS" "$STEPS" "${V0[@]}" --keep-fraction 0.5
row "keep 1.00 (8-bit only, no top-k)" "$ROUNDS" "$STEPS" "${V0[@]}" --keep-fraction 1.0
row "no compression (exact f32)" "$ROUNDS" "$STEPS" "${V0[@]}" --no-compression

header "(b) Aggregation, everything else v0"
row "outer lr 1 (plain mean, v0)" "$ROUNDS" "$STEPS" "${V0[@]}"
row "outer lr 1.25" "$ROUNDS" "$STEPS" "${V0[@]}" --outer-lr 1.25
row "outer lr 1.5" "$ROUNDS" "$STEPS" "${V0[@]}" --outer-lr 1.5
row "outer lr 2" "$ROUNDS" "$STEPS" "${V0[@]}" --outer-lr 2
row "outer lr 3 (sum of 3)" "$ROUNDS" "$STEPS" "${V0[@]}" --outer-lr 3
row "outer lr 4" "$ROUNDS" "$STEPS" "${V0[@]}" --outer-lr 4
row "per-update gate off (mean of all 3)" "$ROUNDS" "$STEPS" "${V0[@]}" --no-update-gate
row "exact, gate off (plain mean of 3 exact deltas)" "$ROUNDS" "$STEPS" "${V0[@]}" --no-compression --no-update-gate
row "gate off, outer lr 3" "$ROUNDS" "$STEPS" "${V0[@]}" --no-update-gate --outer-lr 3

header "(c) Shard order, everything else v0"
row "fixed: shard i to volunteer i" "$ROUNDS" "$STEPS" "${V0[@]}"
row "rotate: shard i to volunteer (i + round) mod 3" "$ROUNDS" "$STEPS" "${V0[@]}" --shard-order rotate

header "(d) Rounds versus local steps, same total steps ($((ROUNDS * VOLUNTEERS * STEPS)))"
row "baseline 10 x 500" 10 500 --baseline
row "baseline 25 x 200" 25 200 --baseline
row "baseline 50 x 100" 50 100 --baseline
row "simulate 5 x 1000" 5 1000 "${V0[@]}"
row "simulate 10 x 500 (v0)" 10 500 "${V0[@]}"
row "simulate 25 x 200" 25 200 "${V0[@]}"
row "simulate 50 x 100" 50 100 "${V0[@]}"

header "Combinations"
row "exact, outer lr 3" "$ROUNDS" "$STEPS" "${V0[@]}" --no-compression --outer-lr 3
row "exact, gate off, outer lr 3" "$ROUNDS" "$STEPS" "${V0[@]}" --no-compression --no-update-gate --outer-lr 3
row "keep 0.05, outer lr 3, 50 x 100" 50 100 "${V0[@]}" --outer-lr 3
row "exact, outer lr 3, 50 x 100" 50 100 "${V0[@]}" --no-compression --outer-lr 3
row "keep 0.20, outer lr 3" "$ROUNDS" "$STEPS" "${V0[@]}" --keep-fraction 0.2 --outer-lr 3
