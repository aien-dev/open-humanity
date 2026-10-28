#!/usr/bin/env bash
# Aienet-0 guard mutants for the open-humanity side of the P0 job path.
#
# usage: scripts/aienet0/mutants.sh EVIDENCE_DIR
#
# Each guard is the line right below a `// AN0-GUARD <name>` comment; it is
# disabled in a scratch copy of the
# workspace. The mutant is KILLED when `cargo test -p oh-core` fails or the
# same-host control that exercises the guard (scripts/aienet0/controls.sh,
# environment as documented there, minus RUN and SERVE) no longer matches.
# The unmutated tree must pass both first. Exit 0 only when that baseline
# passes and every mutant is killed.
set -u -o pipefail
E=${1:?usage: mutants.sh EVIDENCE_DIR}
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$E"
E=$(cd "$E" && pwd)
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$root/target/mutants}
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT

# name@file@guarded line (exact, trimmed)@replacement@control case
mutants=(
  "coordinator-pin@crates/oh-core/src/transport.rs@if theirs.identity() != expected {@if false {@wrong-coordinator-key"
  "volunteer-pin@crates/oh-core/src/transport.rs@if theirs.identity() != expected {@if false {@unpinned-volunteer"
  "carrier-bound@crates/oh-core/src/carrier.rs@if len < min || len > max {@if false {@baseline"
  "replay@crates/oh-volunteer/src/bin/aienet0-serve.rs@if !retry {@if false {@replay"
  "state-lock@crates/oh-volunteer/src/bin/aienet0-serve.rs@lock.try_lock().map_err(|e| Fail(15, format!(\"state lock: {e}\")))?;@let _ = &lock;@baseline"
  "state-read@crates/oh-volunteer/src/bin/aienet0-serve.rs@Err(e) => return Err(state_io(e)),@Err(_) => None,@baseline"
  "state-parse@crates/oh-volunteer/src/bin/aienet0-serve.rs@if text.is_empty() || !text.ends_with('\\n') {@if false {@baseline"
  "recovery@crates/oh-volunteer/src/bin/aienet0-serve.rs@Ok(Admission::Execute)@Ok(Admission::Replay)@baseline"
  "cached-result@crates/oh-volunteer/src/bin/aienet0-serve.rs@return Ok(Admission::Cached(*receipt));@return Ok(Admission::Execute);@retry-completed"
  "output-no-replace@crates/oh-coordinator/src/bin/aienet0-run.rs@fs::hard_link(&tmp, path).map_err(|e| {@fs::rename(&tmp, path).map_err(|e| {@baseline"
  "recompute-pin@crates/oh-coordinator/src/bin/aienet0-run.rs@if got_sha != want_sha.trim() {@if false {@unpinned-recompute"
)

# exercise TREE NAME FILTER -> 0 when unit tests and the control both pass.
# Sets `stage` to the step that failed: build (an invalid mutant, never a
# kill), tests or control.
exercise() {
  local tree=$1 name=$2 filter=$3
  stage=build
  (cd "$tree" && cargo build -q --release --bin aienet0-run --bin aienet0-serve &&
    cargo test -q -p oh-core -p oh-volunteer -p oh-coordinator --no-run) >"$E/$name.build.log" 2>&1 || return 1
  stage=tests
  (cd "$tree" && cargo test -q -p oh-core -p oh-volunteer -p oh-coordinator) >"$E/$name.test.log" 2>&1 || return 1
  stage=control
  local st
  st=$(mktemp -d)
  RUN=$CARGO_TARGET_DIR/release/aienet0-run SERVE=$CARGO_TARGET_DIR/release/aienet0-serve \
    OUT=$st/out WSTATE=$st/wstate FILTER="^(baseline|$filter)\$" \
    bash "$root/scripts/aienet0/controls.sh" "$E/$name.controls" >"$E/$name.controls.log" 2>&1
  local rc=$?
  rm -rf "$st"
  return $rc
}

copy() {
  rm -rf "$scratch/tree"
  mkdir -p "$scratch/tree"
  # -m: fresh mtimes, so cargo's fingerprints never reuse the previous mutant
  (cd "$root" && tar --exclude=./target --exclude=./.git -cf - .) | tar -m -xf - -C "$scratch/tree"
}

copy
if ! exercise "$scratch/tree" baseline 'baseline'; then
  echo "BASELINE FAIL (see $E/baseline.*)"
  exit 1
fi
echo "BASELINE PASS"
killed=0 survived=0
for m in "${mutants[@]}"; do
  IFS='@' read -r name file line repl filter <<<"$m"
  copy
  f=$scratch/tree/$file
  tag="// AN0-GUARD $name"
  n=$(grep -nxE "[[:space:]]*$tag" "$f" | cut -d: -f1)
  if [[ $(grep -cxE "[[:space:]]*$tag" "$f") != 1 ]] ||
    [[ $(sed -n "$((n + 1))p" "$f" | sed 's/^[[:space:]]*//') != "$line" ]]; then
    echo "MUTANT $name NOT_APPLIED (tag not found once, or the line below it is not the guard)"
    survived=$((survived + 1))
    continue
  fi
  awk -v n=$((n + 1)) -v r="$repl // MUTANT $name" \
    'NR == n { match($0, /^[[:space:]]*/); print substr($0, 1, RLENGTH) r; next } { print }' \
    "$f" >"$f.mut" && mv "$f.mut" "$f"
  sed -n "$((n + 1))p" "$f" >"$E/$name.diff"
  if exercise "$scratch/tree" "$name" "$filter"; then
    echo "MUTANT $name SURVIVED"
    survived=$((survived + 1))
  elif [[ $stage == build ]]; then
    echo "MUTANT $name INVALID (does not compile, see $name.build.log)"
    survived=$((survived + 1))
  else
    echo "MUTANT $name KILLED by $stage"
    killed=$((killed + 1))
  fi
done
echo "killed=$killed survived=$survived"
[[ $survived == 0 ]]
