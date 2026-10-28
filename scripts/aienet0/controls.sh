#!/usr/bin/env bash
# Aienet-0 P0 job path: one verified run plus every negative control.
#
# usage: scripts/aienet0/controls.sh EVIDENCE_DIR
#
# The coordinator side (aienet0-run) runs here. The worker side
# (aienet0-serve) runs through $SERVE, a command prefix: the local binary for
# the same-host baseline, or "ssh macbook /Users/.../aienet0-serve" for the
# two-machine run. Every case records the exact commands, stdout, stderr and
# exit codes of both sides under EVIDENCE_DIR/<case>.*, and summary.tsv says
# whether each side exited and printed what the case requires. Exit 0 only
# when every case matches.
#
# Required environment:
#   RUN              path of aienet0-run
#   SERVE            command prefix that runs aienet0-serve
#   LISTEN           coordinator listen address (e.g. 0.0.0.0:47130)
#   CONNECT          address the worker dials
#   KEYS PINS OUT    coordinator key dir, pin dir, output dir
#   ROGUE_KEYS       coordinator key dir with an identity the worker has not pinned
#   RECOMPUTE RECOMPUTE_SHA256   the Omega recompute binary and its pinned sha256
#   WKEYS WPINS WSTATE           worker key dir, pin dir, state dir (worker side paths)
#   WKEYS_ROGUE_EXEC             worker keys: pinned transport, unpinned executor key
#   WKEYS_ROGUE_TRANSPORT        worker keys: unpinned transport identity
# Optional: JOB (default "64 64 64 2716205057"), FILTER (only cases whose name matches).
set -u -o pipefail

# Settlement orchestration belongs to the authenticated protocols adapter.
# Keep the retired unsigned Core792 entrypoint from returning, including as
# a dangling link. The source-only mode also checks frozen before/mutant trees.
settlement_source_check() {
  local root=$1
  if [[ ! -d "$root" || ! -f "$root/Cargo.toml" || ! -f "$root/crates/oh-core/Cargo.toml" || ! -f "$root/scripts/aienet0/controls.sh" ]]; then
    echo "SETTLEMENT_SOURCE INVALID: not an Open Humanity source root: $root" >&2
    return 2
  fi
  if [[ -e "$root/scripts/aienet0/settle-run.sh" || -L "$root/scripts/aienet0/settle-run.sh" ]]; then
    echo "SETTLEMENT_SOURCE FAIL: retired unsigned entrypoint exists: $root/scripts/aienet0/settle-run.sh" >&2
    return 1
  fi
  echo 'SETTLEMENT_SOURCE PASS: no Open Humanity settlement entrypoint'
}
if [[ ${1:-} == --settlement-source ]]; then
  [[ $# == 2 ]] || { echo 'usage: controls.sh --settlement-source SOURCE_ROOT' >&2; exit 2; }
  settlement_source_check "$2"
  exit $?
fi
settlement_source_check "$(cd -- "$(dirname -- "$0")/../.." && pwd)" || exit 1
E=${1:?usage: controls.sh EVIDENCE_DIR}
mkdir -p "$E" "$OUT"
: "${RUN:?}" "${SERVE:?}" "${LISTEN:?}" "${CONNECT:?}" "${KEYS:?}" "${PINS:?}" "${ROGUE_KEYS:?}"
: "${RECOMPUTE:?}" "${RECOMPUTE_SHA256:?}" "${WKEYS:?}" "${WPINS:?}" "${WSTATE:?}"
: "${WKEYS_ROGUE_EXEC:?}" "${WKEYS_ROGUE_TRANSPORT:?}"
read -r M K N SEED <<<"${JOB:-64 64 64 2716205057}"
FILTER=${FILTER:-.}
printf 'case\twant_run\tgot_run\twant_serve\tgot_serve\twant_text\tverdict\n' >"$E/summary.tsv"
fail=0

# case NAME WANT_RUN_RC WANT_SERVE_RC WANT_TEXT "RUN EXTRA FLAGS" "SERVE EXTRA FLAGS"
# Extra flags come first, so they override the defaults after them.
case_() {
  local name=$1 wr=$2 ws=$3 text=$4 rx=$5 sx=$6
  [[ $name =~ $FILTER ]] || return 0
  local scmd="$SERVE $sx --connect $CONNECT --keys $WKEYS --pins $WPINS --state $WSTATE --connect-timeout 60"
  local rcmd="$RUN run $rx --listen $LISTEN --keys $KEYS --pins $PINS --out $OUT --recompute $RECOMPUTE --recompute-sha256 $RECOMPUTE_SHA256 --m $M --k $K --n $N --seed $SEED --accept-timeout 90"
  printf '%s\n%s\n' "serve: $scmd" "run:   $rcmd" >"$E/$name.cmd"
  $scmd >"$E/$name.serve.out" 2>"$E/$name.serve.err" </dev/null &
  local sp=$!
  $rcmd >"$E/$name.run.out" 2>"$E/$name.run.err"
  local rr=$?
  wait "$sp"
  local sr=$?
  local verdict=MATCH
  [[ $rr == "$wr" && $sr == "$ws" ]] || verdict=MISMATCH
  grep -q -- "$text" "$E/$name.run.out" "$E/$name.run.err" "$E/$name.serve.out" "$E/$name.serve.err" || verdict=MISMATCH
  [[ $verdict == MATCH ]] || fail=1
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$wr" "$rr" "$ws" "$sr" "$text" "$verdict" >>"$E/summary.tsv"
  echo "$name run=$rr serve=$sr $verdict :: $(head -n1 "$E/$name.run.out")"
}

case_ baseline 0 0 '^VERIFIED ' '' ''
dag=$(awk '/^VERIFIED /{print $2}' "$E/baseline.run.out" 2>/dev/null)
if [[ -n ${dag:-} && . =~ $FILTER ]]; then
  if "$RUN" check --bundle "$OUT/$dag.an0b" --mjr1 "$OUT/$dag.mjr1" --mjv "$OUT/$dag.mjv" \
    --keys "$KEYS" --pins "$PINS" >"$E/baseline.check.out" 2>&1; then
    echo "baseline.check rc=0 :: $(cat "$E/baseline.check.out")"
  else
    echo "baseline.check FAILED :: $(cat "$E/baseline.check.out")"
    fail=1
  fi
  (cd "$OUT" && sha256sum "$dag.an0b" "$dag.mjr1" "$dag.mjv") >"$E/baseline.artifacts.sha256"
fi
case_ wrong-output        13 0  'REFUSED AN0_RECOMPUTE_MISMATCH' '' '--misbehave wrong-output'
case_ tampered-receipt    12 0  'REFUSED MJB_'                   '' '--misbehave tamper-receipt'
case_ unpinned-executor   12 0  'REFUSED MJB_'                   '' "--keys $WKEYS_ROGUE_EXEC"
case_ not-allowlisted-op  11 11 'AN0_NOT_ALLOWLISTED'            '--op compile' ''
case_ not-allowlisted-kind 11 11 'AN0_NOT_ALLOWLISTED'           '--payload-kind 2' ''
case_ over-budget         11 11 'AN0_OVER_BUDGET'                '--m 512' ''
if [[ -n ${dag:-} ]]; then
  case_ replay            11 11 'AN0_REPLAY'                     "--resend $OUT/$dag.an0b" ''
  case_ retry-completed    0 0 '^VERIFIED '                      "--resend $OUT/$dag.an0b" '--retry'
  if [[ retry-completed =~ $FILTER ]]; then
    if grep -q 'executing dag_id=' "$E/retry-completed.serve.err" ||
       ! cmp -s "$E/baseline.run.out" "$E/retry-completed.run.out"; then
      echo 'retry-completed FAILED: recomputation or different receipt'
      fail=1
    fi
  fi
else
  printf 'replay\t11\tNOT_RUN\t11\tNOT_RUN\tbaseline produced no bundle\tMISMATCH\n' >>"$E/summary.tsv"; fail=1
fi
case_ wrong-coordinator-key 10 10 'WrongCoordinator\|is not the pinned key' "--keys $ROGUE_KEYS" ''
case_ unpinned-volunteer  10 10 'REFUSED TRANSPORT volunteer key' '' "--keys $WKEYS_ROGUE_TRANSPORT"
case_ unpinned-recompute  13 0  'REFUSED AN0_RECOMPUTE_UNPINNED' "--recompute-sha256 $(printf '0%.0s' {1..64})" ''
echo "summary: $E/summary.tsv fail=$fail"
exit $fail
