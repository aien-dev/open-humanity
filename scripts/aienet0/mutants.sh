#!/usr/bin/env bash
# Aienet-0 guard mutants. Usage: mutants.sh EVIDENCE_DIR | --self-test
# Only an exact test's designated semantic assertion can kill its mutant.
# Build/setup failures, missing tests and incomplete executions are INVALID.
set -u -o pipefail

classify_test() {
  local log=$1 test=$2 marker=$3 rc=$4
  awk -v test="$test" -v marker="AN0_SEMANTIC $marker" -v rc="$rc" '
    /^running 1 test$/ { running++ }
    /^test result:/ { summaries++ }
    /^test result: ok\. 1 passed; 0 failed; 0 ignored;/ { pass++ }
    /^test result: FAILED\. 0 passed; 1 failed; 0 ignored;/ { fail++ }
    $0 == "test " test " ... ok" { ok++ }
    $0 == "test " test " ... FAILED" { bad++ }
    /^thread .* panicked at / {
      panics++
      if (index($0, "thread " sprintf("%c",39) test sprintf("%c",39) " (")) targetpanic++
    }
    index($0, marker) { semantic++ }
    END {
      if (running == 1 && summaries == 1 && rc == 0 && pass == 1 && ok == 1 && panics == 0)
        print "SURVIVED"
      else if (running == 1 && summaries == 1 && rc == 101 && fail == 1 && bad == 1 &&
               panics == 1 && targetpanic == 1 && semantic >= 1)
        print "KILLED"
      else print "INVALID"
    }' "$log"
}

self_test() {
  local tmp expected got rc
  tmp=$(mktemp -d) || return 2
  for expected in KILLED SETUP TRUNCATED SIGNAL MISSING EXTRA SURVIVED; do
    rc=101
    {
      echo 'running 1 test'
      if [[ $expected == SURVIVED ]]; then
        rc=0
        echo 'test tests::guard ... ok'
        echo 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
      elif [[ $expected != MISSING ]]; then
        echo 'test tests::guard ... FAILED'
        echo "thread 'tests::guard' (123) panicked at guard.rs:1:1:"
        if [[ $expected == SETUP ]]; then echo 'socket setup: address already in use'; else echo 'AN0_SEMANTIC guard'; fi
        [[ $expected == EXTRA ]] && echo "thread 'tests::other' (124) panicked at other.rs:1:1:"
        [[ $expected != TRUNCATED ]] && echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s'
        [[ $expected == SIGNAL ]] && rc=137
      fi
    } >"$tmp/test.log"
    got=$(classify_test "$tmp/test.log" tests::guard guard "$rc")
    case $expected in KILLED|SURVIVED) ;; *) expected=INVALID ;; esac
    if [[ $got != "$expected" ]]; then
      echo "classifier FAIL expected=$expected got=$got"
      rm -rf "$tmp"; return 1
    fi
    echo "classifier $got MATCH"
  done
  rm -rf "$tmp"
}
if [[ ${1:-} == --self-test ]]; then self_test; exit $?; fi

E=${1:?usage: mutants.sh EVIDENCE_DIR}
root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$E" || exit 2
E=$(cd "$E" && pwd)
for tool in cargo rustc tar awk timeout; do
  if ! command -v "$tool" >/dev/null; then echo "BASELINE NOT_RUN missing $tool"; exit 2; fi
done
if [[ ! -x ${RECOMPUTE:-} || ! -f ${RECOMPUTE:-} ]]; then
  echo 'BASELINE NOT_RUN missing executable RECOMPUTE'; exit 2
fi
scratch=$(mktemp -d) || exit 2
trap 'rm -rf "$scratch"' EXIT
# Never share executables with another invocation, even if a cache was supplied.
export CARGO_TARGET_DIR=$scratch/target

# name@file@guarded line@replacement@package@target selector@test name
mutants=(
  'coordinator-pin@crates/oh-core/src/transport.rs@if theirs.identity() != expected {@if false {@oh-core@--lib@transport::tests::test_wrong_pinned_key_is_refused'
  'volunteer-pin@crates/oh-core/src/transport.rs@if theirs.identity() != expected {@if false {@oh-core@--lib@transport::tests::test_unpinned_volunteer_is_refused_before_the_coordinator_speaks'
  'carrier-bound@crates/oh-core/src/carrier.rs@if len < min || len > max {@if false {@oh-core@--lib@carrier::tests::unknown_tag_and_oversize_length_are_refused_before_the_body'
  'replay@crates/oh-volunteer/src/bin/aienet0-serve.rs@if !retry {@if false {@oh-volunteer@--bin aienet0-serve@tests::crash_recovery'
  'state-lock@crates/oh-volunteer/src/bin/aienet0-serve.rs@lock.try_lock().map_err(|e| Fail(15, format!("state lock: {e}")))?;@let _ = &lock;@oh-volunteer@--bin aienet0-serve@tests::crash_recovery'
  'state-read@crates/oh-volunteer/src/bin/aienet0-serve.rs@Err(e) => return Err(state_io(e)),@Err(_) => None,@oh-volunteer@--bin aienet0-serve@tests::seen_rejects_write_only_file'
  "state-parse@crates/oh-volunteer/src/bin/aienet0-serve.rs@if text.is_empty() || !text.ends_with('\\n') {@if false {@oh-volunteer@--bin aienet0-serve@tests::seen_rejects_corruption"
  'recovery@crates/oh-volunteer/src/bin/aienet0-serve.rs@Ok(Admission::Execute)@Ok(Admission::Replay)@oh-volunteer@--bin aienet0-serve@tests::crash_recovery'
  'cached-result@crates/oh-volunteer/src/bin/aienet0-serve.rs@return Ok(Admission::Cached(*receipt));@return Ok(Admission::Execute);@oh-volunteer@--bin aienet0-serve@tests::crash_recovery'
  'output-no-replace@crates/oh-coordinator/src/bin/aienet0-run.rs@fs::hard_link(&tmp, path).map_err(|e| {@fs::rename(&tmp, path).map_err(|e| {@oh-coordinator@--bin aienet0-run@tests::write_new_refuses_dangling_destination'
  'recompute-pin@crates/oh-coordinator/src/bin/aienet0-run.rs@if got_sha != want_sha.trim() {@if false {@oh-coordinator@--bin aienet0-run@tests::recompute_accepts_pinned_digest_and_refuses_wrong_pin'
  'recompute-deadline@crates/oh-coordinator/src/bin/aienet0-run.rs@if Instant::now() >= deadline {@if false {@oh-coordinator@--bin aienet0-run@tests::recompute_deadline_covers_output_and_exit'
  'recompute-stdin@crates/oh-coordinator/src/bin/aienet0-run.rs@Err(e) => return Err(failed(format!("stdin: {e}"))),@Err(_) => { sent = payload.len(); input_closed = true; },@oh-coordinator@--bin aienet0-run@tests::recompute_refuses_stdin_io_error'
)

copy() {
  rm -rf "$scratch/tree"
  mkdir -p "$scratch/tree" || return 2
  (cd "$root" && tar --exclude=./target --exclude=./.git -cf - .) | tar -m -xf - -C "$scratch/tree"
}
probe() {
  local name=$1 package=$2 selector=$3 test=$4
  local -a target
  read -r -a target <<<"$selector"
  (cd "$scratch/tree" && cargo test --locked -q -p "$package" "${target[@]}" --no-run) >"$E/$name.build.log" 2>&1 || { echo INVALID; return; }
  (cd "$scratch/tree" && timeout 60 cargo test --locked -q -p "$package" "${target[@]}" -- --exact "$test" --format pretty) >"$E/$name.test.log" 2>&1
  local rc=$?
  classify_test "$E/$name.test.log" "$test" "${name#control-}" "$rc"
}

copy || { echo 'BASELINE INVALID copy failed'; exit 2; }
(cd "$scratch/tree" && cargo build --locked -q --release --bin aienet0-run --bin aienet0-serve &&
  cargo test --locked -q --workspace) >"$E/baseline.build-test.log" 2>&1 || {
  echo 'BASELINE INVALID build/tests failed'; exit 2;
}
RUN=$CARGO_TARGET_DIR/release/aienet0-run SERVE=$CARGO_TARGET_DIR/release/aienet0-serve \
  OUT=$scratch/out WSTATE=$scratch/wstate FILTER=. \
  timeout 600 bash "$root/scripts/aienet0/controls.sh" "$E/baseline.controls" >"$E/baseline.controls.log" 2>&1 || {
  echo 'BASELINE INVALID controls/setup failed (not a mutant kill)'; exit 2;
}
echo 'BASELINE PASS'
killed=0 survived=0 invalid=0
for m in "${mutants[@]}"; do
  IFS='@' read -r name file line repl package selector test <<<"$m"
  copy || { echo "MUTANT $name INVALID copy failed"; invalid=$((invalid + 1)); continue; }
  # The precise oracle must execute successfully before guard removal.
  result=$(probe "control-$name" "$package" "$selector" "$test")
  if [[ $result != SURVIVED ]]; then
    echo "MUTANT $name INVALID unmutated oracle=$result"; invalid=$((invalid + 1)); continue
  fi
  f=$scratch/tree/$file
  if ! AN0_LINE="$line" AN0_REPLACEMENT="$repl // MUTANT $name" \
    awk -v tag="// AN0-GUARD $name" '
    BEGIN { want=ENVIRON["AN0_LINE"]; repl=ENVIRON["AN0_REPLACEMENT"] }
    { stripped=$0; sub(/^[[:space:]]*/, "", stripped) }
    previous { if (stripped != want) exit 2; match($0, /^[[:space:]]*/); print substr($0,1,RLENGTH) repl; previous=0; next }
    stripped == tag { count++; previous=1 }
    { print }
    END { if (count != 1 || previous) exit 2 }
  ' "$f" >"$f.mut"; then
    echo "MUTANT $name INVALID guard not applied"; invalid=$((invalid + 1)); continue
  fi
  mv "$f.mut" "$f"
  printf '%s\n' "$repl" >"$E/$name.diff"
  result=$(probe "$name" "$package" "$selector" "$test")
  echo "MUTANT $name $result"
  case $result in
    KILLED) killed=$((killed + 1));;
    SURVIVED) survived=$((survived + 1));;
    *) invalid=$((invalid + 1));;
  esac
done
echo "killed=$killed survived=$survived invalid=$invalid"
[[ $survived == 0 && $invalid == 0 && $killed == ${#mutants[@]} ]]
