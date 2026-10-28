#!/bin/sh
# Aienet-0 P0: one job end to end with escrow settlement in the TUR ledger.
#
# usage: scripts/aienet0/settle-run.sh EVIDENCE_DIR [honest|tampered-receipt]
#
# Fresh ledger journal, prefund the requester, sign the job WITHOUT sending
# it (aienet0-run bundle), reserve escrow on its dag_id, then send exactly
# that bundle (aienet0-run run --resend). Settlement is decided only by the
# job path: on VERIFIED with this dag_id the escrow is settled against the
# printed MJR1 sha256 and the settle is repeated (must be already-settled,
# journal unchanged); on anything else the escrow is refunded and never
# settled. Then audit and balances. The mode only chooses the worker's
# behaviour (tampered-receipt: the worker corrupts its signed receipt) and
# what this script expects at the end; it does not steer the decision.
#
# Every command, its output and exit code go to EVIDENCE_DIR/MODE/transcript.txt;
# the journal and the job artifacts stay under EVIDENCE_DIR/MODE. Exit 0 only
# when the outcome is the expected one for the mode.
#
# Environment (as for controls.sh): RUN SERVE LISTEN CONNECT KEYS PINS
# RECOMPUTE RECOMPUTE_SHA256 WKEYS WPINS WSTATE, plus LEDGER (tur-ledger,
# aien-sovereign-core #792). Split (integer TUR test credits): prefund 100,
# reserve 40, settle provider 27, verifier 3, back to requester 10.
set -u
E=${1:?usage: settle-run.sh EVIDENCE_DIR [honest|tampered-receipt]}
MODE=${2:-honest}
case $MODE in
  honest) SX= ;;
  tampered-receipt) SX='--misbehave tamper-receipt' ;;
  *) echo "unknown mode $MODE" >&2; exit 2 ;;
esac
for v in RUN SERVE LISTEN CONNECT KEYS PINS RECOMPUTE RECOMPUTE_SHA256 WKEYS WPINS WSTATE LEDGER; do
  eval "x=\${$v:-}"
  [ -n "$x" ] || { echo "settle-run.sh: set $v" >&2; exit 2; }
done
D=$E/$MODE
J=$D/journal
if [ -e "$D" ]; then echo "settle-run.sh: $D exists; use a fresh evidence dir" >&2; exit 2; fi
mkdir -p "$J" "$D/out"
T=$D/transcript.txt
: >"$T"

# step NAME CMD...: run, append "$ CMD", its stdout+stderr and "rc=N" to the
# transcript; output also kept in $D/NAME.out, exit code in $rc.
step() {
  name=$1; shift
  printf '$ %s\n' "$*" >>"$T"
  "$@" >"$D/$name.out" 2>&1
  rc=$?
  cat "$D/$name.out" >>"$T"
  printf 'rc=%s\n\n' "$rc" >>"$T"
}
note() { printf '# %s\n' "$*" >>"$T"; }
jsha() { sha256sum "$J/journal" | cut -d' ' -f1; }
fail() { note "RESULT FAIL $MODE: $*"; cat "$T"; echo "RESULT FAIL $MODE: $*"; exit 1; }

note "mode $MODE, $(date -u +%Y-%m-%dT%H:%M:%SZ), ledger $LEDGER sha256 $(sha256sum "$LEDGER" | cut -d' ' -f1)"
step prefund "$LEDGER" --journal "$J" prefund pf-1 requester 100
[ $rc = 0 ] || fail "prefund rc=$rc"

step bundle "$RUN" bundle --keys "$KEYS" --out "$D/out/job.an0b"
[ $rc = 0 ] || fail "bundle rc=$rc"
dag=$(awk '$1 == "BUNDLE" { print $2 }' "$D/bundle.out")
[ -n "$dag" ] || fail "no BUNDLE line"

step reserve "$LEDGER" --journal "$J" reserve "$dag" requester provider verifier 40
[ $rc = 0 ] || fail "reserve rc=$rc"

# The job: worker in the background, coordinator sends the reserved bundle.
scmd="$SERVE $SX --connect $CONNECT --keys $WKEYS --pins $WPINS --state $WSTATE --connect-timeout 60"
note "serve: $scmd"
$scmd >"$D/serve.out" 2>"$D/serve.err" </dev/null &
sp=$!
step run "$RUN" run --resend "$D/out/job.an0b" --listen "$LISTEN" --keys "$KEYS" --pins "$PINS" \
  --out "$D/out" --recompute "$RECOMPUTE" --recompute-sha256 "$RECOMPUTE_SHA256" --accept-timeout 90
run_rc=$rc
wait $sp
src=$?
note "serve rc=$src stdout: $(cat "$D/serve.out")"
note "serve stderr: $(tr '\n' ' ' <"$D/serve.err")"

vline=$(grep '^VERIFIED ' "$D/run.out")
vdag=$(printf '%s\n' "$vline" | awk '{ print $2 }')
vrcpt=$(printf '%s\n' "$vline" | awk '{ print $3 }')
if [ "$run_rc" = 0 ] && [ "$vdag" = "$dag" ] && [ -n "$vrcpt" ]; then
  note "decision: VERIFIED $dag -> settle"
  step settle "$LEDGER" --journal "$J" settle "$dag" "$vrcpt" 27 3 10
  [ $rc = 0 ] || fail "settle rc=$rc"
  before=$(jsha)
  step settle-again "$LEDGER" --journal "$J" settle "$dag" "$vrcpt" 27 3 10
  after=$(jsha)
  note "journal sha256 before repeat $before after $after"
  [ $rc = 0 ] && grep -q '^already-settled ' "$D/settle-again.out" || fail "repeat settle rc=$rc"
  [ "$before" = "$after" ] || fail "repeat settle changed the journal"
  decision=settled
else
  note "decision: not VERIFIED (run rc=$run_rc) -> refund"
  step refund "$LEDGER" --journal "$J" refund "$dag"
  [ $rc = 0 ] || fail "refund rc=$rc"
  decision=refunded
fi

step audit "$LEDGER" --journal "$J" audit
[ $rc = 0 ] || fail "audit rc=$rc"
step show "$LEDGER" --journal "$J" show "$dag"
bal=
for a in requester provider verifier; do
  step "balance-$a" "$LEDGER" --journal "$J" balance "$a"
  [ $rc = 0 ] || fail "balance $a rc=$rc"
  bal="$bal $(awk '{ print $3 }' "$D/balance-$a.out")"
done
bal=${bal# }
settles=$(awk '$3 == "settle"' "$J/journal" | wc -l | tr -d ' ')
note "decision $decision, balances requester provider verifier: $bal, settle records in journal: $settles"
(cd "$D" && sha256sum journal/journal out/*) >"$D/SHA256SUMS"

case $MODE in
  honest) want_decision=settled; want_bal='70 27 3'; want_settles=1 ;;
  tampered-receipt) want_decision=refunded; want_bal='100 0 0'; want_settles=0 ;;
esac
[ "$decision" = "$want_decision" ] || fail "decision $decision, want $want_decision"
[ "$bal" = "$want_bal" ] || fail "balances $bal, want $want_bal"
[ "$settles" = "$want_settles" ] || fail "settle records $settles, want $want_settles"
note "RESULT PASS $MODE: $decision, balances $bal"
cat "$T"
echo "RESULT PASS $MODE: $decision $dag, balances requester provider verifier $bal"
