#!/bin/sh
# Regenerates om/gen (the Rust binding of om/tkcheck.om) with omega-bridge's
# tools/native --host, or with --check compares a fresh generation to om/gen.
#
#   OMEGA_BRIDGE=<omega-bridge checkout at BRIDGE_COMMIT> \
#   OMEGA_NATIVE_OMC=<omc, OMC_SHA256> OMEGA_NATIVE_OMC2=<omc, OMC2_SHA256> \
#   sh crates/oh-infer/om/regen.sh [--check]
#
# The pins are in om/PIN. Exit 0: written, or no difference. Exit 1: --check
# found a difference. Exit 3: a pin does not match (nothing written).
set -eu
cd "$(dirname "$0")/.."
. om/PIN
check=0
[ "${1:-}" != --check ] || check=1
: "${OMEGA_BRIDGE:?set OMEGA_BRIDGE to an omega-bridge checkout}"
: "${OMEGA_NATIVE_OMC:?}" "${OMEGA_NATIVE_OMC2:?}"
have=$(git -C "$OMEGA_BRIDGE" rev-parse HEAD)
[ "$have" = "$BRIDGE_COMMIT" ] || { echo "regen: bridge is at $have, pin is $BRIDGE_COMMIT" >&2; exit 3; }
[ -z "$(git -C "$OMEGA_BRIDGE" status --porcelain)" ] || { echo "regen: bridge checkout has local changes" >&2; exit 3; }
[ "$(sha256sum < "$OMEGA_NATIVE_OMC" | cut -d' ' -f1)" = "$OMC_SHA256" ] || { echo "regen: OMEGA_NATIVE_OMC is not $OMC_SHA256" >&2; exit 3; }
[ "$(sha256sum < "$OMEGA_NATIVE_OMC2" | cut -d' ' -f1)" = "$OMC2_SHA256" ] || { echo "regen: OMEGA_NATIVE_OMC2 is not $OMC2_SHA256" >&2; exit 3; }
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
# Relative unit path: ident.txt records it as path=om/tkcheck.om.
"$OMEGA_BRIDGE/tools/native" --host "$t/out" om/tkcheck.om >/dev/null
mkdir -p "$t/gen"
cp "$t/out/omega_native.c" "$t/out/omega_native.h" "$t/out/omega_native.rs" "$t/gen/"
cp "$t/out/work/ident.txt" "$t/gen/ident.txt"
if [ $check = 1 ]; then
  diff -r om/gen "$t/gen" && echo "regen: om/gen matches" && exit 0
  echo "regen: om/gen differs from a fresh generation" >&2
  exit 1
fi
rm -rf om/gen
cp -r "$t/gen" om/gen
echo "regen: om/gen written"
