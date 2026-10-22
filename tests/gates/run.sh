#!/usr/bin/env bash
# tests/gates/run.sh: the one entry point for the local verification gates of this
# repository. Manifests under tests/gates/ name this script plus one step word, so no
# manifest needs shell expansion (ADR 0028 P6). Observations print as "AIEN-OBS <name> <json>".
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
step="${1:?usage: tests/gates/run.sh <step>}"
obs() { printf 'AIEN-OBS %s %s\n' "$1" "$2"; }

case "$step" in
  zero-disk-secrets)
    found=false
    if find . -type f \( -name '.env' -o -name '.env.*' \) \
         ! -name '*.example' ! -name '*.sample' ! -path './target/*' | head -1 | grep -q .; then
      found=true
      find . -type f \( -name '.env' -o -name '.env.*' \) \
        ! -name '*.example' ! -name '*.sample' ! -path './target/*' | head -5 >&2
    fi
    obs env_files_found "$found"
    [ "$found" = false ]
    ;;
  fmt)    cargo fmt --all -- --check ;;
  check)  cargo check --all-targets ;;
  clippy) cargo clippy --all-targets -- -D warnings ;;
  test)   cargo test --verbose -- --test-threads=1 ;;
  *) echo "run.sh: unknown step $step" >&2; exit 2 ;;
esac
