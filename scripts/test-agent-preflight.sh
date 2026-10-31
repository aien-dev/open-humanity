#!/usr/bin/env bash
# Verification only: run preflight in a synthetic repository with mocked cargo.
set -euo pipefail
CHECK=${PREFLIGHT_UNDER_TEST:-$(cd "$(dirname "$0")" && pwd)/agent-preflight.sh}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/repo" "$WORK/bin"
REAL_GIT=$(command -v git)
export REAL_GIT
cd "$WORK/repo"
git init -q -b fixture
git config user.name Fixture
git config user.email fixture@example.invalid
printf 'baseline\n' > tracked
git add tracked
git commit -qm fixture
cat > "$WORK/bin/cargo" <<'EOF'
#!/bin/sh
touch "$CARGO_MARKER"
EOF
chmod +x "$WORK/bin/cargo"
export CARGO_MARKER="$WORK/cargo-ran"
export PATH="$WORK/bin:$PATH"
run() {
    rm -f "$CARGO_MARKER"
    local status=0
    bash "$CHECK" > "$WORK/result" 2>&1 || status=$?
    if [ "$1" = pass ]; then
        test "$status" -eq 0 && test -f "$CARGO_MARKER"
    else
        test "$status" -ne 0 && test ! -f "$CARGO_MARKER"
    fi
}
run pass
touch .env.fixture
run fail
rm .env.fixture
printf '\u2014\n' > tracked
run fail
printf 'baseline\n' > tracked
for tool in find grep git; do
    if [ "$tool" = git ]; then
        cat > "$WORK/bin/git" <<'EOF'
#!/bin/sh
if [ "$1" = diff ]; then exit 2; fi
exec "$REAL_GIT" "$@"
EOF
    else
        printf '#!/bin/sh\nexit 2\n' > "$WORK/bin/$tool"
    fi
    chmod +x "$WORK/bin/$tool"
    run fail
    rm "$WORK/bin/$tool"
done
run pass
printf 'PASS: clean input; .env and punctuation refusal; find, diff and grep failures stop before cargo\n'
