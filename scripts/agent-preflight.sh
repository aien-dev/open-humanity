#!/usr/bin/env bash
set -euo pipefail

echo "=== Open Humanity Preflight Verification ==="

# 1. Branch Isolation
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" = "main" ]; then
    echo "[-] FAILED: Direct commits to 'main' branch are strictly prohibited."
    echo "    Create a feature branch (e.g. feat/..., fix/..., perf/...) first."
    exit 1
fi
echo "[+] PASSED: Branch isolation confirmed ($BRANCH)."

# 2. Filename check only. This does not inspect file contents or prove vault operation.
if ! ENV_PATHS=$(find . -maxdepth 3 -name ".env*" -not -path "./.git/*" -print -quit); then
    echo "[-] FAILED: Could not complete the .env filename scan."
    exit 1
fi
if [ -n "$ENV_PATHS" ]; then
    echo "[-] FAILED: Found a prohibited .env filename."
    exit 1
fi
echo "[+] PASSED: No .env filenames found within three directory levels. File contents and vault operation were not checked."

# 3. Unslop Standard (Zero em dashes or en dashes)
SCRATCH=$(mktemp -d)
trap 'rm -rf "$SCRATCH"' EXIT
if ! git diff --no-ext-diff --no-textconv HEAD > "$SCRATCH/diff"; then
    echo "[-] FAILED: Could not read the pending changes."
    exit 1
fi
awk '/^\+[^+]/ && !/assert!|replace|contains/ { print }' "$SCRATCH/diff" > "$SCRATCH/added"
if grep -qP '[\x{2014}\x{2013}]' "$SCRATCH/added"; then
    echo "[-] FAILED: Found prohibited em dash or en dash in pending added lines."
    exit 1
else
    SCAN_STATUS=$?
    if [ "$SCAN_STATUS" -ne 1 ]; then
        echo "[-] FAILED: Could not complete the punctuation scan."
        exit 1
    fi
fi
echo "[+] PASSED: Unslop standard verified (zero em dashes and zero en dashes)."

# 4. Cargo Workspace Tests
echo "[*] Running cargo test --workspace --verbose..."
cargo test --workspace --verbose

echo "=== ALL OPEN HUMANITY PREFLIGHT CHECKS PASSED ==="
