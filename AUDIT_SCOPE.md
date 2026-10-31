# Audit scope

Written for an outside, independent security audit. Revision described:
`53c39bf2031c01e28703dfdad7e8cae89de2d756` on main (merged PR #49), 2026-10-29. This is a source review,
not an independent audit or hardware qualification. Test evidence and outstanding checks are
listed below; an open proposal is not merged behavior.

## What this repository is

Open Humanity is an early prototype (version 0.1.0) with two parts. The assistance network
(signal formats, signing and encryption helpers, a secrets firewall, a local SQLite signal store,
a UDP transport and a basic relay) is a set of building blocks not yet joined end to end.
Volunteer compute v0 runs end to end on one machine over loopback with a toy model: a coordinator
sends signed work units, volunteers train locally and return signed, compressed updates over an
encrypted connection, and updates are scored on a held-out set. A teaching mode lets a volunteer
send firewalled text from a model on its own machine. Six Rust crates: `beacon-core`,
`beacon-client`, `beacon`, `oh-core`, `oh-coordinator`, `oh-volunteer`.

## What to review, in priority order

1. `crates/oh-core/src/transport.rs`, `wire.rs`, `identity.rs`: X25519 and ChaCha20-Poly1305
   per connection and direction, refusal of tampered, replayed or reordered messages, padding to
   power-of-two buckets, length-prefixed TCP frames (64 MiB `MAX_FRAME_BYTES` cap per
   `.cargo/audit.toml`), bincode 1.3 decoding of network bytes.
2. `crates/oh-coordinator`: volunteer admission (`--allow-volunteer` keys, one slot per key per
   round, refusal to serve without enough keys), signature checks on updates and teaching
   batches, Turing scoring, append-only ledger, held-out set handling.
3. `crates/oh-volunteer`: coordinator key pinning (`--coordinator-key`; `--trust-first-use`
   accepts the first key with a warning), what leaves the machine (`tests/data_stays_home.rs`),
   teaching mode and the loopback-only teacher check.
4. `crates/oh-core/src/teacher.rs`: `LocalHttpTeacher`, the loopback-only HTTP client.
5. `crates/beacon-core/src/firewall.rs`, `crypto.rs`, `schema.rs`, `cuckoo.rs`.
6. `crates/beacon/src/main.rs`: UDP relay; listens on all interfaces by default (`BEACON_PORT`
   changes the port), keeps the newest 10,000 well-formed signals in memory.
7. `crates/beacon-client`: SQLite store, UDP transport, `preflight.rs` (runs a check command in a
   temporary directory).
8. Vault reads of seeds via `atlas-vault get` (`--key-from-vault`, `--vault-bin`).
9. Aienet-0: `oh-core/src/carrier.rs`, `oh-coordinator/src/bin/aienet0-run.rs`,
   `oh-volunteer/src/bin/aienet0-serve.rs`: pinned coordinator and submitter identities, bounded
   MJB1 admission and MJR1 receipt checks, permanent state lock, atomic recovery snapshots,
   retry returning the exact stored receipt, refusal of changed bundle or executor identities.
   The settlement adapter belongs to aien-protocols-mv; its external ledger boundary needs
   separate review. File-based identities in the Aienet-0 test CLI are test fixtures, not wallets.
10. Scripts: `scripts/agent-preflight.sh`, `demo-local.sh`, `demo-teach.sh`, `volunteer-gap.sh`.
   `.github/workflows/ci.yml` (added by the audit-readiness change) only publishes an SPDX
   SBOM artifact; actions pinned by commit sha, read-only token. Build and test do not run in
   hosted CI: they run locally on the Spark (`cargo test --locked --workspace`,
   `bash scripts/test-agent-preflight.sh`).

## Trust boundaries

- Untrusted: network peers of the relay and client; volunteers (until admitted, and their
  updates after admission); the coordinator from the volunteer side until its key is pinned;
  output of the local teacher model.
- Trusted: the coordinator operator who approves keys; `atlas-vault` and the binary named by
  `--vault-bin`; the local machine.

## Threat model summary

- Assets: volunteer training shards and user data; the held-out set; signing seeds; ledger
  integrity; the shared model.
- Attackers considered: a network observer or active attacker between coordinator and volunteer;
  an unapproved key; a malicious approved volunteer submitting harmful updates; hostile UDP
  packets to the relay.
- Implemented controls for volunteer compute (not the plaintext distress relay): encrypted, authenticated, padded transport; key pinning; operator-approved admission;
  updates accepted only if they improve held-out loss; firewall on teaching text; vault-backed volunteer seeds read in memory; the Aienet-0 test CLI also reads
  explicitly supplied identity files; `.env` files refused by the preflight script.
- Not defended / explicitly out of scope (README): differential privacy; secure aggregation;
  Sybil resistance beyond operator approval; held-out leakage from repeated scoring; timing and
  coarse size leakage; a malicious approved volunteer stalling a submission until timeout. In the
  assistance network prototype, signals are not signed, verified or encrypted, the firewall is
  not called, and titles and summaries travel in plaintext.

## Build from source at a pin

A stable Rust toolchain; no `rust-toolchain.toml`, so the exact version is unknown from the
repository. `Cargo.lock` is committed.

```sh
cargo build --locked --workspace --all-targets
```

## Verification commands

```sh
cargo test --locked --workspace --verbose
cargo audit
bash scripts/test-agent-preflight.sh
./scripts/agent-preflight.sh
```

- Tests include `crates/oh-coordinator/tests/encrypted_transport.rs`, `loopback.rs`,
  `teaching.rs`, `teaching_steps.rs`, and `crates/oh-volunteer/tests/data_stays_home.rs` and
  `teaching.rs`.
- `cargo audit` reads `.cargo/audit.toml`, which ignores RUSTSEC-2025-0141 (bincode 1.3
  unmaintained) with a stated reason.
- `scripts/demo-local.sh` and `demo-teach.sh` need distinct `atlas-vault` identity entries
  (`VOLUNTEER_VAULT_KEYS`, `VOLUNTEER_VAULT_KEY`); teaching mode needs a local model server.
- PR #49 integration: full workspace tests passed (155 passed, 3 existing ignored), strict
  workspace Clippy passed, and cargo audit reported no vulnerabilities or warnings. These
  checks do not establish correctness of settlement or hardware behavior. Build, test and
  preflight results for this proposal come from local Spark runs (`cargo test --locked
  --workspace`, `bash scripts/test-agent-preflight.sh`) recorded on PR #50; hosted CI only
  produces the SBOM. Existing ignored
  measurement tests remain unrun; a passing suite does not imply those tests ran.
- The preflight filename scan covers only `.env*` names within three directory levels.
  It does not inspect secret contents, verify the vault or certify a machine as secret-free.

## Known limitations and NOT_RUN

- The assistance network flow is a design; the README "Today" notes state what the code does.
- The `status` subcommand prints fixed TPM and cuckoo filter lines, not live checks.
- The relay does not forward, verify or expire signals; throughput not measured.
- Volunteer compute uses a toy byte model on the CPU.

## Dependencies and provenance

- `Cargo.lock`; crates for Ed25519, X25519, ChaCha20-Poly1305, SQLite and bincode 1.3 (see
  `crates/*/Cargo.toml`).
- The `aien-microjob` dependency is pinned in `Cargo.toml` to aien-protocols-mv
  `7bfb4ee2fda4fee023a8f9b62639efedc1206391`; review its Aienet-0 validation boundary.
- External programs: `atlas-vault`; an optional local OpenAI-style chat server for teaching.
- Licence: Apache-2.0 (`LICENSE`); `COVENANT.md` is nonbinding.

## Evidence

- No `evidence/` directory. Measured results: `docs/research/2026-10-16-v0-loopback-results.md`,
  `2026-10-16-volunteer-gap.md`, `2026-10-16-qwen-teacher-v0-results.md`.
- Whether `aien-dev/aien-receipts` holds `open-humanity/<sha>/` entries is unknown from the
  repository. Receipts are append-only and never edited.
