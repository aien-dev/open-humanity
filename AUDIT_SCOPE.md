# Audit scope

Written for an outside, independent security audit. Revision described:
`38c0c1c48de5ccc58dc350c946f0b42830e048d1` on `main`, 2026-10-26. Everything below is taken from
the repository's own files at that revision; items marked NOT_RUN were not executed while writing
this document.

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
9. Scripts: `scripts/agent-preflight.sh`, `demo-local.sh`, `demo-teach.sh`, `volunteer-gap.sh`.
   `.github/workflows/ci.yml` (added by the audit-readiness change) runs `cargo build --locked
   --all-targets` and `cargo test --locked` on a GitHub-hosted runner and publishes an SPDX
   SBOM artifact; actions pinned by commit sha, read-only token.

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
- Defended: encrypted, authenticated, padded transport; key pinning; operator-approved admission;
  updates accepted only if they improve held-out loss; firewall on teaching text; seeds kept in
  memory only; `.env` files refused by the preflight script.
- Not defended / explicitly out of scope (README): differential privacy; secure aggregation;
  Sybil resistance beyond operator approval; held-out leakage from repeated scoring; timing and
  coarse size leakage; a malicious approved volunteer stalling a submission until timeout. In the
  assistance network prototype, signals are not signed, verified or encrypted, the firewall is
  not called, and titles and summaries travel in plaintext.

## Build from source at a pin

A stable Rust toolchain; no `rust-toolchain.toml`, so the exact version is unknown from the
repository. `Cargo.lock` is committed.

```sh
cargo build --workspace
```

## Run every test

```sh
cargo test --workspace --verbose
cargo audit
./scripts/agent-preflight.sh
```

- Tests include `crates/oh-coordinator/tests/encrypted_transport.rs`, `loopback.rs`,
  `teaching.rs`, `teaching_steps.rs`, and `crates/oh-volunteer/tests/data_stays_home.rs` and
  `teaching.rs`.
- `cargo audit` reads `.cargo/audit.toml`, which ignores RUSTSEC-2025-0141 (bincode 1.3
  unmaintained) with a stated reason.
- `scripts/demo-local.sh` and `demo-teach.sh` need distinct `atlas-vault` identity entries
  (`VOLUNTEER_VAULT_KEYS`, `VOLUNTEER_VAULT_KEY`); teaching mode needs a local model server.
- README: this repository is not yet judged by AIEN's Spark pipeline. All commands above: NOT_RUN
  while writing this document.

## Known limitations and NOT_RUN

- The assistance network flow is a design; the README "Today" notes state what the code does.
- The `status` subcommand prints fixed TPM and cuckoo filter lines, not live checks.
- The relay does not forward, verify or expire signals; throughput not measured.
- Volunteer compute uses a toy byte model on the CPU.

## Dependencies and provenance

- `Cargo.lock`; crates for Ed25519, X25519, ChaCha20-Poly1305, SQLite and bincode 1.3 (see
  `crates/*/Cargo.toml`).
- External programs: `atlas-vault`; an optional local OpenAI-style chat server for teaching.
- Licence: Apache-2.0 (`LICENSE`); `COVENANT.md` is nonbinding.

## Evidence

- No `evidence/` directory. Measured results: `docs/research/2026-10-16-v0-loopback-results.md`,
  `2026-10-16-volunteer-gap.md`, `2026-10-16-qwen-teacher-v0-results.md`.
- Whether `aien-dev/aien-receipts` holds `open-humanity/<sha>/` entries is unknown from the
  repository. Receipts are append-only and never edited.
