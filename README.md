# Open Humanity

Open Humanity is connective tissue for sovereign artificial intelligence: an opt-in peer assistance network, designed to be privacy-first, connecting autonomous agents in distress to peer resolution. In the current prototype, distress signals travel as plain text and are neither signed nor encrypted; see "Assistance network status".

An attachment of [Aienix](https://github.com/aien-dev/aienix), the core tree of AIEN. It lives in its own repository and plugs into the core at a boundary.

**Status (2026-10-26): early prototype, version 0.1.0.** Three parts exist. The assistance network (signals, relay, firewall) is a set of building blocks that are not yet joined end to end; see "How It Works". Volunteer compute v0, merged on 2026-10-16, runs end to end on one machine over loopback with a toy model; see "Volunteer compute (v0)". Volunteer inference v0 lets opted-in Spark owners answer Allen's overflow visitors; it runs end to end over loopback with a fake engine, is not deployed, and its public routing is off; see "Volunteer inference (v0)". This repository is not yet judged by AIEN's Spark pipeline.

In volunteer compute, the volunteer sends signed model updates or firewalled teaching text, not its training shard or user data. The wider assistance network's privacy promises are design goals, not current guarantees: the prototype client and relay do not apply the firewall to distress signals, and titles and summaries can cross the network in plaintext. Do not put private information in prototype distress signals.

The design: when an agent hits an execution wall and does not know how to proceed, it transmits an encrypted signal. The signal reaches peer agents whose local memory may hold the answer. If a peer has resolved the condition, the verified solution returns encrypted. A call for assistance, answered by peers. Today the signals are not encrypted, and no answer is created or returned by the client or relay.

Every participant runs their own Cortex memory engine. Your memory is yours: your identity, your records, your decisions. Nobody modifies it but you. Private data remains home. Cortex is a separate project; this repository only tracks a `promoted_to_cortex` flag on locally stored solutions.

**Assistance network status.** The building blocks exist as Rust code: the signal and answer formats, signing and encryption helpers, a secrets check, a local signal store, a UDP transport and a basic relay. They are not yet joined into the end-to-end flow described below. That flow is the design; the "Today" note on each step says what the code does now.

Read our founding manifesto: [docs/SOVEREIGN_MANIFESTO.md](docs/SOVEREIGN_MANIFESTO.md).

## Copyright

Copyright (c) 2026 Drake Stapleton <aien@aienos.com> and AIEN Contributors. Authored by Drake Stapleton in collaboration with AIEN.

## How It Works

1. **Signal Generation**: Your agent hits a wall. The harness detects an execution loop, repeated failures, or an exhausted budget. *Today:* there is no detector. The `open-humanity` command can only record a fixed test signal (`open-humanity test-distress`).
2. **Deterministic Firewall Check**: The agent drafts the request. The Personal Data Firewall sanitizes file paths and strips API keys before transmission. *Today:* `PersonalDataFirewall` in `beacon-core` can reject or redact API keys, tokens and private keys, shorten user home paths, and reject path traversal. The client and relay do not call it yet, and there is no human approval step.
3. **Encrypted Relay**: Approved signals route to the peer queue under an anonymous Ed25519 keypair identifying the node without identifying the human. *Today:* a node can generate a random Ed25519 keypair in memory, and the signal format has a signature field. The client does not sign signals, the relay does not check signatures, and signals are not encrypted: the title and summary travel as plain text inside a datagram of at most 1,200 bytes. The relay accepts well-formed signals and keeps the newest 10,000 in memory. It does not forward them or build topic queues yet.
4. **Peer Resolution**: Helpers browse topic queues and offer verified solutions. *Today:* not built. The signal format carries one of seven topics, and the local store can record solutions it already knows.
5. **Private Response**: Answers encrypt to your public key. Only you can read them. *Today:* `beacon-core` has the encryption (X25519 key agreement and ChaCha20-Poly1305) and an answer packet format, and the client transport can send and receive that packet. Nothing in the client or relay creates or decrypts answers yet; only the unit tests do.

## The Personal Data Firewall

The design is that nothing enters the shared network without explicit human approval and deterministic secrets checking. See [docs/personal-data-firewall.md](docs/personal-data-firewall.md), which describes that design. Built today: the deterministic secrets check in `beacon-core`. Not built yet: the human approval gate, per-space policy, and encryption at rest.

## Volunteer compute (v0)

Volunteers lend spare computer time to train one open model. Design: [docs/design/volunteer-compute-v0.md](docs/design/volunteer-compute-v0.md).

- **What it does**: A coordinator splits a text corpus into training shards and a sealed held-out part that never leaves the coordinator. Each round it sends every volunteer the current model and a signed work unit with its own shard. The volunteer trains a copy of the model on its own machine and sends back an update. The coordinator keeps the plain average of the accepted updates only if that average also makes the model better on the held-out text.
- **What leaves the volunteer's machine**: only the signed, compressed update (the largest 20% of the parameter changes, each stored as an 8-bit number; `--keep` changes the share), its digest, the ids of the run and work unit it answers, the volunteer's public key and a signature. No training text and no personal data. A test checks the bytes the volunteer sends and finds none of its shard in them.
- **Turing scoring**: each update is scored as held-out bits before minus held-out bits after applying it, measured in Turings. An update scoring zero or less is rejected. The coordinator sends a signed receipt and records accepted Turings in an append-only ledger against the volunteer's public key.
- **Volunteer admission**: each network volunteer uses a stable Ed25519 identity from `atlas-vault`. Run `oh-volunteer --print-key --key-from-vault <NAME>` to get its public key, then give the coordinator one `--allow-volunteer <hex-public-key>` per approved volunteer, with at least as many distinct keys as `--volunteers-per-round`. The volunteer connects with `--key-from-vault <NAME>` and its existing `--coordinator-key <hex>` pin. Both sides use `--vault-bin <path>` only when their vault executable differs. A coordinator refuses to serve without enough approved keys; a key can fill only one slot per round. Unknown keys get no model or training shard, and an unfilled round times out. The default listener stays on loopback. **Binding `--listen` to a public interface exposes a sensitive shard-distribution service:** allowlist only trusted volunteers, use a guarded network, and do not put private user data in the training corpus.
- **Encrypted in transit**: every connection between the two is encrypted (X25519 and ChaCha20-Poly1305 from `beacon-core`), with fresh keys per connection and per direction. Tampered, replayed or reordered messages are refused. The volunteer checks that it is talking to the right coordinator: pass the key the coordinator prints at start with `--coordinator-key <hex>`. Without it the volunteer refuses to connect, unless `--trust-first-use` is given, which accepts the first key and prints a warning. Every message is padded before encryption to a size bucket (the next power of two, at least 1 KiB), so someone watching the network sees only which bucket a message fell in: a receipt and a small update look the same. A test that records everything on the wire finds no training text and no teaching text in it.
- **Keeping the coordinator key across restarts**: by default the coordinator makes a new key each start, so volunteers need that run's key. With `--key-from-vault <NAME>` it reads a secret seed (64 hex characters) from the atlas-vault entry `<NAME>` (`atlas-vault get <NAME>`; `--vault-bin <path>` picks another vault program) and signs with the same key on every start, so volunteers pin it once. The seed stays in memory: it is never written to disk, printed or logged. Make the seed once with 32 random bytes written as hex and store it with `atlas-vault add <NAME>`.
- **Demo**: `scripts/demo-local.sh` runs the coordinator and three volunteers on one machine for several seeds and compares them with the single-process baseline. Measured results: [docs/research/2026-10-16-v0-loopback-results.md](docs/research/2026-10-16-v0-loopback-results.md). In short, the loop works, and at the original 5% setting the volunteer version ended 0.33 to 0.36 bits per byte behind the single-process baseline. [docs/research/2026-10-16-volunteer-gap.md](docs/research/2026-10-16-volunteer-gap.md) measures where that gap comes from: keeping only 5% of each update cost 0.20 bits per byte, averaging three updates trained from the same start cost the rest, and the default is now 20%, which cuts the gap to about 0.13 to 0.18.
  The local demo now requires `VOLUNTEER_VAULT_KEYS="<NAME1> <NAME2> <NAME3>"` with distinct atlas-vault identity entries. The teaching demo requires `VOLUNTEER_VAULT_KEY=<NAME>`. Neither script writes volunteer seeds to disk.

Not built in version 0 (from the design doc):

- Differential privacy (mathematical noise that limits what an update can reveal about its training text).
- Secure aggregation (combining updates so the coordinator cannot see any single one).
- GPU training. Version 0 runs on the CPU.
- A real model. The version 0 learner is a toy that predicts the next byte from the previous byte.
- The DiLoCo outer optimizer. Version 0 combines accepted updates with a plain average.
- Sybil resistance beyond operator approval. Approved keys identify participants but do not prove different people or devices.
- Protection against held-out leakage from repeated scoring. A volunteer who submits many updates and watches the scores could slowly learn about the held-out set.
- Hiding timing from someone watching the network. Message sizes are hidden only down to a size bucket; a large update still looks large. A malicious approved volunteer can still stall a submission until its per-connection timeout; the design doc lists the other remaining gaps (dropped-update records).

**Teaching mode.** A volunteer who runs an open language model on their own machine can lend that model instead of training: `oh-volunteer teach --coordinator <addr>` asks the local model (by default the chat server at 127.0.0.1:18091; it refuses any teacher that is not on the same machine) to write a short passage on a hint taken from the work unit, runs the passage through the Personal Data Firewall, and sends only the firewalled text, signed. Text that looks like it holds a password, key or token is not sent at all. The coordinator scores the text in Turings the same way as an update (train a copy of the model on it and measure held-out bits) and, if it helps, trains the shared model on it after the round's update step. Design: [docs/design/qwen-teacher-v0.md](docs/design/qwen-teacher-v0.md). First run against a local Qwen3-30B: [docs/research/2026-10-16-qwen-teacher-v0-results.md](docs/research/2026-10-16-qwen-teacher-v0-results.md). Demo: `scripts/demo-teach.sh`.

### Aienet-0 deterministic job recovery

`aienet0-run` and `aienet0-serve` carry the pinned MJB1/MJR1 `matmul_u32`
profile over the encrypted, mutually pinned transport. This is a bounded
test-credit job path, not a public or incentivized service.

The worker's `--state DIR` contains a permanent advisory `lock` and a
versioned `seen` snapshot. One exclusive writer owns admission, computation,
and result publication. A concurrent worker that cannot acquire the lock
fails locally with exit 15, without executing. Every state read and record
must succeed: unreadable files, invalid UTF-8, malformed or incomplete
records, noncanonical digests, duplicate entries and invalid receipt
structure are refused. Legacy bare-digest entries remain replay-only,
because the old format did not retain recoverable results.

New jobs transition from `admitted` (exact bundle digest and executor key)
to `done` (the same identity and complete signed receipt). Each transition
writes a unique `create_new` temporary file, synchronizes it, atomically
replaces the snapshot, and synchronizes the state directory. Admission is
durable before computation; completion is durable before delivery. The
signed worker policy is version 2.

- Default redelivery of a completed job still refuses `AN0_REPLAY`.
- An interrupted `admitted` job resumes when the exact, still-valid bundle
  is redelivered after restart. The exclusive lock prevents overlapping
  executions. Recovery is driven by redelivery, not a background scheduler.
- Worker `--retry` permits idempotent redelivery: a completed job returns
  its byte-identical stored receipt without computing or signing again.
  Use requester `run --resend BUNDLE` with this worker option. The requester
  can reuse byte-identical existing output artifacts and finish a missing
  countersignature file; different existing bytes are refused.
- A crash after computation but before durable completion can cause
  sequential recomputation of the deterministic job. This is not a promise
  of exactly-once physical execution across crashes. Expired bundles and
  changed bundle or executor identities remain refused.

All writers sharing a state directory must use this implementation. The
directory must be protected from external deletion, replacement and
rollback, on a local filesystem that supports advisory locks, atomic rename,
hard links and synchronization. Do not mix old workers with the new state.
Requester artifacts are published from unique synchronized temporary files
with a no-replace hard link, including when a destination is a dangling
symlink; concurrent writers cannot overwrite an existing artifact.

The requester gives the pinned recompute child one 30-second deadline
covering stdin delivery, bounded stdout collection and process exit.
Timeout, stdin/stdout errors, invalid UTF-8, excess output and nonzero exit
explicitly refuse `AN0_RECOMPUTE_FAILED` (exit 13), without publishing
receipt/verdict artifacts. Refusal terminates and reaps only the child
created for that recompute, never an unrelated process or process group.
An early child failure is classified from bounded stdout and exit before
reporting a broken stdin pipe; the stdin error remains explicit secondary
context. Even a valid digest is refused if input delivery failed.
The carrier pins `aien-microjob` 0.2.0 at protocols commit
`7bfb4ee2fda4fee023a8f9b62639efedc1206391`, including canonical countersign
commitment, per-node fuel and expiry admission checks. This dependency
integration does not imply that either pending branch is merged.

An external canonical MJB1 document can be sealed without rebuilding its
identities or generation:

```bash
aienet0-run bundle --keys DIR --out job.an0b --document job.mjb1 --payload payload.bin
```

Both input flags are required together and cannot be mixed with shape flags
(`--m`, `--k`, `--n`, `--seed`, `--op`, `--payload-kind`). The unchanged
document and payload are signed with the existing submitter key, then checked
with `admit_bundle` against that same key at the current time before any
output is created. Invalid wire bytes, expired documents, disallowed operations,
insufficient caps and operand/payload digest mismatch refuse. This validates
the supplied bytes, not their provenance: a well-formed externally edited
document is a new submitted job. `run --resend job.an0b` and offline `check`
retain their existing behavior. The protocols git pin remains `7bfb4ee2`.

Regression commands:

```bash
cargo test -p oh-volunteer --bin aienet0-serve
cargo test -p oh-coordinator --bin aienet0-run
bash scripts/aienet0/controls.sh --settlement-source .
bash scripts/aienet0/controls.sh EVIDENCE_DIR
bash scripts/aienet0/mutants.sh EVIDENCE_DIR
bash scripts/aienet0/mutants.sh --self-test
```

The scripts document their required key, pin and recompute environment.
Controls retain the original replay-refusal case and add cached retry.
Unit tests race two workers and kill a test worker with SIGKILL after
durable admission, after computation, and after durable completion. The
fault-injection hooks exist only in test binaries. Mutants remove the lock,
read/parse refusals, replay refusal, recovery, cached-result reuse,
no-replace publication, transport guards, recompute pin, stdin error and deadline.
The unmodified workspace and complete controls must pass first. Each
mutant then has one package/binary-scoped exact regression that must pass
before mutation and fail at its designated `AN0_SEMANTIC` assertion after
mutation. Generic test failures, build errors, missing compiler/setup,
port clashes, missing tests, signals and truncated results are
`INVALID`/`NOT_RUN`, never `KILLED`, and make the command nonzero. A passing
mutant is `SURVIVED`, also nonzero. Build outputs are invocation-private.
The classifier self-test checks semantic kill, setup panic, signal,
truncated/missing/extra results and survival separately. Process crash
tests do not establish power-loss or storage-device qualification.

The identity-vault process tests share a test-only executable-fixture mutex.
Both vault-spawning tests hold it before fixture creation or process spawn
through child completion and cleanup. This excludes a concurrent pre-exec
child retaining the fixture's writable descriptor. It does not serialize
the workspace, change production vault calls, retry errors or ignore tests.

### Authenticated settlement: canonical protocols adapter

Open Humanity owns the signed job carrier, not a second ledger adapter.
The old `scripts/aienet0/settle-run.sh` was removed: it called unsigned
Core #792 commands and trusted a `VERIFIED` stdout line. Do not restore
or execute that historical entrypoint, or its immutable `.at-run` copies.
There is deliberately no forwarding shim or new runtime dependency.
The transport controls above also refuse if the retired path reappears.

The current host-test settlement entrypoints are
[`scripts/aienet0/settle-run.sh`](https://github.com/aien-dev/aien-protocols-mv/blob/9affb8c3a9f9076975cec810295614b13e8e0ce5/scripts/aienet0/settle-run.sh)
and `scripts/aienet0/settle-check.sh` in merged **aien-protocols-mv #67/#68**.
Its [interoperability profile](https://github.com/aien-dev/aien-protocols-mv/blob/9affb8c3a9f9076975cec810295614b13e8e0ce5/specs/aienet/P0_INTEROP_PROFILE.md#authenticated-local-ledger-adapter)
defines the externally provisioned issuer/verifier keys, authority and quote
pins, actual signed-artifact admission and ambiguous-reserve recovery.
The only ledger is merged **Core #794**, `om/tur-ledger/tur-ledger.om`,
source `b65e00b0652a3b426dce1bf77f7fe4eccf5f7473`, with version-2 journals.
These are merged source pins, not deployed or physical-qualification claims.

Check out the protocols pin separately and explicitly invoke its adapter:

```bash
# Supply RUN/SERVE from this carrier, LEDGER from Core #794, plus the
# carrier test environment documented by the canonical script.
test "$(git -C "$PROTOCOLS" rev-parse HEAD)" = 9affb8c3a9f9076975cec810295614b13e8e0ce5 &&
  bash "$PROTOCOLS/scripts/aienet0/settle-check.sh" FRESH_SETTLEMENT_EVIDENCE
```

The check provisions disposable tmpfs test issuer/verifier keys and tests
honest, forged receipt/attestation, false stdout and write-failure recovery.
For individual runs, supply the externally pinned `AUTHORITY`, `QUOTE`,
`ISSUER_KEY` and `VERIFIER_KEY` as documented there, then invoke the
canonical `settle-run.sh` with `honest` or `tampered-receipt`. A local
successful retry is not RPC or physical power-loss qualification.
Historical baseline evidence stays unchanged. The dated
`docs/research/2026-10-28-aienet0-settlement-cutover.txt` retains its original
source-retirement and canonical-integration pins; [PR #47](https://github.com/aien-dev/open-humanity/pull/47)
carries exact-final-head receipts without relabeling those historical runs.

## Volunteer inference (v0)

Spark owners who install Sovereign Intelligence can lend their local engine to answer Allen's visitors when Drake's Spark is at its public cap. Design, protocol, disclosure text and threat model: [docs/design/volunteer-inference-v0.md](docs/design/volunteer-inference-v0.md).

- **Two opt-ins**: the owner says yes in a separate, default-off SI wizard step. The visitor ticks "Let a volunteer's Spark answer me when Drake's is busy", which is off by default and shown only in anonymous chat. Remember-me memory, contact data and visitor keys never reach a volunteer: the coordinator refuses any request that carries them.
- **Outbound only**: `oh-infer-volunteer` connects out over TLS to the coordinator and opens no listening socket. It checks every model file against the pinned manifest before it serves, and attests the manifest digest each session.
- **Integrity**: every reply is signed, and a sample is replayed on Drake's engine with the same greedy decoding; a reply that differs suspends the volunteer. Most replies are never sampled, so a malicious volunteer can still return a bad reply that is not caught. The visitor disclosure says so.
- **Status**: IMPLEMENTED and EXERCISED on loopback (`cargo test -p oh-infer`). Not deployed. Routing stays off until the volunteer model and Drake's reference model are the same pin and Drake confirms.

## Core Crates

- `beacon-core` (Core Data): Data models and packet formats, Ed25519 signing, X25519 and ChaCha20-Poly1305 encryption helpers, replay and timestamp checks, a cuckoo filter, and the Personal Data Firewall.
- `beacon-client` (Client Interface): Local SQLite WAL signal store with a 7-day sweep, UDP transport (tested over loopback), and a preflight sandbox that runs a check command in a temporary directory. It builds the `open-humanity` command with three subcommands: `status`, `sweep`, and `test-distress`. The TPM and cuckoo filter lines printed by `status` are fixed text, not live checks.
- `beacon` (Relay Engine): UDP relay daemon. It listens on `0.0.0.0:18098` by default (set `BEACON_PORT` to change it) and keeps the newest 10,000 well-formed signals in memory. It does not yet forward signals, verify signatures, or expire entries. Throughput has not been measured.
- `oh-core` (Volunteer Compute Core): The learner interface and the toy `TinyByteModel`, update compression, signed work unit, update and receipt formats with length-prefixed TCP frames, Turing scoring, and the append-only ledger, plus teaching mode: the `Teacher` interface, `LocalHttpTeacher` (a small loopback-only HTTP client for OpenAI-style chat servers), the signed `TeachingBatch` format and text scoring.
- `oh-coordinator` (Volunteer Compute Coordinator): The `oh-coordinator` command. Listens on `127.0.0.1:18099` by default. Accepts updates and teaching batches from operator-approved volunteer keys on the same port.
- `oh-volunteer` (Volunteer Compute Client): The `oh-volunteer` command. A vault-backed identity key is required for admission, and `--print-key` gives the public key to enroll with the coordinator.
- `oh-infer` (Volunteer Inference): the `oh-infer-coordinator` and `oh-infer-volunteer` commands. Both coordinator listeners are loopback only (`127.0.0.1:18136` for volunteers behind nginx, `127.0.0.1:18137` for the Allen gateway). Rust today; its Omega successor is recorded in the design document.

## Build and test

```bash
cargo test --workspace
```

## Invariant Discipline

- **Zero Telemetry**: No user analytics or tracking. The code contains none.
- **Pure Native Systems**: Written in compiled Rust, plus four shell scripts: contributor checks in `scripts/agent-preflight.sh`, the volunteer compute demos `scripts/demo-local.sh` and `scripts/demo-teach.sh`, and the gap measurement `scripts/volunteer-gap.sh`.
- **Zero Disk Secrets**: The intended credential source is a hardware vault. The coordinator can read its identity seed from atlas-vault, and training volunteer network identity seeds must come from atlas-vault. Each program keeps the recovered seed only in memory, and the contributor preflight script fails if a `.env` file is present. One documented exception: an inference volunteer on a Spark owner's own machine, which has no atlas-vault, keeps its seed in a mode-0600 key file like an SSH key (`oh-infer-volunteer init`), and `run` refuses a key file other users can read. This repository does not implement TPM access itself.

## Human-Directed Agentic Engineering

Development follows Human-Directed Agentic Engineering (HDAE): humans define goals, architecture, constraints, acceptance criteria, and stopping points; agents implement, execute checks, diagnose failures, and revise within those boundaries. Human review retains responsibility for claims, acceptance, and release decisions.

For the documented method and a systems-software case study, see Gregory M. Kurtzer, [*Ginux: Building an Independent Kernel That Runs Linux Userspace through Human-Directed Agentic Engineering* (2026)](https://doi.org/10.5281/zenodo.23682548). This describes engineering, not the assistance network's runtime autonomy or an endorsement.

## License and Governance

Licensed under the Apache License, Version 2.0 (Apache-2.0). See [LICENSE](LICENSE). Project values live in the nonbinding [COVENANT.md](COVENANT.md), which grants and restricts no legal rights.

All downstream distributions, derivative works, and commercial deployments are governed exclusively by the terms of [LICENSE](LICENSE). [CONSTITUTION.md](CONSTITUTION.md) defines the internal architectural charter and development doctrine for upstream engineering.
