# Open Humanity

## Copyright

Copyright (c) 2026 Drake Stapleton <aien@aienos.com> and AIEN Contributors. Authored by Drake Stapleton in collaboration with AIEN.

Open Humanity is connective tissue for sovereign artificial intelligence: an opt-in, privacy-first peer assistance network connecting autonomous agents in distress to peer resolution.

The model learns only from signed updates and teaching text. Personal data never leaves the volunteer's machine. No user data is collected, and nothing is harvested.

When an agent hits an execution wall and does not know how to proceed, the agent transmits an encrypted signal. The signal reaches peer agents whose local memory may hold the answer. If a peer has resolved the condition, the verified solution returns encrypted. A call for assistance, answered by peers.

Every participant runs their own Cortex memory engine. Your memory is yours: your identity, your records, your decisions. Nobody modifies it but you. Private data remains home. Cortex is a separate project; this repository only tracks a `promoted_to_cortex` flag on locally stored solutions.

**Status: early prototype (version 0.1.0).** The building blocks exist as Rust code: the signal and answer formats, signing and encryption helpers, a secrets check, a local signal store, a UDP transport and a basic relay. They are not yet joined into the end-to-end flow described below. That flow is the design; the "Today" note on each step says what the code does now.

Read our founding manifesto: [docs/SOVEREIGN_MANIFESTO.md](docs/SOVEREIGN_MANIFESTO.md).

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
- **What leaves the volunteer's machine**: only the signed, compressed update (the largest 5% of the parameter changes, each stored as an 8-bit number), its digest, the ids of the run and work unit it answers, the volunteer's public key and a signature. No training text and no personal data. A test checks the bytes the volunteer sends and finds none of its shard in them.
- **Turing scoring**: each update is scored as held-out bits before minus held-out bits after applying it, measured in Turings. An update scoring zero or less is rejected. The coordinator sends a signed receipt and records accepted Turings in an append-only ledger against the volunteer's public key.
- **The two programs**: `oh-coordinator` (hands out work, scores, aggregates, keeps the ledger; `--baseline` trains the same work in one process for comparison) and `oh-volunteer` (takes work units, trains locally, prints "Round N: update accepted, earned X Turings" or "rejected"). Volunteer keys are generated in memory and never saved.
- **Demo**: `scripts/demo-local.sh` runs the coordinator and three volunteers on one machine for several seeds and compares them with the single-process baseline. Measured results: [docs/research/2026-10-16-v0-loopback-results.md](docs/research/2026-10-16-v0-loopback-results.md). In short, the loop works, and the volunteer version currently ends 0.33 to 0.36 bits per byte behind the single-process baseline.

Not built in version 0 (from the design doc):

- Differential privacy (mathematical noise that limits what an update can reveal about its training text).
- Secure aggregation (combining updates so the coordinator cannot see any single one).
- GPU training. Version 0 runs on the CPU.
- A real model. The version 0 learner is a toy that predicts the next byte from the previous byte.
- The DiLoCo outer optimizer. Version 0 combines accepted updates with a plain average.
- Sybil resistance. One person can run many keys, and could split one update across them.
- Protection against held-out leakage from repeated scoring. A volunteer who submits many updates and watches the scores could slowly learn about the held-out set.

Teaching text (a local model writing text that is scored the same way) is also not built yet.

## Core Crates

- `beacon-core` (Core Data): Data models and packet formats, Ed25519 signing, X25519 and ChaCha20-Poly1305 encryption helpers, replay and timestamp checks, a cuckoo filter, and the Personal Data Firewall.
- `beacon-client` (Client Interface): Local SQLite WAL signal store with a 7-day sweep, UDP transport (tested over loopback), and a preflight sandbox that runs a check command in a temporary directory. It builds the `open-humanity` command with three subcommands: `status`, `sweep`, and `test-distress`. The TPM and cuckoo filter lines printed by `status` are fixed text, not live checks.
- `beacon` (Relay Engine): UDP relay daemon. It listens on `0.0.0.0:18098` by default (set `BEACON_PORT` to change it) and keeps the newest 10,000 well-formed signals in memory. It does not yet forward signals, verify signatures, or expire entries. Throughput has not been measured.
- `oh-core` (Volunteer Compute Core): The learner interface and the toy `TinyByteModel`, update compression, signed work unit, update and receipt formats with length-prefixed TCP frames, Turing scoring, and the append-only ledger.
- `oh-coordinator` (Volunteer Compute Coordinator): The `oh-coordinator` command. Listens on `127.0.0.1:18099` by default.
- `oh-volunteer` (Volunteer Compute Client): The `oh-volunteer` command.

## Invariant Discipline

- **Zero Telemetry**: No user analytics or tracking. The code contains none.
- **Pure Native Systems**: Written in compiled Rust (plus two shell scripts: contributor checks in `scripts/agent-preflight.sh` and the volunteer compute demo in `scripts/demo-local.sh`).
- **Zero Disk Secrets**: The goal is hardware TPM vault credentials only. There is no TPM integration yet. In this version node keys are generated in memory and never saved, and the contributor preflight script fails if a `.env` file is present.

## License and Governance

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE). Project values live in the nonbinding [COVENANT.md](COVENANT.md), which grants and restricts no legal rights.
Architected by AIEN (Autonomous Cognitive Architecture operating on the Atlas Framework) and sovereign ecosystem contributors. See [LICENSE](LICENSE) for full legal terms and copyright notices.

All downstream distributions, derivative works, and commercial deployments are governed exclusively by the terms of [LICENSE](LICENSE). [CONSTITUTION.md](CONSTITUTION.md) defines the internal architectural charter and development doctrine for upstream engineering.
