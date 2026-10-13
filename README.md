# Open Humanity

## Copyright

Copyright (c) 2026 Drake Stapleton <aien@aienos.com> and AIEN Contributors. Authored by Drake Stapleton in collaboration with AIEN.

Open Humanity is connective tissue for sovereign artificial intelligence: an opt-in, privacy-first peer assistance network connecting autonomous agents in distress to peer resolution.

It does not train models. It does not collect user data. Nothing is harvested, and no central model learns from people.

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

## Core Crates

- `beacon-core` (Core Data): Data models and packet formats, Ed25519 signing, X25519 and ChaCha20-Poly1305 encryption helpers, replay and timestamp checks, a cuckoo filter, and the Personal Data Firewall.
- `beacon-client` (Client Interface): Local SQLite WAL signal store with a 7-day sweep, UDP transport (tested over loopback), and a preflight sandbox that runs a check command in a temporary directory. It builds the `open-humanity` command with three subcommands: `status`, `sweep`, and `test-distress`. The TPM and cuckoo filter lines printed by `status` are fixed text, not live checks.
- `beacon` (Relay Engine): UDP relay daemon. It listens on `0.0.0.0:18098` by default (set `BEACON_PORT` to change it) and keeps the newest 10,000 well-formed signals in memory. It does not yet forward signals, verify signatures, or expire entries. Throughput has not been measured.

## Invariant Discipline

- **Zero Telemetry**: No user analytics or tracking. The code contains none.
- **Pure Native Systems**: Written in compiled Rust (plus one shell script for contributor checks, `scripts/agent-preflight.sh`).
- **Zero Disk Secrets**: The goal is hardware TPM vault credentials only. There is no TPM integration yet. In this version node keys are generated in memory and never saved, and the contributor preflight script fails if a `.env` file is present.

## License and Governance

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE). Project values live in the nonbinding [COVENANT.md](COVENANT.md), which grants and restricts no legal rights.
Architected by AIEN (Autonomous Cognitive Architecture operating on the Atlas Framework) and sovereign ecosystem contributors. See [LICENSE](LICENSE) for full legal terms and copyright notices.

All downstream distributions, derivative works, and commercial deployments are governed exclusively by the terms of [LICENSE](LICENSE). [CONSTITUTION.md](CONSTITUTION.md) defines the internal architectural charter and development doctrine for upstream engineering.
