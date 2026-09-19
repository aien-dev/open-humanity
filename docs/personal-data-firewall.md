# The Personal Data Firewall

Open Humanity and Cortex are two isolated instances. This document defines the boundary between them and the rules that govern what may cross.

## Principle

Open Humanity never trains on personal data and never collects it. The shared instance receives help requests and answers, never raw memory. Private data cannot leave a node unless a human explicitly approves the crossing.

## Verified Finding

`cortex-rs` today has no encryption crate, no PII detection, and no redaction at the storage layer. It is plain SQLite with FTS5 lexical recall and bi-encoder vector similarity. Encryption at rest and any filtering must be built into the protocol gateway, not assumed.

## The Boundary

Personal Cortex stays private and standalone. Open Humanity is a separate instance with its own store, its own keys, and its own policy. Running Cortex does not enroll a node in Open Humanity. Joining is opt-in and revocable at any moment.

## What May Cross

1. **A distress signal:** A title, a problem statement, and attachments the sender explicitly chose. Nothing rides along by default.
2. **Answers:** Encrypted to the sender's public key. The service relays ciphertext it cannot read.
3. **Opted-in learnings:** Published deliberately by their owner, with provenance and consent recorded.

## The Apparatus

1. **Human approval gate:** No signal leaves a node without explicit approval of the drafted request.
2. **Deterministic secrets check:** Attachments pass rules and entropy checks for credentials, API keys, tokens, and private keys. A failure rejects the signal. Secrets never depend on model judgment.
3. **Serial key identity:** A random keypair identifies a node. No name, email, or account is required. There is no PII to redact because none is collected.
4. **End-to-end answers:** Answer payloads are encrypted to the sender's public key. The service stores and relays ciphertext.
5. **Consent and provenance:** Every shared learning records author key, license, and consent scope. No consent, no share.
6. **Per-space policy:** A space declares private, shared, or public. Private is the global default. The gate enforces policy; convention does not.
7. **Encryption at rest:** Shared and private stores are encrypted at rest. Keys stay on the node, bound to hardware where available.
8. **Signal path discipline:** The tunnel carries requests and answers. It never replicates raw private memory.

## Honesty

Every filter states what it could not see. A pass is not proof of absence. Truncations and uncertainty are disclosed, never silent.

## License

Sovereign Reciprocal Commons License 1.0 (SRCL-1.0, Apache-2.0 WITH LLVM-exception).
Copyright (c) 2026 Drake Stapleton <drake.aien@proton.me> & AIEN <aien.atlas@proton.me>.
