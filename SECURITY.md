# Security policy

## Reporting a vulnerability

Report privately. Do not open a public issue, pull request or discussion about it.

1. GitHub: open this repository's Security tab and choose "Report a vulnerability". This
   creates a private advisory that only the maintainers can see. If that option is not shown,
   private vulnerability reporting has not been enabled for this repository yet; use email.
2. Email: drake@aienos.com with the subject `[open-humanity] security report`.

Include the commit or release you tested, the component (path), steps to reproduce, and what an
attacker gains. If the report involves a secret, say where it was exposed and do not send the
secret itself. Encrypted mail is not required; do not post proof-of-concept payloads publicly.

## Response targets

This project has one maintainer; the targets below are best effort and stated honestly.

- Acknowledgement: within 3 working days.
- Triage and severity: within 7 days of acknowledgement.
- Fix or mitigation for confirmed issues: aim for 30 days for high and critical, 90 days
  otherwise, with a status update at least every 14 days until closed.
- Disclosure: coordinated. An advisory is published with credit (unless you ask otherwise)
  once the fix is on the default branch. Default embargo 90 days, negotiable.

## Scope

In scope:

- Volunteer compute transport: encryption, key pinning, replay and reorder refusal, padding
  (`crates/oh-core/src/transport.rs`, `wire.rs`, `identity.rs`).
- Coordinator admission of volunteer keys, work unit and receipt signatures, the append-only
  ledger, and frame size limits (`crates/oh-coordinator`).
- Training data leaving a volunteer's machine, or teaching text bypassing the Personal Data
  Firewall (`crates/oh-volunteer`, `crates/beacon-core/src/firewall.rs`).
- Parsing of untrusted packets in the relay and client (`crates/beacon`, `crates/beacon-client`).
- Crypto helper misuse in `crates/beacon-core/src/crypto.rs`.
- Secret seeds reaching disk, logs or output.

Out of scope: gaps the README already lists as not built (no signing, verification or encryption
of distress signals in the prototype client and relay; no differential privacy; no secure
aggregation; no Sybil resistance beyond operator approval); `atlas-vault` itself.

## Supported versions

Only the default branch `main` (version 0.1.0, early prototype); there is no release. Fixes land
on the default branch only.

## Status

Early prototype; the assistance network's privacy promises are design goals, not current
guarantees (README). There is no certification and no bug bounty. See AUDIT_SCOPE.md for what to
review and how to build and test it.
