# Crypto-reuse implementation plan

NOT A MASTER PLAN. Implements open-humanity #29, #30 and #31 under omega-mv #639. Whole-system sequence stays in aien-architecture CURRENT_EXECUTION_PLAN.md.

## Ownership and scope

Inspected base b368ea8f7dcfbc4e7f21d4a9911e4c1c24409440. No open OH PRs or existing crypto-reuse implementation owner at intake. Parent ledger L691; storage worker L693 owns separate repositories. Renda remains sole PR writer. No live deployment, wire-format migration, new cipher, or durable replay subsystem.

## Ordered deliverables

- [x] #29: demonstrate clear-on-full defect with deterministic UUIDs at capacities 0/1/2; return typed ReplayCapacityExceeded without erasing history. Duplicates take precedence. Compile original clear-on-full mutant and require the capacity assertion.
- [x] #30: synthetic all-zero-key forged ciphertext and RFC7748 low-order inputs 0/1/p-1. Both existing helpers check was_contributory before cipher construction. Independently remove each check and require the corresponding agreement assertion. Preserve valid legacy interpretation.
- [x] #31: deterministic byte-at-a-time Read/Write with injected Interrupted, fatal I/O and truncation at header/body boundaries. One terminal bit closes both directions on fatal I/O/protocol/exhaustion; clean boundary EOF only ends reads. Send reserves nonce before writes, receive refuses MAX before I/O. Existing session derivation unchanged, with fixed-shared-secret/fresh-transcript test and transcript-removal mutant.
- [ ] Exact-source Linux full workspace suite and cargo audit; retain any Mac or Linux failures without waiver.
- [ ] Independent review of final source, source/binary/tool pins and raw evidence; focused commits, branch publication and sole-desk intake. No closing keywords until all issue gates pass.

## Contracts and review focus

Empty Read/Write buffers return zero even for a terminal stream, without touching I/O. Interrupted reads/writes retry through standard Read/Write helpers; Interrupted flush retries explicitly. Any non-Interrupted record I/O failure poisons the session, including an error before any header byte, because this wrapper does not retain partial framing state. Later nonempty reads, writes and flushes refuse before raw I/O. Read plaintext buffered before a write failure is not delivered after terminal state. No counter rollback or send retry after a possibly partial record. Authentication, nonce allocation, replay order, session freshness and entropy assumptions remain separate.

Review caller error handling, last usable counter MAX-1, no plaintext after a fatal opposite-direction failure, empty-record behavior, and deterministic mutation classification. Compiler failures, process crashes, timeouts and absent dependencies are INVALID, not detection. Existing tests remain in place.

## Reproduction

`cargo test --locked -p beacon-core -p oh-core`

`python3 scripts/crypto_reuse_mutants.py /absolute/private/output`

The Python program is an external serial qualification orchestrator, not linked product code or a production runtime dependency. It compiles each mutant first, executes the exact test binary, and accepts only the named assertion in the test-source file with one actual failed test. It restores source in finally. Do not run it concurrently with any other build/test in this checkout.

## Compatibility and reachability

`git grep` found ReplayProtector, encrypt_to_peer and decrypt_from_peer call sites only in beacon-core's tests (apart from exports/definitions). Live transport uses checked EphemeralKeyAgreement plus directional SessionCipher, not this replay cache. This fixes exported helper behavior, not a demonstrated live exploit. A new ReplayProtector or restart loses history; its caller must authenticate a new freshness/session boundary. Encryption to a peer public key does not authenticate a sender. Raw shared-DH key use and absent public-key/context KDF/AAD in the legacy helpers remain compatibility limitations. A future version must domain-separate a KDF and bind identities/context explicitly, with versioned ciphertext and interoperability tests; this fix deliberately does not reinterpret old messages.
