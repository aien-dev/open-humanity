# Volunteer compute, version 0 (design)

Status: built and merged (#17); encrypted transport added in follow-up F3. Pure Rust, CPU only.

## Goal

Let volunteers lend spare computer time to train one open model. Each volunteer trains a copy of the model on their own machine and sends back only a small, signed summary of how the model changed (an "update"). A coordinator checks every update against text the volunteers never see, keeps the updates that make the model better, and credits each volunteer for the improvement they caused.

Version 0 proves the full loop end to end on one machine (coordinator plus volunteers talking over the local network) with a toy model. The real model plugs in later behind the same interface.

## Principle change

Until now the README (line 9) said: "It does not train models. It does not collect user data. Nothing is harvested, and no central model learns from people." `docs/SOVEREIGN_MANIFESTO.md` says the same in its own words: "The open network never trains on user queries or builds centralized behavioral databases."

Volunteer compute changes the first half of that promise. The new promise is:

> The model learns only from signed updates and teaching text. Personal data never leaves the volunteer's machine.

Drake approved this direction in writing on 2026-10-16: "implement the Open Humanity idea: start from the beginning, go all the way through". He gave that approval after these decisions:

1. Code and model are licensed AGPL-3.0-or-later.
2. No Python and no CUDA: pure Rust, and CPU is fine for version 0.
3. Volunteers train locally and send back only a compressed update. Each update is scored in Turings (defined below). An update scoring zero or less is rejected. The score is credited to the volunteer.
4. Personal data never leaves the volunteer's machine.
5. Build for Drake's one model first (Qwen as teacher later). Open Humanity does not police what others run.
6. Later, a local model generates teaching text that is scored the same way ("AI v1 teaches AI v2"). Not part of volunteer compute v0; built next, see [qwen-teacher-v0.md](qwen-teacher-v0.md).

The rest of the old promise stands: no user data is collected, and nothing is harvested.

## Invariants

1. The held-out text is sealed. It stays on the coordinator and is never placed in any message sent to a volunteer.
2. A volunteer sends back only its update (a sparse, quantized list of parameter changes), a digest of it, its public key and a signature. It never sends training text back.
3. Every work unit is signed by the coordinator. Every update is signed by the volunteer. Every receipt is signed by the coordinator. Anything with a bad signature is dropped.
4. An update names the exact work unit and starting model it came from (by digest), so it cannot be moved to another run or round.
5. The same update (same delta digest) is accepted at most once per run. A replay is rejected.
6. An update is accepted only if its Turing score is above a small positive threshold.
7. The ledger of credits is append-only.

## Turing definition

The coordinator keeps a sealed held-out set H of bytes that volunteers never see. For a model with parameters p:

    bits(p) = - sum over each predicted byte b in H of log2 P(b | p)

That is the number of bits the model needs to encode H; lower is better. For an update with change d applied to the current model p:

    T = bits(p) - bits(p + d)

T is measured in bits and is called Turings. T > 0 means the update made the model better at predicting text it never trained on. An update is accepted when T > epsilon, a small positive threshold set by the coordinator.

## Wire formats

All messages are Rust structs serialized with bincode 1.3 (the same encoding beacon-core uses). Signatures are Ed25519 from beacon-core (`Keypair::sign`, `verify_signature`). Digests are BLAKE3, 32 bytes.

Signing bytes for a struct are the bincode bytes of that struct with its `sig` field set to empty. The `sig` field then holds the 64-byte signature.

- `WorkUnit { run_id: [u8;16], round: u32, base_digest: [u8;32], shard: Vec<u8>, steps: u32, coordinator_pubkey: [u8;32], sig: Vec<u8> }`
  The coordinator's instruction: "start from the model whose digest is `base_digest`, train for `steps` steps on `shard`".
- `Update { run_id, round, base_digest, work_unit_id: [u8;32], node_pubkey: [u8;32], delta: CompressedDelta, delta_digest: [u8;32], sig: Vec<u8> }`
  `work_unit_id` is the BLAKE3 digest of the work unit's signing bytes. `delta_digest` is the BLAKE3 digest of the bincode bytes of `delta`.
- `CompressedDelta { len: u32, indices: Vec<u32>, values: Vec<i8>, scale: f32 }`
  The change to the model, keeping only the largest few percent of entries by size, each stored as an 8-bit integer times `scale`.
- `Receipt { run_id, round, update_digest: [u8;32], turings: f64, accepted: bool, coordinator_pubkey, sig: Vec<u8> }`
  The coordinator's signed answer: the score and whether the update was kept.

Each message travels in a frame: a 4-byte big-endian length, then that many bytes of bincode. Frames larger than 64 MiB are refused before any memory is set aside for them. Frames never go on the network in the clear: they travel inside the encrypted transport below.

## Encrypted transport

Every connection between `Coordinator::serve` and a volunteer starts with a handshake and then carries only sealed records (`oh_core::transport`, follow-up F3). The primitives are beacon-core's: X25519 key agreement with a fresh one-time key per connection (`EphemeralKeyAgreement`, x25519-dalek) and ChaCha20-Poly1305 (`SessionCipher`, chacha20poly1305). Keys are derived with BLAKE3 `derive_key`. No cryptographic math is written here.

Handshake, one message each way, volunteer first. Each hello is `"OHSEC001" || identity[32] || ephemeral[32] || sig[64]` (136 bytes):

1. The volunteer sends a fresh X25519 public key, signed with its Ed25519 identity over `"open-humanity transport v1: volunteer hello" || identity || ephemeral`.
2. The coordinator sends its own fresh X25519 public key, signed with the run's Ed25519 key over `"open-humanity transport v1: coordinator hello" || the volunteer's whole hello || identity || ephemeral`. Because the signature covers the volunteer's fresh key, a coordinator hello recorded from one session does not verify in another.
3. The volunteer checks the signature and then the coordinator identity against its pin. With `--coordinator-key <hex>` (printed by `oh-coordinator` at start as `coordinator key <hex>`) any other key is refused before a single record is sent. Without a key the volunteer refuses to connect unless `--trust-first-use` is given; then it accepts the first key, prints a warning naming it, and pins it for the rest of the run. Work units must also be signed by the key proven in the handshake.
4. Both sides compute the X25519 shared secret (an all-zero result from a bad public key is refused) and derive two keys: `derive_key("open-humanity transport v1 2026-10-16 volunteer to coordinator", shared || BLAKE3(both hellos))` and the same with "coordinator to volunteer".

Records: `len[4, big endian] || ChaCha20-Poly1305 ciphertext and tag`, with the 4 length bytes as associated data, so changing the length also fails. Everything written between two flushes becomes one record (one wire frame, in practice). The 96-bit nonce is 4 zero bytes and then a 64-bit little-endian record counter for that direction. It is never sent and never reused, since each direction has its own key and counter. The receiver only accepts the next counter value, so a replayed, dropped, reordered or reflected record fails to open and the stream is closed. A connection that fails the handshake is closed and does not take a volunteer slot; the handshake must finish within 30 seconds.

Tests: `crates/oh-core/src/transport.rs` (round trip, tampered ciphertext, tampered length, replayed record, reordered records, reflected record, wrong pinned key, trust on first use, forged coordinator hello, wrong version) and `crates/oh-coordinator/tests/encrypted_transport.rs`. In that test a relay records every byte of a full round (one training and one teaching volunteer) and finds no 16-byte run of the training shards and none of the teaching text. A negative control shows the same check finds both in plain frames.

Teaching mode adds one message, `TeachingBatch { run_id, round, base_digest, node_pubkey, text, text_digest, sig }`, signed the same way and sent in a frame tagged `OHTEACH1`. The coordinator scores it by training a copy of the base on the text and measuring held-out bits, and trains the shared model on accepted text after the round's update aggregate step, keeping each text only if held-out bits drop again. Details: [qwen-teacher-v0.md](qwen-teacher-v0.md).

## Not built in version 0

- Differential privacy (mathematical noise that limits what an update can reveal about its training text).
- Secure aggregation (combining updates so the coordinator cannot see any single one).
- GPU training. Version 0 runs on the CPU.
- A real model. The version 0 learner is a toy that predicts the next byte from the previous byte.
- The DiLoCo outer optimizer. Version 0 combines accepted updates with a plain average.
- Sybil resistance. One person can run many keys, and could split one update across them.
- Protection against held-out leakage from repeated scoring. A volunteer who submits many updates and watches the scores could slowly learn about the held-out set.
- A lasting coordinator identity. The coordinator makes a fresh key at every start, so volunteers need the new key (out of band) for each run, and trust on first use only protects a run, not the next one.
- Hiding sizes and timing. Record lengths and timing are visible on the wire, so an observer can tell a teaching batch from an update and estimate the model size.
- Checking volunteer identities. The coordinator learns each volunteer's key in the handshake but accepts any key; volunteers stay anonymous by design.
- Protection against stalled handshakes. A connection that never finishes the handshake holds up the accept loop for up to 30 seconds.
- Protection against slow or silent volunteers. The coordinator waits for one connection per shard and reads each update with a 10 minute timeout, so one stalled volunteer holds up the round.
- A ledger line for dropped updates. Updates with a bad signature, or that answer the wrong work unit, get no receipt and no ledger line; they are only logged. Accepted updates get a credit line and every other update that gets a receipt gets a rejected line.

## Open questions

- Why the volunteer runs trail the single-process baseline. At equal total steps the volunteer runs end about 0.33 bits per byte behind (`docs/research/2026-10-16-v0-loopback-results.md`). Likely causes are the plain average of updates trained from the same start and keeping only 5% of each update, but neither has been measured on its own. Next measurement: rerun with `--keep 1.0` (no compression) and with one volunteer, to split the two effects.
