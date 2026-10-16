# Volunteer compute, version 0 (design)

Status: design for the first working slice. Pure Rust, CPU only.

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
6. Later, a local model generates teaching text that is scored the same way ("AI v1 teaches AI v2"). Not part of version 0.

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

Over TCP, each message travels in a frame: a 4-byte big-endian length, then that many bytes of bincode. Frames larger than 64 MiB are refused before any memory is set aside for them.

## Not built in version 0

- Differential privacy (mathematical noise that limits what an update can reveal about its training text).
- Secure aggregation (combining updates so the coordinator cannot see any single one).
- GPU training. Version 0 runs on the CPU.
- A real model. The version 0 learner is a toy that predicts the next byte from the previous byte.
- The DiLoCo outer optimizer. Version 0 combines accepted updates with a plain average.
- Sybil resistance. One person can run many keys, and could split one update across them.
- Protection against held-out leakage from repeated scoring. A volunteer who submits many updates and watches the scores could slowly learn about the held-out set.
- Transport encryption. Frames travel in the clear over TCP. Version 0 is meant for loopback only; the shard a volunteer receives and the update it returns are readable by anyone on the path.
- Pinned coordinator identity by default. Unless `--coordinator-key` is given, a volunteer trusts the first coordinator key it sees and holds to it for the rest of its run.
- Protection against slow or silent volunteers. The coordinator waits for one connection per shard and reads each update with a 10 minute timeout, so one stalled volunteer holds up the round.
- A ledger line for dropped updates. Updates with a bad signature, or that answer the wrong work unit, get no receipt and no ledger line; they are only logged. Accepted updates get a credit line and every other update that gets a receipt gets a rejected line.

## Open questions

- Why the volunteer runs trail the single-process baseline. At equal total steps the volunteer runs end about 0.33 bits per byte behind (`docs/research/2026-10-16-v0-loopback-results.md`). Likely causes are the plain average of updates trained from the same start and keeping only 5% of each update, but neither has been measured on its own. Next measurement: rerun with `--keep 1.0` (no compression) and with one volunteer, to split the two effects.
