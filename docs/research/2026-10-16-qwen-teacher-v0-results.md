# Qwen teacher v0: first runs against a local Qwen3-30B

Date: 2026-10-16. Branch `feat/qwen-teacher-v0` (based on main `df500d9`). Command: `LOG_DIR=<dir> scripts/demo-teach.sh` with its defaults, run twice (two different chats, same settings; logs kept under `/tmp/oh-demo-teach` and `/tmp/oh-demo-teach-f` on the Spark).

## Setup

- Teacher: `aien-serve-http` on 127.0.0.1:18091, model id `qwen3-30b-a3b-instruct-2507` (found through `GET /v1/models`). Up to 256 tokens per passage. The server samples (temperature 0.7 on the observed request), so the two runs got different passages.
- Coordinator: corpus = repository `LICENSE` (34523 bytes; 31070 training, 3453 held-out sealed), one volunteer slot per round, 2 rounds, 500 steps, dim 32, seed 1.
- One `oh-volunteer teach` for 2 batches, seed 1. No training volunteers, so every change to the model came from teaching text.

## Server response shape (observed)

A 16-token request returned HTTP 200 with `content-type: application/json` and a `content-length` header (not chunked). Body: `{"choices":[{"finish_reason":"stop","index":0,"message":{"content":"...","role":"assistant"}}],"created":...,"id":"chatcmpl-...","model":"qwen3-30b-a3b-instruct-2507","object":"chat.completion","usage":{...}}`. `usage` also carries a server-specific `aien_sampling` block (temperature 0.7, top_k 20, top_p 0.8 on that request). The client reads `choices[0].message.content`.

## Results

| Run | Batch | Passage size | T (Turings) | Held-out bits per byte change | Verdict |
|---|---|---|---|---|---|
| 1 | 1 | 656 bytes | +6955.627 | -2.0150 | accepted, trained on |
| 1 | 2 | 507 bytes | -758.429 | +0.2197 (not applied) | rejected |
| 2 | 1 | 475 bytes | +6569.912 | -1.9032 | accepted, trained on |
| 2 | 2 | 469 bytes | -308.750 | +0.0894 (not applied) | rejected |

Held-out bits per byte: 8.0065 at the start of both runs (same seed, same corpus). Run 1: 5.9915 after batch 1, unchanged by batch 2. Run 2: 6.1032 after batch 1, unchanged by batch 2. The bits-per-byte change is T divided by the 3452 predicted held-out bytes.

The ignored integration test (`cargo test -p oh-core real_local_qwen -- --ignored`) passed once in each chat. Replies: "Volunteers generously give their time and effort to support causes they care about." and "Volunteers give their time and energy to help others and make a positive difference in their communities."

## Reading the numbers

- Batch 1's large score is mostly the toy model learning English byte statistics for the first time. The start value of 8.0065 bits per byte is worse than guessing uniformly (8 bits), so almost any English text helps a fresh model. This says the loop works end to end; it says little about Qwen's text being good teaching material.
- Batch 2 was rejected in both runs. After batch 1 the model already knew the basic statistics, and 500 training steps on a single passage of about 500 bytes overfit to that passage, which raised held-out bits. The scoring did its job: the shared model was not changed, and the ledger shows one credit and one rejection per run.
- Two runs, one seed, two batches each. The pattern repeated, but two samples are not a spread. UNVERIFIED: how teaching compares with training volunteers at equal cost, and whether fewer steps per batch (or longer passages) would turn batch 2 positive.

## After F1: teaching steps scaled to passage length

The coordinator now trains each passage for one pass over it (`oh_core::teaching_steps`: `ceil((bytes - 1) / 8)` steps, capped at the run's step count) instead of the run's 500 steps. Measured without a network in `crates/oh-coordinator/tests/teaching_steps.rs` (same corpus, split, dim, seed and run steps as above; three hand-written passages of 636, 499 and 501 bytes in the style of the Qwen replies; one batch per round through the real coordinator; three orders):

| Order | Steps | Batch 1 T | Batch 2 T | Batch 3 T |
|---|---|---|---|---|
| 1, 2, 3 | fixed 500 (before) | +6799.366 | -123.917 | -655.329 |
| 1, 2, 3 | one pass (after) | +4920.534 | +2181.755 | +233.960 |
| 3, 1, 2 | fixed 500 (before) | +6720.464 | -640.238 | -45.295 |
| 3, 1, 2 | one pass (after) | +3668.047 | +3067.363 | +792.190 |
| 2, 3, 1 | fixed 500 (before) | +7202.845 | -938.601 | -942.333 |
| 2, 3, 1 | one pass (after) | +3669.925 | +2961.191 | +587.442 |

Before, every second and third batch was rejected; after, every batch is accepted and trained on. Held-out bits per byte in the first order end at 5.8813 (calc:e9bbaeaa) after, against 6.0368 (calc:8059ce38) before. The first batch earns less than before, because it now trains for about 80 steps instead of 500; the credit is spread over the batches that actually taught the model something. The design doc has the full sweep (1, 1.5, 2 and 3 passes).

Not yet rerun against the live Qwen server: it did not answer on 127.0.0.1:18091 when this was measured (2026-10-16). UNVERIFIED for real Qwen passages until `scripts/demo-teach.sh` is run again.

## Next measurements

- Rerun `scripts/demo-teach.sh` against the live Qwen server with the one-pass rule, with more batches.
- Teaching against a model that has already trained for several rounds, to separate "Qwen text helps" from "any English helps a fresh model".
- Several seeds and more batches, with mean and spread.
