# Volunteer compute v0: loopback results

Date: 2026-10-16. Status: measurement note. Every number below is OBSERVED on the DGX Spark (20 Arm CPU cores, CPU only, release build), from the code at commit `42669cb` on branch `feat/volunteer-compute-v0`.

## Summary for Drake

1. The whole loop works on one machine: a coordinator and three volunteer programs talk over the local network, the volunteers train and send back only small signed updates, the coordinator scores each one in Turings, pays out credit, and the shared model gets better every round.
2. Starting from about 8.0 bits per byte (a model that knows nothing), ten rounds brought the shared model to about 4.7 bits per byte on text it never trained on.
3. The same training done in one program, with no network and no shrinking of updates, reached about 4.4 bits per byte. So the volunteer version is about 0.33 to 0.36 bits per byte behind. That gap is the price of averaging and of keeping only 5% of each update; v0 does nothing to close it yet.
4. This proves the plumbing, not model quality. The model is a toy that predicts the next letter from the previous letter, the corpus is one 34 KB file, and everything ran on one computer.

## What was run

Command, from the repository root:

    LOG_DIR=/tmp/oh-demo-logs scripts/demo-local.sh

Defaults used: 10 rounds, 3 volunteers, 500 training steps per work unit, model width 32 (`TinyByteModel`, 17,696 parameters), seeds 1, 2 and 3, 5% of each update kept. Corpus: the repository `LICENSE` file, 34,523 bytes, sha256 starting `0d96a4ff68ad6d4b`. The last 10% (3,453 bytes) is the sealed held-out set; the first 31,070 bytes are split into 3 training shards, one per volunteer, reused every round.

For each seed the script runs:

- `oh-coordinator` with 3 `oh-volunteer` processes (volunteer seeds `seed + 1` to `seed + 3`) over loopback TCP.
- `oh-coordinator --baseline`: one model from the same starting seed, trained in one process on the same 3 shards for the same total steps (10 rounds x 3 shards x 500 steps = 15,000 steps), with full updates and no averaging.

The whole script took about 9 seconds.

## Numbers

Final held-out bits per byte (lower is better). The script was run twice.

| Seed | Start | Volunteers, run 1 | Volunteers, run 2 | Baseline (both runs) |
|---|---|---|---|---|
| 1 | 8.0065 | 4.6533 | 4.6902 | 4.3584 |
| 2 | 8.0000 | 4.7929 | 4.7204 | 4.3878 |
| 3 | 7.9989 | 4.8026 | 4.7585 | 4.4294 |
| Mean | | 4.7496 | 4.7230 | 4.3919 |
| Spread (sample std dev) | | 0.0835 | 0.0342 | 0.0357 |

Updates accepted (out of 30 per seed): run 1: 16, 14, 15. Run 2: 16, 16, 17. Rounds whose averaged update was applied (out of 10): run 1: 10, 9, 10. Run 2: 10, 10, 10.

Round by round, seed 1, run 1 (coordinator log):

| Round | Updates accepted | Turings for the averaged update | Held-out bits per byte after |
|---|---|---|---|
| 1 | 3 | 8211.8 | 5.6276 |
| 2 | 2 | 485.9 | 5.4869 |
| 3 | 2 | 452.5 | 5.3558 |
| 4 | 2 | 399.8 | 5.2400 |
| 5 | 2 | 167.3 | 5.1915 |
| 6 | 1 | 538.0 | 5.0356 |
| 7 | 1 | 389.5 | 4.9228 |
| 8 | 1 | 493.1 | 4.7800 |
| 9 | 1 | 301.4 | 4.6926 |
| 10 | 1 | 135.7 | 4.6533 |

Baseline, seed 1, held-out bits per byte after each round's 1,500 steps: 5.2518, 4.9753, 4.8497, 4.6910, 4.6329, 4.5255, 4.4080, 4.4396, 4.3617, 4.3584. The baseline has no score gate, so it can get worse in a round (round 8); the volunteer run cannot, because a round is thrown away unless the averaged update lowers held-out bits.

## Honest reading

- The pipeline is proven end to end on loopback: signed work units go out, only compressed signed updates come back, every update gets a signed receipt and a Turing score, credits land in the ledger, and held-out bits never rose in any volunteer round.
- The volunteer run is worse than the single-process baseline at equal total steps, by about 0.33 to 0.36 bits per byte on average. Expected causes: the plain mean of 3 updates trained from the same start moves the model about as far as one volunteer's work, and keeping 5% of entries drops most of each update. Which cause dominates is UNVERIFIED; it was not measured separately.
- Run to run, the volunteer numbers change even with the same seeds, because which volunteer gets which shard depends on who connects first. The baseline is deterministic and repeated exactly.
- About half of all updates were rejected. In seed 1, run 1, the update for the middle shard was rejected in every round from round 2 on, and the update for the first shard from round 6 on; from round 6 only the last shard, which sits next to the held-out tail, still helped. The score gate did its job, and that volunteer earned no credit for those rounds.
- None of this says anything about a real model. The learner is a next-byte toy, the corpus is one small file, the network is one machine's loopback, and the held-out set is scored many times (the leakage risk listed in `docs/design/volunteer-compute-v0.md` applies).
