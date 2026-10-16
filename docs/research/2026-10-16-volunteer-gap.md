# Volunteer gap: where the 0.36 bits per byte go

Date: 2026-10-16. Status: measurement note. Every number marked OBSERVED was measured on the DGX Spark (20 Arm CPU cores, CPU only, release build) from the code on branch `research/volunteer-gap` (on top of main `13953d7`). Anything not measured is marked UNVERIFIED.

## Summary for Drake

1. Three volunteers ended about 0.36 bits per byte behind one machine doing the same work (4.75 against 4.39). We now know where that goes. About 0.20 of it is the shrinking of each update to its largest 5% of entries before it is sent. The remaining 0.16 is the averaging: three volunteers start from the same model and their three changes are averaged, so the shared model moves roughly as far as one volunteer's work per round, while the single machine gets all three moves one after another.
2. Storing the kept entries as 8-bit numbers costs nothing we can measure. Which volunteer gets which shard, and how the work is split into rounds, are not the cause either: splitting the same work into more, shorter rounds makes things worse, and shard order moves the result less than the seed-to-seed spread.
3. The textbook fix for the averaging loss, scaling the average up (an "outer learning rate"), does not work on this toy. Scaling by 1.25 or 1.5 gains 0.07 to 0.09 bits per byte, which is inside two spreads; scaling by 2 or more makes the first round overshoot so badly that the coordinator's safety check throws every round away and the model never learns anything.
4. The default is changed: volunteers now keep 20% of each update instead of 5%. On this corpus that recovers 0.18 bits per byte (half the gap) for an update of about 17.7 KB instead of 4.4 KB, still a quarter of the full 70.8 KB. Measured live over loopback: 4.52 bits per byte against the 4.39 baseline, a gap of 0.13.
5. Everything here is on the same toy as before: a next-byte model with 17,696 parameters, one 34 KB file, one machine. The direction of each effect is what carries over; the sizes will not.

## Question

At equal total training steps (10 rounds x 3 volunteers x 500 steps = 15,000), why do 3 volunteers over loopback end at about 4.74 held-out bits per byte while the single-process `--baseline` ends at 4.39 (`docs/research/2026-10-16-v0-loopback-results.md`)? Candidates: (a) compression, (b) averaging, (c) shard assignment by connection order, (d) rounds versus local steps.

## Setup

Corpus: the repository `LICENSE` file, 34,523 bytes, sha256 starting `0d96a4ff68ad6d4b`. Last 10% (3,453 bytes) sealed as held-out; the first 31,070 bytes split into 3 contiguous shards. Model: `TinyByteModel`, width 32, 17,696 parameters, learning rate 0.1, batch 8. Seeds 1, 2, 3 for the starting model; shard `i` is trained with the seed a volunteer started with `--seed (seed + 1 + i)` would use, exactly as `--baseline` assumes.

Method: baseline first, then one variable at a time from the v0 settings (keep 0.05, plain mean, per-update score gate on, 10 x 500), 3 seeds each, mean and sample standard deviation reported.

New in this change, so each variable can be isolated:

- `oh-coordinator --simulate`: runs the volunteer protocol in one process. Each round every shard is trained from the round's base model exactly as `oh_volunteer::train` does, the delta goes through the volunteer's compression (`--keep-fraction`, or `--no-compression` for the exact f32 delta), then the coordinator's per-update score gate (`--no-update-gate` to let every update through), then the aggregate step (`aggregate`, the same function `finish_round` uses) with `--outer-lr`, applied only if it lowers held-out bits, as live. `--shard-order rotate` hands shard `i` to volunteer `(i + round) mod 3` each round, a stand-in for connection order changing. Signatures, receipts and the ledger are left out; they do not touch the numbers. Runs repeat exactly.
- `oh-coordinator --outer-lr <f>` (live and simulated): the mean of the accepted updates is multiplied by `f` before it is scored and applied. Default 1, the plain mean, bit-identical to the old code.
- `scripts/demo-local.sh` takes `KEEP` (volunteer `--keep`) and `OUTER_LR`.
- `scripts/volunteer-gap.sh` runs every table below.

Validation of the simulation against the real network path, OBSERVED: live loopback at v0 settings, run A: 4.6952, 4.7640, 4.7261 (mean 4.7284, spread 0.0345); run B: 4.6715, 4.7778, 4.7246 (mean 4.7246, spread 0.0532). Simulation at v0 settings, fixed shard order: 4.6952, 4.7745, 4.7734 (mean 4.7477, spread 0.0455). Seed 1 of live run A matches the simulation to all four digits (that run happened to connect the volunteers in order); the other seeds differ by up to 0.05, which is the connection-order effect (see (c)). The simulation is a faithful stand-in. The baseline reproduced the earlier note exactly: 4.3584, 4.3878, 4.4294.

## Exact commands

From the repository root, after `cargo build --release -p oh-coordinator -p oh-volunteer`:

    # every simulated table below (about 3.5 minutes)
    scripts/volunteer-gap.sh

    # one cell by hand, for example keep 0.2
    target/release/oh-coordinator --corpus LICENSE --rounds 10 --volunteers-per-round 3 \
        --steps 500 --dim 32 --seed 1 --simulate --keep-fraction 0.2

    # live loopback at v0 settings, and at the new default
    KEEP=0.05 LOG_DIR=/tmp/oh-gap/live-default BASE_PORT=18200 scripts/demo-local.sh
    KEEP=0.2  LOG_DIR=/tmp/oh-gap/live-keep02  BASE_PORT=18400 scripts/demo-local.sh

## Results (all OBSERVED; final held-out bits per byte, lower is better)

Reference:

| Setting | Seed 1 | Seed 2 | Seed 3 | Mean | Spread | Accepted of 30 |
|---|---|---|---|---|---|---|
| baseline (one process, exact, sequential) | 4.3584 | 4.3878 | 4.4294 | 4.3919 | 0.0357 | n/a |
| simulate, v0 settings (keep 0.05, mean, gate on) | 4.6952 | 4.7745 | 4.7734 | 4.7477 | 0.0455 | 16.0 |

Gap at v0 settings: 4.7477 - 4.3919 = 0.3558 bits per byte (calc:a20cdd1a).

### (a) Compression, everything else v0

| Setting | Seed 1 | Seed 2 | Seed 3 | Mean | Spread | Accepted of 30 | Update size |
|---|---|---|---|---|---|---|---|
| keep 0.05 (v0) | 4.6952 | 4.7745 | 4.7734 | 4.7477 | 0.0455 | 16.0 | about 4.4 KB |
| keep 0.10 | 4.5663 | 4.6415 | 4.6766 | 4.6281 | 0.0564 | 16.0 | about 8.9 KB |
| keep 0.20 | 4.5098 | 4.5970 | 4.5987 | 4.5685 | 0.0508 | 15.7 | about 17.7 KB |
| keep 0.50 | 4.4959 | 4.5676 | 4.5806 | 4.5480 | 0.0456 | 15.3 | about 44 KB |
| keep 1.00 (8-bit only, no top-k) | 4.4947 | 4.5669 | 4.5823 | 4.5480 | 0.0468 | 15.3 | about 88 KB |
| no compression (exact f32) | 4.4940 | 4.5671 | 4.5827 | 4.5479 | 0.0474 | 15.3 | 70.8 KB |

Update sizes are arithmetic from the wire format (one 4-byte index and one 1-byte value per kept entry, plus 24 bytes of header; dense f32 is 4 bytes per parameter plus 8): 17,696 x 0.05 x 5 + 24 = 4,448 bytes (calc:3e8f2afe); 17,696 x 0.2 x 5 + 24 = 17,720 bytes (calc:bd43f096); dense 17,696 x 4 + 8 = 70,792 bytes (calc:f9e7bff5). Sizes were not measured on the wire: UNVERIFIED as exact byte counts, the formula is from `CompressedDelta` and `bincode`.

Reading: top-k at 5% costs 4.7477 - 4.5480 = 0.1997 bits per byte (calc:319d09bb), 56% of the gap. The 8-bit quantization costs 0.0001, nothing. Keep 0.2 recovers 0.1792 of the 0.1997, that is 50% of the whole gap (calc:be464161), for 4x the bytes; going to 0.5 or 1.0 adds 0.02 more, inside the spread, for 2.5x to 5x more bytes again.

### (b) Aggregation, everything else v0

| Setting | Seed 1 | Seed 2 | Seed 3 | Mean | Spread | Accepted of 30 |
|---|---|---|---|---|---|---|
| outer lr 1 (plain mean, v0) | 4.6952 | 4.7745 | 4.7734 | 4.7477 | 0.0455 | 16.0 |
| outer lr 1.25 | 4.6240 | 4.6832 | 4.7311 | 4.6794 | 0.0536 | 18.0 |
| outer lr 1.5 | 4.5924 | 4.6860 | 4.6935 | 4.6573 | 0.0563 | 19.3 |
| outer lr 2 | 5.5995 | 8.0000 | 7.9989 | 7.1995 | 1.3856 | 30.0 |
| outer lr 3 (sum of 3) | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 | 30.0 |
| outer lr 4 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 | 30.0 |
| per-update gate off (mean of all 3) | 4.9923 | 5.0315 | 5.0386 | 5.0208 | 0.0249 | 30.0 |
| exact, gate off (plain mean of 3 exact deltas) | 4.7760 | 4.8603 | 4.8420 | 4.8261 | 0.0443 | 30.0 |
| gate off, outer lr 3 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 | 30.0 |

Reading: a final value equal to the start (8.0065, 8.0000, 7.9989) means the aggregate was never applied. Seed 1 at outer lr 3, rounds 1 to 3: `aggregate_T=-12398`, `-13486`, `-14823`, `applied=no`. The first round's 500-step delta from a blank model is already a very large move (it takes held-out bits from 8.0 to 5.6 on its own); doubled or tripled it overshoots, the aggregate gate discards the round, the model stays at the start, and every later round repeats the same failure. All 30 updates are "accepted" because each is scored against the unchanged start model. This is a stall, not a divergence: the gate protected the model, at the price of wasting all volunteer work. Outer lr 1.25 and 1.5 gain 0.07 and 0.09, which is one to two spreads, and the usable window closes between 1.5 and 2.

The plain mean of three exact deltas with no gate ends 0.43 behind the baseline (4.8261 against 4.3919): that is the averaging loss by itself. The per-update gate recovers 0.28 of it (4.5479 with the gate) by dropping updates that do not help on the held-out tail on their own; about half of all updates are dropped, so about half of the volunteer work is thrown away each round. Note the gate is a selection on held-out data, repeated 30 times; the leakage risk from the design note applies.

### (c) Shard order, everything else v0

| Setting | Seed 1 | Seed 2 | Seed 3 | Mean | Spread | Accepted of 30 |
|---|---|---|---|---|---|---|
| fixed: shard i to volunteer i (what baseline assumes) | 4.6952 | 4.7745 | 4.7734 | 4.7477 | 0.0455 | 16.0 |
| rotate: shard i to volunteer (i + round) mod 3 | 4.6820 | 4.7654 | 4.7310 | 4.7261 | 0.0419 | 16.7 |
| live loopback run A (connection order) | 4.6952 | 4.7640 | 4.7261 | 4.7284 | 0.0345 | 16.0 |
| live loopback run B (connection order) | 4.6715 | 4.7778 | 4.7246 | 4.7246 | 0.0532 | 16.0 |

Reading: the shard order only changes which training seed samples which shard; the shards themselves and the baseline's shards are the same bytes (`shard_ranges` in both paths). The effect is 0.02 on the mean, under one spread. Connection order is not a cause of the gap; it is why live runs with the same seeds differ by a few hundredths. Making the assignment deterministic would need a protocol change (the volunteer would have to identify itself before the work unit is sent) for no measurable gain, so it was not done.

### (d) Rounds versus local steps, same 15,000 total steps

| Setting | Seed 1 | Seed 2 | Seed 3 | Mean | Spread | Accepted |
|---|---|---|---|---|---|---|
| baseline 10 x 500 | 4.3584 | 4.3878 | 4.4294 | 4.3919 | 0.0357 | n/a |
| baseline 25 x 200 | 4.4241 | 4.4574 | 4.4309 | 4.4375 | 0.0176 | n/a |
| baseline 50 x 100 | 4.3653 | 4.4816 | 4.3950 | 4.4140 | 0.0604 | n/a |
| simulate 5 x 1000 | 4.7224 | 4.7182 | 4.7798 | 4.7401 | 0.0344 | 9.0 of 15 |
| simulate 10 x 500 (v0) | 4.6952 | 4.7745 | 4.7734 | 4.7477 | 0.0455 | 16.0 of 30 |
| simulate 25 x 200 | 4.8772 | 4.9489 | 4.8279 | 4.8847 | 0.0608 | 28.7 of 75 |
| simulate 50 x 100 | 5.0235 | 5.0488 | 5.0312 | 5.0345 | 0.0130 | 42.3 of 150 |

Reading: the baseline barely cares how the steps are split (4.39 to 4.44). The volunteer run gets worse with more, shorter rounds: 0.14 worse at 25 x 200 and 0.29 worse at 50 x 100. Shorter local runs give smaller, noisier deltas, of which 5% top-k keeps even less that matters, and the acceptance rate falls from 53% to 28%. Fewer, longer rounds (5 x 1000) are no better than 10 x 500. Rounds versus steps is not the cause; the v0 split is already at the good end.

### Combinations

| Setting | Seed 1 | Seed 2 | Seed 3 | Mean | Spread |
|---|---|---|---|---|---|
| exact, outer lr 3 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 |
| exact, gate off, outer lr 3 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 |
| keep 0.05, outer lr 3, 50 x 100 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 |
| exact, outer lr 3, 50 x 100 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 |
| keep 0.20, outer lr 3 | 8.0065 | 8.0000 | 7.9989 | 8.0018 | 0.0041 |

Reading: summing the three updates stalls the run in every combination tried, including shorter local runs (100 steps). On this model the first-round delta is too large to be scaled, whatever else changes.

### Live validation of the new default (OBSERVED)

`KEEP=0.2 scripts/demo-local.sh`, 10 rounds, 3 volunteers over loopback: 4.4811, 4.5650, 4.5109 (mean 4.5190, spread 0.0425), rounds applied 10 of 10 for every seed, updates accepted 18, 17, 16 of 30. Baseline unchanged at 4.3919. Gap 0.13 live, 0.18 in the simulation (4.5685); the difference is connection order, as in (c).

## Honest reading

- Measured decomposition of the 0.36 gap at v0 settings: 0.20 from keeping only 5% of each update (calc:319d09bb), 0.16 from averaging three updates trained from the same start and gating them (calc:3eceb44e). The 8-bit storage, the shard order and the round split contribute nothing measurable.
- The averaging loss has no cheap fix here. A plain mean of three parallel changes moves the model about as far as one change; scaling it up is the standard answer (DiLoCo's outer step) but on this toy the first round is far too large a move to scale, so lr 2 and above stall and 1.25 to 1.5 gain only one to two spreads. DiLoCo uses an outer optimizer with momentum and far smaller inner learning rates, neither of which exists here: UNVERIFIED whether that would close the gap on this model.
- The per-update gate does two things at once: it protects the model and pays volunteers only for help, but it also throws away about half of the work and steers the model toward whatever shard resembles the held-out tail. With a real model and a held-out set that is not the tail of the same file, UNVERIFIED how much of the 0.16 remains.
- The numbers are from a 17,696-parameter next-byte model on one 34 KB file. Expect the sign of each effect to hold on a real model, not the size.

## Recommendation (defaults)

- `oh-volunteer --keep`: change the default from 0.05 to 0.2. Done in this change (`DEFAULT_KEEP_FRACTION`), with `demo-local.sh` following. Measured: 4.7477 to 4.5685 simulated and 4.7284 to 4.5190 live, for 17.7 KB instead of 4.4 KB per update (dense would be 70.8 KB). Keep 0.5 and 1.0 are inside the spread of 0.2 and cost 2.5x and 5x more bytes.
- `oh-coordinator --outer-lr`: keep 1 (the plain mean). 2 and above stall every seed; 1.25 to 1.5 are inside two spreads of 1. Flag added so the next aggregate design (momentum or error feedback) can be measured the same way.
- Rounds and local steps: keep 10 x 500. More, shorter rounds are worse (up to 0.29); fewer, longer rounds are no better.
- Shard assignment: leave as is. Connection order moves the result by at most a few hundredths and the baseline already trains the same bytes.
- Next things worth measuring, in order: error feedback on the compression (send the dropped remainder next round), an outer step with momentum at lr 1, and a held-out set drawn from across the corpus rather than its tail.
