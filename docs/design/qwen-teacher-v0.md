# Qwen teacher, version 0

Status: built on branch `feat/qwen-teacher-v0`. Builds on [volunteer-compute-v0.md](volunteer-compute-v0.md); read that first for work units, updates, receipts and Turings.

## Goal

"AI version 1 trains AI version 2" (Drake). A volunteer who runs an open model on their own machine can lend that model's knowledge instead of (or as well as) their processor time. The volunteer's model writes teaching text; the coordinator scores the text in Turings exactly like an update and, if it helps, trains the shared model on it.

## Flow

1. The volunteer runs `oh-volunteer teach --coordinator <addr>`. It connects like any volunteer and receives the current model and a signed work unit.
2. It checks the work unit's signature and that the model matches `base_digest`. Nothing is sent if either check fails.
3. It takes a topic hint from the work unit's shard: at most 200 bytes, printable ASCII only, whitespace collapsed, starting on a word boundary (`oh_volunteer::topic_hint`). The start position comes from the volunteer's seed and the round.
4. It asks the local teacher: "Write a short clear passage that continues or explains this text. Reply with the passage only." followed by the hint (`teach_prompt`).
5. The reply goes through the Personal Data Firewall (`firewall_teaching_text`): home directory paths are rewritten to `~/`; anything that looks like a credential, private key block or path traversal refuses the whole passage. A refused passage is not sent; the volunteer prints "Batch N: not sent, ..." naming the kind of finding, never the finding itself.
6. The firewalled text is signed into a `TeachingBatch` and sent in one frame.
7. The coordinator verifies it, refuses replays, scores it, records the result in the ledger and returns a signed receipt. The volunteer prints "Batch N: accepted, earned X Turings" or "Batch N: rejected".

The teacher is any `oh_core::Teacher`. Version 0 ships `LocalHttpTeacher`, a minimal HTTP/1.1 client (standard library sockets plus serde_json, no new dependencies) for OpenAI-style chat servers: `POST /v1/chat/completions` with `{"model", "messages", "max_tokens", "stream": false}`, answer read from `choices[0].message.content` (or `choices[0].text`). It handles Content-Length, chunked and read-to-close bodies, caps any response at 64 MiB and times out after 10 minutes. `discover_model` reads `GET /v1/models` and takes the first id; the server on the Spark (`aien-serve-http`, 127.0.0.1:18091) rejects any other id, so `teach` discovers it unless `--model` is given.

## What leaves the volunteer's machine

Only the `TeachingBatch`:

    TeachingBatch { run_id: [u8;16], round: u32, base_digest: [u8;32], node_pubkey: [u8;32],
                    text: Vec<u8>, text_digest: [u8;32], sig: Vec<u8> }

`text` is the firewalled passage, `text_digest` is its BLAKE3 hash, and `sig` is an Ed25519 signature over the bincode bytes of the batch with `sig` emptied (the same scheme as `Update`). Nothing else: no prompt, no hint on its own, no raw model output, no model name, no files.

The teacher must be on the same machine. `LocalHttpTeacher` refuses any address that does not resolve only to loopback (127.0.0.0/8 or ::1, which covers `localhost`) unless its `allow_remote` field is set, and the `teach` command does not set it. Reason: the prompt and the unfiltered reply travel between the volunteer and the teacher before the firewall sees them; on loopback they never touch a network.

The hint itself comes from the coordinator's own training shard, so sending it to a local teacher reveals nothing new. A model that echoes its hint will send those (at most 200) shard bytes back inside its passage; tests check that no other shard bytes leave.

Frames: an update frame is unchanged. A teaching frame is the 8 bytes `OHTEACH1` followed by the bincode batch (`send_teaching`, `recv_submission`). An update frame begins with its run id, a BLAKE3-derived value, so it collides with the tag with probability 2^-64; existing volunteers keep working unmodified.

## Scoring

`Scorer::score_text(model, text, steps, seed)` returns bits(base) minus bits(base trained on the text for `steps` steps) on the sealed held-out set, restoring the model afterwards. `steps` is the run's per-work-unit step count; `seed` is the first 8 bytes of `text_digest`, so the same text always gets the same score. Accepted when T > epsilon, as for updates. Batches over 1 MiB are rejected. Replays are refused by text digest through the same ledger `mark_seen` record as delta digests, so the same text under a second key earns nothing.

Ordering inside a round (`Coordinator::finish_round_with_teaching`):

1. The plain mean of the accepted updates is scored against held-out and applied only if T > 0 (unchanged from version 0). It goes first because the updates were all trained from this round's base, so their mean only makes sense applied to that base.
2. Then, for each accepted teaching batch in arrival order, the shared model is trained on the text (same steps and seed as when scored) from wherever it now stands. The result is kept only if held-out bits drop; otherwise that text is undone. The round report counts `taught` (accepted) and `taught_applied` (kept).

A batch's Turings are measured from the round's base, not from the post-aggregate model, so credit does not depend on what other volunteers sent that round.

## Open models

Drake builds for his own model first: Qwen3-30B-A3B-Instruct-2507 served locally by `aien-serve-http`. The `Teacher` seam takes any model behind any OpenAI-style server, and Open Humanity does not police which model a volunteer plugs in. The coordinator judges only the text, and only by held-out bits.

License note: the copy at `~/models/qwen3-30b-a3b-instruct-2507-fp8` ships an Apache License 2.0 `LICENSE` file and its README declares `license: apache-2.0` (read 2026-10-16). Whether the running server loads that exact directory is UNVERIFIED; it reports the model id `qwen3-30b-a3b-instruct-2507`. Whether the Qwen license terms place conditions on using model output to train another model has not been reviewed: UNVERIFIED.

## Not built in version 0

- Streaming replies. Requests set `"stream": false`.
- More than one teacher per volunteer, or choosing between teachers.
- A guard against model collapse beyond Turings on real held-out data. If the held-out set itself came from model output, scores would reward imitation of that model; version 0 relies on the held-out set being human text.
- Differential privacy for teaching text.
- A remote teacher from the command line. `allow_remote` exists in the library only.
- Checking that the text is new rather than paraphrased from earlier batches; replay protection is exact-digest only.
- Fair credit when one passage is cut into many small batches (the Sybil splitting gap from version 0 applies here too).
- A ledger line or receipt for a batch the volunteer refused to send; it never reaches the coordinator.
- Scores at the start of a run partly reward any text at all. A freshly initialised model guesses worse than uniform, so even random bytes earn a few Turings from it (measured +4.8 on the dim 16 test model, against +454.6 for real text; `test_random_bytes_as_teaching_text_score_at_most_zero`). From a model that already knows the language, random bytes score negative (-223.1 in the same test).
