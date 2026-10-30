# Volunteer inference, version 0 (design and protocol `OHINF001`)

Status (2026-10-26): IMPLEMENTED and EXERCISED on loopback with a fake engine (`crates/oh-infer`, tests below). Not deployed. Public routing is OFF and stays off until Drake confirms it; the open blocker is under "Before routing goes on".

## Goal

Drake asked on 2026-10-26: "For AienOS, give Spark owners the option to sign up for Open Humanity and offer their Spark as compute to back Allen."

Allen on aienos.com runs on Drake's own Spark, which answers at most two public visitors at a time. When both slots are busy, a visitor waits or is turned away. Volunteer inference lets a Spark owner who installed Sovereign Intelligence (SI) lend their local engine to answer those overflow visitors, and only those visitors who said yes.

## Decisions

1. Opt in twice.
   - The Spark owner opts in through a separate, default-off step in the SI wizard. It states what runs, when, how much power, GPU and network it uses, how to pause or quit, and that the Spark will process strangers' chat text. The wording is under "Disclosure text".
   - The visitor opts in too. A chat goes to a volunteer only if the visitor ticked "Let a volunteer's Spark answer me when Drake's is busy". The box is off by default and is shown only in anonymous chat. Remember-me memory and contact data never go to volunteers. A volunteer receives only Allen's public system prompt and the anonymous conversation text needed for that reply. Nothing about the visitor is added, but whatever the visitor typed is included as typed: the coordinator does not scrub conversation text.
2. The volunteer node is outbound only. It connects to Drake's coordinator on the hub, over TLS through nginx, and opens no listening socket. It is identified by an Ed25519 key registered at opt-in. It runs the same model and engine build as Drake's Spark (see "Pinned model and engine"), and checks every weight file against the pinned manifest before it can serve.
3. The coordinator, on Drake's side, routes overflow to healthy volunteers, streams their tokens through the Allen gateway and caps each volunteer's load. Integrity rests on four checks:
   - a model-hash attestation in every session;
   - sampled re-verification: a sample of volunteer replies is replayed on Drake's engine with the same greedy decoding, and a reply that differs suspends the volunteer;
   - volunteer output goes through the same gateway path and page rendering as Drake's own replies;
   - a reputation score.
   A malicious volunteer can still return bad text on a reply that was not sampled. The visitor disclosure says so.

## Parts

| Part | Where | Language |
|---|---|---|
| Protocol, coordinator, volunteer agent | `crates/oh-infer` in this repository | Rust (recorded below with its Omega successor) |
| Owner opt-in step | `installer/wizard/lend.om` in aien-dev/sovereign-intelligence | Omega (.om) |
| Overflow hook | `scripts/allen/allen_chat.py` in aien-dev/aienos.com | Python today (the gateway's own migration to .om is tracked there) |
| Visitor tick box and privacy text | aienos.com `/allen/` and `/privacy/` | site sources |

## Network layout

```
visitor -> www.aienos.com -> Allen gateway (Drake's Spark) -> Drake's engine 127.0.0.1:18091
                                   | public cap reached, visitor ticked, anonymous, flag on
                                   v
                     hub nginx (tailnet only) -> oh-infer-coordinator API 127.0.0.1:18137
                                                         |
          volunteer Spark: oh-infer-volunteer --TLS 443--> hub nginx /oh/v1/volunteer -> 127.0.0.1:18136
                       \-> its own SI engine 127.0.0.1:18100 (loopback only)
```

Both coordinator listeners refuse non-loopback addresses. nginx terminates TLS for volunteers on the existing `www.aienos.com` server and passes the `Upgrade: ohinf1` connection through. The gateway API is reachable only from the gateway's tailnet address. The deployment plan with backups, `nginx -t` and rollback lives outside this repository with the operator, because it names private hosts.

## Protocol

### Connection

1. The volunteer opens TLS to the hub (web PKI roots, `webpki-roots`) or, for tests and a local coordinator only, plain TCP to a loopback address. Plain TCP to any other address is refused.
2. HTTP upgrade: `GET /oh/v1/volunteer HTTP/1.1`, `Upgrade: ohinf1`, `Connection: Upgrade`. The coordinator answers `101 Switching Protocols`. Heads are read one byte at a time, so no transport byte is consumed.
3. The Open Humanity encrypted transport (`oh_core::transport`, see [volunteer-compute-v0.md](volunteer-compute-v0.md)): Ed25519 identities, X25519 per connection, ChaCha20-Poly1305 records padded to power-of-two buckets. The volunteer pins the coordinator's Ed25519 key (`--coordinator-key`). There is no trust-on-first-use mode here. Because the pin is checked inside TLS, a TLS interception proxy cannot impersonate the coordinator.

### Messages

Every message is one bincode frame inside the encrypted transport. Signed messages sign `context || bincode(message with sig emptied)`. Inference contexts (`open-humanity inference v0: attestation`, `open-humanity inference v0: completion`) differ from every training-protocol signing input, so an inference signature cannot be replayed into the training protocol.

Coordinator to volunteer (`CoordMsg`):

- `Challenge { protocol: "OHINF001", nonce[32], model_id, model_digest[32] }`: first message after the handshake, unless the key is unregistered or suspended, in which case it is `Refused`.
- `Accepted { max_inflight: 1 }`, `Refused { reason }`.
- `Job { job_id[16], model_id, messages: [{role: system|user|assistant, content}], max_tokens, seed }`.
- `Ping { nonce }`, sent every 15 seconds while idle.
- `Suspended { reason }`.

Volunteer to coordinator (`VolMsg`):

- `Attest { protocol, nonce, node_pubkey, model_id, model_digest, engine_digest, sig }`. The signer must be the identity proven in the handshake, and the nonce must be the challenge's.
- `Token { job_id, text }`, one per streamed piece.
- `Done { job_id, job_digest, output, finish_reason, node_pubkey, sig }`. `job_digest` is BLAKE3 of the job's bincode bytes. `output` must equal the concatenated tokens.
- `Failed { job_id, reason }`.
- `Pong { nonce, accepting }`. `accepting` is false while the owner has paused lending.

### Model digest

`model_digest` is the SHA-256 of the SI `model.manifest` bytes: header lines `name`, `url`, `bytes` and `files`, then one `sha256 size path` line per file. Pinning the manifest digest pins every file's hash and size. Before connecting, `oh-infer-volunteer run` hashes every file under `--model-dir` and refuses to start if any file differs (exit 5). The coordinator refuses an attestation whose digest or model id is not the pinned one. If it was given `--engine-digest`, it also refuses an engine binary digest that differs.

### Pinned model and engine

Drake decided on 2026-10-26 that volunteers run the 35B: the same model and engine build that Drake's Spark serves on 18091. The 27B is not offered for now.

- **Model:** `Qwen/Qwen3.6-35B-A3B-FP8` at revision `95a723d08a9490559dae23d0cff1d9466213d989`, model id `qwen3.6-35b-a3b-fp8-95a723d0`. The manifest has 56 files and 37,493,015,668 bytes, with `download.log` excluded. Pinned manifest digest `cfdc1f53a65e4b8b9b6fc87667af7c1e528b71597a766d1f7664d5a40e0064a1`. It was built twice, independently: once from local file hashes, and once from the Hugging Face tree API, where the LFS object ids equal the SHA-256 of each file. The two results were byte-identical. SI alpha-20261026.2 ships it as `installer/share/model.manifest`. `oh-infer-volunteer verify` passed on the real 56 files of Drake's Spark.
- **Engine:** the `aien-serve-http` build 18091 runs, sha256 `19173f9ec3b609fe79af644f84741d8808b92ea8eb3ecec4bc945af6f22b3aeb` (`bin-19173f9e`). The coordinator pins it with `--engine-digest`, and the volunteer attests it with `--engine-bin`.
- **Serve flags:** the same as 18091: `--engine omega --max-context 49152 --max-tokens-cap 16384 --thinking off --batch-slots 8`, on the volunteer's own port 18100. Replay cannot attest flags; it catches a difference that changes the text.

### Decoding

Every job and every replay uses the same request: greedy decoding (`temperature 0`, `top_p 1`, `seed 0`), the same messages and the same `max_tokens`. Volunteer and reference run the same engine build and serve flags. A volunteer cannot tell a sampled job from any other.

## Integrity

- **Attestation.** Every session attests the model digest over a fresh nonce. This is a claim by the volunteer's software. A modified agent can lie, and that is what replay is for.
- **Signed replies.** A reply whose signed text differs from the streamed text suspends the volunteer at once.
- **Sampled re-verification.** A reply is sampled with probability 0.5 until the volunteer has 20 verified replies, then 0.1 (`--probation-sample-rate`, `--probation-jobs`, `--sample-rate`). Sampled jobs wait in a memory-only queue of at most 256. The gateway pulls one only when one of Drake's slots is free and no visitor is waiting (`GET /v1/replay/next`), runs it on Drake's engine with the same request, and posts the text back (`POST /v1/replay/result`). An exact match adds 1 to the volunteer's reputation. Any difference subtracts 100, suspends the key, ends its live session with `Suspended`, and refuses reconnection until the operator runs `oh-infer-coordinator reinstate`. The evidence line in `events.jsonl` holds the job digest, both outputs' SHA-256 and the volunteer's signature, never the text.
- **Reputation.** Routing prefers the highest reputation, then the volunteer used longest ago. A timeout or dropped reply costs 1.
- **Load caps.** Each volunteer answers one reply at a time and at most 60 per hour (`--max-jobs-per-hour`). Each reply is capped at 1,024 tokens (`--max-tokens`) and 64 KiB. A volunteer must produce its first token within 60 s, each later piece within 30 s, and the whole reply within 300 s.
- **Output.** Volunteer text travels the same gateway path as Drake's replies and is rendered as plain text (`textContent`) on the page.

What this does not stop:

- A malicious volunteer can return bad, false or offensive text on a reply that is not sampled. With the 0.1 steady-state rate, most replies are never checked. Detection happens after the visitor already saw the reply.
- Exact-match replay assumes the same weights on the same engine build with the same flags give the same greedy text. Both engines run with `--batch-slots 8`, and which other requests share a batch can in principle change a near-tie token. A divergence therefore suspends the volunteer for review rather than banning it, and the operator decides.
- Approved keys identify machines, not people. There is no Sybil resistance beyond Drake approving each key.
- Visitors' chat text is processed on the volunteer's machine. The protocol keeps the volunteer from receiving more than that text. It cannot stop a modified volunteer from storing the text it does receive.

## Privacy

- The gateway sends only `volunteer_consent` and user and assistant messages. The coordinator's request type uses `deny_unknown_fields`. A request carrying any other field (a visitor key, memory, contact, name or address) is refused whole with 400. A system message is refused, because the coordinator adds Allen's public system prompt itself. A request carrying `X-Allen-Key`, `Cookie`, `Authorization`, `X-Forwarded-For` or `X-Real-IP` is refused with 403. A request without `"volunteer_consent": true` is refused.
- `Job` has no field for any visitor detail. The privacy test destructures it exhaustively, so adding a field breaks the test and forces a review.
- The coordinator writes no visitor text to disk. The replay queue is in memory and the event log holds digests only.
- The volunteer's engine must be on loopback, and the agent's log never contains chat text.

## Disclosure text

### SI wizard step (owner)

> **Lend this Spark to Allen (Open Humanity). Optional, off unless you say yes.**
> What runs: a small program, oh-infer-volunteer, that connects out to aienos.com. It opens no ports on your network.
> What it does: when my Spark is answering its maximum number of visitors, a visitor who chose to let a volunteer answer may be sent to your Spark. Your Spark then processes that stranger's chat text and streams Allen's reply back.
> What a visitor's message carries: only Allen's public instructions and the text of the visitor's anonymous conversation. Nothing about the visitor is added: no visitor key, stored memories, contact record or address. Anything the visitor typed is included as typed.
> When: only while the program runs and is not paused, and only when my Spark is busy.
> Load: one reply at a time, at most 60 an hour, each at most 1,024 tokens. While it answers, the GPU is fully busy: the GB10 is rated at 140 W, the whole Spark at most 240 W. Your own chats with Allen may be slower then.
> Network: about 1 MB per reply at most, about 64 MB an hour at most.
> Checks: before it serves, your model files are checked against the release. Some of your replies are repeated on my Spark. If one differs, your Spark is suspended until I review it.
> Pause: aienos lend pause. Resume: aienos lend resume. Quit for good: aienos lend quit.
> Type yes to lend this Spark, or press Enter to skip.

### Visitor tick box (anonymous chat only, off by default)

> ☐ Let a volunteer's Spark answer me when Drake's is busy.
> If you tick this and my Spark is full, your messages in this chat go to a computer owned by a volunteer, outside my house. It gets only the text of this anonymous conversation. I add no visitor key, stored memories, contact record or IP address, but anything you type here is sent as you typed it. I check a sample of volunteer replies, not every one. A volunteer could still send a wrong or bad reply that I don't catch. Each reply says which machine answered.

### /privacy/ section

> **Volunteer Sparks (Open Humanity).** When my Spark is busy, and only if you ticked "Let a volunteer's Spark answer me", your anonymous chat may be answered by a DGX Spark that belongs to a volunteer who opted in. That volunteer's computer receives Allen's public instructions and the text of your current anonymous conversation. No visitor key, stored memories, contact record or IP address is added; anything you typed in the conversation is included as you typed it. Remember-me chats are never sent to volunteers. The relay that passes your chat to a volunteer writes none of its text to disk: the replies it is about to check stay in memory, and its log records only fingerprints (hashes) of them. I repeat a sample of volunteer replies on my own Spark and suspend any volunteer whose reply differs, but I don't check every reply, so a volunteer could return a wrong or harmful reply that I don't catch. A volunteer's computer could also keep the text it received. If that matters to you, leave the box unticked. Every volunteer reply is labelled with the machine that answered.

## Before routing goes on

- **The shared model (decided).** Drake chose the 35B on 2026-10-26: volunteers run `Qwen3.6-35B-A3B-FP8` at revision `95a723d0` on the engine build 18091 runs (see "Pinned model and engine"). The coordinator's `--model-digest` takes the sha256 of the manifest the SI prerelease ships, and its `--engine-digest` takes the shipped engine's sha256. Both must equal what 18091 serves before routing can go on.
- **Replay wiring (Drake's approval).** The gateway does not yet pull and replay sampled jobs. Running coordinator-supplied requests on Drake's shared engine adds load to it, so the Allen gateway owners have declined to do it without Drake's approval. Until replay runs, the sampled re-verification above exists only in the coordinator, and the disclosure sentence about repeating a sample is not yet true. Routing stays off.
- Drake's confirmation for public routing, after the `/privacy/` and page text above are live.

## Commands

```
oh-infer-volunteer init --key-file ~/.local/share/aienos/lend/key       # prints "volunteer key <hex>" to register
oh-infer-volunteer verify --manifest M --model-dir D --model-digest HEX
oh-infer-volunteer run --coordinator https://www.aienos.com/oh/v1/volunteer --coordinator-key HEX \
    --key-file K --manifest M --model-dir D --model-digest HEX [--engine 127.0.0.1:18100] [--pause-file P]
oh-infer-volunteer pause|resume --pause-file P

oh-infer-coordinator --model-id qwen3.6-35b-a3b-fp8-95a723d0 --model-digest HEX --engine-digest HEX \
    --approved-file F --state-dir D \
    [--system-prompt-file P] [--key-from-vault NAME] [--routing off|on]
oh-infer-coordinator reinstate --state-dir D HEX
```

The volunteer identity seed is a 64-hex-character file, mode 0600, in the owner's home. `init` creates it and never overwrites an existing key, and `run` refuses a key file that other users can read. This departs from the repository's vault-only rule for training volunteers. Volunteer owners do not have atlas-vault, so the key is stored like an SSH key. `--key-from-vault` still works where a vault exists. The successor is a TPM-sealed key (see below).

## Tests

`cargo test -p oh-infer`:

- `loopback_e2e::binaries_answer_a_visitor_through_a_volunteer`: the real `oh-infer-coordinator` and `oh-infer-volunteer` binaries, a fake OpenAI-style engine (chunked SSE), the gateway request, streamed text, headers and a replay verdict. Run with `--nocapture` for the transcript.
- `loopback_e2e::routing_off_sends_nothing_to_volunteers` and `no_volunteer_means_503`.
- `tampered_model`: a modified weight byte is refused (library and binary, exit 5). A consistent but different manifest is refused against the pin. The coordinator refuses an attestation with a tampered hash, and the same key with the pinned hash is accepted as the control. An unregistered key is refused. An honest agent pinned to another model never attests.
- `divergence`: a volunteer whose reply differs from the reference is suspended, its session ends, routing stops, reconnection is refused, the suspension survives a restart, the event log holds no text, and reinstatement clears it. The control: an honest volunteer gains 3 reputation over 3 verified replies. A volunteer that signs a reply different from what it streamed is suspended immediately.
- `privacy`: seven bodies carrying forbidden fields get 400, four identity headers get 403, missing or false consent is refused, and none of it reaches the volunteer. The one clean request reaches the volunteer as exactly the system prompt plus three messages, with only the expected JSON keys and none of six planted markers. A negative control shows that the marker check detects a planted marker.

Mutation check (2026-10-26, each mutant applied alone to a scratch copy): each of these makes its test fail.

- dropping `deny_unknown_fields`
- skipping the model-digest comparison
- forcing every replay to match
- accepting `system` messages from the gateway
- ignoring the routing flag

## Host code record and Omega successor

The coordinator and the volunteer agent are Rust. They extend the Rust transport and crypto this repository already uses (beacon-core, oh-core). They are not Omega because the seeded Omega words they need are not on omega-mv main at the time of writing: Ed25519, X25519, ChaCha20-Poly1305, a TLS client and sockets. That work is in progress on other branches: OmegaTLS (`feat/om-tls`: SHA-2, X25519, ChaCha20-Poly1305 and X.509) and OmegaNet (sockets, HTTP, JSON).

| Dependency | Version (Cargo.lock) | What it does here | Omega successor |
|---|---|---|---|
| rustls (ring provider) | 0.23.46 | volunteer TLS client to the hub | the om/tls client from OmegaTLS |
| webpki-roots | 1.0.10 | web PKI root set for that TLS | the root set shipped with om/tls |
| sha2 | 0.10.9 | model manifest and file SHA-256 | `om/sha256` (already on omega-mv, used by the SI wizard) |
| ed25519-dalek, x25519-dalek, chacha20poly1305 (through beacon-core) | as locked | identities, handshake, records | the om/tls primitives |
| serde, serde_json, bincode | as locked | message encoding, gateway JSON | OmegaNet JSON words, plus a fixed binary layout |

Once those words merge, the successor is `oh-infer` as one `.om` unit for the volunteer agent and one for the coordinator, speaking the same `OHINF001` bytes, tested against this Rust implementation as the reference.
