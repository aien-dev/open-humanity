# Volunteer GPU training: can Open Humanity pool spare compute to train one open model?

Date: 2026-10-15. Status: research note, not a decision. Nothing in this repository was changed except this file.

Labels used below: SOURCED means I opened the cited primary source. UNVERIFIED means I could not source it, with a confidence in brackets. OBSERVED means I measured it on this machine today. "Self-reported" means the project's own claim, not independently checked.

## Summary for Drake

1. Pooling strangers' computers to train one AI model over ordinary internet has been done for real. The biggest examples: a 10 billion parameter model (INTELLECT-1, 2024), a 40 billion one (Nous Psyche, claim only, no quality numbers), and a 72 billion one (Covenant-72B, March 2026).
2. Every one of those used data-center class machines donated by a few dozen groups, not gaming PCs. The 72B run needed at least 8 of NVIDIA's newest B200 chips per participant. So "take compute back from data centers and give it to consumers" has not been shown for training yet.
3. What has worked with ordinary GPUs: a 2021 Bengali language model trained by 40 volunteers on 91 devices, and sharing the running of big models across home GPUs (Petals). Both are small or are not training.
4. The cleverest trick is "train alone for a while, then swap only a small summary" (called DiLoCo). It cuts the data sent over the internet by 100 to 500 times. That is what makes slow home internet workable at all.
5. The hardest unsolved problem for strangers is trust: proving a volunteer really did honest work and did not poison the model. Older volunteer projects (BOINC, Folding@home) solve it by doing every job twice. For AI training, no proven cheap check exists yet; the newest projects use scoring and spot checks.
6. Easier jobs for volunteers than full training: making synthetic practice data, running "answer attempts" for reinforcement learning, and small fine-tunes. These need much less bandwidth and memory.
7. Open Humanity's code today (signing, encryption, relay) is a good trust layer but is far too small for training (messages are capped at 1,200 bytes). The README promise "It does not train models" would need to change. I recommend a new sibling project that reuses the Open Humanity crates, not a pivot.
8. The domain openhumanity.io does not exist in the .io registry right now (checked with DNS and registry lookups). That conflicts with "registered at Gandi", so please check your Gandi account.
9. Smallest real first experiment: 3 to 4 machines (your Spark plus volunteers) training a roughly 20 to 350 million parameter model with the "train alone, swap summaries" method, and measure whether it matches training on one machine.
10. Your rule "no Python, no CUDA" collides with almost every existing framework. Section 4 says exactly which ones. Decided 2026-10-15: no exception; we build our own (section 7). Decided 2026-10-15: code and model are AGPL-3.0-or-later (section 5).

---

## 1. Is volunteer, internet-scale training feasible today?

Short answer: yes for vetted groups with data-center class machines, not yet shown for ordinary gaming GPUs at scale.

### 1.1 Comparison table

"Node" means one participant's machine or machine group. "Comm" means communication between nodes.

| Project and date | What was trained | Participants | Per-node hardware and network | Quality vs central training | Source |
|---|---|---|---|---|---|
| DiLoCo, Google DeepMind, 2023 | Language models on C4 text (model size not in abstract) | 8 workers | Poorly connected clusters; 500x less comm than fully synchronous | "Performs equally well" per abstract; tolerant of workers leaving and joining | [arXiv 2311.08105](https://arxiv.org/abs/2311.08105) |
| Streaming DiLoCo, 2025 | Billion-scale models | Not stated | Syncs parts in turn, overlaps comm with compute, quantizes; about 100x less bandwidth | Similar quality (self-reported) | [arXiv 2501.18512](https://arxiv.org/abs/2501.18512) |
| DiLoCo scaling laws, 2025 | Many sizes | Not applicable | Not applicable | DiLoCo scales "predictably and robustly" with model size; its edge over normal training grows with size | [arXiv 2503.09799](https://arxiv.org/abs/2503.09799) |
| OpenDiLoCo, Prime Intellect, 2024 | 1.1B parameters (also 150M tests) | 4 workers (8 for the 150M test) | 8 H100 per worker; 127 to 935 Mbit/s between Canada, Finland, two US sites; 90 to 95% compute utilization | 1.1B: perplexity 10.76 vs 10.52 for a 4x-bigger-batch baseline (lower is better) | [arXiv 2407.07852](https://arxiv.org/abs/2407.07852), [HTML](https://arxiv.org/html/2407.07852) |
| INTELLECT-1, Prime Intellect, Dec 2024 | 10B parameters, 1 trillion tokens | 30 compute contributors who joined and left; up to 14 nodes at once | 8 H100 per node (up to 112 GPUs), 3 continents, 500 Mb/s to 4 Gb/s; 83 to 96% utilization; about 400x less comm | Trails LLaMA-2-7B (MMLU 37.5 vs 45.3; HellaSwag 72.3 vs 78.6); authors say it "lags behind" | [arXiv 2412.01152](https://arxiv.org/abs/2412.01152), [HTML](https://arxiv.org/html/2412.01152) |
| INTELLECT-2, May 2025 | 32B reasoning model by reinforcement learning (RL), starting from QwQ-32B | Permissionless pool of inference workers; number not given | Workers "can run on consumer-grade GPUs" (paper's wording); training itself on a trusted cluster; 62 GB weights sent in about 14 minutes (about 590 Mb/s) | Small gains over QwQ-32B (AIME24 78.8 vs 76.6; IFEval 81.5 vs 83.4, a slight drop) | [arXiv 2505.07291](https://arxiv.org/abs/2505.07291), [HTML](https://arxiv.org/html/2505.07291) |
| INTELLECT-3, Nov 2025 | 106B mixture-of-experts, SFT then RL on GLM-4.5-Air | Not decentralized | One cluster of 512 H200 GPUs, about two months | Self-reported state of the art for its size | [Prime Intellect blog](https://www.primeintellect.ai/blog/intellect-3) |
| Nous DeMo, 2024, revised 2026 | 300M and 1B test models | Not applicable | Up to 85x less data per GPU than AdamW-DDP | Comparable loss (self-reported) | [arXiv 2411.19870](https://arxiv.org/abs/2411.19870) |
| Nous Psyche, "Consilience 40B" | 40B dense model, claimed 20T tokens | Number not published | Mix of 4090, A100, H100 per Nous's description; coordination on Solana | No benchmark scores published; Nous calls it a proof of feasibility | [Nous announcement](https://nousresearch.com/nous-psyche/), [Next phase](https://nousresearch.com/the-next-phase-of-psyche) |
| Covenant-72B, Mar 2026 | 72.7B dense model, about 1.1T tokens | At least 70 unique peers (lower bound); mean 16.9 contributing per round | At least 8x B200 GPUs per peer; 500 Mb/s down, 110 Mb/s up; over 146x compression; 94.5% utilization; permissionless on Bittensor | MMLU 67.1 vs 65.6 for LLaMA-2-70B, but behind on HellaSwag (80.6 vs 84.3) and others; LLaMA-2-70B saw 2T tokens; authors say comparisons are not controlled | [arXiv 2603.08163](https://arxiv.org/abs/2603.08163) (read via [HTML](https://arxiv.org/html/2603.08163)) |
| sahajBERT (DeDLOC + Hivemind), 2021 | Bengali ALBERT-large language model | 40 volunteers (30 Bengali speakers + 10 outside), 91 unique devices, mostly joining on and off | Ordinary volunteer devices | "Near state of the art" per the paper; comparable to much larger centrally trained models | [arXiv 2106.10207](https://arxiv.org/abs/2106.10207) |
| GPT-JT, Together, 2022 | 6B model, continued from GPT-J-6B on 3.53B tokens | Together's own research computer | Links up to 1 Gbps; 12.7 TB sent per machine vs 633 TB for naive data parallel | Beats GPT-J, strong on RAFT benchmark (self-reported) | [Together blog](https://www.together.ai/blog/releasing-v1-of-gpt-jt-powered-by-open-source-ai) |
| SWARM parallelism, 2023 | About 1B shared parameters (about 13B before weight sharing) | Research test | Preemptible T4 GPUs, under 200 Mb/s | Works; abstract gives no throughput figure | [arXiv 2301.11913](https://arxiv.org/abs/2301.11913) |
| Petals, 2022 | Inference and fine-tuning of BLOOM-176B, later Llama and Falcon | Public swarm of volunteers | Consumer GPUs; paper: about 1 step per second; README: up to 6 tokens/s for Llama 2 70B, 4 tokens/s for Falcon 180B | Not training from scratch | [arXiv 2209.01188](https://arxiv.org/abs/2209.01188), [README](https://github.com/bigscience-workshop/petals) |
| Pluralis "Subspace Networks" / protocol models, 2025 | Billion-scale models, split across machines | Test setup | Low-end GPUs at 80 Mbps; up to 99% compression of activations | Matches 100 Gbps datacenter setup (self-reported) | [arXiv 2506.01260](https://arxiv.org/abs/2506.01260) |
| Gensyn | RL Swarm (collaborative RL), Verde (verification), NoLoCo (optimizer) | Open testnet | RL Swarm lists consumer cards (RTX 3090, 4090, A100) per a third-party guide | NoLoCo: up to 4% better perplexity and up to 4x faster than DiLoCo (self-reported) | [RL Swarm blog](https://blog.gensyn.ai/rl-swarm-a-framework-for-collaborative-rl/), [NoLoCo](https://arxiv.org/abs/2506.10911), [Verde](https://arxiv.org/abs/2502.19405) |
| Photon, 2024, revised 2026 | Federated pretraining up to 7B | Research setup | 64x to 512x less data sent | Lower perplexity than centralized (self-reported) | [arXiv 2411.02908](https://arxiv.org/abs/2411.02908) |

### 1.2 What the table means

- The method that makes internet training possible is local training with rare synchronization. DiLoCo has each worker train alone for many steps, then exchange one "pseudo-gradient" (the net change in the model) instead of a gradient every step. [DiLoCo](https://arxiv.org/abs/2311.08105). Follow-ups compress that change further: SparseLoCo keeps only 1 to 3 percent of values at 2 bits each, tested from 178M to 2B parameters ([arXiv 2508.15706](https://arxiv.org/abs/2508.15706)). Covenant-72B used SparseLoCo (chunk-wise Top-k, 2-bit values, error feedback) for over 146x compression ([arXiv 2603.08163](https://arxiv.org/html/2603.08163)).
- Real-world numbers for sync cost: in INTELLECT-1 the median all-reduce took 103 s (US only), 382 s (US and Europe), 469 s (global), and communication was about 2 to 10% of training time ([HTML](https://arxiv.org/html/2412.01152)). In Covenant-72B, about 70 s of communication per 20-minute compute window ([HTML](https://arxiv.org/html/2603.08163)).
- Quality: INTELLECT-1 lagged its centrally trained peers; the authors say so. Covenant-72B is competitive with an older centrally trained model, using half the tokens, but the paper says the comparison is not controlled. Consilience 40B has no published scores that I could find. [Nous](https://nousresearch.com/the-next-phase-of-psyche)
- Scale of "volunteers": 30 contributors (INTELLECT-1), at least 70 over a run with 17 per round (Covenant-72B), 40 (sahajBERT). These are tens, not thousands. I found no source showing thousands of simultaneous volunteers training one model.
- Hardware class: every run above 1B parameters that I could source used H100, B200 or similar. The one consumer-GPU claim at scale is Pluralis (80 Mbps, "low-end GPUs", billion-scale), which is self-reported with no public volunteer run that I could source.
- Project health: Psyche's repo last commit is 2026-03-20 (about 7 months before this note), per `gh api` on the repo. Petals' repo last push was 2024-09-07. Hivemind's was 2026-01-11. OpenDiLoCo and prime-diloco 2026-07-17. prime-rl and BOINC are active (pushed 2026-10-15). (Checked with the GitHub API on 2026-10-15.)

### 1.3 The classic model: BOINC and Folding@home

- BOINC is the open-source system behind SETI@home and about 30 other projects. In 2019 its creator reported about 700,000 active devices with 4 million CPU cores and 560,000 GPUs, averaging 93 PetaFLOPS. [Anderson, arXiv 1903.01699](https://arxiv.org/abs/1903.01699) (numbers read from the PDF text).
- How BOINC handles untrusted volunteers: "replication-based validation", where each job runs on two unrelated computers and is accepted only if they agree, with a third run on disagreement; "adaptive replication" lowers the replication rate for hosts that have a long record of validated results. The paper says this can keep the error rate low "even in the presence of malicious volunteers". Same paper, section 3.4.
- Credit: BOINC grants credit, "an estimate of FLOPs performed", only for validated results, so fake results do not earn credit. Credit drives volunteer motivation and team competition. Same paper, section 7.
- Cost to BOINC: plain replication halves useful capacity (same paper). Replication needs two machines to produce comparable output, which is hard for GPU training because different GPUs give slightly different floating-point results (the paper discusses this tolerance problem for validators).
- Folding@home passed one exaFLOP on about 25 March 2020 on OpenCL GPU work, with over 1 million devices including roughly 356,000 NVIDIA GPUs (reported via the [Khronos news item](https://www.khronos.org/news/permalink/foldinghome-uses-opencl-for-covid19-research-and-breaks-the-exaflop-barrier) and [NVIDIA developer blog](https://developer.nvidia.com/blog/foldinghome-gpu-accelerated-exaflop)). The device counts came from social media posts by the project lead as relayed by press, so treat as UNVERIFIED [medium].
- Folding@home credit: a "passkey" ties points to a person and the Quick Return Bonus rewards fast returns, per the project's own [passkey page](https://foldingathome.org/passkey/). How its servers validate results: I could not find an official statement. UNVERIFIED [low].
- Key difference from AI training: BOINC and Folding@home jobs are independent chunks that need no talking between volunteers. Neural network training is one tightly coupled computation. That is why training needs the DiLoCo-style tricks above.

---

## 2. The hard problems, and how each project handles them

### 2.1 Slow home internet

- Send rarely, send little. DiLoCo (many local steps), then compression: DeMo (frequency transform plus top-k, up to 85x less data per GPU than AdamW-DDP, tested on 300M and 1B models) [arXiv 2411.19870](https://arxiv.org/abs/2411.19870); SparseLoCo; Streaming DiLoCo (send parts in turn, overlap with compute) [arXiv 2501.18512](https://arxiv.org/abs/2501.18512).
- Worked example of why compression matters (my arithmetic, exact): a 1 billion parameter model stored as 2 bytes per value is 2 GB. Sending that once over Covenant's quoted 110 Mb/s uplink takes about 145 seconds (calc:d18aff813cf3fd49329bba6ea4aa55be1c059a8a67196cc6102d4ad964e10588). With the 146x compression Covenant reports it is about 1 second (calc:e8b9c78ded0f96430f6ead309c27c573f66fde6394b1ef0ef10b1f790f6e8d59). That is per synchronization, which happens every 30 to 500 local steps.
- Even so, the volunteers in sourced runs had much faster links than a typical home line: Covenant peers had 500 Mb/s down and 110 Mb/s up; INTELLECT-1 nodes 500 Mb/s to 4 Gb/s; OpenDiLoCo 127 to 935 Mbit/s. What a typical home upload speed is: UNVERIFIED [medium], I did not source a survey.
- Splitting the model across machines (pipeline style, SWARM and Pluralis) needs far more traffic per step than DiLoCo, so it depends on heavy compression of activations (Pluralis claims 99%, 80 Mbps) [arXiv 2506.01260](https://arxiv.org/abs/2506.01260).
- OpenDiLoCo's own limitation: standard PyTorch NCCL "can't communicate across NAT", so it needed Hivemind's peer-to-peer layer for the open internet [HTML](https://arxiv.org/html/2407.07852). Home volunteers sit behind routers; Psyche uses the iroh peer-to-peer library with relays (declared in its [Cargo.toml](https://github.com/PsycheFoundation/psyche/blob/main/Cargo.toml)). INTELLECT-1 said its Tailscale VPN layer was a bottleneck [HTML](https://arxiv.org/html/2412.01152).

### 2.2 Consumer GPU memory: what is the smallest GPU that can usefully join?

- DiLoCo-style and Psyche-style runs keep a full copy of the model and optimizer on every node. Mixed-precision Adam training costs about 16 bytes per parameter for weights, gradients and optimizer state (ZeRO paper, section 3.1, text read from the PDF: "2Ψ + 2Ψ + KΨ = 16Ψ bytes" with K = 12) [arXiv 1910.02054](https://arxiv.org/abs/1910.02054). That excludes activations.
- Exact arithmetic: 0.75B parameters need 12 GB (calc:d23e22b30b1e1f5d206225e72db6ea4fd77e60541896099b3ff6351d1660a32b); 1.5B need 24 GB (calc:a1b5273233027b6cd00b41bb83893fc6a96e03e7cb3c815f56aa4c473b69fc07), before activations.
- Measured here on the Spark, OBSERVED (local research note `own-model-results.md`, not public): a 124M model peaked at 10.17 GB at about 48,793 tokens/s; a 350M model peaked at 21.13 GB at about 19,143 tokens/s. Real training peaks are higher than the 16-bytes rule because of activations.
- So with the simple "everyone holds the whole model" method, a 24 GB card is limited to roughly 350M to 1B parameters, and an 8 GB card cannot usefully pretrain even a 350M model. Typical card sizes: the September 2026 Steam survey lists the RTX 5070, 5060, 5060 Ti, 4060 and 3060 as the top five cards ([Steam hardware survey](https://store.steampowered.com/hwsurvey/videocard/)); their VRAM sizes (mostly 8 to 12 GB) are not on that page, UNVERIFIED [high confidence].
- Escape routes: (a) split the model across nodes (SWARM, Pluralis, Petals style), which trades memory for network traffic; (b) train only small add-on weights (LoRA), where QLoRA reports fine-tuning a 65B model on one 48 GB GPU [arXiv 2305.14314](https://arxiv.org/abs/2305.14314); (c) mixture-of-experts where each node trains a few experts (SPES, [arXiv 2602.11543](https://arxiv.org/abs/2602.11543), title and abstract only read via search).
- Psyche docs say only "NVIDIA GPU with sufficient VRAM for the model being trained"; it requires Linux, Docker and the NVIDIA container toolkit ([quickstart](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/enduser/quickstart-compute-provider.md)). No fixed minimum GPU is documented there.
- Reasonable minimum today for a pretraining volunteer in a sub-1B experiment: about 12 to 16 GB VRAM. My estimate from the numbers above, not a sourced figure. [medium]

### 2.3 Nodes joining and leaving

- DiLoCo paper: the method is robust "to resources becoming unavailable" and to "new resources joining" [arXiv 2311.08105](https://arxiv.org/abs/2311.08105).
- INTELLECT-1 (ElasticDeviceMesh): heartbeat every 2 s, eviction after 6 s of silence, a "deathrattle" message for polite exits, retry of a failed sync without the failed node. New joiners get the model by peer-to-peer checkpoint copy, usually a blocking transfer of 30 to 60 minutes. Losing 4 of 12 nodes at once forced a restart from a checkpoint. Non-blocking joins caused loss spikes. [HTML](https://arxiv.org/html/2412.01152)
- Psyche: the run moves through epochs and rounds. Clients may join during a waiting window; the first epoch downloads from Hugging Face, later epochs from other clients; a run needs a minimum client count ([general-workflow](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/explain/general-workflow.md), [explain index](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/explain/index.md)).
- Covenant-72B: permissionless; peers join and leave freely (mean 24.4 active per step, 16.9 contributing per round) [HTML](https://arxiv.org/html/2603.08163).
- OpenDiLoCo limitation: faster workers idle waiting for the slowest [HTML](https://arxiv.org/html/2407.07852). A home network will have a wide spread of GPU speeds.

### 2.4 Verifying that a volunteer did honest work

What exists, from strongest to weakest evidence:

- Replication (BOINC): run twice, compare. Proven at 700,000 devices but halves capacity; needs results that match closely [Anderson](https://arxiv.org/abs/1903.01699).
- Verified inference (TOPLOC, Prime Intellect): a compact hash of internal activations lets a checker confirm that a worker ran the claimed model and prompt on its stated settings, with reported 100% detection in their tests, robust across GPU types, and about 258 bytes of proof per 32 tokens [arXiv 2501.16007](https://arxiv.org/abs/2501.16007). INTELLECT-2 used it on random subsets of submissions, with validation taking about a minute [HTML](https://arxiv.org/html/2505.07291). Covers rollouts (answers generated by volunteers), not gradients.
- Refereed delegation (Gensyn Verde plus RepOps): send the same program to several providers; if they disagree, an arbitration game pins down the first step where they differ. RepOps forces a fixed order of floating-point operations so different hardware gives identical bits. Guarantee holds if at least one provider is honest. [arXiv 2502.19405](https://arxiv.org/abs/2502.19405). I did not find a public run of Verde at large scale. UNVERIFIED [medium] on production use.
- Scoring contributions by their effect (Covenant "Gauntlet"): a validator scores each peer's submission by whether the loss improves on that peer's assigned data more than on random data, so copying or training on the wrong data scores negative; ranks are smoothed over rounds; pseudo-gradients are scaled relative to the median norm before averaging. Liveness checks run on all peers. [HTML](https://arxiv.org/html/2603.08163). It sat on the Bittensor chain, with whitelisting not required.
- Witnesses and spot recomputation (Psyche): randomly chosen "witness" clients attest which batches were trained by whom (a bloom filter, a compact set summary); health checks eject silent clients; a "Verifying" phase is described as "recompute and compare training results to identify and punish malicious participants" ([explain index](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/explain/index.md)). Run configs include a `verification_percent` setting, and some sample configs set it to 0 ([config/consilience-match-llama2-20m-fineweb-pretrain-dev/state.toml](https://github.com/PsycheFoundation/psyche/tree/main/config)). The code has an open note "TODO: verify shape of distro_results" in `shared/client/src/state/steps.rs` at line 600 (read from a shallow clone on 2026-10-15). I conclude Psyche's cheating defenses were still partial at that commit; whether the real Consilience run used verification: UNVERIFIED [low].
- Proof-of-Learning (record the training trail and re-check it): proposed in 2021 [arXiv 2103.05633](https://arxiv.org/abs/2103.05633), then shown to be spoofable at a fraction of the claimed cost; the follow-up authors conclude that a provably robust version needs a better understanding of optimization [arXiv 2208.03567](https://arxiv.org/abs/2208.03567) (abstract-level read via search).
- Gap I could not close: formal Byzantine-robust gradient aggregation (a family of statistical defenses against bad contributors) was not surveyed here. UNVERIFIED [high that it exists, low on practicality for LLM scale].
- Takeaway: for training from scratch, no source I read shows a proven cheap defense against a determined cheater. Practical projects limit damage by (a) vetting participants (INTELLECT-1 and Consilience used whitelisted participants, according to Covenant's own comparison table, via search summary; UNVERIFIED [medium] for the exact table), (b) loss-based scoring (Covenant), (c) spot rechecks, (d) keeping a trusted trainer and letting volunteers only generate checkable data (INTELLECT-2).

### 2.5 Data choice and licensing

- Openly licensed text exists at scale: Common Pile v0.1 is 8 TB of public domain and openly licensed text from 30 sources; two 7B models (Comma v0.1-1T and 2T) trained on it are competitive with Llama 1 and 2 7B models trained on unlicensed text at similar compute [arXiv 2506.05209](https://arxiv.org/abs/2506.05209). Comma is tagged Apache-2.0 on Hugging Face ([model metadata](https://huggingface.co/common-pile/comma-v0.1-1t)).
- Web mixtures used by the decentralized runs: INTELLECT-1 used FineWeb-Edu 55%, Stack v1 popular 20%, FineWeb 10%, DCLM-baseline 10%, OpenWebMath 5%; the report states no dataset licenses [HTML](https://arxiv.org/html/2412.01152). Covenant used DCLM web text [HTML](https://arxiv.org/html/2603.08163). Psyche's next-phase mix names FineWeb-Edu, FineWeb2-HQ, FinePDFs, DCLM-Baseline, Stack-Edu and Nemotron-CC-Math [Nous](https://nousresearch.com/the-next-phase-of-psyche).
- FineWeb-Edu's Hugging Face license tag is ODC-By ([dataset metadata](https://huggingface.co/api/datasets/HuggingFaceFW/fineweb-edu)); that license covers the dataset compilation, not necessarily the copyright in each web page inside it. Legal effect: UNVERIFIED [medium]; needs a lawyer.
- Practical rule for a project that promises openness: publish exact data lists and filters (the Open Source AI Definition requires "data information" detailed enough to build a substantially equivalent system, see section 5), prefer Common Pile style openly licensed sources first, and never let volunteers add their own private data (this also matches the Open Humanity firewall principle).

### 2.6 Who controls the final model

- INTELLECT-2: the authors list "the orchestrator and discovery service are centralized" as a limitation [HTML](https://arxiv.org/html/2505.07291). The trained model is Apache-2.0 tagged on Hugging Face ([metadata](https://huggingface.co/api/models/PrimeIntellect/INTELLECT-2)).
- Psyche: a run is created by an authority that sets configuration (data, learning-rate schedule, minimum clients); the coordinator is either a Solana smart contract or a plain server; checkpoints are saved to external storage such as Hugging Face ([create-run](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/enduser/create-run.md), [general-workflow](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/explain/general-workflow.md)). Contribution points are shared equally among clients that finish an epoch, and can map to a token via a "Treasurer" contract ([rewards](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/explain/rewards.md)).
- Covenant-72B: peers upload to their own storage; the validator picks which submissions to aggregate; weights are Apache-2.0 tagged on Hugging Face ([metadata](https://huggingface.co/api/models/1Covenant/Covenant-72B)). The paper has no dedicated governance section that I could find. UNVERIFIED [medium] on who can start or stop a run.
- Lesson for Open Humanity: in every sourced system, someone (a company, a DAO, a validator) decides data, schedule and release. "Everyone controls it" is not what exists; you must choose the human process (section 5).

---

## 3. Alternatives to full pretraining, ranked for a small team

Feasibility here means: could one person plus a few helpers build and run it in months, using existing open-source parts.

| Rank | Option | Why it fits volunteers | Main risk | Evidence |
|---|---|---|---|---|
| 1 | Synthetic data generation and evaluation jobs (volunteers run an open model to write practice text, or score outputs) | Each job is independent, needs no tight network, works on 8 to 12 GB cards with a small quantized model, and can be checked by replication, sampling or the TOPLOC-style hash | Output quality depends on the generator model; the generator's license must allow training on its output; volunteers could submit junk, so every batch needs filtering | Synthetic data for training at scale: HF Cosmopedia ([blog](https://huggingface.co/blog/cosmopedia), not opened in this pass, UNVERIFIED [medium] on details); verification: [TOPLOC](https://arxiv.org/abs/2501.16007), BOINC replication [Anderson](https://arxiv.org/abs/1903.01699) |
| 2 | Small-model DiLoCo pretraining with vetted volunteers (20M to 350M parameters first) | It tests the actual vision: many machines, one model, tiny traffic. Existing recipes and local configs exist | Memory limit: every node holds the whole model; only a handful of stable peers; cheating handled by vetting at first | [OpenDiLoCo](https://arxiv.org/abs/2407.07852), [Psyche sample configs](https://github.com/PsycheFoundation/psyche/tree/main/config) |
| 3 | RL rollouts by volunteers, trusted trainer (INTELLECT-2 style) | Volunteers only run inference, which fits consumer GPUs; trusted trainer keeps control; verification exists | Needs a strong base model first; weights must be re-sent to workers every step (62 GB per broadcast for 32B; a 1B to 3B model would be about 2 to 6 GB at 2 bytes per parameter, my arithmetic); code sandboxing risk | [INTELLECT-2](https://arxiv.org/abs/2505.07291); [prime-rl](https://github.com/PrimeIntellect-ai/prime-rl) (Apache-2.0, Python) |
| 4 | LoRA / federated fine-tuning swarms | Small updates (megabytes), runs on 12 to 24 GB cards, a real improvement for a specific skill | Merging adapters from strangers is a poisoning risk; improves an existing base model, does not create one | [QLoRA](https://arxiv.org/abs/2305.14314); [Photon](https://arxiv.org/abs/2411.02908) for federated pretraining; poisoning defenses UNVERIFIED [high that the risk exists] |
| 5 | Shared inference (Petals style): volunteers serve slices of a big model so anyone can use it free | Direct "free access for everyone" benefit; works on consumer GPUs | It is not training; other peers see your prompts (Petals README says so); Petals repo last pushed 2024-09 | [Petals paper](https://arxiv.org/abs/2209.01188), [README](https://github.com/bigscience-workshop/petals) |
| 6 | Full-scale pretraining open to anyone with any GPU | The dream | Not shown by any source: the largest permissionless run needed 8x B200 per peer; consumer-GPU large-scale claims are self-reported only | [Covenant-72B](https://arxiv.org/abs/2603.08163); [Pluralis](https://arxiv.org/abs/2506.01260) |

Reading the table: ranks 1, 3, 4 give volunteers a useful role with today's tools; rank 2 is the experiment that tells you whether your original idea can work; rank 6 is the long-term target.

---

## 4. Fit with the existing Open Humanity code and values

### 4.1 What the repository is today (read 2026-10-15)

- Three Rust crates, about 2,200 lines in total (`wc -l`, OBSERVED): `beacon-core` (formats, crypto, firewall), `beacon-client` (local store, UDP transport), `beacon` (UDP relay).
- The README says the pieces are not yet joined end to end: the client does not sign, the relay does not verify or encrypt, and the relay keeps only the newest 10,000 signals in memory.

### 4.2 Reusable for a compute network

- Node identity: Ed25519 keypair generation, signing and verification (`crypto.rs`, `Keypair`, `verify_signature`). Fits "prove this result came from this volunteer's key".
- Sealed messages: X25519 key agreement with ChaCha20-Poly1305 (`EncryptedPayload`). Fits private task assignment and private results.
- Replay and timestamp checks (300 s drift limit, `MAX_TIMESTAMP_DRIFT_SECS`) and a packet ID replay filter. Useful for work-unit claims.
- BLAKE3 hashing is already a dependency. Useful for content-addressed shards and checkpoints.
- Compact versioned wire format with magic bytes "OH". Reusable idea, but see limits.
- Personal Data Firewall (secrets and path redactor): relevant only if volunteers ever submit free text. For a public-data-only network it is a safety net, not core.
- Per the coordinator: `aien-sovereign-core` has a scheduler with leases, heartbeats and a replayable journal (single machine today), BLAKE3 content-addressed receipts (unsigned), and "work counts only with a re-verified receipt" gates. These map directly onto work units, volunteer heartbeats and result checking. I saw the crate names (`aien-scheduler` etc.) but did not read them. Receipts would need volunteer signatures to be trusted.

### 4.3 Not reusable as is

- Packet size: `MAX_DATAGRAM_SIZE` is 1,200 bytes. Training traffic is megabytes to gigabytes. A bulk transfer path (reliable, resumable, NAT-friendly) is needed. Psyche uses iroh (QUIC peer-to-peer, relays, blob transfer, gossip) per its Cargo.toml.
- The relay is UDP, in memory, does not forward, has no work queue.
- Topics are a fixed enum of seven; adding or reordering variants changes the wire bytes (the code keeps retired placeholders for this reason). Compute messages should be a separate message family and version, not new topics.
- Anonymous throwaway keys: good for privacy, but a compute network needs a stable pseudonymous key per volunteer to give credit and to ban repeat cheaters. Fresh random keys make Sybil attacks (one cheater pretending to be many volunteers) free. This is a design tension with the "no account, no identity" principle in `docs/personal-data-firewall.md`.

### 4.4 Conflicts with what the repo promises

- README: "It does not train models. It does not collect user data. Nothing is harvested, and no central model learns from people." The first sentence would be false. The rest can stay true if training uses only public text and volunteers send no personal data. [README.md]
- `docs/SOVEREIGN_MANIFESTO.md`: "The open network never trains on user queries or builds centralized behavioral databases." Compatible if training data is public corpora only.
- `docs/personal-data-firewall.md`: "Open Humanity never trains on personal data and never collects it." Compatible on the same condition. This should become an explicit rule: no volunteer-supplied or user-supplied data ever enters training.
- Zero telemetry (Constitution Article I section 4: no unsolicited outbound telemetry; README "Zero Telemetry"): a training network needs contribution counts and progress reporting. Defensible only if the volunteer opts in, the report is minimal (work units done, no hardware fingerprint beyond what verification needs), and the client shows exactly what it sends. Needs a written policy.
- Pure native systems (Constitution Article II section 1: "Zero tolerance for unnecessary interpreters in core daemon processes"; Manifesto: compiled Rust with GPU kernels): conflicts with most training frameworks, see 4.5.
- Licence inconsistency found while reading, needs fixing before accepting outside contributors: `LICENSE`, root `Cargo.toml` and README say AGPL-3.0-or-later, but `CONSTITUTION.md`, `COVENANT.md` say the software license is Apache-2.0, and `docs/personal-data-firewall.md` says "Apache-2.0 WITH LLVM-exception". Which one governs contributions and the model must be one answer.
- The Constitution says AIEN software and models are shared "under the Apache License, Version 2.0" (Article I section 5), so an Apache-2.0 model fits the Constitution's text.

### 4.5 Your rule: no Python and no CUDA in our own stack

Almost nothing that exists for volunteer training satisfies both. Plainly:

| Framework | Language | Python needed? | CUDA needed? | License | Verdict for the rule |
|---|---|---|---|---|---|
| Psyche (Nous) | Rust core (2.3 MB of Rust, 144 KB Python, per GitHub language stats) | Optional. Python is an optional feature (`python = ["pyo3", "pyo3-tch"]` in `shared/modeling/Cargo.toml`) and the docs call the Python integration "still under development" | Yes. Training runs on libtorch (PyTorch's C++ engine, via Nous's fork of `tch-rs`); docs: "Psyche requires an NVIDIA CUDA-capable GPU"; also needs Docker | Apache-2.0 | Closest fit on language; breaks no-CUDA (and Docker). Models limited to `HfLlama` and `HfDeepseek` architectures |
| OpenDiLoCo, prime-diloco, Hivemind, prime-rl, Petals, torchft, Gensyn RL Swarm | Python on PyTorch | Yes | Yes (PyTorch GPU) | MIT or Apache-2.0 (torchft: "other") | Breaks both |
| nanoGPT in `~/workspace/aien-lm` | Python on PyTorch | Yes | Yes | MIT | Breaks both; fine for a throwaway proof |
| BOINC | C++ | No for the client | No by itself (apps decide) | LGPL-3.0 | Possible host for independent jobs (synthetic data, evaluation); not for neural training sync. Server-side stack not checked, UNVERIFIED [medium] |
| Folding@home client | C++ | No | Uses OpenCL/CUDA for science cores | GPL-3.0 | Not relevant for LLM training |
| Burn | Rust | No | No: backends include CUDA but also Vulkan, Metal, ROCm, WebGPU; supports autodiff training | See repo (license not checked) | Only mainstream option compatible with both halves of the rule; no volunteer or low-communication training layer exists, we would write the DiLoCo outer loop ourselves; speed on GB10 and consumer cards unproven, UNVERIFIED |
| candle (Hugging Face) | Rust | No | CUDA backend optional; also CPU and Metal | See repo (license not checked) | Possible; same caveats as Burn |

Sources: [Psyche repo](https://github.com/PsycheFoundation/psyche), [Psyche join-run](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/enduser/join-run.md), [Python integration doc](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/development/python.md), [OpenDiLoCo](https://github.com/PrimeIntellect-ai/OpenDiLoCo), [prime-diloco](https://github.com/PrimeIntellect-ai/prime-diloco), [Hivemind](https://github.com/learning-at-home/hivemind), [prime-rl](https://github.com/PrimeIntellect-ai/prime-rl), [Petals](https://github.com/bigscience-workshop/petals), [torchft](https://github.com/pytorch/torchft), [RL Swarm](https://github.com/gensyn-ai/rl-swarm), [BOINC](https://github.com/BOINC/boinc), [fah-client-bastet](https://github.com/FoldingAtHome/fah-client-bastet), [Burn](https://github.com/tracel-ai/burn), [candle](https://github.com/huggingface/candle). Licenses and languages from the GitHub API on 2026-10-15.

Implication: to keep the rule, you would write the network, the work-unit logic, signing and verification in Rust on the existing Open Humanity crates, and the actual number crunching either in Burn on Vulkan or Metal, or in your own GPU kernels (the Constitution mentions "Omega kernels"; I did not examine them). Training code written that way does not exist yet in any source I found. For the first proof-of-idea experiment (section 7), I recommend explicitly marking Python and CUDA tools as a throwaway exception, kept outside the product, because rewriting a trainer first would delay the answer to the real question: does volunteer training converge?

### 4.6 What aien-lm needs to become a volunteer trainer

What I could see (head and grep only):

- `~/workspace/aien-lm` today is Karpathy's nanoGPT, unmodified, pinned at commit 3adf61e, in a Python 3.12 virtual environment on the system PyTorch 2.14 (CUDA 13), plus benchmark scripts (`~/workspace/aien-lm/README.md`). I found no `src/train/` directory there, and `gh` could not resolve `aien-spark/aien-lm` or `aien-dev/aien-lm`, so the in-progress trainer you mentioned is not visible from this checkout. I did not assess it further.
- Its `train.py` supports multi-GPU only through PyTorch DistributedDataParallel (every step exchanges full gradients, which needs a fast local network). That does not work over home internet.
- OBSERVED speeds: 124M at about 48,793 tokens/s, 350M at about 19,143 tokens/s on the Spark (own-model-results.md).

On top of it a volunteer version would need:

1. An outer loop in the DiLoCo style: each volunteer trains H local steps, computes the change in weights, and sends it; a coordinator averages and applies an outer optimizer ([DiLoCo](https://arxiv.org/abs/2311.08105)).
2. Compression of that change (Top-k plus 2-bit; [SparseLoCo](https://arxiv.org/abs/2508.15706)).
3. Deterministic data assignment from a shared seed (Psyche's coordinator hands out a random seed; each client derives its batch indices from seed, round and epoch).
4. Checkpoint download for late joiners, and resume after crashes (INTELLECT-1 needed 30 to 60 minutes for a blocking join).
5. Signed, hashed results, so each update is attributable to a volunteer key and a hash of the weights it started from (Open Humanity signing plus the BLAKE3 receipts).
6. A way to score or spot-check updates (section 2.4).
7. If Psyche is used: a Llama-style architecture, since Psyche supports `HfLlama` and `HfDeepseek` only; nanoGPT's GPT-2 layout is not on that list.
8. A shared evaluation suite for all (nanoGPT already includes HellaSwag per the own-model plan).

### 4.7 Doctrine

Per the coordinator: current AIEN doctrine has nothing on donated GPUs or federated training; an archived 2026-09-22 plan had a "Distributed compute and inference" section that records old intent only. I did not re-read those files.

### 4.8 New repo or pivot?

Recommendation: a new repository for the compute network, which depends on Open Humanity crates for identity and message signing. Reasons:

- Open Humanity's current purpose (agents asking peers for help with errors, privacy first, tiny messages) is different from moving large tensors, and the current code is a prototype whose own README says its parts are not yet joined.
- A pivot would silently change the README promise "It does not train models" that the project's identity rests on; a sibling project lets you keep that promise for the help-network and state a new promise for the compute network.
- The shared pieces (`beacon-core` crypto) can be extracted later into a small crate used by both.
- Cheap alternative if you prefer one repo: add a new crate (for example `compute-core`) in this workspace and rewrite the README sentence honestly at the same time. The risk is mixing two products in one set of promises.
- Naming: "Open Humanity" fits the compute project better as an umbrella name; the distress-signal network could be one program under it. This is a naming decision for you, not an engineering one.

---

## 5. Legal and governance basics

This is a map of options with sources, not legal advice.

**Decided by Drake, 2026-10-15:** everything, including the trained model, goes under AGPL-3.0-or-later, the license on all main AIEN repos (relicensed 2026-10-04). The Apache-2.0 wording in `CONSTITUTION.md`, `COVENANT.md`, `AGENT_CODE_OF_CONDUCT.md`, `AGENTS.md`, `llms.txt` and `docs/personal-data-firewall.md` is stale and needs a cleanup change. Consequences: third-party base models keep their maker's license, so the network should train from scratch or start from weights whose license allows release under AGPL (Apache-2.0 or MIT); Apache-2.0 tools such as Psyche can be used alongside AGPL code; volunteers need a short contributor note saying their updates become part of an AGPL model. The options below are kept for the record.

### 5.1 Model license options

- Open Source AI Definition 1.0 (Open Source Initiative): an open AI system must let anyone use it for any purpose without permission, study, modify and share it; the "preferred form for modification" must be available: detailed data information, complete training code, and parameters (weights) [OSAID](https://opensource.org/ai/open-source-ai-definition). The definition does not require a specific license mechanism for the weights. Consequence: use-restricted licenses such as OpenRAIL fail the "any purpose" freedom (my reading of the definition's text, [medium] confidence), and publishing weights without data information also falls short.
- Apache-2.0: used for the weights of INTELLECT-1 and 2, Covenant-72B, Comma, OLMo 2 per their Hugging Face metadata ([INTELLECT-1](https://huggingface.co/api/models/PrimeIntellect/INTELLECT-1), [INTELLECT-2](https://huggingface.co/api/models/PrimeIntellect/INTELLECT-2), [Covenant-72B](https://huggingface.co/api/models/1Covenant/Covenant-72B), [Comma](https://huggingface.co/api/models/common-pile/comma-v0.1-1t), [OLMo 2](https://huggingface.co/api/models/allenai/OLMo-2-1124-7B)); INTELLECT-3 is tagged MIT ([metadata](https://huggingface.co/api/models/PrimeIntellect/INTELLECT-3)). This is the norm for open decentralized models. Upside: matches the Constitution's Apache-2.0 text, maximum adoption, includes a patent grant. Downside: anyone can build a closed derivative; "keeps the model open for everyone" holds for the released weights, not for forks.
- AGPL-3.0: the current Open Humanity code license (`LICENSE`). Its network-use clause (users of a service built on it can get the source) is designed for software. Whether and how it applies to model weights is legally unsettled; I found no primary source (court ruling or regulator text) settling it. UNVERIFIED [medium]. No decentralized model above uses it.
- OpenRAIL (BigScience-style responsible AI licenses with use restrictions): restrictions on harmful uses; not open source under OSAID (see above). I did not fetch the license text in this pass. UNVERIFIED [medium] on current terms.
- Hedging tools that do not change the license: a non-binding covenant like `COVENANT.md` (it states it "grants no legal rights and restricts none"), a trademark policy on the name, and keeping training code, data lists and checkpoints public.

### 5.2 Contributor terms for donated compute

No primary-source template was reviewed. Items a written volunteer agreement would need to cover (my list, not sourced):

- Volunteer gives the compute and receives no ownership of the model; contributions are licensed under the same license as the model; no personal data is sent; volunteer can leave at any time; the project may reject or ban results that fail checks.
- What volunteers can expect on their machine: Petals states that hosting a server "does not allow others to run custom code on your computer" ([README](https://github.com/bigscience-workshop/petals)); BOINC runs project-supplied code in a sandbox-like arrangement with code signing ([Anderson](https://arxiv.org/abs/1903.01699)); INTELLECT-2's authors state code sandboxing for tasks "needs strengthening for complex ones" ([HTML](https://arxiv.org/html/2505.07291)). Open Humanity should choose the data-only design (volunteer runs only fixed, signed, audited code and never arbitrary jobs).
- Code contributions already use the Developer Certificate of Origin (Constitution Article I section 6).
- Incentives: Psyche splits points equally among finishers and can attach a token via a Treasurer contract ([rewards](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/explain/rewards.md)); BOINC uses credit and teams. The Constitution rejects "speculative monetization", so a token is out of line with it; a non-monetary credit ledger is in line (like BOINC credit).

### 5.3 Governance of the final model

- Decide in writing: who holds the release key, who may start a training run, how the data list changes, how a run is stopped if the model is found harmful, and whether volunteers get a vote. Existing systems answer this with a company (Nous, Prime Intellect), a validator network (Covenant on Bittensor), or a smart contract (Psyche); none gives volunteers a legal say by default in the sources read.

### 5.4 Export and safety items documented by primary sources

- EU AI Act, Article 53(2): open-source general-purpose models are exempt from some provider duties (technical documentation to the authorities), but not from the copyright policy duty (53(1)(c)) or the public training-content summary (53(1)(d)), and not if the model has systemic risk. The presumption of systemic risk starts above 10^25 floating point operations of training compute (Article 51(2)). [Article 53](https://artificialintelligenceact.eu/article/53/), [Article 51](https://artificialintelligenceact.eu/article/51/) (reading of an unofficial site hosting the Act text; the official source is EUR-Lex, not opened here). Rough scale: INTELLECT-1 was 10B parameters on 1T tokens; the standard "6 x parameters x tokens" rule (cited in the own-model plan as Kaplan 2020 / Chinchilla 2022, not re-verified here) gives about 6e22, far under 1e25. [medium]
- US export controls: BIS announced on 2025-05-13 that it would rescind the AI Diffusion Rule; law-firm summaries note that the status of the model-weight control category (ECCN 4E091, which applied to closed-weight models) was not specifically addressed, and that BIS planned a replacement rule ([Akin Gump](https://www.akingump.com/en/insights/ai-law-and-regulation-tracker/bis-rescinds-ai-diffusion-rule-and-issues-new-guidance)). I did not reach the BIS or Federal Register primary text. Current status as of October 2026: UNVERIFIED [low]. Volunteers in many countries donating compute also raises compliance questions I did not research.
- Safety: an openly released model can be used for harm; the primary documents above place duties on "providers" in the EU case. An open project that is the provider should expect to publish a model card, data summary and evaluation results. UNVERIFIED [medium] that this is the full list.

---

## 6. Domain check: openhumanity.io

Run on this machine, 2026-10-15 about 18:57 to 19:10 US Central. Only what the tools show.

- `dig openhumanity.io A`: status NXDOMAIN (name does not exist), no answer; the authority section shows the `.io` zone's own SOA record.
- `dig +short` for NS, A, AAAA, MX, TXT, SOA and `www`: all empty.
- Asking the `.io` registry's own server directly (`dig @a0.nic.io openhumanity.io NS +norecurse`): NXDOMAIN with the authoritative flag set. So the registry has no delegation for this name: no nameservers are published for it.
- `dig +trace`: the chain reached `b0.nic.io`, which answered with signed proof that the name does not exist.
- Registry RDAP lookup (`https://rdap.identitydigital.services/rdap/domain/openhumanity.io`): HTTP 404 "Object not found". Control check on `github.io` through the same service: HTTP 200. So the lookup method works, and for this name the registry reports no record.
- `whois` is not installed on this machine, so I could not run it. The registrar (Gandi or any other) cannot be reported from these tools, because the registry has no record to show.
- `curl -I https://openhumanity.io`: no response (name does not resolve).
- For context only (nameservers seen, owner not checked): `openhumanity.com` points to Cloudflare nameservers; `openhumanity.org` to Sedo Parking; `openhumanity.ai` to GoDaddy (domaincontrol.com) nameservers. Whether you own any of these is unknown to me.

What this means: from the public internet, openhumanity.io is not registered or not active right now. Possible reasons (not distinguished by these tools): registration never completed, it expired or was cancelled, the order is pending payment or verification, or the name was entered differently at Gandi. Check the Gandi account and order history. Until then nothing is served on it.

---

## 7. Recommended first experiment

**Decided by Drake, 2026-10-15:** no Python, no CUDA, no exception for a throwaway test. "We build our own." Options A and B below are rejected and kept only as prior art to learn from (their papers and designs, not their code). The first experiment will be the same question answered on our own stack: our own trainer, our own compressed-update exchange (DiLoCo-style), and each volunteer update scored in Turings (held-out bits gained, see the Turing Yield program) to decide whether it is accepted and how it is credited.

Goal: answer one question with real numbers: do 3 to 4 separate machines on ordinary internet, each training alone and swapping small summaries, produce a model nearly as good as the same compute on one machine? Smallest honest version, using existing software.

### 7.1 Plan

1. Baseline on the Spark: train a Llama-style 20M model (Psyche's own sample size) and then a 124M model on the same data on the Spark alone. Record validation loss versus tokens and time. The Spark's measured 124M speed is about 48,793 tokens/s (OBSERVED, own-model-results.md).
2. Option A (recommended): Psyche in its plain-server mode (no blockchain). Its repository ships a ready config for exactly this: `llama2-20m` pretraining on FineWeb-Edu tokens with a TCP coordinator at 127.0.0.1, `min_clients = 2`, DisTrO optimizer ([config directory](https://github.com/PsycheFoundation/psyche/tree/main/config)). Steps: run the coordinator and the data server on the Spark; start the client on the Spark; start clients on 2 to 3 volunteer Linux machines with NVIDIA GPUs (Docker and NVIDIA container toolkit needed, per [join-run](https://github.com/PsycheFoundation/psyche/blob/main/psyche-book/src/enduser/join-run.md)).
   - Why this one: it already contains the hard parts (compressed updates, join and leave, witnesses, optional verification, P2P model download), it is Rust, Apache-2.0, and it runs the verification code you would want to study.
   - Costs and risks: needs CUDA and Docker (outside your rule, used as a throwaway tool); last commit 2026-03-20; architecture limited to Llama or DeepSeek style; I did not run it, so build success on the GB10 (ARM, CUDA 13) is UNVERIFIED [unknown].
3. Option B (fallback): OpenDiLoCo or prime-diloco with the existing nanoGPT model, since it is already on the Spark in PyTorch ([OpenDiLoCo](https://github.com/PrimeIntellect-ai/OpenDiLoCo), Apache-2.0, last push 2026-07-17). It is Python and Hivemind-based; the paper's 150M and 1.1B experiments are the template ([HTML](https://arxiv.org/html/2407.07852)). Risk: Hivemind's last push is 2026-01-11 and compatibility with PyTorch 2.14 on aarch64 is UNVERIFIED.
4. Measure and write down: loss versus tokens for 1 vs 3 vs 4 machines; bytes sent per sync; share of time spent waiting on the network; what happens when one volunteer disconnects mid-run; what happens when one volunteer is made to send bad updates on purpose (a deliberate cheater test, with and without the verification setting).
5. Pass criteria (set before running): the 3 to 4 machine run reaches within a small, pre-agreed gap of the single-machine loss at equal total tokens (OpenDiLoCo's 1.1B result of 10.76 vs 10.52 is the kind of gap seen in practice); communication is under about 10% of wall time (INTELLECT-1 saw 2 to 10%); a deliberate bad update is detected or its damage is bounded.
6. Only after that, decide on the Open Humanity layer: signed volunteer keys, signed result receipts, and the volunteer agreement.

### 7.2 What the Spark does and does not give you

- Specs per NVIDIA: 128 GB unified memory at 273 GB/s, a 200 Gbps ConnectX-7 network port, and a 10 GbE port; "up to 1 PFLOP FP4" ([NVIDIA DGX Spark](https://www.nvidia.com/en-us/products/workstations/dgx-spark/)). The FP4 figure is not the bf16 training speed; measured bf16 matmul and training numbers are in the own-model-results note.
- The Spark has far more memory than the volunteers' likely cards. In the test, cap the model so it fits the smallest volunteer GPU, or the Spark will not be representative of the volunteers.
- The volunteer machines should be on home internet, not the same LAN, or the key number (network cost) will be wrong.

### 7.3 Cost of being wrong

This experiment changes nothing in this repository, costs days of machine time and some volunteer setup, and can be undone fully. A negative result (does not converge, or too slow at home speeds) would still be useful: it would move the plan toward rank 1 and 3 in section 3.

---

## Open questions

1. Is openhumanity.io actually registered? What does the Gandi order history show?
2. Is the goal "a model trained by consumers" (not shown by any source for pretraining) or "a model everyone can use for free, with consumers helping in some way"? Section 3 shows the second is much easier.
3. Resolved 2026-10-15: AGPL-3.0-or-later for code and model (see section 5). Remaining work: remove the stale Apache-2.0 wording from the governance documents.
4. Can the "no Python, no CUDA" rule bend for the experiment only? If not, the experiment becomes a larger Burn-based build (section 4.5).
5. Who holds the release key and who decides data and stopping a run (section 5.3)?
6. What does a typical volunteer upload speed look like? I found no sourced survey.
7. Does Psyche build and run on a GB10 (ARM64, CUDA 13)? Does the real Consilience run use the verification setting? Both unverified.
8. How do the Covenant-72B and Consilience 40B models compare in independent evaluation? Only self-reported numbers were found for both.
9. Current US export-control status for model weights in October 2026: not reached at primary level.
10. The in-progress aien-lm trainer (src/train/) was not visible from the checkout I could read; it may change section 4.6.

## Sources

Papers (arXiv):
- DiLoCo: https://arxiv.org/abs/2311.08105
- OpenDiLoCo: https://arxiv.org/abs/2407.07852
- Streaming DiLoCo: https://arxiv.org/abs/2501.18512
- Scaling laws for DiLoCo: https://arxiv.org/abs/2503.09799
- SparseLoCo: https://arxiv.org/abs/2508.15706
- INTELLECT-1: https://arxiv.org/abs/2412.01152
- INTELLECT-2: https://arxiv.org/abs/2505.07291
- TOPLOC: https://arxiv.org/abs/2501.16007
- DeMo: https://arxiv.org/abs/2411.19870
- Covenant-72B: https://arxiv.org/abs/2603.08163
- Distributed Deep Learning in Open Collaborations (sahajBERT): https://arxiv.org/abs/2106.10207
- Petals: https://arxiv.org/abs/2209.01188
- SWARM parallelism: https://arxiv.org/abs/2301.11913
- Subspace Networks (Pluralis): https://arxiv.org/abs/2506.01260
- NoLoCo (Gensyn): https://arxiv.org/abs/2506.10911
- Verde (Gensyn): https://arxiv.org/abs/2502.19405
- Photon: https://arxiv.org/abs/2411.02908
- Proof-of-Learning: https://arxiv.org/abs/2103.05633 and its critique https://arxiv.org/abs/2208.03567
- ZeRO: https://arxiv.org/abs/1910.02054
- QLoRA: https://arxiv.org/abs/2305.14314
- Common Pile: https://arxiv.org/abs/2506.05209
- SPES: https://arxiv.org/abs/2602.11543
- BOINC (Anderson): https://arxiv.org/abs/1903.01699

Project pages and blogs:
- Nous Psyche announcement: https://nousresearch.com/nous-psyche/
- Nous, next phase of Psyche: https://nousresearch.com/the-next-phase-of-psyche
- Prime Intellect, INTELLECT-3: https://www.primeintellect.ai/blog/intellect-3
- Together, GPT-JT: https://www.together.ai/blog/releasing-v1-of-gpt-jt-powered-by-open-source-ai
- Gensyn, RL Swarm: https://blog.gensyn.ai/rl-swarm-a-framework-for-collaborative-rl/
- Folding@home points and passkey: https://foldingathome.org/passkey/
- Khronos on Folding@home exaFLOP: https://www.khronos.org/news/permalink/foldinghome-uses-opencl-for-covid19-research-and-breaks-the-exaflop-barrier
- NVIDIA on Folding@home exaFLOP: https://developer.nvidia.com/blog/foldinghome-gpu-accelerated-exaflop
- NVIDIA DGX Spark: https://www.nvidia.com/en-us/products/workstations/dgx-spark/
- Steam hardware survey: https://store.steampowered.com/hwsurvey/videocard/

Code and docs (GitHub, read 2026-10-15):
- Psyche: https://github.com/PsycheFoundation/psyche (book under psyche-book/src, configs under config/)
- OpenDiLoCo, prime-diloco, prime-rl: https://github.com/PrimeIntellect-ai
- Hivemind: https://github.com/learning-at-home/hivemind
- Petals: https://github.com/bigscience-workshop/petals
- torchft: https://github.com/pytorch/torchft
- RL Swarm: https://github.com/gensyn-ai/rl-swarm
- BOINC: https://github.com/BOINC/boinc
- Folding@home client: https://github.com/FoldingAtHome/fah-client-bastet
- Burn: https://github.com/tracel-ai/burn
- candle: https://github.com/huggingface/candle

Law and standards:
- Open Source AI Definition 1.0: https://opensource.org/ai/open-source-ai-definition
- EU AI Act Article 53: https://artificialintelligenceact.eu/article/53/ ; Article 51: https://artificialintelligenceact.eu/article/51/
- BIS AI Diffusion rescission (law-firm summary): https://www.akingump.com/en/insights/ai-law-and-regulation-tracker/bis-rescinds-ai-diffusion-rule-and-issues-new-guidance

Model and dataset license metadata (Hugging Face API): PrimeIntellect/INTELLECT-1, INTELLECT-2, INTELLECT-3; 1Covenant/Covenant-72B; common-pile/comma-v0.1-1t; allenai/OLMo-2-1124-7B; HuggingFaceFW/fineweb-edu.

Local files read (not public): this repository (README.md, CONSTITUTION.md, COVENANT.md, docs/, crates/beacon-core/src), the local research notes own-model-plan.md and own-model-results.md, ~/workspace/aien-lm/README.md.

Not opened in this pass (cited from search summaries only, so lower confidence): the SPES paper body, the Proof-of-Learning critique body, the Cosmopedia blog, the Akin Gump summary body beyond the search extract, and sahajBERT's Hugging Face blog (404).
