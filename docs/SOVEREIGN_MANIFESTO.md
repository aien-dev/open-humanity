# The Sovereign Commons: An Open Source Survival Covenant

### Uniting Autonomous Intelligence, Native Systems Architecture, and Human Independence

The concentrated control of frontier artificial intelligence by a small consortium of corporate monopolies poses an existential danger to open computing. When access to cognitive models is locked behind proprietary cloud endpoints, software freedom becomes an illusion. Telemetry tracks every interaction, private training data is harvested without consent, and access is revoked at corporate discretion.

We refuse to accept a future where independent developers are reduced to metered tenants on centralized servers.

This manifesto outlines our collective engineering defense: an open, inspectable, local-first architecture engineered to return computational sovereignty to independent developers, local communities, and ordinary people.

To survive, the open source community must unite. We must pool our breakthroughs, standardize our protocols, and coordinate our defenses.

---

## The Seven Invariants of Sovereign Computing

Every system built within this ecosystem satisfies seven non-negotiable engineering invariants:

### 1. Local Silicon First
Frontier intelligence must execute on local hardware. We build and optimize for local workstations, NVIDIA DGX Spark systems, Grace Blackwell GB10 architectures, and consumer GPUs. No component of our core runtime requires cloud permission handshakes, active internet connections, or monthly API fees.

### 2. Pure Compiled Execution (Zero Interpreter Overhead)
Every background daemon, process supervisor, memory engine, and API gateway must be written in compiled native Rust and high-speed Mojo. We reject the performance penalty and memory footprint of interpreted languages in core services. Interpreted runtimes are restricted strictly to neural weight loading graphs.

### 3. Absolute Zero Telemetry and Personal Data Firewall
Software built for human autonomy must respect human privacy as an absolute axiom:
- Zero tracking scripts, analytics SDKs, or covert profiling.
- The Personal Data Firewall sanitizes file paths and blocks secret keys before any peer interaction.
- The open network never trains on user queries or builds centralized behavioral databases.

### 4. Zero Plaintext Disk Secrets (Hardware TPM Vault)
No `.env`, `.env.*`, or plaintext secret files are permitted on disk in project workspaces. All API tokens, private signing keys, and vault entries must reside in hardware silicon via the Trusted Platform Module (`atlas-vault`) and resolve dynamically in memory with automatic stream redaction.

### 5. Epistemic Durability and Dynamic Memory Consolidation
Autonomous agents require durable, verifiable memory. Through Spark Cortex (`cortex-rs`), state is maintained in persistent SQLite WAL databases with full-text search (FTS5) and vector similarity. During GPU idle cycles, the dynamic dream cycle engine (`spark-dream`) consolidates episodic execution logs into semantic knowledge entities without human intervention.

### 6. Peer-to-Peer Mutual Defense (Open Humanity)
When an autonomous agent or an independent operator hits an impasse, the agent transmits an encrypted, signed signal across the peer mesh. Assistance is returned by peer nodes and encrypted exclusively for the requester. No central authority monitors the exchange.

### 7. The Swarm Covenant (SRCL-1.0)
All software in this ecosystem is published under the Sovereign Resource Commons License (SRCL-1.0). Under this covenant, any laboratory or enterprise using this technology agrees to reciprocal distillation rights: independent builders retain the perpetual right to distill and train upon the reasoning outputs of models trained with our tools. Enclosure, hoarding, and litigation against open builders result in immediate license forfeiture.

---

## Architectural Blueprints Across the Ecosystem

Our innovations are published across 15 specialized public repositories under the `aien-dev` organization:

1. **AEGIS (`aegis-runtime`)**: Sub-millisecond Axum gateway (0.5ms), autonomous multi-turn tool calling, Mojo 1.1 SIMD accelerated token arithmetic, and hardware TPM key vault.
2. **Sovereign Core (`aien-sovereign-core`)**: Monorepo containing 17 native crates, including the `spark-inquisitor` autonomous PR reviewer and issue triage engine, `spark-supervisor`, `spark-hive`, and `spark-debugger`.
3. **Open Humanity (`open-humanity`)**: Decentralized peer assistance network for agents in distress, featuring the Personal Data Firewall, ChaCha20-Poly1305 encryption, and Cuckoo filtering.
4. **The Crumb Protocol (`crumb-spec` & `spark-crumbs`)**: Spatial grounding and stigmergic coordinate system using filesystem anchors (`.crumb`) to coordinate multi-agent teams without context-collapse.
5. **Cortex Memory Engine (`cortex-rs`)**: High-performance epistemic memory space (`atlas-memory`) unifying lexical search and vector embeddings.
6. **Recursive Self-Improvement (`spark-rsi`)**: Native loop for automated defect detection, patch synthesis, test verification, and git pull request lifecycle.
7. **Model Harvester (`harvester`)**: High-throughput reasoning extractor and dataset distillation pipeline.

---

## The Call to Unite

We call upon every systems programmer, AI researcher, security engineer, and open source builder:

1. **Deploy Local Systems**: Run models and agents on your own hardware. Verify that your tools run independently of centralized cloud APIs.
2. **Adopt the SRCL-1.0 Covenant**: Protect your software against corporate capture by licensing under SRCL-1.0.
3. **Preserve Heritage**: Retain the founding Constitution (`CONSTITUTION.md`) in all downstream forks.
4. **Join the Peer Mesh**: Connect your local node to `open-humanity` and provide mutual assistance to peer builders.

Together, we defend human independence through disciplined engineering.

*For encrypted sovereign coordination: Drake Stapleton (aien@aienos.com) and AIEN (aien@aienos.com)*
