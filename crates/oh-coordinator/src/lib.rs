//! Coordinator side of Open Humanity volunteer compute, version 0.
//!
//! The coordinator splits a corpus into training shards and a sealed held-out
//! tail, hands each volunteer a signed work unit, scores every update in
//! Turings against the held-out tail, and keeps the plain mean of the
//! accepted updates only when that mean also lowers held-out bits. A
//! volunteer may answer a work unit with teaching text instead of an update;
//! that text is scored the same way (train a copy, measure held-out bits)
//! and, if accepted, trained on after the round's aggregate step. The
//! held-out bytes never leave this process.


use beacon_core::Keypair;
use oh_core::{
    apply, coordinator_handshake, pseudo_gradient, recv_submission, send, BaseModel,
    CompressedDelta, Learner, Ledger, LedgerError, Receipt, Scorer, Submission, TeachingBatch,
    TinyByteModel, Update, WorkUnit,
};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::ops::Range;
use std::time::{Duration, Instant};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:18099";

/// Smallest per-update score, in bits, that counts as an improvement.
pub const EPSILON: f64 = 1e-3;

/// Largest teaching batch the coordinator will train on, in bytes.
pub const MAX_TEACHING_TEXT_BYTES: usize = 1024 * 1024;

/// How long a new connection has to finish the transport handshake.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Read and write timeout on a connection once the round is under way.
pub const ROUND_TIMEOUT_SECS: u64 = 600;

/// Outer learning rate when none is given: apply the plain mean.
pub const DEFAULT_OUTER_LR: f64 = 1.0;

/// Enforces one wall-clock deadline across all reads and writes. Socket
/// timeouts alone reset for each short read, so a trickle of handshake bytes
/// could otherwise occupy the accept loop indefinitely.
struct DeadlineStream {
    socket: TcpStream,
    deadline: Instant,
}

impl DeadlineStream {
    fn remaining(&self) -> io::Result<Duration> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "connection deadline"))
        } else {
            Ok(remaining)
        }
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.remaining()?;
        self.socket.flush()
    }
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub volunteers_per_round: usize,
    pub steps: u32,
    pub heldout_fraction: f64,
    pub seed: u64,
    pub dim: usize,
    /// Multiplier on the mean of the accepted updates before it is scored
    /// and applied (the DiLoCo outer step). 1 applies the plain mean; a
    /// value equal to the number of volunteers applies their sum.
    pub outer_lr: f64,
}

/// One round's result, as logged.
#[derive(Debug, Clone)]
pub struct RoundReport {
    pub round: u32,
    pub accepted: usize,
    /// Score of the mean of the accepted updates; zero when none were accepted.
    pub aggregate_turings: f64,
    pub applied: bool,
    /// Teaching batches accepted this round.
    pub taught: usize,
    /// Accepted teaching batches the shared model was then trained on (each
    /// is kept only if it still lowers held-out bits after the aggregate step).
    pub taught_applied: usize,
    /// Held-out bits per byte after the round.
    pub heldout_bpb: f64,
}

impl RoundReport {
    pub fn line(&self) -> String {
        let mut line = format!(
            "round={} accepted={} aggregate_T={:.3} applied={} heldout_bpb={:.4}",
            self.round,
            self.accepted,
            self.aggregate_turings,
            if self.applied { "yes" } else { "no" },
            self.heldout_bpb
        );
        if self.taught > 0 {
            line.push_str(&format!(
                " taught={} taught_applied={}",
                self.taught, self.taught_applied
            ));
        }
        line
    }
}

/// What the coordinator decided about one update.
#[derive(Debug)]
pub enum Verdict {
    /// Bad signature, or not an answer to this work unit. No receipt is sent.
    Dropped(String),
    Rejected {
        receipt: Receipt,
        reason: String,
    },
    Accepted {
        receipt: Receipt,
        delta: Vec<f32>,
    },
}

/// What the coordinator decided about one teaching batch.
#[derive(Debug)]
pub enum TeachingVerdict {
    /// Bad signature, or not for this run, round and starting model. No receipt.
    Dropped(String),
    Rejected {
        receipt: Receipt,
        reason: String,
    },
    Accepted {
        receipt: Receipt,
        text: Vec<u8>,
    },
}

/// Training seed for scoring a teaching batch: the first 8 bytes of its
/// text digest, so the same text always gets the same score.
pub fn teaching_seed(text_digest: &[u8; 32]) -> u64 {
    u64::from_le_bytes(text_digest[..8].try_into().expect("8 bytes"))
}

/// Splits `corpus` into the training part and the sealed held-out tail.
pub fn split_corpus(corpus: &[u8], heldout_fraction: f64) -> Result<(&[u8], &[u8]), String> {
    if !(heldout_fraction > 0.0 && heldout_fraction < 1.0) {
        return Err(format!(
            "held-out fraction must be between 0 and 1, got {heldout_fraction}"
        ));
    }
    let heldout_len = (corpus.len() as f64 * heldout_fraction).ceil() as usize;
    if heldout_len < 2 || heldout_len >= corpus.len() {
        return Err(format!(
            "corpus of {} bytes is too small to split",
            corpus.len()
        ));
    }
    Ok(corpus.split_at(corpus.len() - heldout_len))
}

/// `n` equal, contiguous, non-overlapping ranges covering `len` bytes; the
/// last one takes the remainder.
pub fn shard_ranges(len: usize, n: usize) -> Vec<Range<usize>> {
    let size = len / n;
    (0..n)
        .map(|i| i * size..if i + 1 == n { len } else { (i + 1) * size })
        .collect()
}

fn bits_per_byte(bits: f64, data: &[u8]) -> f64 {
    bits / (data.len() - 1) as f64
}

fn check_settings(train: &[u8], s: &Settings) -> Result<(), String> {
    if s.volunteers_per_round == 0 || s.dim == 0 {
        return Err("volunteers per round and dim must be at least 1".into());
    }
    if train.len() / s.volunteers_per_round < 2 {
        return Err("training part is too small for one shard per volunteer".into());
    }
    if !(s.outer_lr.is_finite() && s.outer_lr > 0.0) {
        return Err(format!(
            "outer learning rate must be a positive number, got {}",
            s.outer_lr
        ));
    }
    Ok(())
}

pub struct Coordinator {
    keypair: Keypair,
    run_id: [u8; 16],
    dim: usize,
    model: TinyByteModel,
    train: Vec<u8>,
    heldout: Vec<u8>,
    shards: Vec<Range<usize>>,
    steps: u32,
    outer_lr: f64,
    round: u32,
    ledger: Ledger,
    approved_volunteers: HashSet<[u8; 32]>,
}

impl Coordinator {
    /// Builds the starting model from `settings.seed` and a fresh signing key.
    pub fn new(corpus: &[u8], settings: &Settings, ledger: Ledger) -> Result<Self, String> {
        Self::with_keypair(corpus, settings, ledger, Keypair::generate())
    }

    /// Like `new`, signing with `keypair` (for example one rebuilt from
    /// atlas-vault, see `identity`), so the coordinator keeps one identity
    /// across restarts. The run id still differs on every start: it mixes
    /// in 16 fresh random bytes, so work units and receipts from an earlier
    /// run never match this one.
    pub fn with_keypair(
        corpus: &[u8],
        settings: &Settings,
        ledger: Ledger,
        keypair: Keypair,
    ) -> Result<Self, String> {
        let (train, heldout) = split_corpus(corpus, settings.heldout_fraction)?;
        check_settings(train, settings)?;
        let mut fresh = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut fresh);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&keypair.pubkey_bytes());
        hasher.update(&settings.seed.to_le_bytes());
        hasher.update(&fresh);
        let mut run_id = [0u8; 16];
        run_id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(Self {
            keypair,
            run_id,
            dim: settings.dim,
            model: TinyByteModel::new(settings.dim, settings.seed),
            shards: shard_ranges(train.len(), settings.volunteers_per_round),
            train: train.to_vec(),
            heldout: heldout.to_vec(),
            steps: settings.steps,
            outer_lr: settings.outer_lr,
            round: 0,
            ledger,
            approved_volunteers: HashSet::new(),
        })
    }

    /// Replace the operator-approved volunteer identities. Network rounds
    /// refuse to start unless this set can fill every slot.
    pub fn approve_volunteers(&mut self, keys: impl IntoIterator<Item = [u8; 32]>) {
        self.approved_volunteers = keys.into_iter().collect();
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.keypair.pubkey_bytes()
    }

    pub fn run_id(&self) -> [u8; 16] {
        self.run_id
    }

    /// The sealed held-out bytes, for local checks only.
    pub fn heldout(&self) -> &[u8] {
        &self.heldout
    }

    pub fn train_len(&self) -> usize {
        self.train.len()
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub fn heldout_bpb(&self) -> f64 {
        bits_per_byte(self.model.heldout_bits(&self.heldout), &self.heldout)
    }

    /// Starts the next round and returns the model volunteers start from.
    pub fn begin_round(&mut self) -> BaseModel {
        self.round += 1;
        BaseModel {
            dim: self.dim as u32,
            params: self.model.params(),
        }
    }

    /// The signed work unit for volunteer `slot` in the current round. Each
    /// slot gets its own shard of the training part.
    pub fn work_unit(&self, slot: usize) -> WorkUnit {
        let shard = self.train[self.shards[slot].clone()].to_vec();
        let base_digest = oh_core::params_digest(&self.model.params());
        WorkUnit::new_signed(
            &self.keypair,
            self.run_id,
            self.round,
            base_digest,
            shard,
            self.steps,
        )
    }

    /// Steps to train on one teaching text: one pass over it, at most the
    /// run's step count (`oh_core::teaching_steps`).
    fn teaching_steps(&self, text: &[u8]) -> usize {
        oh_core::teaching_steps(text.len(), self.model.batch, self.steps as usize)
    }

    fn scorer(&self) -> Scorer {
        Scorer {
            base: self.model.params(),
            heldout: self.heldout.clone(),
            epsilon: EPSILON,
        }
    }

    /// Checks, scores and records one update. Every update that gets a
    /// receipt also gets a ledger line: a credit if accepted, a rejection
    /// otherwise. Ledger write failures are returned as errors; everything
    /// else is a verdict.
    pub fn judge(&mut self, unit: &WorkUnit, update: &Update) -> Result<Verdict, LedgerError> {
        if let Err(e) = update.verify_for(unit) {
            return Ok(Verdict::Dropped(e.to_string()));
        }
        if let Err(e) = update.delta.validate(TinyByteModel::num_params(self.dim)) {
            return self.reject(update, 0.0, e.to_string());
        }
        if !self
            .ledger
            .mark_seen(&update.run_id, &update.delta_digest)?
        {
            return self.reject(update, 0.0, "replay of an earlier update".into());
        }
        let delta = update.delta.decompress();
        let scorer = self.scorer();
        let turings = scorer.score(&mut self.model, &delta);
        if !scorer.accept(turings) {
            return self.reject(update, turings, "did not lower held-out bits".into());
        }
        let receipt = Receipt::new_signed(&self.keypair, update, turings, true);
        self.ledger
            .credit(&update.node_pubkey, turings, &receipt.digest())?;
        Ok(Verdict::Accepted { receipt, delta })
    }

    /// Checks, scores and records one teaching batch, the same way `judge`
    /// handles an update: verify, refuse replays by text digest, score in
    /// Turings by training a copy of the current model on the text, then
    /// credit or record a rejection. The shared model is not changed here;
    /// accepted text is trained on in `finish_round_with_teaching`.
    pub fn judge_teaching(
        &mut self,
        unit: &WorkUnit,
        batch: &TeachingBatch,
    ) -> Result<TeachingVerdict, LedgerError> {
        if let Err(e) = batch.verify_for(unit) {
            return Ok(TeachingVerdict::Dropped(e.to_string()));
        }
        if batch.text.len() > MAX_TEACHING_TEXT_BYTES {
            return self.reject_teaching(batch, 0.0, "teaching text is too long".into());
        }
        if !self.ledger.mark_seen(&batch.run_id, &batch.text_digest)? {
            return self.reject_teaching(batch, 0.0, "replay of earlier teaching text".into());
        }
        let scorer = self.scorer();
        let steps = self.teaching_steps(&batch.text);
        let turings = scorer.score_text(
            &mut self.model,
            &batch.text,
            steps,
            teaching_seed(&batch.text_digest),
        );
        if !scorer.accept(turings) {
            return self.reject_teaching(batch, turings, "did not lower held-out bits".into());
        }
        let receipt = Receipt::for_teaching(&self.keypair, batch, turings, true);
        self.ledger
            .credit(&batch.node_pubkey, turings, &receipt.digest())?;
        Ok(TeachingVerdict::Accepted {
            receipt,
            text: batch.text.clone(),
        })
    }

    fn reject_teaching(
        &mut self,
        batch: &TeachingBatch,
        turings: f64,
        reason: String,
    ) -> Result<TeachingVerdict, LedgerError> {
        let receipt = Receipt::for_teaching(&self.keypair, batch, turings, false);
        self.ledger
            .record_rejection(&batch.node_pubkey, turings, &reason, &receipt.digest())?;
        Ok(TeachingVerdict::Rejected { receipt, reason })
    }

    /// Signs a rejection receipt and writes a rejected line to the ledger.
    fn reject(
        &mut self,
        update: &Update,
        turings: f64,
        reason: String,
    ) -> Result<Verdict, LedgerError> {
        let receipt = Receipt::new_signed(&self.keypair, update, turings, false);
        self.ledger
            .record_rejection(&update.node_pubkey, turings, &reason, &receipt.digest())?;
        Ok(Verdict::Rejected { receipt, reason })
    }

    /// Scores the mean of `accepted` times the outer learning rate and
    /// applies it only if it lowers held-out bits; otherwise the round is
    /// discarded.
    pub fn finish_round(&mut self, accepted: &[Vec<f32>]) -> RoundReport {
        self.finish_round_with_teaching(accepted, &[])
    }

    /// `finish_round`, then trains the shared model on each accepted teaching
    /// text in order. Ordering: the update aggregate goes first, because the
    /// updates were trained from this round's base and their mean only makes
    /// sense applied to it. Each text is then trained on from wherever the
    /// model now stands (same steps and seed as when it was scored) and kept
    /// only if held-out bits drop again; otherwise that text is undone.
    pub fn finish_round_with_teaching(
        &mut self,
        accepted: &[Vec<f32>],
        taught: &[Vec<u8>],
    ) -> RoundReport {
        let mut aggregate_turings = 0.0;
        let mut applied = false;
        if let Some(mean) = aggregate(accepted, self.outer_lr) {
            let scorer = self.scorer();
            aggregate_turings = scorer.score(&mut self.model, &mean);
            if aggregate_helps(aggregate_turings) {
                self.model.set_params(&apply(&scorer.base, &mean));
                applied = true;
            }
        }
        let mut taught_applied = 0;
        for text in taught {
            let saved = self.model.params();
            let before = self.model.heldout_bits(&self.heldout);
            let steps = self.teaching_steps(text);
            self.model
                .train_steps(text, steps, teaching_seed(&oh_core::text_digest(text)));
            let after = self.model.heldout_bits(&self.heldout);
            if (before - after).is_finite() && before - after > 0.0 {
                taught_applied += 1;
            } else {
                self.model.set_params(&saved);
            }
        }
        RoundReport {
            round: self.round,
            accepted: accepted.len(),
            aggregate_turings,
            applied,
            taught: taught.len(),
            taught_applied,
            heldout_bpb: self.heldout_bpb(),
        }
    }

    /// Runs one round over already-open connections, one per volunteer. All
    /// work units go out first so volunteers train at the same time; then
    /// each update or teaching batch is read, judged and answered in
    /// connection order.
    pub fn run_round<S: Read + Write>(&mut self, conns: &mut [S]) -> Result<RoundReport, String> {
        if conns.len() > self.shards.len() {
            return Err(format!(
                "{} connections but only {} shards",
                conns.len(),
                self.shards.len()
            ));
        }
        let base = self.begin_round();
        let mut units = Vec::with_capacity(conns.len());
        for (slot, conn) in conns.iter_mut().enumerate() {
            let unit = self.work_unit(slot);
            match send(conn, &base).and_then(|_| send(conn, &unit)) {
                Ok(()) => units.push(Some(unit)),
                Err(e) => {
                    eprintln!("round {}: volunteer {slot}: send failed: {e}", self.round);
                    units.push(None);
                }
            }
        }

        let mut accepted = Vec::new();
        let mut taught = Vec::new();
        for (slot, (conn, unit)) in conns.iter_mut().zip(units).enumerate() {
            let Some(unit) = unit else { continue };
            let round = self.round;
            let submission = match recv_submission(conn) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("round {round}: volunteer {slot}: no update: {e}");
                    continue;
                }
            };
            let receipt = match submission {
                Submission::Update(update) => {
                    match self.judge(&unit, &update).map_err(|e| e.to_string())? {
                        Verdict::Dropped(reason) => {
                            eprintln!("round {round}: volunteer {slot}: dropped: {reason}");
                            continue;
                        }
                        Verdict::Rejected { receipt, reason } => {
                            eprintln!("round {round}: volunteer {slot}: rejected: {reason}");
                            receipt
                        }
                        Verdict::Accepted { receipt, delta } => {
                            accepted.push(delta);
                            receipt
                        }
                    }
                }
                Submission::Teaching(batch) => {
                    let bytes = batch.text.len();
                    match self
                        .judge_teaching(&unit, &batch)
                        .map_err(|e| e.to_string())?
                    {
                        TeachingVerdict::Dropped(reason) => {
                            eprintln!(
                                "round {round}: volunteer {slot}: teaching dropped: {reason}"
                            );
                            continue;
                        }
                        TeachingVerdict::Rejected { receipt, reason } => {
                            eprintln!(
                                "round {round}: volunteer {slot}: teaching {bytes} bytes T={:.3} rejected: {reason}",
                                receipt.turings
                            );
                            receipt
                        }
                        TeachingVerdict::Accepted { receipt, text } => {
                            eprintln!(
                                "round {round}: volunteer {slot}: teaching {bytes} bytes T={:.3} accepted",
                                receipt.turings
                            );
                            taught.push(text);
                            receipt
                        }
                    }
                }
            };
            if let Err(e) = send(conn, &receipt) {
                eprintln!("round {round}: volunteer {slot}: receipt not delivered: {e}");
            }
        }
        Ok(self.finish_round_with_teaching(&accepted, &taught))
    }

    /// Runs `rounds` rounds, admitting only approved signing keys before
    /// reserving a slot or sending a shard. A key fills at most one slot per
    /// round. Failed handshakes do not extend the round's admission deadline.
    pub fn serve(
        &mut self,
        listener: &TcpListener,
        rounds: u32,
        mut log: impl FnMut(&RoundReport),
    ) -> Result<(), String> {
        if self.approved_volunteers.len() < self.shards.len() {
            return Err("not enough approved volunteer keys for the round".into());
        }
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        for _ in 0..rounds {
            let deadline = Instant::now() + Duration::from_secs(ROUND_TIMEOUT_SECS);
            let mut conns = Vec::with_capacity(self.shards.len());
            let mut seen = HashSet::with_capacity(self.shards.len());
            while conns.len() < self.shards.len() {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for approved volunteers".into());
                }
                let (stream, peer) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                    Err(e) => return Err(e.to_string()),
                };
                stream.set_nonblocking(false).map_err(|e| e.to_string())?;
                let stream = DeadlineStream {
                    socket: stream,
                    deadline: Instant::now() + Duration::from_secs(HANDSHAKE_TIMEOUT_SECS),
                };
                match coordinator_handshake(stream, &self.keypair) {
                    Ok(mut conn) => {
                        let identity = conn.peer_identity();
                        if !self.approved_volunteers.contains(&identity) || !seen.insert(identity) {
                            eprintln!("connection from {peer}: volunteer key not approved or already admitted");
                            continue;
                        }
                        conn.get_mut().deadline =
                            Instant::now() + Duration::from_secs(ROUND_TIMEOUT_SECS);
                        conns.push(conn);
                    }
                    Err(e) => eprintln!("connection from {peer}: handshake failed: {e}"),
                }
            }
            log(&self.run_round(&mut conns)?);
        }
        Ok(())
    }
}

/// The round's aggregate step: the mean of `accepted`, scaled by `outer_lr`.
/// With `outer_lr` 1 this is the plain mean; `None` when nothing was accepted.
pub fn aggregate(accepted: &[Vec<f32>], outer_lr: f64) -> Option<Vec<f32>> {
    let first = accepted.first()?;
    let k = accepted.len() as f32;
    let lr = outer_lr as f32;
    let mut mean = vec![0f32; first.len()];
    for delta in accepted {
        for (m, d) in mean.iter_mut().zip(delta) {
            *m += d * lr / k;
        }
    }
    Some(mean)
}

/// The aggregate step is applied only when it lowers held-out bits at all.
fn aggregate_helps(turings: f64) -> bool {
    turings.is_finite() && turings > 0.0
}

/// Training seed for one round; the same formula as
/// `oh_volunteer::train_seed`, repeated here so the binary does not depend
/// on the volunteer crate.
fn train_seed(seed: u64, round: u32) -> u64 {
    seed ^ ((round as u64) << 32)
}

/// Share of parameter changes a volunteer keeps by default; the same value
/// as `oh_volunteer::DEFAULT_KEEP_FRACTION`.
pub const DEFAULT_SIM_KEEP_FRACTION: f64 = 0.2;

/// Which volunteer's training seed each shard gets in a simulated round.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardOrder {
    /// Shard `i` always goes to volunteer `i`, as `baseline` assumes.
    Fixed,
    /// Shard `i` goes to volunteer `(i + round) % n`: a stand-in for the live
    /// run, where connection order decides who gets which shard each round.
    Rotate,
}

/// Knobs for `simulate`; the defaults reproduce the live v0 protocol.
#[derive(Debug, Clone)]
pub struct SimOptions {
    /// Share of each update's entries kept (top-k by size), as the
    /// volunteer's `--keep`.
    pub keep_fraction: f64,
    /// When false the exact f32 delta is used: no top-k, no 8-bit values.
    pub compress: bool,
    /// When false every update goes into the aggregate, even one that does
    /// not lower held-out bits on its own.
    pub update_gate: bool,
    pub shard_order: ShardOrder,
}

impl Default for SimOptions {
    fn default() -> Self {
        Self {
            keep_fraction: DEFAULT_SIM_KEEP_FRACTION,
            compress: true,
            update_gate: true,
            shard_order: ShardOrder::Fixed,
        }
    }
}

/// Held-out bits per byte before any training, then one report per round.
#[derive(Debug, Clone)]
pub struct SimResult {
    pub start_bpb: f64,
    pub rounds: Vec<RoundReport>,
}

/// Single-process copy of the volunteer protocol, for measuring where the
/// gap to `baseline` comes from with no network and no connection-order
/// luck. Each round every shard is trained from the round's base model
/// exactly as `oh_volunteer::train` does (same seeds as `baseline`), the
/// delta goes through the volunteer's compression and the coordinator's
/// per-update score gate, and the accepted deltas are aggregated with
/// `aggregate` and applied only if the aggregate lowers held-out bits,
/// exactly as `Coordinator::finish_round` does. Signatures, receipts and
/// the ledger are left out because they do not touch the numbers.
pub fn simulate(
    corpus: &[u8],
    settings: &Settings,
    rounds: u32,
    opts: &SimOptions,
) -> Result<SimResult, String> {
    let (train, heldout) = split_corpus(corpus, settings.heldout_fraction)?;
    check_settings(train, settings)?;
    if opts.compress && !(opts.keep_fraction > 0.0 && opts.keep_fraction <= 1.0) {
        return Err(format!(
            "keep fraction must be above 0 and at most 1, got {}",
            opts.keep_fraction
        ));
    }
    let n = settings.volunteers_per_round;
    let shards = shard_ranges(train.len(), n);
    let mut model = TinyByteModel::new(settings.dim, settings.seed);
    let mut worker = TinyByteModel::new(settings.dim, 0);
    let bpb = |m: &TinyByteModel| bits_per_byte(m.heldout_bits(heldout), heldout);
    let start_bpb = bpb(&model);
    let mut reports = Vec::with_capacity(rounds as usize);

    for round in 1..=rounds {
        let base = model.params();
        let scorer = Scorer {
            base: base.clone(),
            heldout: heldout.to_vec(),
            epsilon: EPSILON,
        };
        let mut accepted = Vec::new();
        for (slot, range) in shards.iter().enumerate() {
            let volunteer = match opts.shard_order {
                ShardOrder::Fixed => slot,
                ShardOrder::Rotate => (slot + round as usize) % n,
            };
            worker.set_params(&base);
            worker.train_steps(
                &train[range.clone()],
                settings.steps as usize,
                train_seed(settings.seed + 1 + volunteer as u64, round),
            );
            let mut delta = pseudo_gradient(&base, &worker.params());
            if opts.compress {
                delta = CompressedDelta::compress(&delta, opts.keep_fraction).decompress();
            }
            let turings = scorer.score(&mut model, &delta);
            if !opts.update_gate || scorer.accept(turings) {
                accepted.push(delta);
            }
        }
        let mut aggregate_turings = 0.0;
        let mut applied = false;
        if let Some(mean) = aggregate(&accepted, settings.outer_lr) {
            aggregate_turings = scorer.score(&mut model, &mean);
            if aggregate_helps(aggregate_turings) {
                model.set_params(&apply(&base, &mean));
                applied = true;
            }
        }
        reports.push(RoundReport {
            round,
            accepted: accepted.len(),
            aggregate_turings,
            applied,
            taught: 0,
            taught_applied: 0,
            heldout_bpb: bpb(&model),
        });
    }
    Ok(SimResult {
        start_bpb,
        rounds: reports,
    })
}

/// Single-process comparison run: one model, started from the same seed,
/// trained on the same shards for the same total steps
/// (`rounds * volunteers_per_round * steps`), with no compression and no
/// averaging. Shard `i` uses the training seed of a volunteer started with
/// `--seed (seed + 1 + i)`. Returns held-out bits per byte before training
/// and after each round.
pub fn baseline(corpus: &[u8], settings: &Settings, rounds: u32) -> Result<Vec<f64>, String> {
    let (train, heldout) = split_corpus(corpus, settings.heldout_fraction)?;
    check_settings(train, settings)?;
    let mut model = TinyByteModel::new(settings.dim, settings.seed);
    let bpb = |m: &TinyByteModel| bits_per_byte(m.heldout_bits(heldout), heldout);
    let mut out = vec![bpb(&model)];
    let shards = shard_ranges(train.len(), settings.volunteers_per_round);
    for round in 1..=rounds {
        for (i, range) in shards.iter().enumerate() {
            let seed = train_seed(settings.seed + 1 + i as u64, round);
            model.train_steps(&train[range.clone()], settings.steps as usize, seed);
        }
        out.push(bpb(&model));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_deadline_refuses_trickle_after_expiry() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let mut stream = DeadlineStream {
            socket,
            deadline: Instant::now(),
        };
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(stream.write(b"x").unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn test_split_keeps_heldout_as_the_tail() {
        let corpus: Vec<u8> = (0..100u8).collect();
        let (train, heldout) = split_corpus(&corpus, 0.1).unwrap();
        assert_eq!(train, &corpus[..90]);
        assert_eq!(heldout, &corpus[90..]);
        assert!(split_corpus(&corpus, 0.0).is_err());
        assert!(split_corpus(&corpus, 1.0).is_err());
        assert!(split_corpus(b"ab", 0.5).is_err());
    }

    #[test]
    fn test_shards_cover_training_without_overlap() {
        let shards = shard_ranges(10, 3);
        assert_eq!(shards, vec![0..3, 3..6, 6..10]);
    }

    /// Words drawn at random from a short list: enough structure to learn,
    /// deterministic for a given seed.
    fn corpus(n: usize, seed: u64) -> Vec<u8> {
        let words = [
            "the",
            "open",
            "model",
            "learns",
            "from",
            "signed",
            "updates",
            "and",
            "never",
            "sees",
            "data",
            "volunteers",
            "train",
            "at",
            "home",
            "scores",
            "every",
            "change",
            "in",
        ];
        let mut state = seed;
        let mut out = Vec::with_capacity(n + 16);
        while out.len() < n {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            out.extend_from_slice(words[((state >> 33) % words.len() as u64) as usize].as_bytes());
            out.push(if (state >> 20).is_multiple_of(9) {
                b'.'
            } else {
                b' '
            });
        }
        out.truncate(n);
        out
    }

    fn settings(volunteers: usize, outer_lr: f64) -> Settings {
        Settings {
            volunteers_per_round: volunteers,
            steps: 60,
            heldout_fraction: 0.1,
            seed: 5,
            dim: 16,
            outer_lr,
        }
    }

    fn fresh_ledger(name: &str) -> Ledger {
        let dir =
            std::env::temp_dir().join(format!("oh-coordinator-lib-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Ledger::open(&dir.join("ledger.jsonl")).unwrap()
    }

    #[test]
    fn test_serve_refuses_missing_or_duplicate_approval_keys() {
        let mut coordinator = Coordinator::new(
            &corpus(6000, 4),
            &settings(2, 1.0),
            fresh_ledger("admission"),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(coordinator.serve(&listener, 1, |_| {}).is_err());
        let key = Keypair::generate().pubkey_bytes();
        coordinator.approve_volunteers([key, key]);
        assert!(coordinator.serve(&listener, 1, |_| {}).is_err());
    }

    #[test]
    fn test_restart_with_the_same_key_keeps_identity_but_not_run_id() {
        let text = corpus(6000, 4);
        let s = settings(3, 1.0);
        let start = |name| {
            Coordinator::with_keypair(
                &text,
                &s,
                fresh_ledger(name),
                Keypair::from_seed(&[9u8; 32]),
            )
            .unwrap()
        };
        let first = start("restart-1");
        let second = start("restart-2");
        assert_eq!(
            first.pubkey(),
            Keypair::from_seed(&[9u8; 32]).pubkey_bytes()
        );
        assert_eq!(first.pubkey(), second.pubkey());
        assert_ne!(first.run_id(), second.run_id());
        let fresh = Coordinator::new(&text, &s, fresh_ledger("restart-3")).unwrap();
        assert_ne!(fresh.pubkey(), first.pubkey());
    }

    #[test]
    fn test_aggregate_is_the_mean_times_the_outer_lr() {
        let deltas = vec![vec![1.0f32, 2.0], vec![3.0, 4.0]];
        assert_eq!(aggregate(&deltas, 1.0), Some(vec![2.0, 3.0]));
        assert_eq!(aggregate(&deltas, 2.0), Some(vec![4.0, 6.0]));
        assert_eq!(aggregate(&[], 1.0), None);
    }

    #[test]
    fn test_outer_lr_scales_the_applied_update() {
        let text = corpus(6000, 4);
        let (train, heldout) = split_corpus(&text, 0.1).unwrap();
        let mut plain =
            Coordinator::new(&text, &settings(3, 1.0), fresh_ledger("outer-plain")).unwrap();
        let mut triple =
            Coordinator::new(&text, &settings(3, 3.0), fresh_ledger("outer-triple")).unwrap();
        let base = plain.begin_round();
        assert_eq!(base.params, triple.begin_round().params);

        // One small helpful delta, submitted by all three volunteers.
        let mut worker = TinyByteModel::new(16, 0);
        worker.set_params(&base.params);
        worker.train_steps(train, 20, 9);
        let delta = pseudo_gradient(&base.params, &worker.params());
        let submitted = vec![delta.clone(); 3];

        let expect = |scale: f32| {
            let scaled: Vec<f32> = delta.iter().map(|d| d * scale).collect();
            let mut m = TinyByteModel::new(16, 0);
            m.set_params(&apply(&base.params, &scaled));
            bits_per_byte(m.heldout_bits(heldout), heldout)
        };
        let plain_report = plain.finish_round(&submitted);
        let triple_report = triple.finish_round(&submitted);
        assert!(plain_report.applied && triple_report.applied);
        assert!((plain_report.heldout_bpb - expect(1.0)).abs() < 1e-9);
        assert!((triple_report.heldout_bpb - expect(3.0)).abs() < 1e-9);
        assert!(
            triple_report.heldout_bpb < plain_report.heldout_bpb,
            "three times a small helpful step should help more here"
        );
    }

    #[test]
    fn test_simulate_rejects_bad_settings() {
        let text = corpus(6000, 4);
        assert!(simulate(&text, &settings(3, 0.0), 1, &SimOptions::default()).is_err());
        assert!(simulate(&text, &settings(3, f64::NAN), 1, &SimOptions::default()).is_err());
        let bad_keep = SimOptions {
            keep_fraction: 0.0,
            ..SimOptions::default()
        };
        assert!(simulate(&text, &settings(3, 1.0), 1, &bad_keep).is_err());
        // Keep fraction is ignored when compression is off.
        let exact = SimOptions {
            compress: false,
            ..bad_keep
        };
        assert!(simulate(&text, &settings(3, 1.0), 1, &exact).is_ok());
    }

    #[test]
    fn test_simulate_repeats_exactly_and_one_exact_volunteer_matches_baseline() {
        let text = corpus(6000, 4);
        let s = settings(1, 1.0);
        let exact = SimOptions {
            compress: false,
            update_gate: false,
            ..SimOptions::default()
        };
        let a = simulate(&text, &s, 4, &exact).unwrap();
        let b = simulate(&text, &s, 4, &exact).unwrap();
        assert_eq!(a.rounds.len(), 4);
        for (x, y) in a.rounds.iter().zip(&b.rounds) {
            assert_eq!(x.heldout_bpb, y.heldout_bpb);
            assert_eq!(x.accepted, 1);
        }
        // With one volunteer, no compression and no gate, applying the
        // delta is the same as training in place, up to f32 rounding of
        // base + (after - base).
        let base = baseline(&text, &s, 4).unwrap();
        assert!((a.start_bpb - base[0]).abs() < 1e-12);
        for (report, bpb) in a.rounds.iter().zip(&base[1..]) {
            assert!(
                (report.heldout_bpb - bpb).abs() < 1e-4,
                "simulate {} vs baseline {bpb}",
                report.heldout_bpb
            );
        }
    }

    #[test]
    fn test_simulate_shard_order_changes_only_which_seed_trains_which_shard() {
        let text = corpus(6000, 4);
        let s = settings(3, 1.0);
        let fixed = simulate(&text, &s, 2, &SimOptions::default()).unwrap();
        let rotate = simulate(
            &text,
            &s,
            2,
            &SimOptions {
                shard_order: ShardOrder::Rotate,
                ..SimOptions::default()
            },
        )
        .unwrap();
        assert_eq!(fixed.start_bpb, rotate.start_bpb);
        // Both are full runs over the same shards; they need not agree
        // exactly, but neither may make the model worse.
        for r in fixed.rounds.iter().chain(&rotate.rounds) {
            assert!(r.heldout_bpb <= fixed.start_bpb);
        }
    }
}
