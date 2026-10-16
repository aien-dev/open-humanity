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
    apply, coordinator_handshake, recv_submission, send, BaseModel, Learner, Ledger, LedgerError,
    Receipt, Scorer, Submission, TeachingBatch, TinyByteModel, Update, WorkUnit,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ops::Range;
use std::time::Duration;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:18099";

/// Smallest per-update score, in bits, that counts as an improvement.
pub const EPSILON: f64 = 1e-3;

/// Largest teaching batch the coordinator will train on, in bytes.
pub const MAX_TEACHING_TEXT_BYTES: usize = 1024 * 1024;

/// How long a new connection has to finish the transport handshake.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Read and write timeout on a connection once the round is under way.
pub const ROUND_TIMEOUT_SECS: u64 = 600;

#[derive(Debug, Clone)]
pub struct Settings {
    pub volunteers_per_round: usize,
    pub steps: u32,
    pub heldout_fraction: f64,
    pub seed: u64,
    pub dim: usize,
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
    round: u32,
    ledger: Ledger,
}

impl Coordinator {
    /// Builds the starting model from `settings.seed` and a fresh signing key.
    pub fn new(corpus: &[u8], settings: &Settings, ledger: Ledger) -> Result<Self, String> {
        let (train, heldout) = split_corpus(corpus, settings.heldout_fraction)?;
        check_settings(train, settings)?;
        let keypair = Keypair::generate();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&keypair.pubkey_bytes());
        hasher.update(&settings.seed.to_le_bytes());
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
            round: 0,
            ledger,
        })
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

    /// Scores the plain mean of `accepted` and applies it only if it lowers
    /// held-out bits; otherwise the round is discarded.
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
        if let Some(first) = accepted.first() {
            let k = accepted.len() as f32;
            let mut mean = vec![0f32; first.len()];
            for delta in accepted {
                for (m, d) in mean.iter_mut().zip(delta) {
                    *m += d / k;
                }
            }
            let scorer = self.scorer();
            aggregate_turings = scorer.score(&mut self.model, &mean);
            if aggregate_turings.is_finite() && aggregate_turings > 0.0 {
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

    /// Runs `rounds` rounds on `listener`, waiting each round for one
    /// connection per shard, and passes each round's report to `log`. Every
    /// connection starts with the encrypted-transport handshake
    /// (`oh_core::coordinator_handshake`, signed with this run's key); one
    /// that fails it is closed and not counted.
    pub fn serve(
        &mut self,
        listener: &TcpListener,
        rounds: u32,
        mut log: impl FnMut(&RoundReport),
    ) -> Result<(), String> {
        for _ in 0..rounds {
            let mut conns = Vec::with_capacity(self.shards.len());
            while conns.len() < self.shards.len() {
                let (stream, peer) = listener.accept().map_err(|e| e.to_string())?;
                let set_timeout = |secs| {
                    let t = Some(Duration::from_secs(secs));
                    stream
                        .set_read_timeout(t)
                        .and_then(|_| stream.set_write_timeout(t))
                        .map_err(|e| e.to_string())
                };
                set_timeout(HANDSHAKE_TIMEOUT_SECS)?;
                match coordinator_handshake(stream, &self.keypair) {
                    Ok(conn) => {
                        let s = conn.get_ref();
                        let t = Some(Duration::from_secs(ROUND_TIMEOUT_SECS));
                        s.set_read_timeout(t)
                            .and_then(|_| s.set_write_timeout(t))
                            .map_err(|e| e.to_string())?;
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

/// Training seed for one round; the same formula as
/// `oh_volunteer::train_seed`, repeated here so the binary does not depend
/// on the volunteer crate.
fn train_seed(seed: u64, round: u32) -> u64 {
    seed ^ ((round as u64) << 32)
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
}
