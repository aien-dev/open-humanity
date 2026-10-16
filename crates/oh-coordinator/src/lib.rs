//! Coordinator side of Open Humanity volunteer compute, version 0.
//!
//! The coordinator splits a corpus into training shards and a sealed held-out
//! tail, hands each volunteer a signed work unit, scores every update in
//! Turings against the held-out tail, and keeps the plain mean of the
//! accepted updates only when that mean also lowers held-out bits. The
//! held-out bytes never leave this process.

use beacon_core::Keypair;
use oh_core::{
    apply, recv, send, BaseModel, Learner, Ledger, LedgerError, Receipt, Scorer, TinyByteModel,
    Update, WorkUnit,
};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ops::Range;
use std::time::Duration;

pub const DEFAULT_LISTEN: &str = "127.0.0.1:18099";

/// Smallest per-update score, in bits, that counts as an improvement.
pub const EPSILON: f64 = 1e-3;

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
    /// Held-out bits per byte after the round.
    pub heldout_bpb: f64,
}

impl RoundReport {
    pub fn line(&self) -> String {
        format!(
            "round={} accepted={} aggregate_T={:.3} applied={} heldout_bpb={:.4}",
            self.round,
            self.accepted,
            self.aggregate_turings,
            if self.applied { "yes" } else { "no" },
            self.heldout_bpb
        )
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

    fn scorer(&self) -> Scorer {
        Scorer {
            base: self.model.params(),
            heldout: self.heldout.clone(),
            epsilon: EPSILON,
        }
    }

    /// Checks, scores and records one update. Ledger write failures are
    /// returned as errors; everything else is a verdict.
    pub fn judge(&mut self, unit: &WorkUnit, update: &Update) -> Result<Verdict, LedgerError> {
        if let Err(e) = update.verify_for(unit) {
            return Ok(Verdict::Dropped(e.to_string()));
        }
        let reject = |coordinator: &Self, turings: f64, reason: String| Verdict::Rejected {
            receipt: Receipt::new_signed(&coordinator.keypair, update, turings, false),
            reason,
        };
        if let Err(e) = update.delta.validate(TinyByteModel::num_params(self.dim)) {
            return Ok(reject(self, 0.0, e.to_string()));
        }
        if !self
            .ledger
            .mark_seen(&update.run_id, &update.delta_digest)?
        {
            return Ok(reject(self, 0.0, "replay of an earlier update".into()));
        }
        let delta = update.delta.decompress();
        let scorer = self.scorer();
        let turings = scorer.score(&mut self.model, &delta);
        if !scorer.accept(turings) {
            return Ok(reject(self, turings, "did not lower held-out bits".into()));
        }
        let receipt = Receipt::new_signed(&self.keypair, update, turings, true);
        self.ledger
            .credit(&update.node_pubkey, turings, &receipt.digest())?;
        Ok(Verdict::Accepted { receipt, delta })
    }

    /// Scores the plain mean of `accepted` and applies it only if it lowers
    /// held-out bits; otherwise the round is discarded.
    pub fn finish_round(&mut self, accepted: &[Vec<f32>]) -> RoundReport {
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
        RoundReport {
            round: self.round,
            accepted: accepted.len(),
            aggregate_turings,
            applied,
            heldout_bpb: self.heldout_bpb(),
        }
    }

    /// Runs one round over already-open connections, one per volunteer. All
    /// work units go out first so volunteers train at the same time; then
    /// each update is read, judged and answered in connection order.
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
        for (slot, (conn, unit)) in conns.iter_mut().zip(units).enumerate() {
            let Some(unit) = unit else { continue };
            let update: Update = match recv(conn) {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("round {}: volunteer {slot}: no update: {e}", self.round);
                    continue;
                }
            };
            let receipt = match self.judge(&unit, &update).map_err(|e| e.to_string())? {
                Verdict::Dropped(reason) => {
                    eprintln!("round {}: volunteer {slot}: dropped: {reason}", self.round);
                    continue;
                }
                Verdict::Rejected { receipt, reason } => {
                    eprintln!("round {}: volunteer {slot}: rejected: {reason}", self.round);
                    receipt
                }
                Verdict::Accepted { receipt, delta } => {
                    accepted.push(delta);
                    receipt
                }
            };
            if let Err(e) = send(conn, &receipt) {
                eprintln!(
                    "round {}: volunteer {slot}: receipt not delivered: {e}",
                    self.round
                );
            }
        }
        Ok(self.finish_round(&accepted))
    }

    /// Runs `rounds` rounds on `listener`, waiting each round for one
    /// connection per shard, and passes each round's report to `log`.
    pub fn serve(
        &mut self,
        listener: &TcpListener,
        rounds: u32,
        mut log: impl FnMut(&RoundReport),
    ) -> Result<(), String> {
        for _ in 0..rounds {
            let mut conns = Vec::with_capacity(self.shards.len());
            while conns.len() < self.shards.len() {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                let timeout = Some(Duration::from_secs(600));
                stream
                    .set_read_timeout(timeout)
                    .map_err(|e| e.to_string())?;
                stream
                    .set_write_timeout(timeout)
                    .map_err(|e| e.to_string())?;
                conns.push(stream);
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
