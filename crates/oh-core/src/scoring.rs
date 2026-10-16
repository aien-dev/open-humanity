//! Scoring updates in Turings, and the append-only ledger of credits.
//!
//! T = held-out bits with the base model minus held-out bits with the base
//! plus the delta. The held-out bytes live only inside `Scorer` on the
//! coordinator; they are never put on the wire.

use crate::learner::Learner;
use crate::update::apply;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Scores deltas against a sealed held-out set.
pub struct Scorer {
    pub base: Vec<f32>,
    pub heldout: Vec<u8>,
    /// Smallest score, in bits, that counts as an improvement.
    pub epsilon: f64,
}

impl Scorer {
    /// Turings earned by `delta`: bits(base) - bits(base + delta) on the
    /// held-out set. The model's own parameters are restored afterwards.
    ///
    /// Panics if `delta` or `base` does not match the model's parameter
    /// count; validate untrusted deltas first.
    pub fn score<L: Learner>(&self, model: &mut L, delta: &[f32]) -> f64 {
        let saved = model.params();
        model.set_params(&self.base);
        let before = model.heldout_bits(&self.heldout);
        model.set_params(&apply(&self.base, delta));
        let after = model.heldout_bits(&self.heldout);
        model.set_params(&saved);
        before - after
    }

    /// True when `t` is a finite score above `epsilon`.
    pub fn accept(&self, t: f64) -> bool {
        t.is_finite() && t > self.epsilon
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("ledger i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("ledger line {line} is unreadable: {reason}")]
    Corrupt { line: usize, reason: String },
    #[error("only finite, positive Turings can be credited (got {0})")]
    InvalidTurings(f64),
}

/// One line of the ledger file. Byte fields are lowercase hex.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Entry {
    /// A delta digest the coordinator has already scored in this run.
    Seen {
        run_id: String,
        delta_digest: String,
    },
    /// Turings credited to a volunteer for one accepted update.
    Credit {
        node_pubkey: String,
        turings: f64,
        receipt_digest: String,
    },
    /// An update that was scored or checked and turned down. It earns
    /// nothing; the line is kept so every receipt sent has a ledger record.
    Rejected {
        node_pubkey: String,
        /// `None` when the score was not a finite number.
        turings: Option<f64>,
        reason: String,
        receipt_digest: String,
    },
}

/// Append-only JSON Lines ledger. Opening an existing file replays it, so
/// totals and replay protection survive a restart.
pub struct Ledger {
    file: File,
    totals: HashMap<[u8; 32], f64>,
    /// BLAKE3 of run id and delta digest, so protection is per run.
    seen: HashSet<[u8; 32]>,
}

impl Ledger {
    /// Opens or creates the ledger at `path`. A file whose last line was
    /// cut short (no final newline) is refused rather than appended to.
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        let mut ledger = Self {
            file: file.try_clone()?,
            totals: HashMap::new(),
            seen: HashSet::new(),
        };

        let len = file.seek(SeekFrom::End(0))?;
        if len > 0 {
            file.seek(SeekFrom::Start(len - 1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            if last[0] != b'\n' {
                return Err(LedgerError::Corrupt {
                    line: 0,
                    reason: "file does not end with a newline".into(),
                });
            }
        }
        file.seek(SeekFrom::Start(0))?;
        for (i, line) in BufReader::new(&file).lines().enumerate() {
            let line = line?;
            let corrupt = |reason: String| LedgerError::Corrupt {
                line: i + 1,
                reason,
            };
            let entry: Entry = serde_json::from_str(&line).map_err(|e| corrupt(e.to_string()))?;
            match entry {
                Entry::Seen {
                    run_id,
                    delta_digest,
                } => {
                    let run = from_hex::<16>(&run_id).ok_or_else(|| corrupt("run_id".into()))?;
                    let delta = from_hex::<32>(&delta_digest)
                        .ok_or_else(|| corrupt("delta_digest".into()))?;
                    ledger.seen.insert(seen_key(&run, &delta));
                }
                Entry::Credit {
                    node_pubkey,
                    turings,
                    ..
                } => {
                    let node = from_hex::<32>(&node_pubkey)
                        .ok_or_else(|| corrupt("node_pubkey".into()))?;
                    *ledger.totals.entry(node).or_insert(0.0) += turings;
                }
                Entry::Rejected { node_pubkey, .. } => {
                    from_hex::<32>(&node_pubkey).ok_or_else(|| corrupt("node_pubkey".into()))?;
                }
            }
        }
        Ok(ledger)
    }

    /// Records that `delta_digest` was submitted in `run_id`. Returns
    /// `false`, and writes nothing, if it was already recorded: a replay.
    pub fn mark_seen(
        &mut self,
        run_id: &[u8; 16],
        delta_digest: &[u8; 32],
    ) -> Result<bool, LedgerError> {
        let key = seen_key(run_id, delta_digest);
        if self.seen.contains(&key) {
            return Ok(false);
        }
        self.append(&Entry::Seen {
            run_id: to_hex(run_id),
            delta_digest: to_hex(delta_digest),
        })?;
        self.seen.insert(key);
        Ok(true)
    }

    pub fn is_seen(&self, run_id: &[u8; 16], delta_digest: &[u8; 32]) -> bool {
        self.seen.contains(&seen_key(run_id, delta_digest))
    }

    /// Credits `turings` to `node_pubkey` for the receipt `receipt_digest`.
    pub fn credit(
        &mut self,
        node_pubkey: &[u8; 32],
        turings: f64,
        receipt_digest: &[u8; 32],
    ) -> Result<(), LedgerError> {
        if !(turings.is_finite() && turings > 0.0) {
            return Err(LedgerError::InvalidTurings(turings));
        }
        self.append(&Entry::Credit {
            node_pubkey: to_hex(node_pubkey),
            turings,
            receipt_digest: to_hex(receipt_digest),
        })?;
        *self.totals.entry(*node_pubkey).or_insert(0.0) += turings;
        Ok(())
    }

    /// Records a rejected update for the receipt `receipt_digest`. Nothing
    /// is credited; totals do not change.
    pub fn record_rejection(
        &mut self,
        node_pubkey: &[u8; 32],
        turings: f64,
        reason: &str,
        receipt_digest: &[u8; 32],
    ) -> Result<(), LedgerError> {
        self.append(&Entry::Rejected {
            node_pubkey: to_hex(node_pubkey),
            turings: turings.is_finite().then_some(turings),
            reason: reason.to_string(),
            receipt_digest: to_hex(receipt_digest),
        })
    }

    /// Total Turings credited to `node_pubkey`; zero if never credited.
    pub fn total(&self, node_pubkey: &[u8; 32]) -> f64 {
        self.totals.get(node_pubkey).copied().unwrap_or(0.0)
    }

    fn append(&mut self, entry: &Entry) -> Result<(), LedgerError> {
        let mut line = serde_json::to_string(entry).expect("ledger entries always encode");
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        Ok(())
    }
}

fn seen_key(run_id: &[u8; 16], delta_digest: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(run_id);
    hasher.update(delta_digest);
    *hasher.finalize().as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learner::{SplitMix64, TinyByteModel};
    use crate::update::{pseudo_gradient, CompressedDelta};
    use std::path::PathBuf;

    const TRAIN: &str =
        "the cat sat on the mat. the dog sat on the log. a cat and a dog met on the mat. ";
    const HELDOUT: &str =
        "the dog sat on the mat. the cat met a dog on the log. a dog and a cat sat. ";

    fn corpus(text: &str, n: usize) -> Vec<u8> {
        text.bytes().cycle().take(n).collect()
    }

    fn scorer(base: Vec<f32>) -> Scorer {
        Scorer {
            base,
            heldout: HELDOUT.as_bytes().to_vec(),
            epsilon: 1e-6,
        }
    }

    fn temp_path(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("oh-core-{}-{}.jsonl", std::process::id(), name));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// A volunteer trains on text like the held-out set and sends a 5% delta.
    #[test]
    fn test_honest_delta_scores_positive() {
        let mut model = TinyByteModel::new(16, 1);
        let base = model.params();
        model.train_steps(&corpus(TRAIN, 2048), 400, 2);
        let delta = pseudo_gradient(&base, &model.params());
        let sent = CompressedDelta::compress(&delta, 0.05).decompress();

        let s = scorer(base);
        let t_full = s.score(&mut model, &delta);
        let t_sent = s.score(&mut model, &sent);
        eprintln!(
            "honest delta: {t_full:.2} Turings dense, {t_sent:.2} Turings after 5% compression"
        );
        assert!(s.accept(t_full), "dense delta scored {t_full}");
        assert!(s.accept(t_sent), "compressed delta scored {t_sent}");
    }

    #[test]
    fn test_zero_delta_scores_zero_and_is_rejected() {
        let mut model = TinyByteModel::new(16, 1);
        let s = scorer(model.params());
        let t = s.score(&mut model, &vec![0.0; s.base.len()]);
        assert_eq!(t, 0.0);
        assert!(!s.accept(t));
    }

    #[test]
    fn test_random_delta_scores_negative() {
        let mut model = TinyByteModel::new(16, 1);
        model.train_steps(&corpus(TRAIN, 2048), 400, 2);
        let s = scorer(model.params());
        let mut rng = SplitMix64::new(99);
        let noise: Vec<f32> = (0..s.base.len())
            .map(|_| rng.next_signed_unit() * 0.5)
            .collect();
        let t = s.score(&mut model, &noise);
        eprintln!("random delta: {t:.2} Turings");
        assert!(t < 0.0, "random delta scored {t}");
        assert!(!s.accept(t));
    }

    #[test]
    fn test_score_restores_the_model() {
        let mut model = TinyByteModel::new(16, 4);
        let own = model.params();
        let s = scorer(TinyByteModel::new(16, 5).params());
        let _ = s.score(&mut model, &vec![0.01; own.len()]);
        assert_eq!(model.params(), own);
    }

    #[test]
    fn test_nan_score_is_rejected() {
        let s = scorer(Vec::new());
        assert!(!s.accept(f64::NAN));
        assert!(!s.accept(f64::INFINITY));
        assert!(s.accept(0.5));
    }

    #[test]
    fn test_replayed_delta_digest_is_rejected() {
        let path = temp_path("replay");
        let (run_a, run_b, digest) = ([1u8; 16], [2u8; 16], [7u8; 32]);
        {
            let mut ledger = Ledger::open(&path).unwrap();
            assert!(ledger.mark_seen(&run_a, &digest).unwrap());
            assert!(
                !ledger.mark_seen(&run_a, &digest).unwrap(),
                "replay must be refused"
            );
            assert!(
                ledger.mark_seen(&run_b, &digest).unwrap(),
                "other runs are separate"
            );
        }
        let mut reopened = Ledger::open(&path).unwrap();
        assert!(reopened.is_seen(&run_a, &digest));
        assert!(
            !reopened.mark_seen(&run_a, &digest).unwrap(),
            "replay refused after reopen"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_ledger_totals_sum_and_survive_reopen() {
        let path = temp_path("totals");
        let (alice, bob) = ([0xAA; 32], [0xBB; 32]);
        {
            let mut ledger = Ledger::open(&path).unwrap();
            ledger.credit(&alice, 1.5, &[1; 32]).unwrap();
            ledger.credit(&bob, 0.25, &[2; 32]).unwrap();
            ledger.credit(&alice, 2.75, &[3; 32]).unwrap();
            assert_eq!(ledger.total(&alice), 4.25);
            assert_eq!(ledger.total(&bob), 0.25);
            assert_eq!(ledger.total(&[0; 32]), 0.0);
            assert!(matches!(
                ledger.credit(&bob, 0.0, &[4; 32]),
                Err(LedgerError::InvalidTurings(_))
            ));
            assert!(matches!(
                ledger.credit(&bob, f64::NAN, &[4; 32]),
                Err(LedgerError::InvalidTurings(_))
            ));
        }
        let mut reopened = Ledger::open(&path).unwrap();
        assert_eq!(reopened.total(&alice), 4.25);
        assert_eq!(reopened.total(&bob), 0.25);
        reopened.credit(&bob, 1.0, &[5; 32]).unwrap();
        assert_eq!(reopened.total(&bob), 1.25);

        let lines = std::fs::read_to_string(&path).unwrap();
        assert_eq!(lines.lines().count(), 4, "append-only: one line per credit");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_rejections_are_recorded_but_never_credited() {
        let path = temp_path("rejected");
        let node = [0xCC; 32];
        {
            let mut ledger = Ledger::open(&path).unwrap();
            ledger.credit(&node, 2.0, &[1; 32]).unwrap();
            ledger
                .record_rejection(&node, -3.5, "did not lower held-out bits", &[2; 32])
                .unwrap();
            ledger
                .record_rejection(&node, f64::NAN, "score was not a number", &[3; 32])
                .unwrap();
            assert_eq!(ledger.total(&node), 2.0);
        }
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.matches("\"kind\":\"rejected\"").count(), 2);
        assert!(text.contains("\"turings\":null"));
        let reopened = Ledger::open(&path).unwrap();
        assert_eq!(reopened.total(&node), 2.0);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_torn_last_line_is_refused() {
        let path = temp_path("torn");
        std::fs::write(&path, "{\"kind\":\"credit\",\"node_pub").unwrap();
        assert!(matches!(
            Ledger::open(&path),
            Err(LedgerError::Corrupt { .. })
        ));
        std::fs::remove_file(&path).unwrap();
    }
}
