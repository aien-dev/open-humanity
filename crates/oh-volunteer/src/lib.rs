//! Volunteer side of Open Humanity volunteer compute, version 0.
//!
//! A volunteer receives the starting model and a signed work unit, trains on
//! the shard on its own machine, and sends back only a signed, compressed
//! update. The shard and the trained parameters stay in this process.

use beacon_core::Keypair;
use oh_core::{
    pseudo_gradient, recv, send, BaseModel, CompressedDelta, Learner, Receipt, TinyByteModel,
    Update, WireError, WorkUnit,
};
use std::io::{Read, Write};

/// Share of parameter changes kept in each update.
pub const DEFAULT_KEEP_FRACTION: f64 = 0.05;

pub struct Settings {
    /// Seeds the order in which training samples the shard.
    pub seed: u64,
    pub keep_fraction: f64,
    /// When set, work units signed by any other key are refused.
    pub coordinator_key: Option<[u8; 32]>,
}

#[derive(Debug, thiserror::Error)]
pub enum VolunteerError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error("starting model does not match the work unit: {0}")]
    BadBase(&'static str),
    #[error("receipt does not answer the update that was sent")]
    ReceiptMismatch,
}

/// What came back for one work unit.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub round: u32,
    pub accepted: bool,
    pub turings: f64,
    pub receipt: Receipt,
    pub coordinator_key: [u8; 32],
}

/// Training seed for one round. The coordinator's `--baseline` mode uses
/// the same formula.
pub fn train_seed(seed: u64, round: u32) -> u64 {
    seed ^ ((round as u64) << 32)
}

/// Takes one work unit over `stream`: receive, check, train, send the
/// update, and check the receipt. Nothing is written to `stream` unless the
/// work unit's signature and starting model check out.
pub fn run_once<S: Read + Write>(
    stream: &mut S,
    keypair: &Keypair,
    settings: &Settings,
) -> Result<Outcome, VolunteerError> {
    let base: BaseModel = recv(stream)?;
    let unit: WorkUnit = recv(stream)?;
    match &settings.coordinator_key {
        Some(key) => unit.verify_from(key)?,
        None => unit.verify()?,
    }
    let update = train(&base, &unit, keypair, settings)?;
    send(stream, &update)?;

    let receipt: Receipt = recv(stream)?;
    receipt.verify_from(&unit.coordinator_pubkey)?;
    if receipt.update_digest != update.digest()
        || receipt.run_id != unit.run_id
        || receipt.round != unit.round
    {
        return Err(VolunteerError::ReceiptMismatch);
    }
    Ok(Outcome {
        round: unit.round,
        accepted: receipt.accepted,
        turings: receipt.turings,
        coordinator_key: unit.coordinator_pubkey,
        receipt,
    })
}

/// Trains from `base` on the unit's shard and returns the signed update.
/// Only the compressed parameter change goes into the update.
pub fn train(
    base: &BaseModel,
    unit: &WorkUnit,
    keypair: &Keypair,
    settings: &Settings,
) -> Result<Update, VolunteerError> {
    if base.digest() != unit.base_digest {
        return Err(VolunteerError::BadBase("digest differs from base_digest"));
    }
    let dim = base.dim as usize;
    if TinyByteModel::num_params(dim) != base.params.len() {
        return Err(VolunteerError::BadBase("parameter count does not fit dim"));
    }
    let mut model = TinyByteModel::new(dim, 0);
    model.set_params(&base.params);
    model.train_steps(
        &unit.shard,
        unit.steps as usize,
        train_seed(settings.seed, unit.round),
    );
    let delta = pseudo_gradient(&base.params, &model.params());
    let compressed = CompressedDelta::compress(&delta, settings.keep_fraction);
    Ok(Update::new_signed(keypair, unit, compressed))
}

/// One plain-English line for the person running the volunteer.
pub fn summary_line(outcome: &Outcome) -> String {
    if outcome.accepted {
        format!(
            "Round {}: update accepted, earned {:.3} Turings",
            outcome.round, outcome.turings
        )
    } else {
        format!("Round {}: update rejected", outcome.round)
    }
}

/// Parses 64 hex characters into a 32-byte key.
pub fn parse_key(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_round_trip() {
        let key = Keypair::generate().pubkey_bytes();
        let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(parse_key(&hex), Some(key));
        assert_eq!(parse_key("abc"), None);
        assert_eq!(parse_key(&"zz".repeat(32)), None);
    }

    #[test]
    fn test_summary_line_wording() {
        let kp = Keypair::generate();
        let unit = WorkUnit::new_signed(&kp, [0; 16], 4, [0; 32], vec![], 1);
        let update = Update::new_signed(&kp, &unit, CompressedDelta::compress(&[1.0], 1.0));
        let mut outcome = Outcome {
            round: 4,
            accepted: true,
            turings: 2.5,
            receipt: Receipt::new_signed(&kp, &update, 2.5, true),
            coordinator_key: kp.pubkey_bytes(),
        };
        assert_eq!(
            summary_line(&outcome),
            "Round 4: update accepted, earned 2.500 Turings"
        );
        outcome.accepted = false;
        assert_eq!(summary_line(&outcome), "Round 4: update rejected");
    }
}
