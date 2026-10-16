//! Volunteer side of Open Humanity volunteer compute, version 0.
//!
//! A volunteer receives the starting model and a signed work unit, trains on
//! the shard on its own machine, and sends back only a signed, compressed
//! update. The shard and the trained parameters stay in this process.
//!
//! In teaching mode (`teach_once`) a local language model writes a passage
//! on a short hint from the shard; only the firewalled passage is sent.

use beacon_core::{FirewallViolation, Keypair, PersonalDataFirewall};
use oh_core::{
    pseudo_gradient, recv, send, send_teaching, BaseModel, CompressedDelta, Learner, Receipt,
    Teacher, TeacherError, TeachingBatch, TinyByteModel, Update, WireError, WorkUnit,
};
use std::io::{Read, Write};

/// Share of parameter changes kept in each update. Raised from 0.05 after
/// `docs/research/2026-10-16-volunteer-gap.md` measured that keeping 5%
/// cost 0.18 bits per byte against 20%, for a quarter of the bytes.
pub const DEFAULT_KEEP_FRACTION: f64 = 0.2;

/// Widest model a volunteer will build. Keeps the parameter count
/// arithmetic far from overflow for any `dim` a coordinator sends.
pub const MAX_DIM: u32 = 4096;

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
    #[error("local teacher failed: {0}")]
    Teacher(#[from] TeacherError),
    #[error(
        "teaching text refused by the Personal Data Firewall: it contains {0}; nothing was sent"
    )]
    Firewall(&'static str),
    #[error("teacher returned no text; nothing was sent")]
    EmptyTeaching,
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
    if base.dim == 0 || base.dim > MAX_DIM {
        return Err(VolunteerError::BadBase("dim is zero or too large"));
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

/// Longest topic hint taken from a work unit's shard, in bytes.
pub const MAX_HINT_BYTES: usize = 200;

/// Default length limit for each teaching passage, in model tokens.
pub const DEFAULT_TEACH_MAX_TOKENS: u32 = 256;

/// Default address of the local teacher (aien-serve-http on the Spark).
pub const DEFAULT_TEACHER_ADDR: &str = "127.0.0.1:18091";

/// A short printable snippet of `shard` to use as a topic hint: at most
/// `MAX_HINT_BYTES`, printable ASCII only, whitespace collapsed, starting
/// and ending on word boundaries where the shard allows. `seed` picks where
/// in the shard it starts.
pub fn topic_hint(shard: &[u8], seed: u64) -> String {
    if shard.is_empty() {
        return String::new();
    }
    let mut start = (seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 11) as usize % shard.len();
    // Start after the next whitespace so the hint begins on a whole word.
    if start > 0 {
        if let Some(gap) = shard[start..]
            .iter()
            .take(MAX_HINT_BYTES / 2)
            .position(|b| b.is_ascii_whitespace())
        {
            start += gap + 1;
        }
    }
    let mut hint = String::with_capacity(MAX_HINT_BYTES);
    for &b in &shard[start..] {
        let c = if b.is_ascii_graphic() { b as char } else { ' ' };
        if c == ' ' && (hint.is_empty() || hint.ends_with(' ')) {
            continue;
        }
        if hint.len() == MAX_HINT_BYTES {
            // Cut back to the last whole word if that leaves something.
            if let Some(cut) = hint.rfind(' ').filter(|&i| i > MAX_HINT_BYTES / 2) {
                hint.truncate(cut);
            }
            break;
        }
        hint.push(c);
    }
    hint.trim_end().to_string()
}

/// The prompt sent to the local teacher for one hint.
pub fn teach_prompt(hint: &str) -> String {
    format!(
        "Write a short clear passage that continues or explains this text. \
         Reply with the passage only.\n\n{hint}"
    )
}

/// Runs teaching text through the Personal Data Firewall. Home directory
/// paths are rewritten to `~/` (redacted); anything that looks like a
/// credential, private key or path traversal refuses the whole text.
pub fn firewall_teaching_text(text: &str) -> Result<String, VolunteerError> {
    let cleaned = PersonalDataFirewall::sanitize_paths(text.trim());
    PersonalDataFirewall::verify_clean(&cleaned)
        .map_err(|v| VolunteerError::Firewall(violation_kind(&v)))?;
    if cleaned.trim().is_empty() {
        return Err(VolunteerError::EmptyTeaching);
    }
    Ok(cleaned)
}

/// A name for the kind of violation, without the matched text, so a found
/// secret is never echoed to the screen or a log.
fn violation_kind(v: &FirewallViolation) -> &'static str {
    match v {
        FirewallViolation::AwsKey(_) => "an AWS access key",
        FirewallViolation::GitHubToken(_) => "a GitHub token",
        FirewallViolation::OpenAiKey(_) => "an OpenAI API key",
        FirewallViolation::AnthropicKey(_) => "an Anthropic API key",
        FirewallViolation::GoogleApiKey(_) => "a Google API key",
        FirewallViolation::StripeKey(_) => "a Stripe key",
        FirewallViolation::HuggingFaceToken(_) => "a HuggingFace token",
        FirewallViolation::PrivateKeyBlock => "a private key block",
        FirewallViolation::GenericSecret(_) => "a secret token",
        FirewallViolation::PathTraversal(_) => "a path traversal",
    }
}

/// Takes one work unit over `stream` in teaching mode: receive and check
/// it, ask the local `teacher` to write a passage on a hint from the shard,
/// firewall the passage, send it as a signed `TeachingBatch`, and check the
/// receipt. Nothing is written to `stream` unless the work unit checks out
/// and the firewall passes the text. The only bytes sent are the batch:
/// run, round and model ids, the firewalled text, its digest, the public
/// key and the signature.
pub fn teach_once<S: Read + Write, T: Teacher + ?Sized>(
    stream: &mut S,
    keypair: &Keypair,
    settings: &Settings,
    teacher: &T,
    max_tokens: u32,
) -> Result<Outcome, VolunteerError> {
    let base: BaseModel = recv(stream)?;
    let unit: WorkUnit = recv(stream)?;
    match &settings.coordinator_key {
        Some(key) => unit.verify_from(key)?,
        None => unit.verify()?,
    }
    if base.digest() != unit.base_digest {
        return Err(VolunteerError::BadBase("digest differs from base_digest"));
    }
    let hint = topic_hint(&unit.shard, train_seed(settings.seed, unit.round));
    let raw = teacher.generate(&teach_prompt(&hint), max_tokens)?;
    let text = firewall_teaching_text(&raw)?;
    let batch = TeachingBatch::new_signed(keypair, &unit, text.into_bytes());
    send_teaching(stream, &batch)?;

    let receipt: Receipt = recv(stream)?;
    receipt.verify_from(&unit.coordinator_pubkey)?;
    if receipt.update_digest != batch.digest()
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

/// One plain-English line per teaching batch.
pub fn teach_summary_line(batch: u32, outcome: &Outcome) -> String {
    if outcome.accepted {
        format!(
            "Batch {batch}: accepted, earned {:.3} Turings",
            outcome.turings
        )
    } else {
        format!("Batch {batch}: rejected")
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
    fn test_topic_hint_is_short_printable_and_from_the_shard() {
        let shard: Vec<u8> = b"The\tquick  brown\x00fox jumps over the lazy dog. "
            .iter()
            .cycle()
            .take(5000)
            .copied()
            .collect();
        for seed in 0..50 {
            let hint = topic_hint(&shard, seed);
            assert!(!hint.is_empty());
            assert!(hint.len() <= MAX_HINT_BYTES, "{} bytes", hint.len());
            assert!(hint.bytes().all(|b| b.is_ascii_graphic() || b == b' '));
            assert!(!hint.contains("  "), "{hint:?}");
        }
        assert_eq!(topic_hint(b"", 1), "");
        assert_eq!(topic_hint(b"\x01\x02 hi \xff", 0), "hi");
        assert!(teach_prompt("abc").ends_with("\n\nabc"));
    }

    #[test]
    fn test_firewall_redacts_paths_and_refuses_secrets() {
        assert_eq!(
            firewall_teaching_text("  see /home/bob/x.txt  ").unwrap(),
            "see ~/x.txt"
        );
        let key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        assert!(matches!(
            firewall_teaching_text(&format!("text {key}")),
            Err(VolunteerError::Firewall("an AWS access key"))
        ));
        assert!(matches!(
            firewall_teaching_text(" \n"),
            Err(VolunteerError::EmptyTeaching)
        ));
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
