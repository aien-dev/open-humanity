//! Wire formats for volunteer compute: work units, updates, receipts, and
//! the length-prefixed frames that carry them over TCP.
//!
//! Signing bytes for each message are the bincode bytes of the message with
//! its `sig` field emptied. Signatures are Ed25519 from beacon-core; digests
//! are BLAKE3.

use crate::update::CompressedDelta;
use beacon_core::{verify_signature, Keypair};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Largest frame payload either side will send or accept.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_BYTES} byte cap")]
    FrameTooLarge(u64),
    #[error("could not decode message: {0}")]
    Decode(String),
    #[error("signature missing or invalid")]
    BadSignature,
    #[error("signed by an unexpected key")]
    WrongSigner,
    #[error("delta digest does not match the delta")]
    DeltaDigestMismatch,
    #[error("update does not belong to this work unit")]
    WorkUnitMismatch,
    #[error("text digest does not match the text")]
    TextDigestMismatch,
}

/// The coordinator's instruction: start from the model whose digest is
/// `base_digest` and train for `steps` steps on `shard`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkUnit {
    pub run_id: [u8; 16],
    pub round: u32,
    pub base_digest: [u8; 32],
    pub shard: Vec<u8>,
    pub steps: u32,
    pub coordinator_pubkey: [u8; 32],
    pub sig: Vec<u8>,
}

/// A volunteer's answer to one work unit: the compressed change, never the data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Update {
    pub run_id: [u8; 16],
    pub round: u32,
    pub base_digest: [u8; 32],
    /// `WorkUnit::digest` of the work unit this answers.
    pub work_unit_id: [u8; 32],
    pub node_pubkey: [u8; 32],
    pub delta: CompressedDelta,
    /// `delta_digest(&delta)`.
    pub delta_digest: [u8; 32],
    pub sig: Vec<u8>,
}

/// Teaching text a volunteer's local model wrote for one work unit, after
/// the volunteer ran it through the Personal Data Firewall. Like an update it
/// is pinned to a run, round and starting model; unlike an update it carries
/// text, which the coordinator trains on to score it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeachingBatch {
    pub run_id: [u8; 16],
    pub round: u32,
    pub base_digest: [u8; 32],
    pub node_pubkey: [u8; 32],
    pub text: Vec<u8>,
    /// `text_digest(&text)`.
    pub text_digest: [u8; 32],
    pub sig: Vec<u8>,
}

/// The coordinator's signed verdict on one update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub run_id: [u8; 16],
    pub round: u32,
    /// `Update::digest` of the scored update.
    pub update_digest: [u8; 32],
    pub turings: f64,
    pub accepted: bool,
    pub coordinator_pubkey: [u8; 32],
    pub sig: Vec<u8>,
}

/// The starting model, sent just before a work unit. It is not signed on its
/// own: the signed work unit pins it through `base_digest`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaseModel {
    /// `TinyByteModel` width, so the volunteer can build the right shape.
    pub dim: u32,
    pub params: Vec<f32>,
}

impl BaseModel {
    /// `params_digest` of the parameters; compare with `WorkUnit::base_digest`.
    pub fn digest(&self) -> [u8; 32] {
        params_digest(&self.params)
    }
}

/// BLAKE3 of the parameters as little-endian f32 bytes.
pub fn params_digest(params: &[f32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for p in params {
        hasher.update(&p.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// BLAKE3 of the raw teaching text.
pub fn text_digest(text: &[u8]) -> [u8; 32] {
    *blake3::hash(text).as_bytes()
}

/// BLAKE3 of the bincode bytes of a compressed delta.
pub fn delta_digest(delta: &CompressedDelta) -> [u8; 32] {
    *blake3::hash(&encode(delta)).as_bytes()
}

fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    // Plain structs of integers, floats and vectors always encode.
    bincode::serialize(value).expect("bincode encodes plain structs")
}

fn check_sig(pubkey: &[u8; 32], message: &[u8], sig: &[u8]) -> Result<(), WireError> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| WireError::BadSignature)?;
    verify_signature(pubkey, message, &sig).map_err(|_| WireError::BadSignature)
}

/// Shared signing logic: every message is signed over itself with `sig` emptied.
macro_rules! signed_message {
    ($ty:ty, $signer:ident) => {
        impl $ty {
            /// Bincode bytes of this message with `sig` emptied.
            pub fn signing_bytes(&self) -> Vec<u8> {
                let mut unsigned = self.clone();
                unsigned.sig = Vec::new();
                encode(&unsigned)
            }

            /// BLAKE3 of `signing_bytes`.
            pub fn digest(&self) -> [u8; 32] {
                *blake3::hash(&self.signing_bytes()).as_bytes()
            }

            /// Sets the signer's public key, then signs.
            pub fn sign(&mut self, keypair: &Keypair) {
                self.$signer = keypair.pubkey_bytes();
                self.sig = keypair.sign(&self.signing_bytes()).to_vec();
            }

            /// Checks the signature against the key named in the message.
            /// This proves integrity only; use `verify_from` to also pin who signed.
            pub fn verify(&self) -> Result<(), WireError> {
                check_sig(&self.$signer, &self.signing_bytes(), &self.sig)?;
                self.check_contents()
            }

            /// `verify`, and the signer must be `expected`.
            pub fn verify_from(&self, expected: &[u8; 32]) -> Result<(), WireError> {
                if &self.$signer != expected {
                    return Err(WireError::WrongSigner);
                }
                self.verify()
            }
        }
    };
}

signed_message!(WorkUnit, coordinator_pubkey);
signed_message!(Update, node_pubkey);
signed_message!(TeachingBatch, node_pubkey);
signed_message!(Receipt, coordinator_pubkey);

impl WorkUnit {
    pub fn new_signed(
        keypair: &Keypair,
        run_id: [u8; 16],
        round: u32,
        base_digest: [u8; 32],
        shard: Vec<u8>,
        steps: u32,
    ) -> Self {
        let mut unit = Self {
            run_id,
            round,
            base_digest,
            shard,
            steps,
            coordinator_pubkey: [0; 32],
            sig: Vec::new(),
        };
        unit.sign(keypair);
        unit
    }

    fn check_contents(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl Update {
    /// Builds and signs the answer to `unit`, copying its run, round, base
    /// and id so the update cannot be moved to another work unit.
    pub fn new_signed(keypair: &Keypair, unit: &WorkUnit, delta: CompressedDelta) -> Self {
        let mut update = Self {
            run_id: unit.run_id,
            round: unit.round,
            base_digest: unit.base_digest,
            work_unit_id: unit.digest(),
            node_pubkey: [0; 32],
            delta_digest: delta_digest(&delta),
            delta,
            sig: Vec::new(),
        };
        update.sign(keypair);
        update
    }

    /// `verify`, and the update must answer exactly `unit`.
    pub fn verify_for(&self, unit: &WorkUnit) -> Result<(), WireError> {
        if self.run_id != unit.run_id
            || self.round != unit.round
            || self.base_digest != unit.base_digest
            || self.work_unit_id != unit.digest()
        {
            return Err(WireError::WorkUnitMismatch);
        }
        self.verify()
    }

    fn check_contents(&self) -> Result<(), WireError> {
        if delta_digest(&self.delta) != self.delta_digest {
            return Err(WireError::DeltaDigestMismatch);
        }
        Ok(())
    }
}

impl Receipt {
    pub fn new_signed(keypair: &Keypair, update: &Update, turings: f64, accepted: bool) -> Self {
        let mut receipt = Self {
            run_id: update.run_id,
            round: update.round,
            update_digest: update.digest(),
            turings,
            accepted,
            coordinator_pubkey: [0; 32],
            sig: Vec::new(),
        };
        receipt.sign(keypair);
        receipt
    }

    fn check_contents(&self) -> Result<(), WireError> {
        Ok(())
    }
}

impl TeachingBatch {
    /// Builds and signs teaching text for `unit`, copying its run, round and
    /// starting model so the batch cannot be moved to another run or round.
    pub fn new_signed(keypair: &Keypair, unit: &WorkUnit, text: Vec<u8>) -> Self {
        let mut batch = Self {
            run_id: unit.run_id,
            round: unit.round,
            base_digest: unit.base_digest,
            node_pubkey: [0; 32],
            text_digest: text_digest(&text),
            text,
            sig: Vec::new(),
        };
        batch.sign(keypair);
        batch
    }

    /// `verify`, and the batch must belong to exactly `unit`'s run, round
    /// and starting model.
    pub fn verify_for(&self, unit: &WorkUnit) -> Result<(), WireError> {
        if self.run_id != unit.run_id
            || self.round != unit.round
            || self.base_digest != unit.base_digest
        {
            return Err(WireError::WorkUnitMismatch);
        }
        self.verify()
    }

    fn check_contents(&self) -> Result<(), WireError> {
        if text_digest(&self.text) != self.text_digest {
            return Err(WireError::TextDigestMismatch);
        }
        Ok(())
    }
}

impl Receipt {
    /// The signed verdict on a teaching batch. `update_digest` holds
    /// `TeachingBatch::digest`.
    pub fn for_teaching(
        keypair: &Keypair,
        batch: &TeachingBatch,
        turings: f64,
        accepted: bool,
    ) -> Self {
        let mut receipt = Self {
            run_id: batch.run_id,
            round: batch.round,
            update_digest: batch.digest(),
            turings,
            accepted,
            coordinator_pubkey: [0; 32],
            sig: Vec::new(),
        };
        receipt.sign(keypair);
        receipt
    }
}

/// Marks a frame that carries a `TeachingBatch`. Update frames are sent
/// without a tag, exactly as before teaching mode existed; an update frame
/// starts with its 16-byte run id, a BLAKE3-derived value, so it matches
/// this tag only with probability 2^-64.
pub const TEACHING_FRAME_TAG: &[u8; 8] = b"OHTEACH1";

/// What a volunteer can send back for a work unit.
#[derive(Debug, Clone, PartialEq)]
pub enum Submission {
    Update(Update),
    Teaching(TeachingBatch),
}

/// Writes a teaching batch as one tagged frame.
pub fn send_teaching<W: Write>(w: &mut W, batch: &TeachingBatch) -> Result<(), WireError> {
    let mut payload = TEACHING_FRAME_TAG.to_vec();
    payload.extend_from_slice(&encode(batch));
    write_frame(w, &payload)
}

/// Reads one frame and decodes it as a teaching batch if it carries the
/// teaching tag, otherwise as an update.
pub fn recv_submission<R: Read>(r: &mut R) -> Result<Submission, WireError> {
    let payload = read_frame(r)?;
    let decode_err = |e: bincode::Error| WireError::Decode(e.to_string());
    match payload.strip_prefix(TEACHING_FRAME_TAG.as_slice()) {
        Some(rest) => Ok(Submission::Teaching(
            bincode::deserialize(rest).map_err(decode_err)?,
        )),
        None => Ok(Submission::Update(
            bincode::deserialize(&payload).map_err(decode_err)?,
        )),
    }
}

/// Writes one frame: a 4-byte big-endian length, then the payload.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), WireError> {
    if payload.len() as u64 > MAX_FRAME_BYTES as u64 {
        return Err(WireError::FrameTooLarge(payload.len() as u64));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

/// Reads one frame. The length is checked against the cap before any
/// buffer is set aside for the payload.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>, WireError> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header);
    if len > MAX_FRAME_BYTES {
        return Err(WireError::FrameTooLarge(len as u64));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)?;
    Ok(payload)
}

/// Encodes `msg` with bincode and writes it as one frame.
pub fn send<W: Write, T: Serialize>(w: &mut W, msg: &T) -> Result<(), WireError> {
    write_frame(w, &encode(msg))
}

/// Reads one frame and decodes it with bincode.
pub fn recv<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T, WireError> {
    let payload = read_frame(r)?;
    bincode::deserialize(&payload).map_err(|e| WireError::Decode(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn unit(kp: &Keypair) -> WorkUnit {
        WorkUnit::new_signed(kp, [7; 16], 3, [9; 32], b"shard bytes".to_vec(), 100)
    }

    fn delta() -> CompressedDelta {
        CompressedDelta::compress(&[0.0, 0.5, -1.0, 0.25], 0.5)
    }

    #[test]
    fn test_work_unit_sign_then_verify() {
        let kp = Keypair::generate();
        let wu = unit(&kp);
        assert_eq!(wu.coordinator_pubkey, kp.pubkey_bytes());
        assert_eq!(wu.sig.len(), 64);
        wu.verify().unwrap();
        wu.verify_from(&kp.pubkey_bytes()).unwrap();
        assert!(matches!(
            wu.verify_from(&Keypair::generate().pubkey_bytes()),
            Err(WireError::WrongSigner)
        ));
    }

    #[test]
    fn test_flipped_shard_byte_fails_verify() {
        let kp = Keypair::generate();
        let mut wu = unit(&kp);
        wu.shard[0] ^= 1;
        assert!(matches!(wu.verify(), Err(WireError::BadSignature)));
    }

    #[test]
    fn test_missing_or_short_signature_fails_verify() {
        let kp = Keypair::generate();
        let mut wu = unit(&kp);
        wu.sig.truncate(63);
        assert!(matches!(wu.verify(), Err(WireError::BadSignature)));
        wu.sig.clear();
        assert!(matches!(wu.verify(), Err(WireError::BadSignature)));
    }

    #[test]
    fn test_update_binds_to_its_work_unit() {
        let coordinator = Keypair::generate();
        let node = Keypair::generate();
        let wu = unit(&coordinator);
        let up = Update::new_signed(&node, &wu, delta());
        assert_eq!(up.work_unit_id, wu.digest());
        assert_eq!(up.node_pubkey, node.pubkey_bytes());
        up.verify_for(&wu).unwrap();

        let other = WorkUnit::new_signed(
            &coordinator,
            [7; 16],
            4,
            [9; 32],
            b"shard bytes".to_vec(),
            100,
        );
        assert!(matches!(
            up.verify_for(&other),
            Err(WireError::WorkUnitMismatch)
        ));
    }

    #[test]
    fn test_tampered_update_fails_verify() {
        let wu = unit(&Keypair::generate());
        let node = Keypair::generate();
        let up = Update::new_signed(&node, &wu, delta());

        let mut changed_value = up.clone();
        changed_value.delta.values[0] = changed_value.delta.values[0].wrapping_add(1);
        assert!(changed_value.verify().is_err());

        let mut moved_round = up.clone();
        moved_round.round += 1;
        assert!(matches!(moved_round.verify(), Err(WireError::BadSignature)));

        // Re-signing a forged digest still fails: the digest must match the delta.
        let mut forged = up.clone();
        forged.delta.values[0] = 0;
        forged.sign(&node);
        assert!(matches!(
            forged.verify(),
            Err(WireError::DeltaDigestMismatch)
        ));
    }

    #[test]
    fn test_receipt_flipped_turings_fails_verify() {
        let coordinator = Keypair::generate();
        let wu = unit(&coordinator);
        let up = Update::new_signed(&Keypair::generate(), &wu, delta());
        let receipt = Receipt::new_signed(&coordinator, &up, 12.5, true);
        assert_eq!(receipt.update_digest, up.digest());
        receipt.verify_from(&coordinator.pubkey_bytes()).unwrap();

        let mut inflated = receipt.clone();
        inflated.turings = f64::from_bits(inflated.turings.to_bits() ^ 1);
        assert!(matches!(inflated.verify(), Err(WireError::BadSignature)));

        let mut flipped = receipt.clone();
        flipped.accepted = false;
        assert!(matches!(flipped.verify(), Err(WireError::BadSignature)));
    }

    #[test]
    fn test_digest_ignores_signature() {
        let wu = unit(&Keypair::generate());
        let mut resigned = wu.clone();
        resigned.sig = vec![0; 64];
        assert_eq!(wu.digest(), resigned.digest());
        assert_eq!(params_digest(&[1.0, 2.0]), params_digest(&[1.0, 2.0]));
        assert_ne!(params_digest(&[1.0, 2.0]), params_digest(&[2.0, 1.0]));
    }

    #[test]
    fn test_frame_round_trip() {
        let kp = Keypair::generate();
        let wu = unit(&kp);
        let mut buf = Vec::new();
        send(&mut buf, &wu).unwrap();
        write_frame(&mut buf, b"").unwrap();
        write_frame(&mut buf, b"second").unwrap();
        assert_eq!(
            &buf[..4],
            &((buf.len() - 4 - 4 - 4 - 6) as u32).to_be_bytes()
        );

        let mut cursor = Cursor::new(buf);
        let back: WorkUnit = recv(&mut cursor).unwrap();
        assert_eq!(back, wu);
        back.verify().unwrap();
        assert_eq!(read_frame(&mut cursor).unwrap(), b"");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"second");
        assert!(matches!(read_frame(&mut cursor), Err(WireError::Io(_))));
    }

    /// Only the 4-byte header is present. Reading the body would hit end of
    /// input, so `FrameTooLarge` shows the length was refused before any
    /// buffer was set aside or any body read was attempted.
    #[test]
    fn test_oversize_length_rejected_without_allocating() {
        let header = (MAX_FRAME_BYTES + 1).to_be_bytes();
        let mut cursor = Cursor::new(header.to_vec());
        assert!(matches!(
            read_frame(&mut cursor),
            Err(WireError::FrameTooLarge(n)) if n == MAX_FRAME_BYTES as u64 + 1
        ));

        let mut cursor = Cursor::new(u32::MAX.to_be_bytes().to_vec());
        assert!(matches!(
            read_frame(&mut cursor),
            Err(WireError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn test_truncated_frame_is_an_error() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        buf.truncate(buf.len() - 1);
        assert!(matches!(
            read_frame(&mut Cursor::new(buf)),
            Err(WireError::Io(_))
        ));
    }

    #[test]
    fn test_garbage_payload_is_a_decode_error() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &[1, 2, 3]).unwrap();
        let result: Result<WorkUnit, _> = recv(&mut Cursor::new(buf));
        assert!(matches!(result, Err(WireError::Decode(_))));
    }

    fn teaching(node: &Keypair, wu: &WorkUnit) -> TeachingBatch {
        TeachingBatch::new_signed(
            node,
            wu,
            b"A short clear passage about open models.".to_vec(),
        )
    }

    #[test]
    fn test_teaching_batch_sign_then_verify() {
        let wu = unit(&Keypair::generate());
        let node = Keypair::generate();
        let batch = teaching(&node, &wu);
        assert_eq!(batch.node_pubkey, node.pubkey_bytes());
        assert_eq!(batch.text_digest, text_digest(&batch.text));
        assert_eq!(batch.sig.len(), 64);
        batch.verify().unwrap();
        batch.verify_for(&wu).unwrap();
        batch.verify_from(&node.pubkey_bytes()).unwrap();

        // The signing bytes are the batch with `sig` emptied.
        let mut unsigned = batch.clone();
        unsigned.sig.clear();
        assert_eq!(batch.signing_bytes(), encode(&unsigned));
        assert_eq!(batch.digest(), *blake3::hash(&encode(&unsigned)).as_bytes());

        let next_round = WorkUnit::new_signed(&Keypair::generate(), [7; 16], 4, [9; 32], vec![], 1);
        assert!(matches!(
            batch.verify_for(&next_round),
            Err(WireError::WorkUnitMismatch)
        ));
    }

    #[test]
    fn test_tampered_teaching_batch_fails_verify() {
        let wu = unit(&Keypair::generate());
        let node = Keypair::generate();
        let batch = teaching(&node, &wu);

        let mut changed_text = batch.clone();
        changed_text.text[0] ^= 1;
        assert!(changed_text.verify().is_err());

        let mut moved_round = batch.clone();
        moved_round.round += 1;
        assert!(matches!(moved_round.verify(), Err(WireError::BadSignature)));

        let mut other_key = batch.clone();
        other_key.node_pubkey = Keypair::generate().pubkey_bytes();
        assert!(matches!(other_key.verify(), Err(WireError::BadSignature)));

        // Re-signing after changing the text still fails: the digest must match.
        let mut forged = batch.clone();
        forged.text.push(b'!');
        forged.sign(&node);
        assert!(matches!(
            forged.verify(),
            Err(WireError::TextDigestMismatch)
        ));
    }

    #[test]
    fn test_replayed_teaching_text_is_caught_by_the_ledger() {
        let path = std::env::temp_dir().join(format!(
            "oh-core-wire-{}-teach-replay.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let mut ledger = crate::scoring::Ledger::open(&path).unwrap();
        let wu = unit(&Keypair::generate());
        let batch = teaching(&Keypair::generate(), &wu);
        assert!(ledger.mark_seen(&batch.run_id, &batch.text_digest).unwrap());

        // The same text under another key is still a replay.
        let copied = teaching(&Keypair::generate(), &wu);
        assert_eq!(copied.text_digest, batch.text_digest);
        assert!(!ledger
            .mark_seen(&copied.run_id, &copied.text_digest)
            .unwrap());

        // Replay protection survives a restart.
        drop(ledger);
        let mut reopened = crate::scoring::Ledger::open(&path).unwrap();
        assert!(!reopened
            .mark_seen(&batch.run_id, &batch.text_digest)
            .unwrap());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_teaching_receipt_names_the_batch() {
        let coordinator = Keypair::generate();
        let wu = unit(&coordinator);
        let batch = teaching(&Keypair::generate(), &wu);
        let receipt = Receipt::for_teaching(&coordinator, &batch, 3.25, true);
        assert_eq!(receipt.update_digest, batch.digest());
        assert_eq!((receipt.run_id, receipt.round), (batch.run_id, batch.round));
        receipt.verify_from(&coordinator.pubkey_bytes()).unwrap();
        let mut inflated = receipt.clone();
        inflated.turings = 99.0;
        assert!(matches!(inflated.verify(), Err(WireError::BadSignature)));
    }

    #[test]
    fn test_submissions_dispatch_by_frame_tag() {
        let wu = unit(&Keypair::generate());
        let node = Keypair::generate();
        let update = Update::new_signed(&node, &wu, delta());
        let batch = teaching(&node, &wu);

        let mut buf = Vec::new();
        send(&mut buf, &update).unwrap();
        send_teaching(&mut buf, &batch).unwrap();
        let mut cursor = Cursor::new(buf.clone());
        assert_eq!(
            recv_submission(&mut cursor).unwrap(),
            Submission::Update(update.clone())
        );
        assert_eq!(
            recv_submission(&mut cursor).unwrap(),
            Submission::Teaching(batch.clone())
        );

        // An untagged update frame is byte for byte what `send` wrote before
        // teaching mode existed, so older volunteers still work.
        let update_frame_len = 4 + u32::from_be_bytes(buf[..4].try_into().unwrap()) as usize;
        let mut old = Vec::new();
        send(&mut old, &update).unwrap();
        assert_eq!(&buf[..update_frame_len], old.as_slice());

        // A tagged frame with a broken body is a decode error, not an update.
        let mut bad = TEACHING_FRAME_TAG.to_vec();
        bad.extend_from_slice(&[1, 2, 3]);
        let mut frame = Vec::new();
        write_frame(&mut frame, &bad).unwrap();
        assert!(matches!(
            recv_submission(&mut Cursor::new(frame)),
            Err(WireError::Decode(_))
        ));
    }

    #[test]
    fn test_base_model_digest_matches_its_params() {
        let base = BaseModel {
            dim: 2,
            params: vec![0.5, -1.0, 2.0],
        };
        assert_eq!(base.digest(), params_digest(&[0.5, -1.0, 2.0]));
        let mut buf = Vec::new();
        send(&mut buf, &base).unwrap();
        let back: BaseModel = recv(&mut Cursor::new(buf)).unwrap();
        assert_eq!(back, base);
    }
}
