//! Bounded encoding, sealed envelopes and small frames for sharing messages.
//!
//! Every message is bincode 1.3 with fixed-width integers, a hard size limit
//! and no trailing bytes, so a decoder never allocates more than the limit
//! and two encoders always agree on the bytes that are signed. Sealing reuses
//! the beacon-core X25519 + ChaCha20-Poly1305 helpers; nothing here is new
//! cryptography.

use beacon_core::{decrypt_from_peer, encrypt_to_peer, verify_signature};
use bincode::Options;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::io::{Read, Write};
use x25519_dalek::StaticSecret;

/// Largest encoded notice, acknowledgement or key rotation.
pub const MAX_CONTROL_BYTES: u64 = 4096;
/// Largest encoded capsule (header plus payload) a receiver will open.
pub const MAX_CAPSULE_BYTES: u64 = 256 * 1024;
/// Magic at the start of a sealed envelope.
pub const SEAL_MAGIC: &[u8; 8] = b"OHSEAL01";
/// `magic[8] || ephemeral[32] || nonce[12]` before the ciphertext.
pub const SEAL_HEADER_LEN: usize = 8 + 32 + 12;
/// ChaCha20-Poly1305 tag bytes.
pub const SEAL_TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    #[error("message exceeds the {0} byte limit")]
    TooLarge(u64),
    #[error("could not decode message: {0}")]
    Decode(String),
    #[error("envelope does not open with this key")]
    Undecryptable,
    #[error("envelope magic or header is wrong")]
    BadEnvelope,
    #[error("i/o error: {0}")]
    Io(String),
}

fn options(limit: u64) -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(limit)
        .reject_trailing_bytes()
}

/// Encodes `value` within `limit` bytes.
pub fn encode<T: Serialize>(value: &T, limit: u64) -> Result<Vec<u8>, CodecError> {
    options(limit)
        .serialize(value)
        .map_err(|_| CodecError::TooLarge(limit))
}

/// Decodes exactly one value from `bytes`, refusing anything over `limit`.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], limit: u64) -> Result<T, CodecError> {
    if bytes.len() as u64 > limit {
        return Err(CodecError::TooLarge(limit));
    }
    options(limit)
        .deserialize(bytes)
        .map_err(|e| CodecError::Decode(e.to_string()))
}

/// Encrypts `plaintext` to the holder of the X25519 key `box_pubkey`.
pub fn seal(box_pubkey: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CodecError> {
    let sealed = encrypt_to_peer(box_pubkey, plaintext).map_err(|_| CodecError::Undecryptable)?;
    let mut out = Vec::with_capacity(SEAL_HEADER_LEN + sealed.ciphertext.len());
    out.extend_from_slice(SEAL_MAGIC);
    out.extend_from_slice(&sealed.ephemeral_pubkey);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    Ok(out)
}

/// Opens an envelope made by `seal`. The envelope size is checked against
/// `limit` (plaintext limit plus seal overhead) before any decryption.
pub fn open(secret: &StaticSecret, envelope: &[u8], limit: u64) -> Result<Vec<u8>, CodecError> {
    let overhead = (SEAL_HEADER_LEN + SEAL_TAG_LEN) as u64;
    if envelope.len() as u64 > limit + overhead {
        return Err(CodecError::TooLarge(limit));
    }
    if envelope.len() < SEAL_HEADER_LEN + SEAL_TAG_LEN || &envelope[..8] != SEAL_MAGIC {
        return Err(CodecError::BadEnvelope);
    }
    let ephemeral: [u8; 32] = envelope[8..40].try_into().expect("32 bytes");
    let nonce: [u8; 12] = envelope[40..52].try_into().expect("12 bytes");
    decrypt_from_peer(secret, &ephemeral, &nonce, &envelope[SEAL_HEADER_LEN..])
        .map_err(|_| CodecError::Undecryptable)
}

/// Writes `len[4, big endian] || payload`.
pub fn write_frame<W: Write>(w: &mut W, payload: &[u8], limit: u64) -> Result<(), CodecError> {
    if payload.len() as u64 > limit {
        return Err(CodecError::TooLarge(limit));
    }
    let io = |e: std::io::Error| CodecError::Io(e.to_string());
    w.write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(io)?;
    w.write_all(payload).map_err(io)?;
    w.flush().map_err(io)
}

/// Reads one frame, checking the declared length against `limit` before
/// setting aside any buffer.
pub fn read_frame<R: Read>(r: &mut R, limit: u64) -> Result<Vec<u8>, CodecError> {
    let io = |e: std::io::Error| CodecError::Io(e.to_string());
    let mut header = [0u8; 4];
    r.read_exact(&mut header).map_err(io)?;
    let len = u32::from_be_bytes(header) as u64;
    if len > limit {
        return Err(CodecError::TooLarge(limit));
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload).map_err(io)?;
    Ok(payload)
}

/// True when `sig` is a valid Ed25519 signature by `pubkey` over `message`.
pub fn signature_ok(pubkey: &[u8; 32], message: &[u8], sig: &[u8]) -> bool {
    match <[u8; 64]>::try_from(sig) {
        Ok(sig) => verify_signature(pubkey, message, &sig).is_ok(),
        Err(_) => false,
    }
}

/// Signing support for a message with a `sig: Vec<u8>` field and a signer
/// key field. The signed bytes are a per-type context string followed by the
/// message encoded with `sig` emptied, so a signature over one message type
/// can never be replayed as another.
macro_rules! signed_message {
    ($ty:ty, $signer:ident, $context:expr, $limit:expr) => {
        impl $ty {
            /// Context string followed by the encoding with `sig` emptied.
            pub fn signing_bytes(&self) -> Vec<u8> {
                let mut unsigned = self.clone();
                unsigned.sig = Vec::new();
                let mut out = $context.to_vec();
                out.extend_from_slice(
                    &$crate::codec::encode(&unsigned, u64::MAX)
                        .expect("plain structs always encode"),
                );
                out
            }

            /// BLAKE3 of `signing_bytes`: names this exact message.
            pub fn digest(&self) -> [u8; 32] {
                *blake3::hash(&self.signing_bytes()).as_bytes()
            }

            /// Sets the signer key from `keypair` and signs.
            pub fn sign_with(&mut self, keypair: &beacon_core::Keypair) {
                self.$signer = keypair.pubkey_bytes();
                self.sig = keypair.sign(&self.signing_bytes()).to_vec();
            }

            /// True when the signature verifies under the named signer key.
            /// Says nothing about whether that key is authorized.
            pub fn signature_valid(&self) -> bool {
                $crate::codec::signature_ok(&self.$signer, &self.signing_bytes(), &self.sig)
            }

            /// Encodes the signed message, refusing one over its size limit.
            pub fn to_bytes(&self) -> Result<Vec<u8>, $crate::codec::CodecError> {
                $crate::codec::encode(self, $limit)
            }

            /// Decodes one message, refusing anything over the size limit.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, $crate::codec::CodecError> {
                $crate::codec::decode(bytes, $limit)
            }
        }
    };
}
pub(crate) use signed_message;
