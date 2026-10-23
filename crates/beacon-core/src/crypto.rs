//! Cryptographic primitives for Open Humanity nanobeacons and capsules.
//!
//! Provides Ed25519 node authentication and X25519-ChaCha20-Poly1305
//! end-to-end authenticated payload encryption.

use crate::schema::BeaconError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashSet;
use uuid::Uuid;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

pub const MAX_TIMESTAMP_DRIFT_SECS: u64 = 300;

pub struct Keypair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Rebuilds the keypair whose 32-byte Ed25519 secret seed is `seed`
    /// (ed25519-dalek `SigningKey::from_bytes`). The same seed always gives
    /// the same keypair, so an identity can outlive one process.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn pubkey_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

pub fn verify_signature(
    pubkey: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), BeaconError> {
    let verifying_key =
        VerifyingKey::from_bytes(pubkey).map_err(|_| BeaconError::SignatureVerificationFailed)?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| BeaconError::SignatureVerificationFailed)
}

pub struct EncryptedPayload {
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub fn encrypt_to_peer(
    peer_x25519_pubkey: &[u8; 32],
    plaintext: &[u8],
) -> Result<EncryptedPayload, BeaconError> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pubkey = X25519PublicKey::from(&ephemeral_secret);

    let peer_public = X25519PublicKey::from(*peer_x25519_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&peer_public);

    if !shared_secret.was_contributory() {
        return Err(BeaconError::KeyAgreementFailed);
    }
    let key = Key::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| BeaconError::Serialization("Encryption failed".into()))?;

    Ok(EncryptedPayload {
        ephemeral_pubkey: *ephemeral_pubkey.as_bytes(),
        nonce: nonce_bytes,
        ciphertext,
    })
}

pub fn decrypt_from_peer(
    my_x25519_secret: &StaticSecret,
    sender_ephemeral_pubkey: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, BeaconError> {
    let sender_public = X25519PublicKey::from(*sender_ephemeral_pubkey);
    let shared_secret = my_x25519_secret.diffie_hellman(&sender_public);

    if !shared_secret.was_contributory() {
        return Err(BeaconError::KeyAgreementFailed);
    }
    let key = Key::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BeaconError::DecryptionFailed)
}

/// One side of an X25519 key agreement with a one-time secret, for setting
/// up a session. The secret is used once (`agree` consumes it) and is wiped
/// when dropped (x25519-dalek zeroizes it).
pub struct EphemeralKeyAgreement {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl EphemeralKeyAgreement {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = *X25519PublicKey::from(&secret).as_bytes();
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// The X25519 shared secret with `peer_public`. Refuses a peer key that
    /// gives an all-zero (non-contributory) result, such as a low-order point.
    pub fn agree(self, peer_public: &[u8; 32]) -> Result<[u8; 32], BeaconError> {
        let shared = self
            .secret
            .diffie_hellman(&X25519PublicKey::from(*peer_public));
        if !shared.was_contributory() {
            return Err(BeaconError::KeyAgreementFailed);
        }
        Ok(*shared.as_bytes())
    }
}

/// ChaCha20-Poly1305 under one fixed key, with the nonce chosen by the
/// caller. The caller must never use the same nonce twice under one key.
pub struct SessionCipher(ChaCha20Poly1305);

impl SessionCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(ChaCha20Poly1305::new(Key::from_slice(key)))
    }

    /// Encrypts `plaintext` and binds `aad` (sent in the clear) to it.
    pub fn seal(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, BeaconError> {
        self.0
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| BeaconError::Serialization("Encryption failed".into()))
    }

    /// Decrypts and checks `ciphertext` against `nonce` and `aad`. Any
    /// change to the ciphertext, nonce or aad fails.
    pub fn open(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, BeaconError> {
        self.0
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| BeaconError::DecryptionFailed)
    }
}

pub fn verify_timestamp_drift(
    timestamp: u64,
    current_time: u64,
    max_drift_secs: u64,
) -> Result<(), BeaconError> {
    let diff = if timestamp >= current_time {
        timestamp - current_time
    } else {
        current_time - timestamp
    };
    if diff > max_drift_secs {
        return Err(BeaconError::TimestampDrift {
            drift_secs: diff,
            max_allowed: max_drift_secs,
        });
    }
    Ok(())
}

/// Bounded per-session history. Full capacity refuses new IDs without eviction.
/// Restart/new instances require an authenticated higher-level freshness rule.
#[derive(Debug, Clone)]
pub struct ReplayProtector {
    seen: HashSet<Uuid>,
    max_capacity: usize,
}

impl ReplayProtector {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            max_capacity,
        }
    }

    pub fn check_and_record(&mut self, packet_id: &Uuid) -> Result<(), BeaconError> {
        if self.seen.contains(packet_id) {
            return Err(BeaconError::ReplayDetected(*packet_id));
        }
        if self.seen.len() >= self.max_capacity {
            return Err(BeaconError::ReplayCapacityExceeded(self.max_capacity));
        }
        self.seen.insert(*packet_id);
        Ok(())
    }

    pub fn is_seen(&self, packet_id: &Uuid) -> bool {
        self.seen.contains(packet_id)
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_from_seed_is_stable_and_signs() {
        let a = Keypair::from_seed(&[7u8; 32]);
        let b = Keypair::from_seed(&[7u8; 32]);
        let c = Keypair::from_seed(&[8u8; 32]);
        assert_eq!(a.pubkey_bytes(), b.pubkey_bytes());
        assert_ne!(a.pubkey_bytes(), c.pubkey_bytes());
        let sig = a.sign(b"hello");
        assert!(verify_signature(&b.pubkey_bytes(), b"hello", &sig).is_ok());
        assert!(verify_signature(&c.pubkey_bytes(), b"hello", &sig).is_err());
    }

    #[test]
    fn test_ephemeral_agreement_matches_on_both_sides() {
        let a = EphemeralKeyAgreement::generate();
        let b = EphemeralKeyAgreement::generate();
        let (a_pub, b_pub) = (a.public_bytes(), b.public_bytes());
        assert_eq!(a.agree(&b_pub).unwrap(), b.agree(&a_pub).unwrap());
    }

    #[test]
    fn test_ephemeral_agreement_refuses_low_order_point() {
        let a = EphemeralKeyAgreement::generate();
        assert!(matches!(
            a.agree(&[0u8; 32]),
            Err(BeaconError::KeyAgreementFailed)
        ));
    }

    #[test]
    fn test_session_cipher_round_trip_and_tamper() {
        let c = SessionCipher::new(&[7u8; 32]);
        let nonce = [1u8; 12];
        let sealed = c.seal(&nonce, b"hdr", b"hello").unwrap();
        assert_eq!(c.open(&nonce, b"hdr", &sealed).unwrap(), b"hello");
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(c.open(&nonce, b"hdr", &bad).is_err());
        assert!(c.open(&[2u8; 12], b"hdr", &sealed).is_err());
        assert!(c.open(&nonce, b"HDR", &sealed).is_err());
    }
}

#[cfg(test)]
#[path = "crypto_hardening_tests.rs"]
mod hardening_tests;
