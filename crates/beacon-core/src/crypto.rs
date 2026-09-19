//! Cryptographic primitives for Open Humanity nanobeacons and capsules.
//!
//! Provides Ed25519 node authentication and X25519-ChaCha20-Poly1305
//! end-to-end authenticated payload encryption.

use crate::schema::BeaconError;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

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
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|_| BeaconError::SignatureVerificationFailed)?;
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

    let key = Key::from_slice(shared_secret.as_bytes());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BeaconError::DecryptionFailed)
}
