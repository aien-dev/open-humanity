//! Wire messages for volunteer inference (protocol `OHINF001`).
//!
//! Every message travels as one bincode frame (`oh_core::send` / `recv`)
//! inside the encrypted transport (`oh_core::coordinator_handshake` /
//! `volunteer_handshake`). Signed messages are signed over a domain string
//! followed by their bincode bytes with `sig` emptied, so an inference
//! signature can never be replayed as a training-protocol signature.
//!
//! Privacy by type: a [`Job`] carries a model id, a list of chat messages,
//! a token limit and a seed. There is no field for a visitor key, a memory,
//! a contact, an address or any other visitor detail, so none can be sent.

use beacon_core::{verify_signature, Keypair};
use serde::{Deserialize, Serialize};

/// Protocol name and version, sent in the challenge and the attestation.
pub const PROTOCOL: [u8; 8] = *b"OHINF001";

const ATTEST_CONTEXT: &[u8] = b"open-humanity inference v0: attestation";
const COMPLETION_CONTEXT: &[u8] = b"open-humanity inference v0: completion";

/// Largest message list, message text and reply the protocol carries.
pub const MAX_MESSAGES: usize = 64;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("signature missing or invalid")]
    BadSignature,
    #[error("signed by an unexpected key")]
    WrongSigner,
    #[error("wrong protocol version")]
    WrongProtocol,
    #[error("attestation answers a different challenge")]
    WrongNonce,
    #[error("completion answers a different job")]
    WrongJob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    System,
    User,
    Assistant,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::System => "system",
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: Role,
    pub content: String,
}

/// One reply to write. Decoding is always greedy (temperature 0) with
/// `seed`, so the coordinator can replay a sampled job on its own engine
/// and expect the same text. The volunteer cannot tell a sampled job from
/// any other: every job looks like this.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Job {
    pub job_id: [u8; 16],
    pub model_id: String,
    pub messages: Vec<ChatMessage>,
    pub max_tokens: u32,
    pub seed: u64,
}

impl Job {
    /// BLAKE3 of the job's bincode bytes.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&bincode::serialize(self).expect("a job always encodes")).as_bytes()
    }
}

/// Coordinator to volunteer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CoordMsg {
    /// First message of a session: the pinned model and a fresh nonce the
    /// attestation must sign.
    Challenge {
        protocol: [u8; 8],
        nonce: [u8; 32],
        model_id: String,
        model_digest: [u8; 32],
    },
    /// The attestation passed; jobs may follow.
    Accepted {
        max_inflight: u32,
    },
    /// The session ends; the reason is safe to show the owner.
    Refused {
        reason: String,
    },
    Job(Job),
    /// Liveness check while idle. The volunteer answers with `Pong`.
    Ping {
        nonce: u64,
    },
    /// Sampled re-verification found a divergent reply; the key may not
    /// serve until the operator reinstates it.
    Suspended {
        reason: String,
    },
}

/// Volunteer to coordinator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VolMsg {
    Attest(Attestation),
    /// The next piece of the reply to the current job.
    Token {
        job_id: [u8; 16],
        text: String,
    },
    /// The whole reply, signed. Must equal the concatenated tokens.
    Done(Completion),
    /// The volunteer could not answer; the coordinator tells the gateway.
    Failed {
        job_id: [u8; 16],
        reason: String,
    },
    /// `accepting` is false while the owner has paused lending.
    Pong {
        nonce: u64,
        accepting: bool,
    },
}

/// The volunteer's claim, once per session, about what it serves. The
/// volunteer agent checks every weight file against the pinned manifest
/// before it sends this. A modified agent can lie here; sampled
/// re-verification is what catches a volunteer that serves something else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub protocol: [u8; 8],
    pub nonce: [u8; 32],
    pub node_pubkey: [u8; 32],
    pub model_id: String,
    /// SHA-256 of the model manifest bytes (one line per file with its
    /// SHA-256 and size), as pinned by the coordinator.
    pub model_digest: [u8; 32],
    /// SHA-256 of the engine binary, or all zero if not known.
    pub engine_digest: [u8; 32],
    pub sig: Vec<u8>,
}

/// The volunteer's signed reply to one job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Completion {
    pub job_id: [u8; 16],
    pub job_digest: [u8; 32],
    pub output: String,
    /// "stop" or "length".
    pub finish_reason: String,
    pub node_pubkey: [u8; 32],
    pub sig: Vec<u8>,
}

fn signing_bytes<T: Serialize>(context: &[u8], value: &T) -> Vec<u8> {
    let mut out = context.to_vec();
    out.extend_from_slice(&bincode::serialize(value).expect("a message always encodes"));
    out
}

fn check(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<(), ProtocolError> {
    let sig: [u8; 64] = sig.try_into().map_err(|_| ProtocolError::BadSignature)?;
    verify_signature(pubkey, msg, &sig).map_err(|_| ProtocolError::BadSignature)
}

impl Attestation {
    pub fn new_signed(
        keypair: &Keypair,
        nonce: [u8; 32],
        model_id: &str,
        model_digest: [u8; 32],
        engine_digest: [u8; 32],
    ) -> Self {
        let mut a = Attestation {
            protocol: PROTOCOL,
            nonce,
            node_pubkey: keypair.pubkey_bytes(),
            model_id: model_id.to_string(),
            model_digest,
            engine_digest,
            sig: Vec::new(),
        };
        a.sig = keypair.sign(&a.signing_bytes()).to_vec();
        a
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.sig = Vec::new();
        signing_bytes(ATTEST_CONTEXT, &unsigned)
    }

    /// Checks the signature, the protocol, the nonce and that the signer is
    /// the identity proven in the transport handshake.
    pub fn verify(&self, peer: &[u8; 32], nonce: &[u8; 32]) -> Result<(), ProtocolError> {
        if &self.node_pubkey != peer {
            return Err(ProtocolError::WrongSigner);
        }
        check(&self.node_pubkey, &self.signing_bytes(), &self.sig)?;
        if self.protocol != PROTOCOL {
            return Err(ProtocolError::WrongProtocol);
        }
        if &self.nonce != nonce {
            return Err(ProtocolError::WrongNonce);
        }
        Ok(())
    }
}

impl Completion {
    pub fn new_signed(keypair: &Keypair, job: &Job, output: String, finish_reason: &str) -> Self {
        let mut c = Completion {
            job_id: job.job_id,
            job_digest: job.digest(),
            output,
            finish_reason: finish_reason.to_string(),
            node_pubkey: keypair.pubkey_bytes(),
            sig: Vec::new(),
        };
        c.sig = keypair.sign(&c.signing_bytes()).to_vec();
        c
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.sig = Vec::new();
        signing_bytes(COMPLETION_CONTEXT, &unsigned)
    }

    pub fn verify(&self, peer: &[u8; 32], job: &Job) -> Result<(), ProtocolError> {
        if &self.node_pubkey != peer {
            return Err(ProtocolError::WrongSigner);
        }
        check(&self.node_pubkey, &self.signing_bytes(), &self.sig)?;
        if self.job_id != job.job_id || self.job_digest != job.digest() {
            return Err(ProtocolError::WrongJob);
        }
        Ok(())
    }
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job() -> Job {
        Job {
            job_id: [7; 16],
            model_id: "m".into(),
            messages: vec![ChatMessage {
                role: Role::User,
                content: "hi".into(),
            }],
            max_tokens: 16,
            seed: 1,
        }
    }

    #[test]
    fn attestation_binds_signer_nonce_and_model() {
        let kp = Keypair::generate();
        let a = Attestation::new_signed(&kp, [1; 32], "m", [2; 32], [0; 32]);
        assert_eq!(a.verify(&kp.pubkey_bytes(), &[1; 32]), Ok(()));
        assert_eq!(
            a.verify(&kp.pubkey_bytes(), &[9; 32]),
            Err(ProtocolError::WrongNonce)
        );
        assert_eq!(
            a.verify(&Keypair::generate().pubkey_bytes(), &[1; 32]),
            Err(ProtocolError::WrongSigner)
        );
        let mut forged = a.clone();
        forged.model_digest = [3; 32];
        assert_eq!(
            forged.verify(&kp.pubkey_bytes(), &[1; 32]),
            Err(ProtocolError::BadSignature)
        );
    }

    #[test]
    fn completion_binds_job_and_output() {
        let kp = Keypair::generate();
        let j = job();
        let c = Completion::new_signed(&kp, &j, "hello".into(), "stop");
        assert_eq!(c.verify(&kp.pubkey_bytes(), &j), Ok(()));
        let mut other = j.clone();
        other.seed = 2;
        assert_eq!(
            c.verify(&kp.pubkey_bytes(), &other),
            Err(ProtocolError::WrongJob)
        );
        let mut tampered = c.clone();
        tampered.output.push('!');
        assert_eq!(
            tampered.verify(&kp.pubkey_bytes(), &j),
            Err(ProtocolError::BadSignature)
        );
    }
}
