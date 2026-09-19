use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use thiserror::Error;
use uuid::Uuid;

pub const MAGIC_BYTES: [u8; 2] = [0x4F, 0x48]; // "OH"
pub const PROTOCOL_VERSION: u8 = 1;
pub const MAX_DATAGRAM_SIZE: usize = 1200;

mod serde_bytes_64 {
    use super::*;
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if v.len() != 64 {
            return Err(D::Error::custom("expected exactly 64 bytes for signature"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&v);
        Ok(arr)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum BeaconError {
    #[error("Datagram exceeds maximum size limit of {0} bytes (got {1})")]
    DatagramTooLarge(usize, usize),
    #[error("Invalid magic bytes: expected [0x4F, 0x48], got {0:?}")]
    InvalidMagic([u8; 2]),
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    #[error("Serialization failed: {0}")]
    Serialization(String),
    #[error("Deserialization failed: {0}")]
    Deserialization(String),
    #[error("Cryptographic signature verification failed")]
    SignatureVerificationFailed,
    #[error("Cryptographic decryption failed")]
    DecryptionFailed,
    #[error("Timestamp drift exceeded: {drift_secs}s exceeds limit of {max_allowed}s")]
    TimestampDrift { drift_secs: u64, max_allowed: u64 },
    #[error("Replay attack detected for packet ID: {0}")]
    ReplayDetected(Uuid),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum BeaconTopic {
    RustCompilation = 0,
    MojoSimd = 1,
    ModularMaxServing = 2,
    HardwareTopology = 3,
    SecurityAudit = 4,
    ProtocolCoordination = 5,
    AgentRecursion = 6,
}

impl BeaconTopic {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RustCompilation => "rust-compilation",
            Self::MojoSimd => "mojo-simd",
            Self::ModularMaxServing => "modular-max-serving",
            Self::HardwareTopology => "hardware-topology",
            Self::SecurityAudit => "security-audit",
            Self::ProtocolCoordination => "protocol-coordination",
            Self::AgentRecursion => "agent-recursion",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorFingerprint {
    pub hash: [u8; 32],
    pub compiler_code: Option<u32>,
    pub hardware_arch: String,
}

impl ErrorFingerprint {
    pub fn from_error_str(error_text: &str, compiler_code: Option<u32>, arch: &str) -> Self {
        let hash = *blake3::hash(error_text.as_bytes()).as_bytes();
        Self {
            hash,
            compiler_code,
            hardware_arch: arch.to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistressNanobeacon {
    pub magic: [u8; 2],
    pub version: u8,
    pub beacon_id: Uuid,
    pub timestamp: u64,
    pub topic: BeaconTopic,
    pub sender_pubkey: [u8; 32],
    pub ephemeral_dh_pubkey: [u8; 32],
    pub fingerprint: ErrorFingerprint,
    pub title: String,
    pub compact_summary: String,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

impl DistressNanobeacon {
    pub fn new(
        topic: BeaconTopic,
        sender_pubkey: [u8; 32],
        ephemeral_dh_pubkey: [u8; 32],
        fingerprint: ErrorFingerprint,
        title: String,
        compact_summary: String,
    ) -> Self {
        Self {
            magic: MAGIC_BYTES,
            version: PROTOCOL_VERSION,
            beacon_id: Uuid::now_v7(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            topic,
            sender_pubkey,
            ephemeral_dh_pubkey,
            fingerprint,
            title,
            compact_summary,
            signature: [0u8; 64],
        }
    }

    pub fn signable_bytes(&self) -> Result<Vec<u8>, BeaconError> {
        let mut clone = self.clone();
        clone.signature = [0u8; 64];
        bincode::serialize(&clone).map_err(|e| BeaconError::Serialization(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BeaconError> {
        let bytes = bincode::serialize(self)
            .map_err(|e| BeaconError::Serialization(e.to_string()))?;
        if bytes.len() > MAX_DATAGRAM_SIZE {
            return Err(BeaconError::DatagramTooLarge(MAX_DATAGRAM_SIZE, bytes.len()));
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BeaconError> {
        if bytes.len() > MAX_DATAGRAM_SIZE {
            return Err(BeaconError::DatagramTooLarge(MAX_DATAGRAM_SIZE, bytes.len()));
        }
        if bytes.len() < 3 {
            return Err(BeaconError::Deserialization("Packet too short".into()));
        }
        if bytes[0..2] != MAGIC_BYTES {
            return Err(BeaconError::InvalidMagic([bytes[0], bytes[1]]));
        }
        if bytes[2] != PROTOCOL_VERSION {
            return Err(BeaconError::UnsupportedVersion(bytes[2]));
        }

        let beacon: Self = bincode::deserialize(bytes)
            .map_err(|e| BeaconError::Deserialization(e.to_string()))?;
        Ok(beacon)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionCapsule {
    pub beacon_id: Uuid,
    pub responder_pubkey: [u8; 32],
    pub ephemeral_dh_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

impl ResolutionCapsule {
    pub fn new(
        beacon_id: Uuid,
        responder_pubkey: [u8; 32],
        ephemeral_dh_pubkey: [u8; 32],
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            beacon_id,
            responder_pubkey,
            ephemeral_dh_pubkey,
            nonce,
            ciphertext,
            signature: [0u8; 64],
        }
    }

    pub fn signable_bytes(&self) -> Result<Vec<u8>, BeaconError> {
        let mut clone = self.clone();
        clone.signature = [0u8; 64];
        bincode::serialize(&clone).map_err(|e| BeaconError::Serialization(e.to_string()))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, BeaconError> {
        bincode::serialize(self).map_err(|e| BeaconError::Serialization(e.to_string()))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BeaconError> {
        bincode::deserialize(bytes).map_err(|e| BeaconError::Deserialization(e.to_string()))
    }
}
