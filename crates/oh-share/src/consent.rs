//! Owner consent and the Discovery Capsule that carries one shared package.
//!
//! Field names follow the aien-protocols #51 drafts `OwnerConsentV1` and
//! `DiscoveryCapsuleV1`. The byte encoding here is Open Humanity local and
//! provisional (bincode, Ed25519, BLAKE3 from the existing beacon-core
//! signer) until the protocols crate publishes the canonical bytes.

use crate::codec::{signed_message, MAX_CAPSULE_BYTES, MAX_CONTROL_BYTES};
use serde::{Deserialize, Serialize};

/// An Ed25519 public key.
pub type Key = [u8; 32];
/// Random id of one shared package. It is never derived from the content,
/// so a package id or tombstone does not link back to the shared text.
pub type PackageId = [u8; 16];

pub const CONSENT_VERSION: u16 = 1;
pub const CAPSULE_VERSION: u16 = 1;

/// Uses an owner can grant and later withdraw. One bit vocabulary serves
/// consent grants and retraction scopes; unknown bits fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Uses(pub u8);

impl Uses {
    /// Serve or read the package back (retrieval).
    pub const RETRIEVAL: Uses = Uses(1);
    /// Pass the package on to anyone else.
    pub const REPUBLICATION: Uses = Uses(2);
    /// List the package metadata in a research index.
    pub const INDEX: Uses = Uses(4);
    /// Train any model on the package. Never implied by any other bit.
    pub const TRAINING: Uses = Uses(8);
    /// Keep in an owner-controlled private archive. Not public learning.
    pub const ARCHIVE: Uses = Uses(16);
    pub const NONE: Uses = Uses(0);
    pub const ALL: Uses = Uses(31);

    pub fn contains(self, other: Uses) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn union(self, other: Uses) -> Uses {
        Uses(self.0 | other.0)
    }

    /// False when any bit outside the known vocabulary is set.
    pub fn is_known(self) -> bool {
        self.0 & !Uses::ALL.0 == 0
    }
}

/// What a receiver may do with a package once it holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UseAction {
    Serve,
    Republish,
    Index,
    Train,
    Archive,
}

impl UseAction {
    pub fn required(self) -> Uses {
        match self {
            UseAction::Serve => Uses::RETRIEVAL,
            UseAction::Republish => Uses::REPUBLICATION,
            UseAction::Index => Uses::INDEX,
            UseAction::Train => Uses::TRAINING,
            UseAction::Archive => Uses::ARCHIVE,
        }
    }
}

/// The owner's signed grant of one package to one exact recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerConsent {
    pub version: u16,
    /// The owner's first (genesis) key: the stable pseudonymous identity.
    pub owner_id: Key,
    /// The owner key that signed this consent (current after rotations).
    pub signer: Key,
    pub package_id: PackageId,
    /// The one recipient this grant names.
    pub recipient: Key,
    pub uses: Uses,
    /// License identifier; receivers accept only licenses they list.
    pub license: String,
    /// After this time (unix seconds) no use is permitted.
    pub retention_end: u64,
    /// Keys the owner declares may sign a retraction on the owner's behalf.
    /// A custodian can only withdraw; it can never grant.
    pub custodians: Vec<Key>,
    pub issued_at: u64,
    /// The owner's sequence number when this consent was issued.
    pub seq: u64,
    pub sig: Vec<u8>,
}

signed_message!(
    OwnerConsent,
    signer,
    b"open-humanity share v1: owner consent\0",
    MAX_CONTROL_BYTES
);

impl OwnerConsent {
    /// The terms that two consents for one package must agree on.
    pub fn same_terms(&self, other: &OwnerConsent) -> bool {
        self.owner_id == other.owner_id
            && self.package_id == other.package_id
            && self.recipient == other.recipient
            && self.uses == other.uses
            && self.license == other.license
            && self.retention_end == other.retention_end
            && self.custodians == other.custodians
    }
}

/// The exact environment a capsule claims to apply to. A receiver compares
/// every field to its own environment; there is no partial match.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Environment {
    pub abi: String,
    pub model: String,
    pub precision: String,
    pub hardware: String,
}

/// Capabilities a capsule asks the receiver to allow. Possessing a capsule
/// grants none of them; the receiver's own policy decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capabilities(pub u16);

impl Capabilities {
    /// Read the capsule as inert data.
    pub const DATA_READ: Capabilities = Capabilities(1);
    /// Re-run the claim under the receiver's own verifier.
    pub const REPRODUCE: Capabilities = Capabilities(2);
    /// Build and run native code from the procedure on the receiver.
    pub const NATIVE_EXECUTE: Capabilities = Capabilities(4);
    /// Open network connections.
    pub const NETWORK_EGRESS: Capabilities = Capabilities(8);
    /// Write outside the receiver's sandbox.
    pub const FILE_WRITE: Capabilities = Capabilities(16);
    /// Call tools or services on the receiver.
    pub const TOOL_CALL: Capabilities = Capabilities(32);
    pub const KNOWN: Capabilities = Capabilities(63);
    /// External effects no capsule is ever allowed to request.
    pub const EXTERNAL_EFFECTS: Capabilities = Capabilities(8 | 16 | 32);

    pub fn contains(self, other: Capabilities) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn intersects(self, other: Capabilities) -> bool {
        self.0 & other.0 != 0
    }
}

/// How strong the sender says its evidence is. Receivers record it and
/// never act on it: a claim is reproduced only by the receiver's verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceTier {
    /// The sender ran it once.
    SelfReported,
    /// A verifier the sender names re-ran it.
    IndependentlyVerified,
    /// A counterexample or failed replication.
    Negative,
}

/// The sender's evidence claim, carried as untrusted data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub tier: EvidenceTier,
    pub verifier: Key,
    pub claim: String,
}

/// The shared content: a validated `.om` procedure, its trace and outcome,
/// already sanitized and approved by the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsulePayload {
    pub program: String,
    pub trace: String,
    pub outcome: String,
}

impl CapsulePayload {
    /// BLAKE3 of the encoding.
    pub fn digest(&self) -> [u8; 32] {
        let bytes = crate::codec::encode(self, u64::MAX).expect("plain strings always encode");
        *blake3::hash(&bytes).as_bytes()
    }

    /// All text fields, for the firewall scan.
    pub fn texts(&self) -> [&str; 3] {
        [&self.program, &self.trace, &self.outcome]
    }
}

/// Signed capsule header. The signature covers `content_digest`, not the
/// payload bytes, so an edited payload is caught as a digest mismatch and
/// an edited header as a bad signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleHeader {
    pub version: u16,
    pub capsule_id: [u8; 16],
    /// Earlier revision this one replaces, if any.
    pub parent: Option<[u8; 16]>,
    pub consent: OwnerConsent,
    pub content_digest: [u8; 32],
    pub environment: Environment,
    pub capabilities: Capabilities,
    pub evidence: Evidence,
    pub created_at: u64,
    /// After this time the capsule is stale.
    pub expires_at: u64,
    /// The owner's highest retraction sequence number at signing time.
    pub revocation_head: u64,
    pub signer: Key,
    pub sig: Vec<u8>,
}

signed_message!(
    CapsuleHeader,
    signer,
    b"open-humanity share v1: capsule header\0",
    MAX_CAPSULE_BYTES
);

/// One capsule: signed header plus the payload it names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capsule {
    pub header: CapsuleHeader,
    pub payload: CapsulePayload,
}

impl Capsule {
    /// Encodes the capsule, refusing one over `MAX_CAPSULE_BYTES`.
    pub fn encode(&self) -> Result<Vec<u8>, crate::codec::CodecError> {
        crate::codec::encode(self, MAX_CAPSULE_BYTES)
    }
}
